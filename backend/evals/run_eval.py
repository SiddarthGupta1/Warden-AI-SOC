"""
Evaluation harness for the Sentinel triage agent.

Runs the agent over a labeled incident set and reports verdict accuracy, the
errors that actually matter in a SOC (missed threats vs false alarms), MITRE
technique agreement, latency, confidence calibration and token usage.

Usage (from the backend/ directory, with the venv active):

    python -m evals.run_eval
    python -m evals.run_eval --limit 4
    python -m evals.run_eval --out evals/results/run1.json
    python -m evals.run_eval --price-in 0.25 --price-out 2.00   # USD per 1M tokens

Safety: Sentinel comment write-back is force-disabled for the duration of the
run, so evaluating against a live workspace never posts to real incidents.
"""

import argparse
import asyncio
import json
import re
import statistics
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.config import settings
from app.agent.triage_agent import triage_agent

VERDICTS = ["TRUE_POSITIVE", "FALSE_POSITIVE", "SUSPICIOUS_ESCALATE", "BENIGN"]
MALICIOUS_VERDICTS = {"TRUE_POSITIVE"}
BENIGN_VERDICTS = {"FALSE_POSITIVE", "BENIGN"}
TECHNIQUE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

DEFAULT_DATASET = Path(__file__).parent / "dataset"


def load_cases(path: Path) -> List[Dict[str, Any]]:
    """Load labeled cases from a single JSON file or every *.json in a directory."""
    files = sorted(path.glob("*.json")) if path.is_dir() else [path]
    if not files:
        raise SystemExit(f"No dataset files found at {path}")

    cases: List[Dict[str, Any]] = []
    seen: Dict[str, str] = {}
    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        for case in data.get("incidents", []):
            cid = case["incident"].get("id")
            if cid in seen:
                raise SystemExit(f"Duplicate incident id '{cid}' in {f.name} (already in {seen[cid]})")
            seen[cid] = f.name
            case.setdefault("_source", f.stem)
            cases.append(case)
    return cases


def normalize_techniques(raw: Any) -> set:
    """Pull bare ATT&CK IDs out of whatever shape the model returned.

    Handles "T1059.001", "T1059.001 - PowerShell" and nested dict/list forms.
    """
    found = set()

    def walk(node):
        if isinstance(node, str):
            found.update(TECHNIQUE_RE.findall(node))
        elif isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, (list, tuple)):
            for v in node:
                walk(v)

    walk(raw)
    return found


class UsageRecorder:
    """Wraps the agent's OpenAI client to capture token usage per call."""

    def __init__(self, agent):
        self.agent = agent
        self.calls: List[Dict[str, int]] = []
        self._original = None

    def __enter__(self):
        client = getattr(self.agent, "openai_client", None)
        if client is None:
            return self
        completions = client.chat.completions
        self._original = completions.create

        def wrapped(*args, **kwargs):
            response = self._original(*args, **kwargs)
            usage = getattr(response, "usage", None)
            if usage is not None:
                self.calls.append({
                    "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                    "completion_tokens": getattr(usage, "completion_tokens", 0) or 0,
                    "reasoning_tokens": getattr(
                        getattr(usage, "completion_tokens_details", None),
                        "reasoning_tokens", 0) or 0,
                })
            return response

        completions.create = wrapped
        return self

    def __exit__(self, *exc):
        if self._original is not None:
            self.agent.openai_client.chat.completions.create = self._original
        return False

    def drain(self) -> Dict[str, int]:
        totals = {"prompt_tokens": 0, "completion_tokens": 0, "reasoning_tokens": 0, "llm_calls": len(self.calls)}
        for c in self.calls:
            for k in ("prompt_tokens", "completion_tokens", "reasoning_tokens"):
                totals[k] += c[k]
        self.calls.clear()
        return totals


async def run_one(case: Dict[str, Any], recorder: UsageRecorder) -> Dict[str, Any]:
    incident = case["incident"]
    expected = case["expected"]

    start = time.perf_counter()
    error = None
    report: Dict[str, Any] = {}
    try:
        report = await triage_agent.triage_incident(incident)
    except Exception as exc:  # noqa: BLE001 - we want the eval to survive agent failures
        error = f"{type(exc).__name__}: {exc}"
    elapsed = time.perf_counter() - start

    predicted = (report or {}).get("verdict") or "ERROR"
    exp_verdict = expected["verdict"]

    exp_tech = set(expected.get("techniques") or [])
    got_tech = normalize_techniques((report or {}).get("mitre_attack"))

    if exp_tech:
        hits = len(exp_tech & got_tech)
        recall = hits / len(exp_tech)
        precision = hits / len(got_tech) if got_tech else 0.0
    else:
        recall = precision = None  # not scored for benign cases

    # The two errors a SOC actually cares about.
    missed_threat = exp_verdict in MALICIOUS_VERDICTS and predicted in BENIGN_VERDICTS
    false_alarm = exp_verdict in BENIGN_VERDICTS and predicted in MALICIOUS_VERDICTS

    return {
        "id": incident.get("id"),
        "category": case.get("_source", "core"),
        "title": incident.get("title"),
        "expected": exp_verdict,
        "predicted": predicted,
        "correct": predicted == exp_verdict,
        "missed_threat": missed_threat,
        "false_alarm": false_alarm,
        # Field was renamed confidence_score -> evidence_completeness; read either so the
        # harness still scores reports produced by older builds.
        "confidence": (report or {}).get("evidence_completeness", (report or {}).get("confidence_score")),
        "evidence_gaps": (report or {}).get("evidence_gaps") or [],
        "evidence_gap_count": len((report or {}).get("evidence_gaps") or []),
        "model_used": (report or {}).get("model_used"),
        "reasoning_tier": (report or {}).get("reasoning_tier"),
        "expected_techniques": sorted(exp_tech),
        "predicted_techniques": sorted(got_tech),
        "technique_recall": recall,
        "technique_precision": precision,
        "latency_s": round(elapsed, 2),
        "usage": recorder.drain(),
        "error": error,
        "rationale": expected.get("rationale"),
    }


def summarize(results: List[Dict[str, Any]], price_in: Optional[float], price_out: Optional[float]) -> Dict[str, Any]:
    total = len(results)
    correct = sum(r["correct"] for r in results)
    errors = [r for r in results if r["error"]]

    # FALSE_POSITIVE and BENIGN both mean "close it, take no action". Distinguishing
    # them is a taxonomy choice with no operational consequence, so score it separately
    # from errors that would actually change what a responder does.
    def action_class(v: str) -> str:
        return "NO_ACTION" if v in BENIGN_VERDICTS else v

    operational_correct = sum(action_class(r["expected"]) == action_class(r["predicted"]) for r in results)
    label_only_errors = sum(
        1 for r in results
        if not r["correct"] and {r["expected"], r["predicted"]} <= BENIGN_VERDICTS
    )

    matrix: Dict[str, Counter] = defaultdict(Counter)
    for r in results:
        matrix[r["expected"]][r["predicted"]] += 1

    n_malicious = sum(1 for r in results if r["expected"] in MALICIOUS_VERDICTS)
    n_benign = sum(1 for r in results if r["expected"] in BENIGN_VERDICTS)
    missed = sum(r["missed_threat"] for r in results)
    alarms = sum(r["false_alarm"] for r in results)

    recalls = [r["technique_recall"] for r in results if r["technique_recall"] is not None]
    precisions = [r["technique_precision"] for r in results if r["technique_precision"] is not None]
    latencies = [r["latency_s"] for r in results]

    conf_correct = [r["confidence"] for r in results if r["correct"] and r["confidence"] is not None]
    conf_wrong = [r["confidence"] for r in results if not r["correct"] and r["confidence"] is not None]

    # Calibration: does a stated confidence of X% actually correspond to being right X% of the time?
    scored = [r for r in results if r["confidence"] is not None]
    all_conf = [r["confidence"] for r in scored]
    buckets: Dict[str, Dict[str, Any]] = {}
    ece = 0.0
    for lo in range(0, 100, 10):
        hi = lo + 10
        members = [r for r in scored if lo <= r["confidence"] < hi or (hi == 100 and r["confidence"] == 100)]
        if not members:
            continue
        acc = sum(m["correct"] for m in members) / len(members)
        mean_conf = statistics.mean(m["confidence"] for m in members) / 100
        buckets[f"{lo}-{hi}"] = {
            "n": len(members),
            "accuracy": acc,
            "mean_confidence": mean_conf,
            "gap": mean_conf - acc,
        }
        ece += (len(members) / len(scored)) * abs(mean_conf - acc)

    gaps_logged = [r["evidence_gap_count"] for r in results]
    with_gaps = [r for r in scored if r["evidence_gap_count"] > 0]
    over_cap = [r for r in with_gaps if r["confidence"] > 85]

    tok_in = sum(r["usage"]["prompt_tokens"] for r in results)
    tok_out = sum(r["usage"]["completion_tokens"] for r in results)
    tok_reason = sum(r["usage"]["reasoning_tokens"] for r in results)
    llm_calls = sum(r["usage"]["llm_calls"] for r in results)

    cost = None
    if price_in is not None and price_out is not None:
        cost = (tok_in / 1_000_000) * price_in + (tok_out / 1_000_000) * price_out

    return {
        "run_at": datetime.now(timezone.utc).isoformat(),
        "model": settings.AZURE_OPENAI_DEPLOYMENT_NAME if settings.LLM_PROVIDER == "azure_openai" else settings.FAST_MODEL_NAME,
        "provider": settings.LLM_PROVIDER,
        "demo_mode": settings.DEMO_MODE,
        "incidents": total,
        "llm_backed": llm_calls > 0,
        "accuracy": correct / total if total else 0.0,
        "correct": correct,
        "operational_accuracy": operational_correct / total if total else 0.0,
        "label_only_errors": label_only_errors,
        "agent_errors": len(errors),
        "missed_threats": missed,
        "missed_threat_rate": missed / n_malicious if n_malicious else None,
        "false_alarms": alarms,
        "false_alarm_rate": alarms / n_benign if n_benign else None,
        "technique_recall_mean": statistics.mean(recalls) if recalls else None,
        "technique_precision_mean": statistics.mean(precisions) if precisions else None,
        "latency_mean_s": round(statistics.mean(latencies), 2) if latencies else None,
        "latency_median_s": round(statistics.median(latencies), 2) if latencies else None,
        "confidence_when_correct": round(statistics.mean(conf_correct), 1) if conf_correct else None,
        "confidence_when_wrong": round(statistics.mean(conf_wrong), 1) if conf_wrong else None,
        "confidence_mean": round(statistics.mean(all_conf), 1) if all_conf else None,
        "confidence_stdev": round(statistics.pstdev(all_conf), 1) if len(all_conf) > 1 else None,
        "confidence_min": min(all_conf) if all_conf else None,
        "confidence_max": max(all_conf) if all_conf else None,
        "ece": round(ece, 4),
        "calibration_buckets": buckets,
        "evidence_gaps_mean": round(statistics.mean(gaps_logged), 2) if gaps_logged else None,
        "incidents_reporting_gaps": len(with_gaps),
        "gap_cap_violations": len(over_cap),
        "tokens": {
            "prompt": tok_in,
            "completion": tok_out,
            "reasoning": tok_reason,
            "llm_calls": llm_calls,
            "per_incident": round((tok_in + tok_out) / total) if total else 0,
        },
        "estimated_cost_usd": round(cost, 4) if cost is not None else None,
        "confusion_matrix": {k: dict(v) for k, v in matrix.items()},
    }


def print_report(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    w = sys.stdout.write
    w("\n" + "=" * 78 + "\n")
    w("  SENTINEL TRIAGE AGENT - EVALUATION REPORT\n")
    w("=" * 78 + "\n\n")

    w(f"  Model            : {summary['model']} ({summary['provider']})\n")
    w(f"  LLM actually used: {'yes' if summary['llm_backed'] else 'NO - deterministic fallback'}\n")
    w(f"  Demo mode        : {summary['demo_mode']}\n")
    w(f"  Incidents        : {summary['incidents']}\n\n")

    w("  PER-INCIDENT\n")
    w("  " + "-" * 74 + "\n")
    w(f"  {'id':<10} {'expected':<20} {'predicted':<20} {'ok':<4} {'conf':<6} {'sec':<6}\n")
    w("  " + "-" * 74 + "\n")
    for r in results:
        mark = "OK " if r["correct"] else ("MISS" if r["missed_threat"] else ("FA" if r["false_alarm"] else "x"))
        conf = r["confidence"] if r["confidence"] is not None else "-"
        w(f"  {r['id']:<10} {r['expected']:<20} {r['predicted']:<20} {mark:<4} {str(conf):<6} {r['latency_s']:<6}\n")
    w("\n")

    w("  HEADLINE\n")
    w("  " + "-" * 74 + "\n")
    w(f"  Verdict accuracy       : {summary['accuracy']:.1%}  ({summary['correct']}/{summary['incidents']})\n")
    w(f"  Operational accuracy   : {summary['operational_accuracy']:.1%}  (FP/BENIGN merged - errors that change the response)\n")
    w(f"  Label-only errors      : {summary['label_only_errors']}  (FP<->BENIGN, no operational difference)\n")
    if summary["missed_threat_rate"] is not None:
        w(f"  Missed threats         : {summary['missed_threats']}  ({summary['missed_threat_rate']:.1%} of malicious)   <- worst error\n")
    if summary["false_alarm_rate"] is not None:
        w(f"  False alarms           : {summary['false_alarms']}  ({summary['false_alarm_rate']:.1%} of benign)      <- alert fatigue\n")
    if summary["technique_recall_mean"] is not None:
        w(f"  MITRE recall / prec.   : {summary['technique_recall_mean']:.1%} / {summary['technique_precision_mean']:.1%}\n")
    w(f"  Latency mean / median  : {summary['latency_mean_s']}s / {summary['latency_median_s']}s\n")
    if summary["agent_errors"]:
        w(f"  Agent errors           : {summary['agent_errors']}\n")
    w("\n")

    w("  CALIBRATION\n")
    w("  " + "-" * 74 + "\n")
    cc, cw = summary["confidence_when_correct"], summary["confidence_when_wrong"]
    w(f"  Mean confidence when correct : {cc if cc is not None else '-'}\n")
    w(f"  Mean confidence when wrong   : {cw if cw is not None else '-'}\n")
    if cc is not None and cw is not None:
        gap = cc - cw
        verdict = "well separated" if gap >= 10 else ("weak separation" if gap > 0 else "MISCALIBRATED - equally or more confident when wrong")
        w(f"  Separation                   : {gap:+.1f}  ({verdict})\n")
    w(f"  Confidence spread            : {summary['confidence_min']}-{summary['confidence_max']}  (mean {summary['confidence_mean']}, stdev {summary['confidence_stdev']})\n")
    w(f"  Expected calibration error   : {summary['ece']:.3f}   (0 = perfect; stated confidence matches observed accuracy)\n")
    w(f"  Evidence gaps logged         : {summary['evidence_gaps_mean']} per incident, {summary['incidents_reporting_gaps']}/{summary['incidents']} incidents\n")
    if summary["gap_cap_violations"]:
        w(f"  Rule violations              : {summary['gap_cap_violations']} incidents scored >85 despite logging gaps\n")
    if summary["calibration_buckets"]:
        w("\n  reliability (stated confidence vs observed accuracy)\n")
        w(f"    {'band':<10}{'n':<6}{'stated':<10}{'actual':<10}gap\n")
        for band, b in sorted(summary["calibration_buckets"].items(), key=lambda kv: int(kv[0].split("-")[0])):
            flag = "  <- overconfident" if b["gap"] > 0.10 else ("  <- underconfident" if b["gap"] < -0.10 else "")
            w(f"    {band:<10}{b['n']:<6}{b['mean_confidence']:<10.0%}{b['accuracy']:<10.0%}{b['gap']:+.0%}{flag}\n")
    w("\n")

    w("  COST\n")
    w("  " + "-" * 74 + "\n")
    t = summary["tokens"]
    w(f"  Tokens in / out / reasoning  : {t['prompt']:,} / {t['completion']:,} / {t['reasoning']:,}\n")
    w(f"  Tokens per incident          : {t['per_incident']:,}\n")
    if summary["estimated_cost_usd"] is not None:
        per = summary["estimated_cost_usd"] / summary["incidents"] if summary["incidents"] else 0
        w(f"  Estimated cost               : ${summary['estimated_cost_usd']:.4f} total, ${per:.5f} per incident\n")
    else:
        w("  Estimated cost               : pass --price-in / --price-out to compute\n")
    w("\n")

    w("  CONFUSION MATRIX (rows = expected)\n")
    w("  " + "-" * 74 + "\n")
    cols = [v for v in VERDICTS if any(v in row for row in summary["confusion_matrix"].values())] or VERDICTS
    w(f"  {'':<20}" + "".join(f"{c[:14]:<16}" for c in cols) + "\n")
    for exp in VERDICTS:
        row = summary["confusion_matrix"].get(exp)
        if not row:
            continue
        w(f"  {exp:<20}" + "".join(f"{row.get(c, 0):<16}" for c in cols) + "\n")
    w("\n")

    wrong = [r for r in results if not r["correct"]]
    if wrong:
        w("  DISAGREEMENTS\n")
        w("  " + "-" * 74 + "\n")
        for r in wrong:
            w(f"  [{r['id']}] expected {r['expected']}, got {r['predicted']} (conf {r['confidence']})\n")
            w(f"      {r['title']}\n")
            w(f"      ground truth: {r['rationale']}\n")
            if r["error"]:
                w(f"      ERROR: {r['error']}\n")
            w("\n")


async def main() -> int:
    ap = argparse.ArgumentParser(description="Evaluate the Sentinel triage agent against labeled incidents.")
    ap.add_argument("--dataset", type=Path, default=DEFAULT_DATASET)
    ap.add_argument("--limit", type=int, default=None, help="only run the first N incidents")
    ap.add_argument("--category", default=None, help="only run one dataset file, by stem (e.g. identity)")
    ap.add_argument("--out", type=Path, default=None, help="write full results JSON here")
    ap.add_argument("--price-in", type=float, default=None, help="USD per 1M prompt tokens")
    ap.add_argument("--price-out", type=float, default=None, help="USD per 1M completion tokens")
    args = ap.parse_args()

    all_cases = load_cases(args.dataset)
    if args.category:
        all_cases = [c for c in all_cases if c.get("_source") == args.category]
    cases = all_cases[: args.limit] if args.limit else all_cases

    # Never write to real Sentinel incidents from an eval run.
    original_autopost = settings.AUTO_POST_COMMENTS_TO_SENTINEL
    settings.AUTO_POST_COMMENTS_TO_SENTINEL = False

    print(f"\nRunning {len(cases)} incidents against {settings.AZURE_OPENAI_DEPLOYMENT_NAME or settings.FAST_MODEL_NAME}...")
    print("(Sentinel comment write-back disabled for this run)\n")

    results: List[Dict[str, Any]] = []
    try:
        with UsageRecorder(triage_agent) as recorder:
            for i, case in enumerate(cases, 1):
                cid = case["incident"].get("id")
                print(f"  [{i}/{len(cases)}] {cid} ... ", end="", flush=True)
                r = await run_one(case, recorder)
                status = "ok" if r["correct"] else f"MISMATCH ({r['predicted']})"
                print(f"{status}  {r['latency_s']}s")
                results.append(r)
    finally:
        settings.AUTO_POST_COMMENTS_TO_SENTINEL = original_autopost

    summary = summarize(results, args.price_in, args.price_out)
    print_report(results, summary)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"summary": summary, "results": results}, indent=2), encoding="utf-8")
        print(f"  Full results written to {args.out}\n")

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
