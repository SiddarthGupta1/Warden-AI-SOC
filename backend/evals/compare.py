"""
Compare two evaluation runs.

Usage (from backend/):
    python -m evals.compare evals/results/baseline_gpt5mini.json evals/results/mitre_precision_v2.json

Prints a metric-by-metric delta plus any incident whose verdict changed between
runs, so a prompt or model change can be judged as an improvement or a
regression rather than by eyeballing two reports.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# (label, summary key, higher_is_better, formatter)
METRICS = [
    ("Verdict accuracy",      "accuracy",                   True,  "pct"),
    ("Missed threats",        "missed_threats",             False, "int"),
    ("False alarms",          "false_alarms",               False, "int"),
    ("MITRE recall",          "technique_recall_mean",      True,  "pct"),
    ("MITRE precision",       "technique_precision_mean",   True,  "pct"),
    ("Latency mean (s)",      "latency_mean_s",             False, "num"),
    ("Tokens per incident",   None,                         False, "int"),
    ("Agent errors",          "agent_errors",               False, "int"),
]


def fmt(value: Optional[float], kind: str) -> str:
    if value is None:
        return "-"
    if kind == "pct":
        return f"{value:.1%}"
    if kind == "int":
        return f"{int(value):,}"
    return f"{value:g}"


def delta_str(before: Optional[float], after: Optional[float], higher_is_better: bool, kind: str) -> str:
    if before is None or after is None:
        return ""
    diff = after - before
    if abs(diff) < 1e-9:
        return "  ="
    improved = (diff > 0) == higher_is_better
    arrow = "UP  " if diff > 0 else "DOWN"
    tag = "better" if improved else "WORSE"
    shown = f"{diff:+.1%}" if kind == "pct" else f"{diff:+g}"
    return f"  {arrow} {shown}  ({tag})"


def get(summary: Dict[str, Any], key: Optional[str]) -> Optional[float]:
    if key is None:
        return summary.get("tokens", {}).get("per_incident")
    return summary.get(key)


def main() -> int:
    ap = argparse.ArgumentParser(description="Compare two eval runs.")
    ap.add_argument("before", type=Path)
    ap.add_argument("after", type=Path)
    args = ap.parse_args()

    a = json.loads(args.before.read_text(encoding="utf-8"))
    b = json.loads(args.after.read_text(encoding="utf-8"))
    sa, sb = a["summary"], b["summary"]

    w = sys.stdout.write
    w("\n" + "=" * 78 + "\n")
    w("  EVAL COMPARISON\n")
    w("=" * 78 + "\n\n")
    w(f"  before : {args.before.name}  ({sa.get('model')}, {sa.get('incidents')} incidents, {sa.get('run_at', '')[:19]})\n")
    w(f"  after  : {args.after.name}  ({sb.get('model')}, {sb.get('incidents')} incidents, {sb.get('run_at', '')[:19]})\n\n")

    if sa.get("incidents") != sb.get("incidents"):
        w("  WARNING: runs cover different incident counts - deltas are not directly comparable.\n\n")

    w(f"  {'metric':<22}{'before':<14}{'after':<14}delta\n")
    w("  " + "-" * 74 + "\n")
    for label, key, higher, kind in METRICS:
        va, vb = get(sa, key), get(sb, key)
        w(f"  {label:<22}{fmt(va, kind):<14}{fmt(vb, kind):<14}{delta_str(va, vb, higher, kind)}\n")
    w("\n")

    ra = {r["id"]: r for r in a["results"]}
    rb = {r["id"]: r for r in b["results"]}
    changed = [i for i in ra.keys() & rb.keys() if ra[i]["predicted"] != rb[i]["predicted"]]

    if changed:
        w("  VERDICT CHANGES\n")
        w("  " + "-" * 74 + "\n")
        for i in sorted(changed):
            before_r, after_r = ra[i], rb[i]
            direction = "FIXED" if after_r["correct"] and not before_r["correct"] else (
                "REGRESSED" if before_r["correct"] and not after_r["correct"] else "changed")
            w(f"  [{i}] {before_r['predicted']} -> {after_r['predicted']}  ({direction}, expected {after_r['expected']})\n")
        w("\n")
    else:
        w("  No verdict changed between runs.\n\n")

    tech_moves = []
    for i in sorted(ra.keys() & rb.keys()):
        pa, pb = ra[i].get("technique_precision"), rb[i].get("technique_precision")
        if pa is not None and pb is not None and abs(pb - pa) > 1e-9:
            tech_moves.append((i, pa, pb, ra[i]["predicted_techniques"], rb[i]["predicted_techniques"]))

    if tech_moves:
        w("  MITRE PRECISION BY INCIDENT\n")
        w("  " + "-" * 74 + "\n")
        for i, pa, pb, ta, tb in tech_moves:
            w(f"  [{i}] {pa:.0%} -> {pb:.0%}\n")
            w(f"      before: {', '.join(ta) or '-'}\n")
            w(f"      after : {', '.join(tb) or '-'}\n")
        w("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
