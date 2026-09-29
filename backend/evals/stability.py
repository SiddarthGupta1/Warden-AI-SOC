"""
Measure run-to-run stability across repeated evaluation runs of the SAME config.

An LLM agent gives different answers to identical inputs. Without knowing that
noise floor, a single eval score is unfalsifiable and any A/B comparison between
two prompts or models may be reporting noise as signal.

Usage (from backend/):
    python -m evals.stability evals/results/v2_*.json
    python -m evals.stability evals/results/run1.json evals/results/run2.json evals/results/run3.json

Reports the accuracy spread across runs, which incidents are unstable, and the
minimum accuracy difference a comparison needs before it means anything.
"""

import argparse
import glob
import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List


def load(paths: List[Path]) -> List[Dict[str, Any]]:
    runs = []
    for p in paths:
        data = json.loads(p.read_text(encoding="utf-8"))
        runs.append({"name": p.name, "summary": data["summary"], "results": data["results"]})
    return runs


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure eval run-to-run stability.")
    ap.add_argument("runs", nargs="+", help="result JSON files (globs allowed)")
    args = ap.parse_args()

    paths: List[Path] = []
    for pattern in args.runs:
        matched = [Path(p) for p in glob.glob(pattern)]
        paths.extend(matched if matched else [Path(pattern)])
    paths = [p for p in paths if p.exists()]

    if len(paths) < 2:
        print("Need at least 2 result files to measure stability.")
        return 1

    runs = load(paths)
    w = sys.stdout.write

    w("\n" + "=" * 78 + "\n")
    w("  EVAL STABILITY ANALYSIS\n")
    w("=" * 78 + "\n\n")
    w(f"  Runs analysed: {len(runs)}\n")
    for r in runs:
        w(f"    - {r['name']:<32} accuracy {r['summary']['accuracy']:.1%}   {r['summary'].get('run_at','')[:19]}\n")
    w("\n")

    accs = [r["summary"]["accuracy"] for r in runs]
    spread = max(accs) - min(accs)
    w("  ACCURACY ACROSS IDENTICAL RUNS\n")
    w("  " + "-" * 74 + "\n")
    w(f"  min / mean / max : {min(accs):.1%} / {statistics.mean(accs):.1%} / {max(accs):.1%}\n")
    w(f"  spread           : {spread:.1%}\n")
    if len(accs) > 1:
        w(f"  stdev            : {statistics.pstdev(accs):.1%}\n")
    w("\n")

    # Per-incident stability
    ids = [r["id"] for r in runs[0]["results"]]
    unstable = []
    for iid in ids:
        preds = []
        expected = None
        for r in runs:
            row = next((x for x in r["results"] if x["id"] == iid), None)
            if row:
                preds.append(row["predicted"])
                expected = row["expected"]
        counts = Counter(preds)
        if len(counts) > 1:
            unstable.append((iid, expected, counts))

    stable_n = len(ids) - len(unstable)
    w("  PER-INCIDENT STABILITY\n")
    w("  " + "-" * 74 + "\n")
    w(f"  Stable (same verdict every run)   : {stable_n}/{len(ids)}\n")
    w(f"  Unstable (verdict varied)         : {len(unstable)}/{len(ids)}\n\n")

    if unstable:
        for iid, expected, counts in unstable:
            variants = ", ".join(f"{v}x{n}" for v, n in counts.most_common())
            ever_right = expected in counts
            note = "sometimes correct" if ever_right else "never correct"
            w(f"    [{iid}] expected {expected}\n")
            w(f"        observed: {variants}   ({note})\n")
        w("\n")

    w("  WHAT THIS MEANS\n")
    w("  " + "-" * 74 + "\n")
    if spread == 0:
        w("  Fully deterministic across these runs. A/B differences can be read directly,\n")
        w("  though more runs would firm this up.\n")
    else:
        threshold = spread
        w(f"  Identical configs differ by up to {spread:.1%} on this dataset.\n")
        w(f"  Any A/B comparison showing less than ~{threshold:.1%} difference is indistinguishable\n")
        w("  from noise. To claim a real improvement, either:\n")
        w("    - repeat each config 3-5x and compare means, or\n")
        w("    - enlarge the dataset so a single incident moves the score less, or\n")
        w("    - pin decoding (seed / temperature 0) if the model supports it.\n")
    n = len(ids)
    w(f"\n  Note: with {n} incidents, one incident = {1/n:.1%} of the score.\n")
    w("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
