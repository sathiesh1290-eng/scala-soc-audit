"""Bootstrap confidence intervals for F1 by resampling the reference playbooks.

The reference set is ten playbooks, so every accuracy figure carries wide
uncertainty. This script draws the ten playbooks with replacement, 2,000 times,
recomputes micro F1 for each draw from the saved per-playbook predictions and
labels, and reports the 2.5th and 97.5th percentiles. The seed is fixed so that
the intervals in the write-up can be regenerated exactly.

Usage (from the SCALA folder, with the eval_progress files in outputs/):
    python bootstrap.py                    # every reference-set cell
    python bootstrap.py --seed 20260926    # a different seed
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "outputs"
SEED = 20260926        # the seed used for the intervals in the write-up
DRAWS = 2000


def micro_f1(cells: list[tuple[set, set]]) -> float:
    """Micro F1 over a list of (predicted, actual) constraint-id sets, one per playbook."""
    tp = sum(len(p & a) for p, a in cells)
    fp = sum(len(p - a) for p, a in cells)
    fn = sum(len(a - p) for p, a in cells)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return 2 * prec * rec / (prec + rec) if prec + rec else 0.0


def main() -> int:
    """Resample every reference-set cell found in outputs/ and print its F1 interval."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--seed", type=int, default=SEED)
    ap.add_argument("--draws", type=int, default=DRAWS)
    args = ap.parse_args()
    gt = json.loads((ROOT / "real_derived" / "ground_truth.json").read_text())["annotations"]
    for progress_path in sorted(OUT.glob("eval_progress_real_derived_*.json")):
        tag = progress_path.name[len("eval_progress_real_derived_"):-len(".json")]
        if tag.startswith("MOCK_"):
            continue
        prog = json.loads(progress_path.read_text())["playbooks"]
        # One (predicted, actual) pair per playbook, in a fixed order so that the seed reproduces.
        cells = [(set(r["predicted"]), set(gt[f]["violated"])) for f, r in sorted(prog.items()) if f in gt]
        rng = random.Random(args.seed)
        draws = sorted(micro_f1([cells[rng.randrange(len(cells))] for _ in range(len(cells))]) for _ in range(args.draws))
        lo, hi = draws[int(0.025 * args.draws)], draws[int(0.975 * args.draws) - 1]
        print(f"{tag:55s} F1 {micro_f1(cells):.3f}  95% interval {lo:.2f} to {hi:.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
