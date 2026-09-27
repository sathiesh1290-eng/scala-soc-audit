"""The no-model baselines of Section 6.1, computed on the reference set.

The first flags every decision as a violation. The second applies the containment
keyword rule of corpus_stats.py (the same regular expression, over task names,
automations and descriptions) to each reference playbook and flags every constraint
on the playbooks the rule selects. Both are scored against real_derived/ground_truth.json
with the same micro-averaged precision, recall and F1 as the model cells, and the
stricter floor used in the write-up (the nine playbooks with a containment action,
rd1 excluded by a human reading) is printed as well, so that every floor the models
are compared with can be regenerated.

Usage (from the SCALA folder):
    python baseline.py
"""
from __future__ import annotations

import json
from pathlib import Path

from corpus_stats import CONTAIN
from scala.parser import parse_playbook

ROOT = Path(__file__).parent
CONSTRAINTS = [f"C{i:02d}" for i in range(1, 13)]


def score(flagged: dict[str, set], gt: dict) -> tuple[int, int, int, float, float, float]:
    """Micro precision, recall and F1 of a flagged-constraints map against the labels."""
    tp = fp = fn = 0
    for f, ann in gt.items():
        pred, act = flagged.get(f, set()), set(ann["violated"])
        tp += len(pred & act); fp += len(pred - act); fn += len(act - pred)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return tp, fp, fn, prec, rec, f1


def main() -> int:
    """Print both baselines and which playbooks the keyword rule selects."""
    gt = json.loads((ROOT / "real_derived" / "ground_truth.json").read_text())["annotations"]
    files = sorted(gt)
    everything = {f: set(CONSTRAINTS) for f in files}
    tp, fp, fn, p, r, f1 = score(everything, gt)
    print(f"flag everything:            TP {tp} FP {fp} FN {fn}  P {p:.3f} R {r:.3f} F1 {f1:.3f}")
    selected = {}
    for f in files:
        pb = parse_playbook(ROOT / "real_derived" / f)
        hit = any(CONTAIN.search(" ".join(x for x in (t.name or "", t.automation or "", t.description or "") if x)) for t in pb.tasks)
        selected[f] = hit
        print(f"  keyword rule {'selects' if hit else 'skips  '} {f}")
    rule = {f: set(CONSTRAINTS) for f in files if selected[f]}
    tp, fp, fn, p, r, f1 = score(rule, gt)
    print(f"containment keyword rule:   TP {tp} FP {fp} FN {fn}  P {p:.3f} R {r:.3f} F1 {f1:.3f}  ({sum(selected.values())} of {len(files)} playbooks selected)")
    # The rule as read by a person: rd1 is a feed-processing job with no containment
    # action (its match is a block-list mention), so the write-up's stricter floor flags
    # every constraint on the other nine playbooks. The exclusion is a human reading of
    # the playbook, stated as such in Section 6.1, not a computed selection.
    nine = {f: set(CONSTRAINTS) for f in files if not f.startswith("rd1_")}
    tp, fp, fn, p, r, f1 = score(nine, gt)
    print(f"nine playbooks, rd1 excluded by hand: TP {tp} FP {fp} FN {fn}  P {p:.3f} R {r:.3f} F1 {f1:.3f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
