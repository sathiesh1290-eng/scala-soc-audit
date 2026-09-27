"""Re-score every evaluation cell from its saved reports against the CURRENT ground truth.

Why this exists: the model runs are expensive, but scoring is not. Scoring
compares the verdicts the models gave with the reference labels, so it can be
repeated at any time without a model call. This script re-reads each progress
file written by evaluate.py, takes the model's predicted violations per playbook
from the saved report, compares them with the reference labels, and rewrites the
evaluation_results file for that cell. It is also the quickest way to confirm
that the numbers in the write-up follow from the saved reports.

Usage (from the SCALA folder):
    python rescore.py                  # all cells found in outputs/
    python rescore.py --dir real_derived   # one set only

Nothing is sent to a model. The progress files are read, not modified.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).parent
OUT = ROOT / "outputs"


def score(done: dict, gt: dict) -> dict:
    """Recompute per-playbook and micro-averaged precision, recall and F1.

    done: the "playbooks" dict of a progress file (file name -> saved audit result,
          including the list of constraint ids the model flagged as violated).
    gt:   the "annotations" dict of the ground-truth file (file name -> labels).
    A decision is one (playbook, constraint) pair; a true positive is a flagged
    constraint that the labels list as violated for that playbook.
    """
    tp = fp = fn = 0
    per_playbook = []
    for fname, r in done.items():
        if fname not in gt:
            continue                                   # a playbook without labels cannot be scored
        pred = set(r["predicted"])                     # constraints the model flagged
        act = set(gt[fname]["violated"])               # constraints the labels call violated
        p_tp, p_fp, p_fn = len(pred & act), len(pred - act), len(act - pred)
        tp, fp, fn = tp + p_tp, fp + p_fp, fn + p_fn
        # Per-playbook figures are informative only; the reported numbers are the
        # micro averages below, which weight every decision equally.
        prec = p_tp / (p_tp + p_fp) if pred else (1.0 if not act else 0.0)
        rec = p_tp / (p_tp + p_fn) if act else 1.0
        per_playbook.append({"file": fname, "predicted": sorted(pred), "actual": sorted(act),
                             "precision": round(prec, 4), "recall": round(rec, 4), "seconds": r.get("seconds")})
    micro_p = tp / (tp + fp) if (tp + fp) else 0.0
    micro_r = tp / (tp + fn) if (tp + fn) else 0.0
    micro_f1 = (2 * micro_p * micro_r / (micro_p + micro_r)) if (micro_p + micro_r) else 0.0
    return {"micro_precision": round(micro_p, 4), "micro_recall": round(micro_r, 4),
            "micro_f1": round(micro_f1, 4), "tp": tp, "fp": fp, "fn": fn, "per_playbook": per_playbook}


def main() -> int:
    """Find every progress file in outputs/, score it, and write the matching results file."""
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default=None, help="restrict to one set (seeded or real_derived)")
    args = ap.parse_args()
    n = 0
    # File names are eval_progress_<set>_<model>_<prompt version>.json; the set name
    # identifies which ground-truth file to score against.
    for progress_path in sorted(OUT.glob("eval_progress_*.json")):
        tag = progress_path.name[len("eval_progress_"):-len(".json")]
        # the set name comes first in the tag and may itself contain an underscore
        setname = next((s_ for s_ in ("real_derived", "seeded") if tag.startswith(s_ + "_")), None)
        if setname is None or (args.dir and setname != args.dir):
            continue
        rest = tag[len(setname) + 1:]
        if rest.startswith("MOCK_"):
            continue                                   # mock runs are never scored as results
        prog = json.loads(progress_path.read_text())
        gt_path = ROOT / setname / "ground_truth.json"
        gt = json.loads(gt_path.read_text())["annotations"]
        result = score(prog["playbooks"], gt)
        # Keep the same header fields evaluate.py writes, so the two files are interchangeable.
        result = {"model": prog["model"], "prompt_version": prog["prompt_version"],
                  "kb_backend": prog.get("kb_backend") or next((r["report"].get("kb_backend") for r in prog["playbooks"].values() if "report" in r), None),
                  "playbooks_scored": len(result["per_playbook"]),
                  "rescored_against": str(gt_path.name), **result}
        out = OUT / f"evaluation_results_{tag}.json"
        out.write_text(json.dumps(result, indent=2))
        print(f"{tag:60s} P {result['micro_precision']:.3f}  R {result['micro_recall']:.3f}  F1 {result['micro_f1']:.3f}  "
              f"TP/FP/FN {result['tp']}/{result['fp']}/{result['fn']}  ({result['playbooks_scored']} playbooks)")
        n += 1
    print(f"rescored {n} cell(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
