"""SCALA evaluation harness: score the auditor against a labelled set.

What it does:
  1. Reads ground_truth.json from the chosen set folder. That file lists, for
     every playbook, which constraints a domain expert labelled as violated.
  2. Parses and audits each playbook with the model, back end and strategy
     selected through environment variables (SCALA_MODEL, SCALA_BACKEND,
     SCALA_AUDIT_MODE; see scala/audit.py).
  3. Compares the model's "violated" verdicts with the expert labels, decision
     by decision (one decision = one playbook x one constraint), and reports
     precision, recall and F1.
  4. Reports how often "satisfied" verdicts cited task ids that really exist
     (the evidence check of strategies C to F).

Two labelled sets ship with SCALA:
  seeded/        six synthetic playbooks written with known gaps; used only to
                 develop the prompts (the development set)
  real_derived/  ten real playbooks with expert labels (the reference set)

Progress is saved after EVERY playbook, so a run interrupted by a crash, a
timeout or a closed laptop can simply be started again and will carry on from
where it stopped. Delete the progress file to force a fresh run.

Usage (from the folder that contains this file):
    python evaluate.py --dir real_derived        # real run
    SCALA_MOCK=1 python evaluate.py              # plumbing test only, never a result
"""
from __future__ import annotations

import argparse                # reads the --dir command-line option
import json                    # ground truth, progress and result files are all JSON
import sys                     # sys.exit(main()) returns the exit code to the shell
import time                    # measures how long each audit takes (reported per playbook)
from pathlib import Path       # cross-platform paths relative to this file

from scala.audit import audit_playbook, MODEL, PROMPT_VERSION, AUDIT_MODE
import os as _os
_MOCK = _os.environ.get("SCALA_MOCK") == "1"
_MODEL_TAG = "MOCK" if _MOCK else MODEL     # mock output is named MOCK so it can never be mistaken for a result
if AUDIT_MODE not in ("batched", "per_constraint", "per_constraint_v4", "per_constraint_cot", "per_constraint_sc", "per_constraint_gate"):
    raise SystemExit(f"[eval] unknown SCALA_AUDIT_MODE={AUDIT_MODE!r}; choose one of the six strategies")
from scala.kb import PolicyKB
from scala.parser import parse_playbook

ROOT = Path(__file__).parent                   # the SCALA folder, whatever the current working directory is
_ap = argparse.ArgumentParser()
_ap.add_argument("--dir", default="seeded",
                 help="evaluation set directory: seeded (development set) or real_derived (reference set)")
_ARGS = _ap.parse_args()
SEEDED = ROOT / _ARGS.dir                      # folder holding the playbooks and their ground_truth.json
OUT = ROOT / "outputs"
# A tag made of set + model + prompt version, with characters that are awkward
# in file names replaced, so each configuration writes to its own files.
TAG = f"{_ARGS.dir}_{_MODEL_TAG}_{PROMPT_VERSION}".replace(":", "-").replace("/", "-").replace("@", "-")
PROGRESS = OUT / f"eval_progress_{TAG}.json"


def _load_progress() -> dict:
    """Return saved progress for this exact configuration, or an empty record.

    The model and prompt version are stored inside the file and checked, so a
    progress file from a different configuration is never resumed by mistake.
    """
    if PROGRESS.exists():
        data = json.loads(PROGRESS.read_text())
        if data.get("model") == _MODEL_TAG and data.get("prompt_version") == PROMPT_VERSION:
            return data
        print("[eval] progress file is from a different model/prompt version; starting fresh")
    return {"model": _MODEL_TAG, "prompt_version": PROMPT_VERSION, "playbooks": {}}


def main() -> int:
    """Audit every playbook of the chosen set (skipping ones already recorded), then score the cell."""
    OUT.mkdir(exist_ok=True)
    # The expert labels: {"file name": {"violated": ["C01", ...], ...}, ...}
    gt = json.loads((SEEDED / "ground_truth.json").read_text())["annotations"]
    # The constraint knowledge base; the vector store is persisted under outputs/chroma.
    kb = PolicyKB(ROOT / "standards" / "constraints.json",
                  persist_dir=ROOT / "outputs" / "chroma")
    print(f"[eval] KB backend: {kb.backend} | model: {MODEL} | prompt: {PROMPT_VERSION}")

    progress = _load_progress()
    done = progress["playbooks"]                # file name -> saved result

    # ---- audit loop: one playbook at a time, saving after each ----
    for fname, truth in gt.items():
        if fname in done:
            print(f"[eval] {fname}: already done (resume), skipping")
            continue
        path = SEEDED / fname
        pb = parse_playbook(path)
        if pb is None:
            print(f"[eval] SKIP unparseable: {fname}")
            continue

        t0 = time.time()
        report = audit_playbook(pb, kb, k=12)   # k=12: judge every constraint
        elapsed = time.time() - t0

        predicted = sorted({f.constraint_id for f in report.violations})   # what the model flagged
        actual = sorted(truth["violated"])                                # what the expert labelled
        done[fname] = {
            "predicted": predicted, "actual": actual,
            "seconds": round(elapsed, 1),
            "report": report.model_dump(),      # the full report, so every figure can be regenerated later
        }
        PROGRESS.write_text(json.dumps(progress, indent=2))   # checkpoint
        print(f"[eval] {fname}: predicted={predicted} actual={actual} ({elapsed:.1f}s) [saved]")

    # ---- scoring over everything completed ----
    # Counting per decision:
    #   true positive  (tp): expert says violated, model says violated
    #   false positive (fp): model says violated, expert does not
    #   false negative (fn): expert says violated, model missed it
    tp = fp = fn = 0
    per_playbook = []
    for fname, r in done.items():
        pred, act = set(r["predicted"]), set(r["actual"])
        p_tp, p_fp, p_fn = len(pred & act), len(pred - act), len(act - pred)
        tp, fp, fn = tp + p_tp, fp + p_fp, fn + p_fn
        # Per-playbook precision and recall, with sensible values when a
        # playbook has no predictions or no actual violations.
        prec = p_tp / (p_tp + p_fp) if pred else (1.0 if not act else 0.0)
        rec = p_tp / (p_tp + p_fn) if act else 1.0
        per_playbook.append({"file": fname, "predicted": r["predicted"],
                             "actual": r["actual"], "precision": round(prec, 4),
                             "recall": round(rec, 4), "seconds": r["seconds"]})

    # Micro-averaged figures: computed from the pooled counts, so every decision
    # weighs the same regardless of which playbook it belongs to.
    micro_p = tp / (tp + fp) if (tp + fp) else 0.0       # of the alarms raised, how many were right
    micro_r = tp / (tp + fn) if (tp + fn) else 0.0       # of the real violations, how many were caught
    micro_f1 = (2 * micro_p * micro_r / (micro_p + micro_r)) if (micro_p + micro_r) else 0.0   # harmonic mean of the two

    summary = {
        "model": _MODEL_TAG, "prompt_version": PROMPT_VERSION, "kb_backend": kb.backend,
        "micro_precision": round(micro_p, 4), "micro_recall": round(micro_r, 4),
        "micro_f1": round(micro_f1, 4), "tp": tp, "fp": fp, "fn": fn,
        "per_playbook": per_playbook,
    }
    (OUT / f"evaluation_results_{TAG}.json").write_text(json.dumps(summary, indent=2))
    (OUT / f"audit_reports_{TAG}.json").write_text(
        json.dumps([r["report"] for r in done.values()], indent=2))

    print("\n========== EVALUATION SUMMARY ==========")
    print(f"Model: {MODEL} | prompt {PROMPT_VERSION} | KB: {kb.backend}")
    # Evidence validation (verification layer 5): share of 'satisfied' verdicts
    # whose cited task ids all exist. Only meaningful for strategies C to F.
    try:
        sat = [f for pbv in progress["playbooks"].values() for f in pbv["report"]["findings"]
               if f.get("status") == "satisfied"]
        if sat and any(f.get("evidence_valid") is not None for f in sat):
            ok = sum(1 for f in sat if f.get("evidence_valid") is True)
            print(f"Evidence validation (satisfied verdicts): {ok}/{len(sat)} 'satisfied' verdicts cite valid task ids "
                  f"({100*ok/len(sat):.0f}%)")
    except Exception as exc:  # this extra statistic must never break the scoring above
        print(f"[eval] evidence analytics skipped: {exc}")
    print(f"Micro precision: {micro_p:.3f}  recall: {micro_r:.3f}  F1: {micro_f1:.3f}")
    print(f"Saved: outputs/evaluation_results_{TAG}.json, outputs/audit_reports_{TAG}.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
