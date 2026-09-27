"""SCALA corpus-scale audit: run the auditor over every playbook in a folder tree.

Where evaluate.py scores the auditor against expert labels, this script applies
it at scale to unlabelled playbooks (for example a clone of a public playbook
collection) so the results can be read as a landscape: which constraints are
breached most often, in which formats, and so on.

It is built for long unattended runs:
  - progress is appended to outputs/corpus_progress_<tag>.jsonl after EVERY
    playbook (one JSON record per line), so nothing is lost on interruption
  - re-running resumes: files already recorded are skipped
  - per-file tolerance: files that cannot be parsed, are too large, or make the
    model fail are logged and skipped, and never crash the run
  - the summary statistics are regenerated at the end of every run

Usage (from the SCALA folder, environment configured, Ollama running or API set):
    python corpus_audit.py C:\\path\\to\\playbooks             # full run
    python corpus_audit.py C:\\path\\to\\playbooks --limit 30  # pilot: first 30 only
"""
from __future__ import annotations

import argparse                # command-line options (corpus folder, --limit)
import json                    # progress records and the summary are JSON
import time                    # timestamps and per-playbook durations
from collections import Counter   # tallies (violations per constraint, playbooks per format, skip reasons)
from pathlib import Path       # cross-platform paths

from scala.audit import audit_playbook, MODEL, PROMPT_VERSION
from scala.kb import PolicyKB
from scala.parser import parse_playbook

ROOT = Path(__file__).parent
OUT = ROOT / "outputs"
MAX_TASKS = 60          # skip pathological playbooks whose summary would not fit the model's context window
MAX_FILE_KB = 512       # skip files this large before even trying to parse them


def iter_candidate_files(corpus_dir: Path):
    """Yield every YAML/JSON file under the corpus folder, in a stable sorted order."""
    for p in sorted(corpus_dir.rglob("*")):
        if p.is_file() and p.suffix.lower() in {".yml", ".yaml", ".json", ".bpmn", ".xml"}:
            yield p


def main() -> int:
    """Audit every recognised playbook under the given directory, saving progress after each one."""
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus_dir", type=Path)
    ap.add_argument("--limit", type=int, default=0, help="audit at most N playbooks (pilot mode)")
    args = ap.parse_args()

    OUT.mkdir(exist_ok=True)
    # Output files are tagged with the model and prompt version so runs with
    # different configurations never overwrite each other.
    tag = f"{MODEL}_{PROMPT_VERSION}".replace(":", "-").replace("/", "-").replace("@", "-")
    progress_path = OUT / f"corpus_progress_{tag}.jsonl"
    summary_path = OUT / f"corpus_summary_{tag}.json"

    # ---- resume: load what an earlier run already recorded ----
    done: dict[str, dict] = {}
    if progress_path.exists():
        for line in progress_path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
                done[rec["file"]] = rec
            except json.JSONDecodeError:
                continue                          # a half-written last line is simply ignored
        print(f"[corpus] resuming: {len(done)} playbooks already recorded")

    kb = PolicyKB(ROOT / "standards" / "constraints.json", persist_dir=OUT / "chroma")
    print(f"[corpus] KB: {kb.backend} | model: {MODEL} | prompt: {PROMPT_VERSION}")

    audited = 0
    # The progress file is opened in append mode and flushed after every record.
    with progress_path.open("a", encoding="utf-8") as progress:
        for path in iter_candidate_files(args.corpus_dir):
            rel = str(path.relative_to(args.corpus_dir))      # path relative to the corpus root: the record key
            if rel in done:
                continue
            if args.limit and audited >= args.limit:
                break

            rec: dict = {"file": rel, "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
            try:
                # The three size/parse guards below use StopIteration as a
                # "skip this file" signal that jumps to the matching except
                # branch, where the reason is printed and recorded.
                if path.stat().st_size > MAX_FILE_KB * 1024:
                    rec["status"] = "skipped_too_large"
                    raise StopIteration
                pb = parse_playbook(path)
                if pb is None:
                    rec["status"] = "unparseable"
                    raise StopIteration
                if pb.task_count > MAX_TASKS or pb.task_count == 0:
                    rec["status"] = f"skipped_task_count_{pb.task_count}"
                    raise StopIteration

                t0 = time.time()
                report = audit_playbook(pb, kb, k=12)
                rec.update({
                    "status": "audited",
                    "vendor_format": pb.vendor_format,
                    "name": pb.name,
                    "task_count": pb.task_count,
                    "seconds": round(time.time() - t0, 1),
                    "violated": sorted({f.constraint_id for f in report.violations}),
                    "findings": [f.model_dump() for f in report.findings],
                })
                audited += 1
                print(f"[corpus] {audited}{'/' + str(args.limit) if args.limit else ''} "
                      f"{rel}: violated={rec['violated']} ({rec['seconds']}s)")
            except StopIteration:
                print(f"[corpus] {rel}: {rec['status']}")
            except KeyboardInterrupt:
                print("\n[corpus] interrupted; progress is saved, rerun to resume")
                return 130                          # conventional exit code for Ctrl-C
            except Exception as exc:
                # Anything else (model failure, network error, odd file) is
                # recorded against the file and the run moves on.
                rec["status"] = f"error: {type(exc).__name__}: {str(exc)[:200]}"
                print(f"[corpus] {rel}: {rec['status']}")

            done[rel] = rec
            progress.write(json.dumps(rec) + "\n")
            progress.flush()                        # make sure the record reaches the disk now

    # ---------------- summary ----------------
    # Count, over the audited playbooks only, how often each constraint was
    # flagged and how many playbooks of each format were seen.
    audited_recs = [r for r in done.values() if r.get("status") == "audited"]
    viol_counter = Counter()
    fmt_counter = Counter()
    for r in audited_recs:
        fmt_counter[r["vendor_format"]] += 1
        for c in r["violated"]:
            viol_counter[c] += 1
    n = len(audited_recs)
    summary = {
        "model": MODEL, "prompt_version": PROMPT_VERSION,
        "total_recorded": len(done),
        "audited": n,
        "by_format": dict(fmt_counter),
        # Skip and error reasons, with the detail after the colon removed so
        # they group into a handful of categories.
        "skipped_or_failed": Counter(
            r.get("status", "?").split(":")[0] for r in done.values()
            if r.get("status") != "audited"
        ),
        # For each constraint: how many playbooks were flagged, and what share of the audited total.
        "violation_rates": {
            cid: {"count": cnt, "rate": round(cnt / n, 4) if n else 0}
            for cid, cnt in sorted(viol_counter.items())
        },
        "mean_seconds": round(sum(r["seconds"] for r in audited_recs) / n, 1) if n else 0,
    }
    summary["skipped_or_failed"] = dict(summary["skipped_or_failed"])   # Counter -> plain dict for JSON
    summary_path.write_text(json.dumps(summary, indent=2))
    print("\n========== CORPUS AUDIT SUMMARY ==========")
    print(json.dumps(summary, indent=2)[:1500])
    print(f"Saved: {summary_path.name}, {progress_path.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
