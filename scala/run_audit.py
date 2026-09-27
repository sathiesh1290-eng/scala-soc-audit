"""Audit ONE playbook from the command line and print the report.

This is the quickest way to try a model or a strategy before a full
evaluation run: parse the file, audit it, print each verdict, save the report.

Usage:
    python run_audit.py seeded/pb2_ransomware_no_hitl.yml

The model, back end and strategy come from the same environment variables as
the other scripts (SCALA_MODEL, SCALA_BACKEND, SCALA_AUDIT_MODE).
"""
from __future__ import annotations

import json                    # the report is saved as JSON
import re                      # to make the model name safe in a file name
import sys                     # command-line arguments and the exit code
from pathlib import Path       # cross-platform paths

from scala.audit import audit_playbook, MODEL, AUDIT_MODE
from scala.kb import PolicyKB
from scala.parser import parse_playbook

ROOT = Path(__file__).parent   # the SCALA folder


def main() -> int:
    """Parse the playbook named on the command line, audit it, and print or save the report."""
    # Exactly one argument is expected: the playbook file. Otherwise print the usage text.
    if len(sys.argv) != 2:
        print(__doc__)
        return 1
    path = Path(sys.argv[1])
    pb = parse_playbook(path)
    if pb is None:
        print(f"Could not parse {path} (unsupported or malformed format).")
        return 1

    print(f"Parsed: {pb.name} [{pb.vendor_format}] - {pb.task_count} tasks")
    kb = PolicyKB(ROOT / "standards" / "constraints.json",
                  persist_dir=ROOT / "outputs" / "chroma")
    print(f"KB backend: {kb.backend} | model: {MODEL}\nAuditing...")

    report = audit_playbook(pb, kb, k=12)      # k=12: judge every constraint

    # Print one line per finding, with the recommendation under each violation.
    print(f"\n=== Compliance report: {report.playbook_name} ===")
    if not report.findings:
        print("No findings returned (check model output).")
    for f in report.findings:
        flag = {"violated": "VIOLATION", "satisfied": "ok", "not_applicable": "n/a"}[f.status]
        print(f"[{flag:>9}] {f.constraint_id} ({f.severity}) {f.rationale}")
        if f.status == "violated" and f.recommendation:
            print(f"            fix: {f.recommendation}")

    # Save the full report next to the other outputs, named after the playbook.
    out = ROOT / "outputs" / f"report_{path.stem}_{re.sub(r'[^A-Za-z0-9.-]+', '-', MODEL)}_{AUDIT_MODE}.json"   # one report per playbook, model and strategy
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report.model_dump(), indent=2))
    print(f"\nSaved: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
