"""SCALA parser verification (verification layer 2).

The auditor can only be as good as the structure it is given, so this script
checks the parser's output against the raw file, read independently here and
never through the parser. The checks are invariants, not a full equality test:
counts and identifier sets for R1, reference integrity for R2 and R4, type
vocabulary and name well-formedness, and a non-empty parse for BPMN. They catch
lost, invented or unresolved elements; they do not prove that every edge or name
equals its raw counterpart.

The checks:
  V1 (R1 completeness)   the parsed task count equals the raw file's inventory
                         (XSOAR: entries under `tasks`; Sentinel: triggers plus
                         actions, counted recursively through nested scopes and
                         conditions). For XSOAR the SET of ids must match too.
  V2 (R2/R4 integrity)   every control-flow reference points at a task that
                         exists (XSOAR: every `nexttasks` target is a task id;
                         Sentinel: every `runAfter` key names an action in the
                         same scope or an enclosing scope).
  V3 (R3 vocabulary)     every parsed task type is a known XSOAR type; unknown
                         types are flagged rather than silently accepted.
  V4 (identity)          the playbook has a non-empty name with no unresolved
                         ARM template expression left in it. This is a guard
                         against a name-resolution error that would produce
                         playbooks called "[parameters('PlaybookName')]".

Usage:  python parser_verify.py <corpus_dir>
Writes: outputs/parser_verification.json and prints a summary of pass/fail counts.
"""
from __future__ import annotations

import json                    # Sentinel raw files are JSON; the report is JSON
import re                      # detects leftover template expressions in names
import sys                     # command-line argument
from collections import Counter   # pass/fail tallies per check
from pathlib import Path       # cross-platform paths

import yaml                    # reads the XSOAR raw files independently of the parser

from scala.parser import parse_playbook, detect_format

# The task types an XSOAR export can contain. Anything else is a surprise worth flagging.
XSOAR_TYPES = {"start", "title", "regular", "condition", "playbook", "collection"}


def _raw_xsoar_inventory(path: Path):
    """Read an XSOAR file directly and return (set of task ids, set of referenced ids)."""
    d = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    tasks = d.get("tasks") or {}
    ids = set(map(str, tasks.keys()))
    refs = set()
    for t in tasks.values():
        if isinstance(t, dict):
            for branch in (t.get("nexttasks") or {}).values():
                if isinstance(branch, list):
                    refs.update(map(str, branch))
    return ids, refs


def _raw_sentinel_inventory(path: Path):
    """Read a Sentinel file directly and return (expected task count, list of dangling runAfter references).

    Walks the workflow definition the same way a reader would: every action in
    every nested scope counts once, and each runAfter reference must name an
    action visible from where it sits (same scope or any enclosing scope).
    """
    d = json.loads(path.read_text(encoding="utf-8", errors="replace"))

    def find_def(o):
        """Locate the workflow definition: the object that has both "triggers" and "actions", wherever it sits."""
        if isinstance(o, dict):
            if "triggers" in o and "actions" in o: return o
            for v in o.values():
                f = find_def(v)
                if f is not None: return f
        elif isinstance(o, list):
            for it in o:
                f = find_def(it)
                if f is not None: return f
        return None

    definition = find_def(d)
    dangling = []                                          # runAfter targets not visible from their scope

    count = 0                                             # every action key in the file, wherever it sits
    def walk(actions, scope_names):
        """Count every action in this scope and below, checking that each runAfter target is visible from it."""
        nonlocal count
        local = set(actions.keys())                       # actions visible in this scope
        for name, a in actions.items():
            count += 1
            if not isinstance(a, dict): continue
            for ref in (a.get("runAfter") or {}).keys():
                if ref not in local and ref not in scope_names:
                    dangling.append(f"{name}->runAfter:{ref}")
            # descend into every container a Logic App action can have: the true
            # branch, the else branch, each switch case and the default case. This
            # walk is written independently of the parser so that a container the
            # parser forgets is counted here and the count check fails.
            nested = a.get("actions")
            if isinstance(nested, dict):
                walk(nested, scope_names | local)         # enclosing names stay visible inside
            els = a.get("else")
            if isinstance(els, dict) and isinstance(els.get("actions"), dict):
                walk(els["actions"], scope_names | local)
            cases = a.get("cases")
            if isinstance(cases, dict):
                for case in cases.values():
                    if isinstance(case, dict) and isinstance(case.get("actions"), dict):
                        walk(case["actions"], scope_names | local)
            default = a.get("default")
            if isinstance(default, dict) and isinstance(default.get("actions"), dict):
                walk(default["actions"], scope_names | local)

    n_triggers = len(definition.get("triggers") or {})
    walk(definition.get("actions") or {}, set())
    return n_triggers + count, dangling


def main() -> int:
    """Run the four checks over every playbook file under the given directory and write the report."""
    corpus = Path(sys.argv[1])
    out = Path(__file__).parent / "outputs"
    out.mkdir(exist_ok=True)
    stats = Counter()          # e.g. {"parsed": 472, "V1_count_pass": 472, "V2_refs_FAIL": 2, ...}
    failures = []              # one record per failed check, for inspection

    for path in sorted(corpus.rglob("*")):
        if not (path.is_file() and path.suffix.lower() in {".yml", ".yaml", ".json", ".bpmn"}):
            continue
        fmt = detect_format(path)
        if fmt is None: continue                          # not a playbook format SCALA reads
        try:
            pb = parse_playbook(path)
        except Exception as exc:
            # The parser should never throw; if it does, that is itself a finding.
            stats["parser_exception"] += 1
            failures.append({"file": path.name, "check": "parse", "detail": str(exc)[:150]})
            continue
        if pb is None or pb.task_count == 0:
            stats["unparsed"] += 1
            continue
        stats["parsed"] += 1
        checks = {}                                       # check name -> (passed?, detail text)

        try:
            if pb.vendor_format == "xsoar_yaml":
                ids, refs = _raw_xsoar_inventory(path)
                checks["V1_count"] = (pb.task_count == len(ids), f"parsed={pb.task_count} raw={len(ids)}")
                parsed_ids = {t.task_id for t in pb.tasks}
                checks["V1_ids"] = (parsed_ids == ids, f"missing={sorted(ids - parsed_ids)[:5]}")
                dangling = sorted(refs - ids)             # references to tasks that do not exist
                checks["V2_refs"] = (not dangling, f"dangling={dangling[:5]}")
                bad_types = sorted({t.task_type for t in pb.tasks} - XSOAR_TYPES)
                checks["V3_types"] = (not bad_types, f"unknown={bad_types}")
            elif pb.vendor_format == "sentinel_logicapp":
                raw_n, dangling = _raw_sentinel_inventory(path)
                checks["V1_count"] = (pb.task_count == raw_n, f"parsed={pb.task_count} raw={raw_n}")
                checks["V2_refs"] = (not dangling, f"dangling={dangling[:5]}")
            else:  # BPMN: parsed without exception and non-empty; a raw-count check for BPMN is future work
                checks["V1_parsed"] = (pb.task_count > 0, f"parsed={pb.task_count}")
            checks["V4_name"] = (bool(pb.name) and not re.search(r"\[parameters\(", pb.name),
                                 f"name={pb.name!r}")
        except Exception as exc:
            checks["verifier_error"] = (False, str(exc)[:150])

        # Tally each check as pass or FAIL and keep the detail of every failure.
        for cname, (ok, detail) in checks.items():
            stats[f"{cname}_{'pass' if ok else 'FAIL'}"] += 1
            if not ok:
                failures.append({"file": path.name, "check": cname, "detail": detail})

    report = {"stats": dict(stats), "failures": failures[:200]}
    (out / "parser_verification.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(dict(stats), indent=2))
    print(f"failures recorded: {len(failures)} (first 200 saved)")
    print(f"saved: outputs/parser_verification.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
