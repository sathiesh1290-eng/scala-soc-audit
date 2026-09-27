"""Reproduce the corpus figures of the write-up from a clone of the public playbook collection.

What it does, in plain terms: it walks every file under playbooks/ in a clone of
github.com/luduslibrum/awesome-playbooks, parses the ones the parser recognises
(Cortex XSOAR / Demisto YAML, Microsoft Sentinel Logic Apps, BPMN 2.0), checks
each parse against its raw file with the same independent checks as
parser_verify.py, and then counts the structural properties reported in the
corpus chapter under the definitions written here, so that every number can be
recomputed by anyone with the clone.

Usage:
    python corpus_stats.py /path/to/awesome-playbooks/playbooks

Definitions used (these are the definitions, not conveniences):
- Human decision point (vendor playbooks): an XSOAR condition task with no script
  and no condition expression (an analyst decides), an XSOAR analyst-input task
  (type collection or ask), or a Sentinel step that suspends the workflow until a
  person responds (an approval or options e-mail, an adaptive-card connector, or a
  Teams flow-continuation webhook). A manual trigger is not counted: it starts a playbook,
  it does not decide inside one.
- Branching: at least one condition (XSOAR condition task; Sentinel If or Switch).
- Human task (BPMN): a userTask or manualTask element. Gateway: any gateway element.
- Containment or destructive action: a task whose name, tool or description matches
  block, disable, isolate, quarantine, delete, remove, revoke, reset password, kill,
  terminate, reimage, expire, deny or ban. This is a keyword heuristic and is
  reported as such.
"""
from __future__ import annotations

import json
import re
import statistics
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).parent))
from scala.parser import parse_playbook                      # noqa: E402
from parser_verify import _raw_sentinel_inventory, _raw_xsoar_inventory   # noqa: E402

# Keyword list for the containment/destructive heuristic (see the module docstring).
CONTAIN = re.compile(r"block|disable|isolat|quarantin|delete|remove|revoke|reset.?password|kill|terminate|reimage|expire|deny|\bban\b", re.I)


def _first_workflow_definition(raw: str) -> str:
    """Return the JSON text of the first Logic App workflow definition in an ARM template.

    Templates in the collection sometimes hold several workflows; the parser reads the
    first one it meets, and the e-mail check must look at the same one. The object that
    follows the first '"definition"' key is decoded with the JSON decoder (so braces
    inside strings cannot mislead it) and re-serialised; if no definition is found or
    the text does not decode, the whole file is returned unchanged.
    """
    i = raw.find('"definition"')
    if i < 0:
        return raw
    j = raw.find("{", i)
    if j < 0:
        return raw
    try:
        obj, _ = json.JSONDecoder().raw_decode(raw[j:])
        return json.dumps(obj)
    except ValueError:
        return raw


def human_and_branch(pb, path: Path) -> tuple[int, int]:
    """Return (human decision points, decision points) for one parsed playbook.

    XSOAR is re-read from the raw YAML because the parsed record does not keep
    the script and condition fields that tell an analyst's question apart from
    an automated check. Sentinel and BPMN are counted from the parsed tasks.
    """
    humans = conds = 0
    if pb.vendor_format == "xsoar_yaml":
        d = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        for t in (d.get("tasks") or {}).values():
            if not isinstance(t, dict):
                continue
            inner = t.get("task") or {}
            if t.get("type") == "condition":
                conds += 1
                if not inner.get("scriptName") and not inner.get("script") and not t.get("conditions"):
                    humans += 1                       # an analyst answers the question
            if t.get("type") in ("collection", "ask"):
                humans += 1                           # an analyst supplies input
    elif pb.vendor_format == "sentinel_logicapp":
        for t in pb.tasks:
            if t.task_type in ("If", "Switch"):
                conds += 1
            if (t.automation and any(k in t.automation.lower() for k in ("approval", "adaptivecard"))) \
                    or "WAITS FOR A HUMAN RESPONSE" in (t.description or ""):
                humans += 1
        # The raw template is read again for the Office 365 approval and options e-mails,
        # whose connector operation paths (/approvalmail/, /mailwithoptions/) identify a
        # step that suspends the workflow until a person answers; the parsed record does
        # not carry the operation path.
        # Only the first workflow of a multi-workflow template is parsed, so the count is
        # limited to that workflow's definition rather than the whole file.
        raw = path.read_text(encoding="utf-8", errors="replace")
        wf = _first_workflow_definition(raw)
        humans += len(re.findall(r'"path"\s*:\s*"[^"]*/(?:approvalmail|mailwithoptions)/', wf))
    else:                                             # BPMN
        for t in pb.tasks:
            if t.task_type in ("userTask", "manualTask"):
                humans += 1
            if "gateway" in (t.task_type or "").lower():
                conds += 1
    return humans, conds


def main() -> int:
    """Walk the clone, parse and verify every recognised playbook, then print and save the figures."""
    if len(sys.argv) < 2:
        print(__doc__); return 2
    root = Path(sys.argv[1])
    files_per_dir: dict[str, int] = {}      # file counts per top-level directory (the disposition table)
    parsed = []                             # one record per parsed playbook
    checks = {"sentinel_count_ok": 0, "sentinel_total": 0, "xsoar_ids_ok": 0, "xsoar_refs_ok": 0, "xsoar_total": 0, "bpmn_parsed": 0}
    dangling = []                           # Sentinel files whose run-after references point to absent actions
    # Pass 1: every file in the clone. Files the parser does not recognise are counted but not parsed.
    for f in sorted(root.rglob("*")):
        if not f.is_file():
            continue
        top = f.relative_to(root).parts[0]
        files_per_dir[top] = files_per_dir.get(top, 0) + 1
        try:
            pb = parse_playbook(f)
        except Exception:
            continue                                  # not a playbook the parser recognises
        if pb is None or pb.task_count == 0:
            continue
        rel = str(f.relative_to(root))
        humans, conds = human_and_branch(pb, f)
        contain = any(CONTAIN.search(" ".join(x for x in (t.name or "", t.automation or "", t.description or "") if x)) for t in pb.tasks)
        parsed.append({"file": rel, "format": pb.vendor_format, "tasks": pb.task_count, "human_points": humans, "decision_points": conds, "containment_keyword": contain})
        # Verification against the raw file, independent of the parser's own walk
        # (the same checks as parser_verify.py): task count for Sentinel, identifier
        # set and reference resolution for XSOAR, parse success for BPMN.
        if pb.vendor_format == "sentinel_logicapp":
            raw_n, dang = _raw_sentinel_inventory(f)
            checks["sentinel_total"] += 1; checks["sentinel_count_ok"] += int(raw_n == pb.task_count)
            if dang:
                dangling.append(rel)
        elif pb.vendor_format == "xsoar_yaml":
            ids, refs = _raw_xsoar_inventory(f)
            checks["xsoar_total"] += 1
            checks["xsoar_ids_ok"] += int(ids == {t.task_id for t in pb.tasks})
            checks["xsoar_refs_ok"] += int(refs.issubset(ids))
        else:
            checks["bpmn_parsed"] += 1
    # Pass 2: the figures. "Vendor playbooks" means the two vendor formats; the CISA
    # figures are restricted to the cisa/ directory because BPMN files elsewhere in the
    # collection are not government playbooks.
    total_files = sum(files_per_dir.values())
    by_fmt = {}
    for p in parsed:
        by_fmt.setdefault(p["format"], []).append(p)
    vendor = by_fmt.get("xsoar_yaml", []) + by_fmt.get("sentinel_logicapp", [])
    cisa = [p for p in by_fmt.get("cisa_bpmn", []) if p["file"].replace("\\", "/").startswith("cisa/")]
    pct = lambda n, d: f"{100 * n / d:.1f}%" if d else "n/a"
    print(f"files in the collection: {total_files} across {len(files_per_dir)} directories")
    print(f"parsed: {len(parsed)} = " + ", ".join(f"{k} {len(v)}" for k, v in by_fmt.items()))
    print(f"verification: Sentinel task count {checks['sentinel_count_ok']}/{checks['sentinel_total']}; XSOAR id set {checks['xsoar_ids_ok']}/{checks['xsoar_total']}; "
          f"XSOAR references resolve {checks['xsoar_refs_ok']}/{checks['xsoar_total']}; BPMN parsed {checks['bpmn_parsed']}")
    print(f"Sentinel files with dangling references: {len(dangling)} {dangling}")
    print(f"vendor playbooks: {len(vendor)}; with a human decision point: {sum(p['human_points'] > 0 for p in vendor)} ({pct(sum(p['human_points'] > 0 for p in vendor), len(vendor))}); "
          f"branching: {pct(sum(p['decision_points'] > 0 for p in vendor), len(vendor))}")
    for fmt in ("xsoar_yaml", "sentinel_logicapp"):
        v = by_fmt.get(fmt, [])
        if v:
            print(f"  {fmt}: human {pct(sum(p['human_points'] > 0 for p in v), len(v))}, branching {pct(sum(p['decision_points'] > 0 for p in v), len(v))}, "
                  f"median tasks {statistics.median(p['tasks'] for p in v)}, max {max(p['tasks'] for p in v)}")
    if cisa:
        print(f"CISA BPMN: {len(cisa)}; with human tasks {pct(sum(p['human_points'] > 0 for p in cisa), len(cisa))}; with gateways {pct(sum(p['decision_points'] > 0 for p in cisa), len(cisa))}; "
              f"median tasks {statistics.median(p['tasks'] for p in cisa)}, range {min(p['tasks'] for p in cisa)} to {max(p['tasks'] for p in cisa)}")
    print(f"containment or destructive action (keyword heuristic): {sum(p['containment_keyword'] for p in parsed)} of {len(parsed)}")
    # Everything above is also written as JSON so the tables can be regenerated without re-running.
    out = Path(__file__).parent / "outputs" / "corpus_stats.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"files_per_dir": files_per_dir, "checks": checks, "dangling": dangling, "parsed": parsed}, indent=1))
    print(f"saved: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
