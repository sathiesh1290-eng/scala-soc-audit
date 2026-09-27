"""SCALA R-view (verification layer 3): render a playbook for a human reader.

The auditor reads a compact structural summary. A person checking the parser,
or labelling playbooks by hand, needs the same information laid out under the
four questions the audit rests on:

  R1  TASK INVENTORY      what actions exist and what tool or script each calls
  R2  CONTROL FLOW        what order they run in (Sentinel's "runAfter" links are
                          inverted here into forward "successor" edges)
  R3  HUMAN vs AUTOMATED  who decides: XSOAR condition tasks are classified from
                          the raw file as scripted, value-check or unscripted
                          (a manual candidate); Sentinel is scanned for approval
                          connectors
  R4  BRANCH TOPOLOGY     where each decision's exits lead; exits that land on a
                          terminal title (an end marker) are called out because
                          they end the playbook silently

This is a PRESENTATION layer over the same parsed model the auditor uses. The
auditor's own input format is frozen so results stay comparable; this view is
free to be as readable as possible.

Usage (from the SCALA folder):
  python rview.py seeded\\pb2_ransomware_no_hitl.yml     # one playbook -> printed to the screen
  python rview.py C:\\path\\to\\playbooks                 # a corpus -> outputs\\rviews\\*.txt plus an index
"""
from __future__ import annotations

import re                      # regular expressions: reads "runAfter: [...]" out of descriptions, sanitises file names
import sys                     # command-line argument and exit code
from collections import defaultdict   # successor lists that create themselves on first use
from pathlib import Path       # cross-platform paths

import yaml                    # reads the raw XSOAR file to classify condition tasks

from scala.parser import parse_playbook


def _xsoar_condition_kinds(path: Path) -> dict[str, str]:
    """Classify each XSOAR condition task from the RAW file.

    Three kinds are distinguished:
      scripted              a script decides (automated)
      value-check           a `conditions` array compares field values (automated)
      unscripted, no array  nothing decides automatically, so an analyst must (manual candidate)
    """
    kinds: dict[str, str] = {}
    try:
        d = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return kinds
    for tid, t in (d.get("tasks") or {}).items():
        if not isinstance(t, dict) or t.get("type") != "condition":
            continue
        inner = t.get("task") or {}
        scripted = bool(inner.get("script") or inner.get("scriptName"))
        has_array = isinstance(t.get("conditions"), list) and bool(t["conditions"])
        kinds[str(tid)] = ("AUTOMATED (scripted)" if scripted
                           else "AUTOMATED value-check (conditions array)" if has_array
                           else "MANUAL candidate (unscripted, no conditions array)")
    return kinds


def r_view(path: Path) -> str | None:
    """Build the R1 to R4 text for one playbook, or None if it cannot be parsed."""
    pb = parse_playbook(path)
    if pb is None or pb.task_count == 0:
        return None
    is_x = pb.vendor_format == "xsoar_yaml"
    is_b = pb.vendor_format == "cisa_bpmn"
    L = [f"PLAYBOOK: {pb.name}  [{pb.vendor_format}]  ({pb.task_count} tasks)",
         f"SOURCE:   {path}"]

    # ---- R1: one line per task with identity ----
    L.append("\nR1 - TASK INVENTORY (what actions exist)")
    for t in pb.tasks:
        ident = f"  | tool/op: {t.automation}" if t.automation else ""
        # Sentinel descriptions that only hold runAfter links are not useful here.
        desc = f"  | {t.description[:90]}" if t.description and not t.description.startswith("runAfter") else ""
        L.append(f"  [{t.task_id}] ({t.task_type}) {t.name or '(unnamed)'}{ident}{desc}")

    # ---- R2: successor edges ----
    L.append("\nR2 - CONTROL FLOW (successor edges)")
    succ = defaultdict(list)
    if is_x or is_b:
        # XSOAR and BPMN already store successors (next-task links, sequence flows).
        for t in pb.tasks:
            for n in t.next_tasks:
                succ[t.task_id].append(n)
    else:
        # Sentinel stores predecessors ("runAfter"); invert them into successors.
        for t in pb.tasks:
            m = re.search(r"runAfter: \[(.*?)\]", t.description or "")
            for p in ([x.strip().strip("'\"") for x in m.group(1).split(",")] if m else []):
                if not p:
                    continue
                # The predecessor may be named by its bare name; find the task id it belongs to.
                hits = [x.task_id for x in pb.tasks
                        if x.task_id == p or x.task_id.endswith("/" + p) or x.name == p]
                succ[hits[0] if hits else p].append(t.task_id)
        # Top-level actions with no runAfter run straight after the trigger.
        roots = [t.task_id for t in pb.tasks
                 if not t.task_id.startswith("trigger") and "/" not in t.task_id
                 and "runAfter: [" not in (t.description or "")]
        for tr in [t.task_id for t in pb.tasks if t.task_id.startswith("trigger")]:
            succ[tr] = roots
    for k in sorted(succ):
        L.append(f"  {k} -> {', '.join(succ[k])}")

    # ---- R3: who decides ----
    L.append("\nR3 - HUMAN vs AUTOMATED (who decides / acts)")
    if is_x:
        kinds = _xsoar_condition_kinds(path)
        any_dec = False
        for t in pb.tasks:
            if t.task_type == "condition":
                any_dec = True
                L.append(f"  [{t.task_id}] condition: {t.name} -> {kinds.get(t.task_id, 'unclassified')}")
            elif t.task_type == "collection":
                # A collection task is a form an analyst fills in: human input by definition.
                any_dec = True
                L.append(f"  [{t.task_id}] collection: {t.name} -> HUMAN input (analyst form)")
        if not any_dec:
            L.append("  no decision or collection tasks -> fully automated path")
    elif is_b:
        humans = [t for t in pb.tasks if (t.task_type or "").lower() in ("usertask", "manualtask")]
        gates = [t for t in pb.tasks if "gateway" in (t.task_type or "").lower()]
        for t in humans:
            L.append(f"  [{t.task_id}] {t.task_type}: {t.name} -> HUMAN task")
        for t in gates:
            L.append(f"  [{t.task_id}] {t.task_type}: {t.name or '(unnamed)'} -> decision point (routing on the labelled flows)")
        if not humans:
            L.append("  no user or manual tasks -> no human step in this process")
    else:
        for t in pb.tasks:
            if t.task_type == "If":
                L.append(f"  [{t.task_id}] If -> AUTOMATED value-check (Logic App expression)")
        # Human decision points in Logic Apps appear as approval or adaptive-card connectors.
        approvals = [t.task_id for t in pb.tasks if (t.automation and
                     any(k in t.automation.lower() for k in ("approval", "adaptivecard")))
                     or "WAITS FOR A HUMAN RESPONSE" in (t.description or "")]
        L.append("  approval connectors: " + (", ".join(approvals) if approvals
                 else "NONE -> no human decision point in this playbook"))

    # ---- R4: where each decision's exits lead ----
    L.append("\nR4 - BRANCH TOPOLOGY (where each decision's exits lead)")
    emitted = False
    if is_x:
        # a title task is an end marker only when nothing follows it; a title with successors is a section header
        titles = {t.task_id: (t.name or "") for t in pb.tasks if t.task_type == "title" and not t.next_tasks}
        for t in pb.tasks:
            if t.task_type != "condition":
                continue
            emitted = True
            dests = []
            for n in t.next_tasks:
                nm = titles.get(n, "")
                mark = " (terminal title '" + nm + "' - no escalation)" if nm else ""
                dests.append(n + mark)
            L.append(f"  [{t.task_id}] {t.name}: exits -> {', '.join(dests) or '(none)'}")
    elif is_b:
        for t in pb.tasks:
            if "gateway" in (t.task_type or "").lower():
                emitted = True
                labels = re.search(r"branches: (.*)", t.description or "")
                L.append(f"  [{t.task_id}] {t.name or t.task_type}: exits -> "
                         f"{labels.group(1) if labels else ', '.join(t.next_tasks) or '(none)'}")
    else:
        for t in pb.tasks:
            if t.task_type == "If":
                emitted = True
                # actions nested directly under the condition: the else branch carries "/else/" in its id
                kids = [x.task_id for x in pb.tasks if x.task_id.startswith(t.task_id + "/")]
                true_kids = [k for k in kids if not k.startswith(t.task_id + "/else/")]
                else_kids = [k for k in kids if k.startswith(t.task_id + "/else/")]
                L.append(f"  [{t.task_id}] true-branch -> {', '.join(true_kids) or '(empty)'}; "
                         f"false-branch -> {', '.join(else_kids) if else_kids else 'ABSENT (no else): terminates silently'}")
    if not emitted:
        L.append("  no branching: single linear path")
    return "\n".join(L)


def main() -> int:
    """Render one playbook, or every playbook under a directory, and write the text files."""
    target = Path(sys.argv[1])
    # One file: print to the screen.
    if target.is_file():
        view = r_view(target)
        print(view if view else f"Not parseable: {target}")
        return 0
    # A folder: write one text file per playbook plus an index that maps file names back to sources.
    out = Path(__file__).parent / "outputs" / "rviews"
    out.mkdir(parents=True, exist_ok=True)
    index, n = [], 0
    for f in sorted(target.rglob("*")):
        if not (f.is_file() and f.suffix.lower() in {".yml", ".yaml", ".json", ".bpmn", ".xml"}):
            continue
        view = r_view(f)
        if view is None:
            continue
        n += 1
        # Build a safe output name from the parent folder and file stem; add a
        # numeric suffix if two playbooks would otherwise collide.
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", (f.parent.name + "_" + f.stem))[:110]
        candidate, k = safe, 1
        while (out / f"{candidate}.txt").exists():
            k += 1
            candidate = f"{safe}__{k}"
        (out / f"{candidate}.txt").write_text(view, encoding="utf-8")
        index.append(f"{candidate}.txt\t{f}")
    (out / "_index.txt").write_text("\n".join(index), encoding="utf-8")
    print(f"wrote {n} R-views to {out} (+ _index.txt)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
