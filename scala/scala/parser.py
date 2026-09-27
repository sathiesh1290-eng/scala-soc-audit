"""SCALA structural parser.

Turns a raw playbook file into the normalised ParsedPlaybook record defined in
models.py. Three vendor formats are supported, each handled by its own "walker":

  Cortex XSOAR            YAML export, one entry per task under `tasks`
  Microsoft Sentinel      Logic App workflow embedded in an ARM deployment template (JSON)
  BPMN 2.0 (CISA style)   XML process diagram: tasks, events, gateways and sequence flows

Every walker extracts the same four things and nothing more:
  R1  the inventory of tasks and what each one calls
  R2  the control flow (which task can follow which)
  R3  the type of each step, from which "human or automated decision" is read
  R4  where each branch of a decision leads

There is no compliance logic in this file. Whether a task is destructive, or a
condition counts as a human approval, is decided later by the language model.

The parser also refuses what it should not parse: a file whose layout merely
resembles a supported format is rejected (returns None) rather than being
parsed into an empty, misleading structure.
"""
from __future__ import annotations

import json                    # Sentinel playbooks are JSON documents
import re                      # regular expressions, used to recognise ARM template expressions like [parameters('x')]
from pathlib import Path       # cross-platform file paths

import yaml                    # PyYAML: reads the XSOAR YAML exports (safe_load never executes code)

from .models import ParsedPlaybook, PlaybookTask


def detect_format(path: Path) -> str | None:
    """Guess which vendor format a file is in, from its extension and content.

    Returns one of "xsoar_yaml", "sentinel_logicapp", "cisa_bpmn", or None when
    the file is not a playbook SCALA knows how to read.
    """
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".bpmn":
        return "cisa_bpmn"
    if path.suffix.lower() in {".yml", ".yaml"}:
        return "xsoar_yaml"
    if path.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None                                   # not valid JSON at all
        # Look at the start of the document only (20,000 characters is plenty)
        # for the two markers that identify a Logic App workflow.
        blob = json.dumps(data)[:20000]
        if "Microsoft.Logic/workflows" in blob or '"triggers"' in blob:
            return "sentinel_logicapp"
    return None


def _parse_bpmn(path: Path):
    """BPMN 2.0 walker.

    A BPMN file is XML. Inside <process> there are node elements (tasks, events,
    gateways) and <sequenceFlow> elements that join them. The mapping to the
    normalised model is:
      node element tag  -> task_type   (userTask / manualTask mean a human step;
                                        gateways mean a branching decision)
      sequenceFlow      -> next_tasks  (source -> target edges)
      flow labels       -> written into the source node's description as
                           "branches: label->target; ..." so branch names survive
    """
    import xml.etree.ElementTree as ET                    # standard-library XML reader; imported here because only this walker needs it
    NS = {"bpmn": "http://www.omg.org/spec/BPMN/20100524/MODEL"}   # the BPMN XML namespace
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError:
        return None                                       # malformed XML
    proc = root.find("bpmn:process", NS)
    if proc is None:
        return None                                       # no <process> element: not a BPMN playbook
    # Every node kind that can appear in the diagram. Anything not in this list
    # (for example pure documentation elements) is ignored on purpose.
    node_tags = ["task", "userTask", "manualTask", "serviceTask", "scriptTask",
                 "sendTask", "receiveTask", "businessRuleTask", "callActivity",
                 "startEvent", "endEvent", "intermediateCatchEvent",
                 "intermediateThrowEvent", "exclusiveGateway", "parallelGateway",
                 "inclusiveGateway", "eventBasedGateway", "subProcess"]
    nodes = {}
    for tag in node_tags:
        for el in proc.findall(f"bpmn:{tag}", NS):
            nodes[el.get("id")] = (tag, el.get("name") or "")   # id -> (kind, label)
    flows = []
    for fl in proc.findall("bpmn:sequenceFlow", NS):
        flows.append((fl.get("sourceRef"), fl.get("targetRef"), fl.get("name") or ""))
    if not nodes:
        return None                                       # a process with no nodes is not a workflow
    # Build the successor lists (R2/R4) and collect branch labels per source node.
    succ, labels = {}, {}
    for s, t, lbl in flows:
        succ.setdefault(s, []).append(t)
        if lbl:
            labels.setdefault(s, []).append(f"{lbl}->{t}")
    tasks = []
    for nid, (tag, name) in nodes.items():
        desc = ""
        if nid in labels:
            desc = "branches: " + "; ".join(labels[nid])
        tasks.append(PlaybookTask(
            task_id=nid, name=name, task_type=tag,
            automation=None, description=desc,              # BPMN diagrams do not name a tool or script
            next_tasks=succ.get(nid, []),
        ))
    pname = proc.get("name") or path.stem
    return ParsedPlaybook(playbook_id=proc.get("id") or path.stem, name=pname,
                          # CISA files are organised in folders named after the
                          # lifecycle function (e.g. Respond); record that as context.
                          description=f"CISA BPMN playbook ({path.parent.parent.name} function)",
                          vendor_format="cisa_bpmn", tasks=tasks,
                          source_file=str(path))


def parse_playbook(path: Path) -> ParsedPlaybook | None:
    """Public entry point: detect the format and hand the file to the right walker."""
    fmt = detect_format(path)
    if fmt == "xsoar_yaml":
        return _parse_xsoar(path)
    if fmt == "sentinel_logicapp":
        return _parse_sentinel(path)
    if fmt == "cisa_bpmn":
        return _parse_bpmn(path)
    return None


# ---------------------------------------------------------------- XSOAR ----

def _parse_xsoar(path: Path) -> ParsedPlaybook | None:
    """Cortex XSOAR walker.

    An XSOAR export is a YAML document with a top-level `tasks` mapping. Each
    entry looks like:
        "12":
          type: condition                 <- the task kind (regular, condition, title, ...)
          task: {name: ..., script: ..., description: ...}   <- the inner block
          nexttasks: {"yes": ["13"], "no": ["2"]}             <- outgoing edges per branch label
    """
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    except yaml.YAMLError:
        return None                                       # not valid YAML
    if not isinstance(data, dict) or "tasks" not in data:
        return None                                       # no task list: not a playbook export
    # Reject look-alike schemas. One other product's YAML also has a top-level
    # `tasks` mapping, but its task objects are flat (fields like `next` and
    # `schema`) and have no nested `task` block. Parsing it as XSOAR would
    # produce a playbook full of empty tasks, so it is refused instead.
    tvals = [t for t in (data.get("tasks") or {}).values() if isinstance(t, dict)]
    if tvals and not any("task" in t for t in tvals):
        return None

    tasks: list[PlaybookTask] = []
    for tid, tdata in (data.get("tasks") or {}).items():
        if not isinstance(tdata, dict):
            continue                                      # skip malformed entries rather than crash
        inner = tdata.get("task") or {}                   # the nested block with name/script/description
        # Collect every outgoing edge regardless of which branch label it sits under.
        next_tasks: list[str] = []
        for branch in (tdata.get("nexttasks") or {}).values():
            if isinstance(branch, list):
                next_tasks.extend(str(x) for x in branch)
        tasks.append(
            PlaybookTask(
                task_id=str(tid),
                name=str(inner.get("name", "")),
                # The kind of task is usually on the outer entry; fall back to the inner block.
                task_type=str(tdata.get("type", inner.get("type", ""))),
                # What the task calls: a script or an automation name (R1 identity).
                automation=(
                    str(inner.get("script") or inner.get("scriptName") or "")
                    or None
                ),
                description=str(inner.get("description", ""))[:300],   # trimmed to keep prompts short
                next_tasks=next_tasks,
            )
        )
    return ParsedPlaybook(
        source_file=path.name,
        vendor_format="xsoar_yaml",
        playbook_id=str(data.get("id", "")),
        name=str(data.get("name", "")),
        description=str(data.get("description", ""))[:500],
        tasks=tasks,
    )


# ------------------------------------------------------------- Sentinel ----

def _parse_sentinel(path: Path) -> ParsedPlaybook | None:
    """Microsoft Sentinel walker.

    A Sentinel playbook is a Logic App. The corpus ships them as ARM deployment
    templates: a JSON document whose `resources` list contains a workflow whose
    `definition` holds `triggers` (how the playbook starts) and `actions`
    (the steps). Steps may be nested inside scopes and conditions, and Logic
    Apps record ORDER backwards: each action lists the steps it runs after
    (`runAfter`) rather than the steps that follow it.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None

    # The workflow definition can sit at different depths in the template, so it
    # is searched for rather than addressed by a fixed path.
    definition = _find_definition(data)
    if definition is None:
        return None

    tasks: list[PlaybookTask] = []
    # Triggers become the first tasks, with a "trigger:" prefix so they are recognisable.
    for name, trig in (definition.get("triggers") or {}).items():
        tasks.append(
            PlaybookTask(
                task_id=f"trigger:{name}",
                name=name,
                task_type=f"trigger/{trig.get('type', '')}" if isinstance(trig, dict) else "trigger",
            )
        )
    # Walk all actions, including nested ones, appending to the same list.
    _walk_actions(definition.get("actions") or {}, tasks, prefix="")

    # The display name lives on the workflow resource, and is often an ARM
    # template expression such as "[parameters('PlaybookName')]".
    display_name = ""
    resources = data.get("resources")
    if isinstance(resources, list):
        for r in resources:
            if isinstance(r, dict) and r.get("type") == "Microsoft.Logic/workflows":
                display_name = str(r.get("name", ""))
                break
    # Resolve that expression against the template's parameters block (its
    # defaultValue). Without this step the playbook would be named after the
    # expression itself, which is meaningless to a reader.
    m = re.fullmatch(r"\[parameters\('([^']+)'\)\]", display_name.strip())
    if m:
        param = (data.get("parameters") or {}).get(m.group(1)) or {}
        display_name = str(param.get("defaultValue", "")) or ""

    return ParsedPlaybook(
        source_file=path.name,
        vendor_format="sentinel_logicapp",
        playbook_id=display_name,
        name=display_name or path.stem,                   # last resort: the file name
        description="Azure Sentinel Logic App playbook",
        tasks=tasks,
    )


def _find_definition(data: object) -> dict | None:
    """Search the whole JSON tree for the object that has both 'triggers' and 'actions'.

    Recursive: looks inside every dictionary and list until it finds the Logic
    App definition, or returns None if there is none.
    """
    if isinstance(data, dict):
        if "triggers" in data and "actions" in data:
            return data
        for v in data.values():
            found = _find_definition(v)
            if found is not None:
                return found
    elif isinstance(data, list):
        for item in data:
            found = _find_definition(item)
            if found is not None:
                return found
    return None


def _walk_actions(actions: dict, out: list[PlaybookTask], prefix: str) -> None:
    """Turn a Logic App `actions` mapping into tasks, descending into nested scopes.

    `prefix` carries the path of enclosing scopes, so a step named "Send_email"
    inside a condition named "If_malicious" gets the id "If_malicious/Send_email".
    That keeps ids unique and lets a reader see the nesting.
    """
    for name, action in actions.items():
        if not isinstance(action, dict):
            continue
        # Logic Apps store predecessors, not successors: the keys of runAfter are
        # the steps this one waits for.
        run_after = list((action.get("runAfter") or {}).keys())
        out.append(
            PlaybookTask(
                task_id=f"{prefix}{name}",
                name=name,
                task_type=str(action.get("type", "")),        # e.g. "If", "Scope", "ApiConnection", "Http"
                automation=_connector_of(action),
                description=str(action.get("description", ""))[:300],
                next_tasks=[],  # successors are not stored by Logic Apps; predecessors go in the description instead
            )
        )
        # A Teams "flow continuation" webhook posts an adaptive card to a channel and
        # suspends the workflow until a person submits a response. That is a human
        # decision point, so it is marked as one here for the renderer and the model.
        if _waits_for_person(action):
            out[-1].description = ("WAITS FOR A HUMAN RESPONSE (adaptive card posted to Teams; workflow continues on submit). " + out[-1].description).strip()
        if run_after:
            out[-1].description = (out[-1].description + f" runAfter: {run_after}").strip()
        # Recurse into nested blocks: a condition has `actions` (the true branch)
        # and optionally `else: {actions: ...}` (the false branch); a scope has `actions`.
        # The two branches get different id prefixes ("Cond/" and "Cond/else/") so
        # that a reader, the renderer and the model can tell them apart. (Earlier
        # versions gave both branches the same prefix, which hid else branches.)
        nested = action.get("actions")
        if isinstance(nested, dict):
            _walk_actions(nested, out, prefix=f"{prefix}{name}/")
        els = action.get("else")
        if isinstance(els, dict):
            _walk_actions(els.get("actions", els), out, prefix=f"{prefix}{name}/else/")
        # Switch actions keep their branches under `cases` (each with its own
        # `actions`) and `default`. They are walked so that the tasks inside a case
        # are visible; the case value is carried in the id ("Switch/case:value/").
        cases = action.get("cases")
        if isinstance(cases, dict):
            for cname, case in cases.items():
                if isinstance(case, dict) and isinstance(case.get("actions"), dict):
                    _walk_actions(case["actions"], out, prefix=f"{prefix}{name}/case:{cname}/")
        default = action.get("default")
        if isinstance(default, dict) and isinstance(default.get("actions"), dict):
            _walk_actions(default["actions"], out, prefix=f"{prefix}{name}/default/")


def _waits_for_person(action: dict) -> bool:
    """True when a Logic App action suspends until a person responds (Teams adaptive card)."""
    if action.get("type") != "ApiConnectionWebhook":
        return False
    inputs = action.get("inputs") or {}
    path = str(inputs.get("path", ""))
    body = json.dumps(inputs.get("body", {}))[:4000]
    return "flowcontinuation" in path or ("AdaptiveCard" in body and "Action.Submit" in body)


def _connector_of(action: dict) -> str | None:
    """Work out what external tool a Sentinel action calls (R1 identity).

    Connector actions name their API under inputs.host (apiId or connection)
    plus a path or method; raw HTTP actions carry a uri. Returns a short
    "api operation" string, or None for actions that call nothing outside.
    """
    inputs = action.get("inputs")
    if isinstance(inputs, dict):
        host = inputs.get("host")
        if isinstance(host, dict):
            conn = host.get("connection")
            api = host.get("apiId") or (conn if isinstance(conn, str) else None)
            op = inputs.get("path") or inputs.get("method") or ""
            if api:
                return f"{api} {op}".strip()
        if "uri" in inputs:
            return f"HTTP {inputs.get('method', '')} {inputs['uri']}"[:200]
    return None


# ---------------------------------------------------------------- batch ----