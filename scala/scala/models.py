"""SCALA data models.

This module defines the handful of record types that every other part of SCALA
passes around. Think of them as agreed "forms" with fixed fields:

  PlaybookTask    one step in a playbook (one row of the task inventory)
  ParsedPlaybook  a whole playbook after parsing: its tasks plus some metadata
  Constraint      one audit rule translated from a standard
  Finding         the auditor's verdict on ONE constraint for ONE playbook
  AuditReport     all the findings for one playbook, with provenance

The records are deliberately free of any compliance meaning. The parser only
records what is structurally there; deciding what that structure means is the
language model's job (see audit.py).

Why pydantic? Every record is checked when it is created. If a parser tries to
build a task without an identifier, or the model replies with a status word that
is not one of the three allowed values, the record fails immediately with a
clear error instead of quietly carrying bad data into the results.
"""
from __future__ import annotations   # lets type hints refer to classes defined later in the file

# typing gives the annotations used below:
#   Literal  restricts a field to a fixed set of allowed strings (e.g. the three verdicts)
#   Optional marks a field that may legitimately be empty (None)
from typing import Literal, Optional

# pydantic provides BaseModel (a class whose fields are validated on construction)
# and Field (used here only to give list fields a fresh empty list as default;
# a shared mutable default would be a classic Python bug).
from pydantic import BaseModel, Field


class PlaybookTask(BaseModel):
    """One step of a playbook, in a form common to every vendor format.

    The four information requirements SCALA needs from a playbook are:
      R1  which tasks exist and what each one calls   -> task_id, name, automation, description
      R2  the order tasks run in                       -> next_tasks (the successor links)
      R3  whether a decision is human or automated     -> task_type (e.g. "condition", "userTask")
      R4  where each branch of a decision leads        -> next_tasks again, read per decision
    """
    task_id: str                                   # unique id inside the playbook (XSOAR numbers, Sentinel action names, BPMN ids)
    name: str = ""                                 # human-readable label the author gave the step
    task_type: str = ""                            # vendor type word, e.g. XSOAR: regular|condition|collection|start|title
    automation: Optional[str] = None               # the script, command or connector action the step calls, if any
    description: str = ""                          # free text from the file; Sentinel also carries "runAfter: [...]" here
    next_tasks: list[str] = Field(default_factory=list)   # ids of the steps that can run next (outgoing edges)


class ParsedPlaybook(BaseModel):
    """A whole playbook after parsing: metadata plus the list of tasks."""
    source_file: str                               # file name (or path) the playbook was read from
    vendor_format: Literal["xsoar_yaml", "sentinel_logicapp", "cisa_bpmn"]   # which walker produced it
    playbook_id: str = ""                          # vendor identifier, when the file has one
    name: str = ""                                 # display name
    description: str = ""                          # author's description, trimmed
    tasks: list[PlaybookTask] = Field(default_factory=list)

    @property
    def task_count(self) -> int:
        """Number of tasks; used by size checks and by the verification script."""
        return len(self.tasks)

    def structural_summary(self) -> str:
        """Render the playbook as the compact plain text the language model reads.

        One header block, then one line per task showing its id, type, name, what
        it calls, its description and its successors. This is structure only:
        nothing here says whether a step is "good" or "bad". The format is frozen
        because every evaluation result depends on the model seeing exactly this.
        """
        # Header: name (falling back to id, then file name), format, description, size.
        lines = [
            f"Playbook: {self.name or self.playbook_id or self.source_file}",
            f"Format: {self.vendor_format}",
            f"Description: {self.description or '(none)'}",
            f"Task count: {self.task_count}",
            "Tasks:",
        ]
        # One line per task. Optional parts are only added when present so the
        # summary stays short for small models with limited context windows.
        for t in self.tasks:
            auto = f" | automation: {t.automation}" if t.automation else ""
            nxt = f" -> next: {', '.join(t.next_tasks)}" if t.next_tasks else ""
            desc = f" | {t.description}" if t.description else ""
            lines.append(f"  - [{t.task_id}] ({t.task_type}) {t.name}{auto}{desc}{nxt}")
        return "\n".join(lines)


class Constraint(BaseModel):
    """One audit rule, as stored in standards/constraints.json.

    The first group of fields is what the model is shown. The second group is
    documentation of how the rule was derived from the standards; it is kept
    with the rule so the translation can be reviewed, but it is never sent to
    the model.
    """
    constraint_id: str                             # C01 ... C12
    source: str                                    # the primary standard, e.g. "NIST SP 800-61r3"
    control_ref: str                               # the primary control or function inside that standard
    constraint_text: str                           # the rule in plain language
    audit_question: str                            # the yes/no question an auditor asks of a playbook
    default_severity: Literal["low", "medium", "high"] = "medium"   # how serious a breach is by default
    # --- derivation record (documentation only; not part of the prompt) ---
    sources: list[str] = Field(default_factory=list)                # every standard clause that supports the rule
    inference_type: Literal["direct", "derived"] = "direct"        # direct = stated almost verbatim; derived = interpretation recorded
    derivation: str = ""                                            # the written justification for the translation


class Finding(BaseModel):
    """The auditor's verdict on one constraint for one playbook."""
    constraint_id: str
    status: Literal["violated", "satisfied", "not_applicable"]     # the only three verdicts allowed
    severity: Literal["low", "medium", "high"] = "medium"
    rationale: str = ""                            # the model's one-sentence reason
    recommendation: str = ""                       # the model's one-sentence fix (for violations)
    # Evidence citation and its check (strategies C to F). The model is asked to
    # list the task ids it relied on; code then checks those ids really exist.
    evidence_task_ids: list[str] = Field(default_factory=list)
    evidence_valid: bool | None = None             # True/False after the check; None when the strategy does not cite evidence


class AuditReport(BaseModel):
    """Everything the auditor returns for one playbook."""
    playbook_file: str
    playbook_name: str = ""
    model_name: str = ""                           # e.g. "mistral@ollama" or "z-ai/glm-4.5@openai_compat" (provenance)
    retrieved_constraint_ids: list[str] = Field(default_factory=list)   # which constraints were put to the model
    findings: list[Finding] = Field(default_factory=list)

    @property
    def violations(self) -> list[Finding]:
        """Convenience filter: only the findings whose status is 'violated'."""
        return [f for f in self.findings if f.status == "violated"]
