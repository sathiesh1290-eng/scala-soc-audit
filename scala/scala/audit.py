"""SCALA auditor: asks a language model to judge a playbook against the constraints.

How an audit works, step by step:

  1. The parsed playbook is rendered as a short structural summary (models.py).
  2. The knowledge base returns the relevant constraints (kb.py).
  3. A prompt is built for the selected STRATEGY (see below) and sent to the
     model, either a local model served by Ollama or a remote open-weights
     model behind an OpenAI-compatible API.
  4. The model's reply is expected to be JSON. Because models sometimes wrap
     JSON in prose or markdown, the reply is searched for the JSON, and if
     nothing parseable is found the request is retried up to three times with
     a sterner instruction and a slightly higher temperature.
  5. For strategies that require evidence, the task ids the model cites are
     checked against the parsed playbook by ordinary code.
  6. Every verdict is validated against the Finding form (models.py) and
     assembled into an AuditReport that records which model and back end
     produced it.

The six strategies (selected with the SCALA_AUDIT_MODE environment variable):

  A  batched              all constraints in one request (the baseline)
  B  per_constraint       one request per constraint
  C  per_constraint_v4    per constraint, plus worked examples, an explicit
                          standard of proof, and a required evidence citation
                          that code then checks
  D  per_constraint_cot   strategy C with written reasoning required before
                          the verdict
  E  per_constraint_sc    strategy C sampled three times at a higher
                          temperature; majority vote decides
  F  per_constraint_gate  applicability first: the model is first asked whether
                          the constraint applies at all, and only then for a
                          verdict

Each strategy's purpose and the hypothesis recorded before it was run are
documented next to its prompt below. The prompt texts are frozen: every
evaluation result depends on them being exactly as they are.

Set SCALA_MOCK=1 to bypass the model entirely. That is for checking the
plumbing only; mock output must never be reported as a result.
"""
from __future__ import annotations

import json                    # prompts ask for JSON replies; json parses them and builds request bodies
import os                      # configuration is read from environment variables (model, back end, strategy)
import re                      # regular expressions locate candidate JSON inside a chatty reply
import urllib.request          # standard-library HTTP client, used for both back ends (no extra dependency)
import urllib.error            # the HTTP error types raised by urllib, needed for the retry logic

from .kb import PolicyKB
from .models import AuditReport, Constraint, Finding, ParsedPlaybook

# ------------------------------------------------------------ configuration --
# Everything below is read once at import time from environment variables so a
# run can be configured from the shell without editing code.

# Where the local Ollama server listens. Ollama serves models such as mistral,
# llama3.1 and qwen2.5 on the user's own machine.
OLLAMA_URL = os.environ.get("SCALA_OLLAMA_URL", "http://localhost:11434/api/generate")
# The model name. For Ollama this is a pulled model tag; for the remote back end
# it is the provider's model id (e.g. "deepseek/deepseek-chat").
MODEL = os.environ.get("SCALA_MODEL", "mistral")

# Back ends:
# SCALA_BACKEND=ollama (default): local models through Ollama; the playbook data never leaves the host.
# SCALA_BACKEND=openai_compat: any OpenAI-compatible chat endpoint. Used for the open-weights
#   models that are too large for a workstation; the same weights could be hosted by the
#   organisation on server-class hardware.
#   Requires SCALA_API_BASE (e.g. https://openrouter.ai/api/v1) and SCALA_API_KEY.
#   SCALA_MODEL then names the provider model id, e.g. "deepseek/deepseek-chat",
#   "moonshotai/kimi-k2", "qwen/qwen-2.5-72b-instruct", "z-ai/glm-4.5",
#   "meta-llama/llama-3.3-70b-instruct".
BACKEND = os.environ.get("SCALA_BACKEND", "ollama")
API_BASE = os.environ.get("SCALA_API_BASE", "https://openrouter.ai/api/v1").rstrip("/")
API_KEY = os.environ.get("SCALA_API_KEY", "")
# Upper bound on the length of a remote reply; verdict objects are short, so 2048 tokens is ample.
API_MAX_TOKENS = int(os.environ.get("SCALA_API_MAX_TOKENS", "2048"))
# The strategy. Values: batched | per_constraint | per_constraint_v4 | per_constraint_cot |
# per_constraint_sc | per_constraint_gate (letters A to F in the description above).
AUDIT_MODE = os.environ.get("SCALA_AUDIT_MODE", "batched")
# A version label for the prompt in use. It is written into every output file
# name and report so results from different strategies can never be confused.
PROMPT_VERSION = {"batched": "v2-batched",
                  "per_constraint": "v3-perconstraint",
                  "per_constraint_v4": "v4-perconstraint-calibrated",
                  "per_constraint_cot": "v5-perconstraint-reason-then-verdict",
                  "per_constraint_sc": "v6-perconstraint-selfconsistency-k3",
                  "per_constraint_gate": "v7.1-perconstraint-gate-then-judge"}.get(AUDIT_MODE, "v2-batched")

# ------------------------------------------------------ strategy A prompt --
# Strategy A (batched): one request, one verdict per constraint, returned as a
# JSON array. The instructions are deliberately strict about output format
# because small models tend to add explanations around the JSON.
_PROMPT = """You are a security compliance auditor. Audit the SOAR playbook below
against each numbered constraint. Judge only from the playbook structure given.

PLAYBOOK STRUCTURE:
{summary}

CONSTRAINTS TO AUDIT AGAINST:
{constraints}

For EVERY constraint listed above, output exactly one verdict object:
- "violated": the playbook performs relevant actions but lacks what the constraint requires.
- "satisfied": the playbook contains structure meeting the constraint.
- "not_applicable": the constraint concerns actions this playbook does not perform.
Be conservative: only report "violated" when the structure clearly lacks the required element.

OUTPUT RULES (strict):
1. Output ONLY a JSON array. No text before it. No text after it. No markdown fences.
2. The array must contain exactly {n} objects, one per constraint, in the order listed.
3. Each object: {{"constraint_id": "...", "status": "violated|satisfied|not_applicable",
   "severity": "low|medium|high", "rationale": "one sentence", "recommendation": "one sentence"}}
"""

# Appended to a prompt when the previous reply could not be parsed.
_RETRY_SUFFIX = """

REMINDER: Your previous output could not be parsed. Output ONLY the JSON array
described above starting with [ and ending with ] and nothing else."""

# ------------------------------------------------------ strategy B prompt --
# Strategy B (per_constraint): the same question, but for ONE constraint at a
# time, so the model's attention is not divided across twelve rules.
_SINGLE_PROMPT = """You are a security compliance auditor. Audit the SOAR playbook below
against ONE constraint. Judge only from the playbook structure given.

PLAYBOOK STRUCTURE:
{summary}

CONSTRAINT:
{constraint}

Decide the status:
- "violated": the playbook performs relevant actions but lacks what the constraint requires,
  OR the constraint requires a step/element that should be present and it is absent.
- "satisfied": the playbook contains structure meeting the constraint.
- "not_applicable": the constraint concerns actions this playbook does not perform at all.

Output ONLY one JSON object, nothing else:
{{"constraint_id": "{cid}", "status": "violated|satisfied|not_applicable",
  "severity": "low|medium|high", "rationale": "one sentence", "recommendation": "one sentence"}}
"""


def _extract_json_object(text: str) -> dict:
    """Find the first usable JSON object in a model reply.

    Models sometimes write "Here is my verdict: {...}" or wrap the object in
    markdown fences. Rather than trusting the reply to be pure JSON, every "{"
    in the text is tried as a starting point until one decodes to an object
    that carries a constraint_id and a status (or an applicability flag).
    """
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = decoder.raw_decode(text, m.start())    # raw_decode tolerates trailing text
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "constraint_id" in obj and ("status" in obj or "applies" in obj):
            return obj
    raise ValueError(f"No parseable JSON object in model output: {text[:200]!r}")


def _audit_per_constraint(summary: str, constraints: list[Constraint]) -> list[dict]:
    """Strategy B: loop over the constraints, one request each, with parse retries."""
    out = []
    for c in constraints:
        # The constraint as the model sees it: id, source, severity, rule text and audit question.
        cdesc = (f"{c.constraint_id} [{c.source}, {c.control_ref}] "
                 f"(severity {c.default_severity}): {c.constraint_text} "
                 f"AUDIT CHECK: {c.audit_question}")
        base = _SINGLE_PROMPT.format(summary=summary, constraint=cdesc, cid=c.constraint_id)
        # Up to three attempts. The first is at temperature 0 (deterministic);
        # later attempts add the reminder and nudge the temperature so the model
        # does not repeat the identical unparseable reply.
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            prompt = base if attempt == 0 else base + _RETRY_SUFFIX
            try:
                out.append(_extract_json_object(_call_ollama(prompt, temperature=temp)))
                break
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} parse attempt {attempt + 1} failed: {exc}")
        else:
            # The for/else runs only when the loop was never broken: all three attempts failed.
            print(f"[audit] {c.constraint_id}: unparseable after 3 attempts; recording no verdict")
    return out



# ------------------------------------------------------ strategy C prompt --
# Strategy C (per_constraint_v4): one constraint per request, with three additions
# to strategy B, each addressing a failure observed with the small models:
#   1. Three worked examples, one per verdict (satisfied, violated, not applicable),
#      to counter both over-flagging and the dismissal of real gaps as not applicable.
#      The examples are synthetic and generic; none is taken from the reference set.
#   2. A required citation of the task identifiers the verdict relies on. The cited
#      identifiers are checked against the parsed playbook (verification layer 5),
#      which sets the evidence_valid flag on the finding.
#   3. An explicit standard of proof: a task that plausibly performs the required
#      function in the required position is sufficient; explicit naming is not required.
# Hypothesis: precision above the violation rate of the reference set with recall of at least 0.8.

_V4_EXAMPLES = """WORKED EXAMPLES (calibration follow this standard of proof):

Example A (satisfied). Structure: [1](start) Start -> 2; [2](regular) Collect memory image | tool: forensics|||capture-memory -> 3; [3](condition) Analyst approves eradication? -> 4, 5; [4](regular) Reimage host -> 5; [5](title) Done.
Constraint: evidence must be preserved before eradication.
Verdict: {"status": "satisfied", "evidence_task_ids": ["2"], "rationale": "Task 2 captures a memory image and precedes the reimage at task 4, which satisfies preservation-before-eradication even though the task is not named 'evidence'."}

Example B (violated). Structure: [1](start) Start -> 2; [2](regular) Delete mailbox items | tool: ews|||delete -> 3; [3](title) Done.
Constraint: destructive actions require a prior human decision point.
Verdict: {"status": "violated", "evidence_task_ids": [], "rationale": "Task 2 deletes mailbox items and no condition or analyst task precedes it on the path from start; no task satisfies the constraint."}

Example C (not_applicable). Structure: [1](start) Start -> 2; [2](regular) Enrich IP reputation | tool: vt|||ip-report -> 3; [3](regular) Add note to incident -> 4; [4](title) Done.
Constraint: destructive actions require a prior human decision point.
Verdict: {"status": "not_applicable", "evidence_task_ids": [], "rationale": "The playbook performs only enrichment and note-taking; it executes no destructive action, so the constraint does not govern it."}
"""

_SINGLE_PROMPT_V4 = """You are a security compliance auditor. Audit the SOAR playbook below
against ONE constraint. Judge only from the playbook structure given.

{examples}
STANDARD OF PROOF:
- "satisfied": a task that PLAUSIBLY performs the required function exists in the required
  position (before/after/at a branch as the constraint demands). Do NOT require the task to be
  named explicitly after the constraint; judge by what the task does.
- "violated": the playbook performs actions the constraint governs AND no task plausibly
  performs the required function in the required position.
- "not_applicable": the playbook performs NO action the constraint governs. If a relevant
  action IS present and the safeguard is missing, that is "violated", never "not_applicable".

PLAYBOOK STRUCTURE:
{summary}

CONSTRAINT:
{constraint}

Cite evidence: list the task ID(s) (the [bracketed] ids) that satisfy the constraint, or an
empty list if none does. Output ONLY one JSON object, nothing else:
{{"constraint_id": "{cid}", "status": "violated|satisfied|not_applicable",
  "evidence_task_ids": ["<task id>", ...], "severity": "low|medium|high",
  "rationale": "one sentence citing the task ids", "recommendation": "one sentence"}}
"""


def _validate_evidence(item: dict, task_ids: set[str]) -> dict:
    """Verification layer 5: check that the task ids the model cites really exist.

    For a "satisfied" verdict the model must point at the task(s) that satisfy
    the rule. evidence_valid becomes True when at least one id is cited and every
    cited id exists in the parsed playbook; False when the verdict is "satisfied"
    but the citation is empty or names a task that does not exist (a made-up
    justification); None for other verdicts, where no citation is expected.
    """
    cited = [str(x) for x in (item.get("evidence_task_ids") or [])]   # normalise numbers to strings
    item["evidence_task_ids"] = cited
    if item.get("status") == "satisfied":
        item["evidence_valid"] = bool(cited) and all(c in task_ids for c in cited)
    else:
        item["evidence_valid"] = None
    return item


def _audit_per_constraint_v4(summary: str, constraints: list[Constraint],
                             task_ids: set[str]) -> list[dict]:
    """Strategy C: like strategy B, but with the calibrated prompt and the evidence check."""
    out = []
    for c in constraints:
        cdesc = (f"{c.constraint_id} [{c.source}, {c.control_ref}] "
                 f"(severity {c.default_severity}): {c.constraint_text} "
                 f"AUDIT CHECK: {c.audit_question}")
        base = _SINGLE_PROMPT_V4.format(examples=_V4_EXAMPLES, summary=summary,
                                        constraint=cdesc, cid=c.constraint_id)
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            prompt = base if attempt == 0 else base + _RETRY_SUFFIX
            try:
                item = _extract_json_object(_call_ollama(prompt, temperature=temp))
                out.append(_validate_evidence(item, task_ids))    # the deterministic evidence check
                break
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} parse attempt {attempt + 1} failed: {exc}")
        else:
            print(f"[audit] {c.constraint_id}: unparseable after 3 attempts; recording no verdict")
    return out



# ------------------------------------------------- strategies D and E --
# Strategy D (per_constraint_cot): the strategy C request with three to six lines of
#   written reasoning required before the verdict (chain-of-thought prompting;
#   Wei et al., 2022). Included to measure whether explicit reasoning changes accuracy.
# Strategy E (per_constraint_sc): the strategy C request sampled three times at
#   temperature 0.7; the verdict is decided by majority vote (self-consistency;
#   Wang et al., 2023). The reason and evidence are taken from the first sample that
#   agrees with the majority; the vote counts are kept in the reason field.

_COT_SUFFIX = """
Before the JSON, write 3-6 short lines of reasoning: list the task ids relevant to this
constraint, their order on the execution path, and whether any decision point is human.
Then output the JSON object as the LAST line.
"""

# Self-consistency settings: how many samples to draw and at what temperature.
SC_K = int(os.environ.get("SCALA_SC_K", "3"))
SC_TEMP = float(os.environ.get("SCALA_SC_TEMP", "0.7"))


def _audit_per_constraint_cot(summary: str, constraints: list[Constraint],
                              task_ids: set[str]) -> list[dict]:
    """Strategy D: strategy C's prompt plus the reasoning-first suffix."""
    out = []
    for c in constraints:
        cdesc = (f"{c.constraint_id} [{c.source}, {c.control_ref}] "
                 f"(severity {c.default_severity}): {c.constraint_text} "
                 f"AUDIT CHECK: {c.audit_question}")
        base = _SINGLE_PROMPT_V4.format(examples=_V4_EXAMPLES, summary=summary,
                                        constraint=cdesc, cid=c.constraint_id) + _COT_SUFFIX
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            prompt = base if attempt == 0 else base + _RETRY_SUFFIX
            try:
                # The reasoning lines precede the JSON; _extract_json_object skips them.
                item = _extract_json_object(_call_ollama(prompt, temperature=temp))
                out.append(_validate_evidence(item, task_ids))
                break
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} parse attempt {attempt + 1} failed: {exc}")
        else:
            print(f"[audit] {c.constraint_id}: unparseable after 3 attempts; recording no verdict")
    return out


def _audit_per_constraint_sc(summary: str, constraints: list[Constraint],
                             task_ids: set[str]) -> list[dict]:
    """Strategy E: ask strategy C's question SC_K times at SC_TEMP and keep the majority verdict.

    If the errors of strategy C were random noise, asking several times and
    voting would cancel them out. If the same verdict comes back every time,
    the error is a consistent belief of the model, not noise.
    """
    from collections import Counter                    # tallies the votes; imported here as only this strategy needs it
    out = []
    for c in constraints:
        cdesc = (f"{c.constraint_id} [{c.source}, {c.control_ref}] "
                 f"(severity {c.default_severity}): {c.constraint_text} "
                 f"AUDIT CHECK: {c.audit_question}")
        prompt = _SINGLE_PROMPT_V4.format(examples=_V4_EXAMPLES, summary=summary,
                                          constraint=cdesc, cid=c.constraint_id)
        samples = []
        for _ in range(SC_K):
            try:
                samples.append(_extract_json_object(_call_ollama(prompt, temperature=SC_TEMP)))
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} sample parse failed: {exc}")
        if not samples:
            print(f"[audit] {c.constraint_id}: no parseable samples; recording no verdict")
            continue
        votes = Counter(s.get("status") for s in samples)         # e.g. {"violated": 2, "satisfied": 1}
        majority, n = votes.most_common(1)[0]
        chosen = next(s for s in samples if s.get("status") == majority)   # first sample that agrees with the majority
        chosen["rationale"] = f"[votes {dict(votes)}] " + str(chosen.get("rationale", ""))   # keep the tally for the record
        out.append(_validate_evidence(chosen, task_ids))
    return out



# ------------------------------------------------------ strategy F prompt --
# Strategy F (per_constraint_gate): applicability first. The large models flagged
# constraints whose precondition was absent from the playbook (most often C12, on
# playbooks with no manual decision point) and treated non-response workflows as
# responses. This strategy asks two questions per constraint: first whether any
# element of the playbook makes the constraint apply, with a citation; then, only if
# so, whether the required safeguard is present. Applicability remains a judgement of
# the model; the order of the questions changes, and the gate asks for a citation of
# the element that makes the constraint apply. The wording distinguishes
# precondition-type constraints (a manual point, a restore step, a wide-scope action
# must exist for the constraint to apply) from presence-type constraints (recording,
# notification, review), which apply to every response workflow. Hypothesis: precision
# above 0.65 at recall of at least 0.90.

_GATE_PROMPT = """You are a security compliance auditor. Consider ONE constraint against the SOAR
playbook structure below. Judge only from the structure given.

PLAYBOOK STRUCTURE:
{summary}

CONSTRAINT:
{constraint}

STEP 1 APPLICABILITY. Does this playbook contain ANY action or element that this constraint
governs? (Examples: a constraint about destructive actions applies only if a destructive action
exists; a constraint about manual decision points applies only if a manual decision point exists;
a constraint about restoring/re-enabling applies only if a restore step exists. A workflow that
performs no response/containment action at all is governed by very few constraints.)
IMPORTANT distinction:
- For constraints that require a PRECONDITION element (a destructive action, a manual decision
  point, a restore step, a wide-scope action): the constraint applies only if that element exists.
- For constraints that require the PRESENCE of an activity (recording actions, notifying
  stakeholders, assessing before response, post-incident review, collecting logs): the governed
  action is the incident handling itself. If the playbook performs ANY response or containment
  action, the constraint APPLIES the absence of the required activity is then a violation,
  never a reason to say the constraint does not apply.
Answer with the task id(s) that make the constraint applicable, or an empty list if none.

Output ONLY one JSON object:
{{"constraint_id": "{cid}", "applies": true|false, "governed_task_ids": ["<task id>", ...],
  "why": "one sentence"}}
"""

_JUDGE_PROMPT = """You are a security compliance auditor. The constraint below APPLIES to this playbook
because of task(s) {governed}. Now judge ONLY whether the required safeguard is present.

STANDARD OF PROOF:
- "satisfied": a task that PLAUSIBLY performs the required safeguard exists in the required
  position (before/after/at a branch as the constraint demands). Do NOT require the task to be
  named after the constraint; judge by what the task does.
- "violated": no task plausibly performs the required safeguard in the required position.

PLAYBOOK STRUCTURE:
{summary}

CONSTRAINT:
{constraint}

Cite evidence: the task id(s) that satisfy the constraint, or an empty list if none.
Output ONLY one JSON object:
{{"constraint_id": "{cid}", "status": "violated|satisfied", "evidence_task_ids": ["<task id>", ...],
  "severity": "low|medium|high", "rationale": "one sentence citing the task ids",
  "recommendation": "one sentence"}}
"""


def _audit_per_constraint_gate(summary: str, constraints: list[Constraint],
                               task_ids: set[str]) -> list[dict]:
    """Strategy F: two questions per constraint, applicability then verdict."""
    out = []
    for c in constraints:
        cdesc = (f"{c.constraint_id} [{c.source}, {c.control_ref}] "
                 f"(severity {c.default_severity}): {c.constraint_text} "
                 f"AUDIT CHECK: {c.audit_question}")
        # --- question 1: does the constraint apply to this playbook at all? ---
        gate = None
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            try:
                gate = _extract_json_object(_call_ollama(
                    _GATE_PROMPT.format(summary=summary, constraint=cdesc, cid=c.constraint_id)
                    + ("" if attempt == 0 else _RETRY_SUFFIX), temperature=temp))
                break
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} gate parse attempt {attempt + 1} failed: {exc}")
        if gate is None:
            print(f"[audit] {c.constraint_id}: gate unparseable; recording no verdict"); continue
        governed = [str(x) for x in (gate.get("governed_task_ids") or [])]
        # "Applies" only counts when the model also names at least one governed task;
        # an applicability claim without a citation is treated as not applicable.
        applies = bool(gate.get("applies")) and bool(governed)
        if not applies:
            out.append({"constraint_id": c.constraint_id, "status": "not_applicable",
                        "evidence_task_ids": [], "evidence_valid": None,
                        "severity": c.default_severity,
                        "rationale": "[gate] no governed action: " + str(gate.get("why", "")),
                        "recommendation": ""})
            continue
        # --- question 2: given that it applies, is the safeguard present? ---
        item = None
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            try:
                item = _extract_json_object(_call_ollama(
                    _JUDGE_PROMPT.format(summary=summary, constraint=cdesc, cid=c.constraint_id,
                                         governed=governed)
                    + ("" if attempt == 0 else _RETRY_SUFFIX), temperature=temp))
                break
            except (ValueError, json.JSONDecodeError) as exc:
                print(f"[audit] {c.constraint_id} judge parse attempt {attempt + 1} failed: {exc}")
        if item is None:
            print(f"[audit] {c.constraint_id}: judge unparseable; recording no verdict"); continue
        item["rationale"] = f"[gate: {governed}] " + str(item.get("rationale", ""))   # record which tasks triggered applicability
        out.append(_validate_evidence(item, task_ids))
    return out


def _format_constraints(constraints: list[Constraint]) -> str:
    """Render the constraint list for strategy A: one line per rule."""
    return "\n".join(
        f"{c.constraint_id} [{c.source}, {c.control_ref}] (severity {c.default_severity}): "
        f"{c.constraint_text} AUDIT CHECK: {c.audit_question}"
        for c in constraints
    )


# ------------------------------------------------------------ back ends --

def _call_ollama(prompt: str, temperature: float = 0.0, timeout: int = 1800) -> str:
    """The single doorway to the language model.

    Every strategy calls this function, and it routes to whichever back end is
    configured. That keeps prompt construction, reply parsing and retries
    identical for local and remote models: the only thing that changes between
    a laptop run and a remote run is where the request is sent.
    """
    if BACKEND == "openai_compat":
        return _call_openai_compat(prompt, temperature=temperature, timeout=timeout)
    # Ollama's /api/generate takes the model name, the prompt and generation
    # options. stream=False asks for the whole reply in one response; num_ctx
    # sets the context window (8,192 tokens comfortably holds the largest
    # summaries plus the calibrated prompt).
    payload = json.dumps(
        {"model": MODEL, "prompt": prompt, "stream": False,
         "options": {"temperature": temperature, "num_ctx": 8192}}
    ).encode()
    req = urllib.request.Request(
        OLLAMA_URL, data=payload, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())["response"]


def _call_openai_compat(prompt: str, temperature: float = 0.0, timeout: int = 600) -> str:
    """Chat-completion call to an OpenAI-compatible endpoint, with bounded retries.

    Remote providers rate-limit and occasionally fail. Each attempt waits before
    trying again with an exponential back-off (2, 4, 8, 16, 32, 64, 64, 64 seconds,
    about four and a half minutes in total), honours a Retry-After header when the
    provider sends one, and gives up after eight attempts so a run cannot hang
    forever. A reply whose answer text is empty or cut off (a reasoning model can
    spend the whole token budget on its reasoning) is retried with a larger budget,
    doubling up to 8192 tokens; the reasoning text itself is never used as the
    answer, and a reply that stays empty is an error.
    """
    import time                                       # only needed for the back-off sleeps
    if not API_KEY:
        raise RuntimeError("SCALA_BACKEND=openai_compat requires SCALA_API_KEY")
    max_tokens = API_MAX_TOKENS
    last_err = None
    for attempt in range(8):
        wait = min(2 ** (attempt + 1), 64)             # 2, 4, 8, 16, 32, 64, 64, 64 seconds
        body = json.dumps({
            "model": MODEL,
            "messages": [{"role": "user", "content": prompt}],   # a single user turn; no system prompt, so all instructions are visible in the prompt text
            "temperature": temperature,
            "max_tokens": max_tokens,
        }).encode()
        req = urllib.request.Request(
            f"{API_BASE}/chat/completions", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {API_KEY}",
                     # The two headers below are optional identification some providers
                     # (e.g. OpenRouter) display in their usage dashboards.
                     "HTTP-Referer": "https://github.com/scala-audit",
                     "X-Title": "SCALA compliance audit"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            if "choices" not in data or not data["choices"]:
                # Some providers return HTTP 200 with an error body (rate limit,
                # provider error, moderation). Treat that as retryable.
                last_err = RuntimeError(f"API error body: {str(data)[:300]}")
                print(f"[audit] API returned no choices (attempt {attempt + 1}): {str(data)[:200]}")
                time.sleep(wait)
                continue
            choice = data["choices"][0]
            message = choice.get("message") or {}
            text = message.get("content")
            finish = choice.get("finish_reason")
            if not isinstance(text, str) or not text.strip() or finish == "length":
                # Empty or cut-off answer. Do not fall back to the reasoning field:
                # it is not the verdict. Ask again with a larger budget instead.
                if max_tokens < 8192:
                    max_tokens = min(max_tokens * 2, 8192)
                    print(f"[audit] empty or truncated reply (finish_reason={finish}); retrying with max_tokens={max_tokens}")
                    continue
                last_err = RuntimeError(f"empty or truncated reply at max_tokens={max_tokens}: {str(data)[:300]}")
                print(f"[audit] {last_err}")
                time.sleep(wait)
                continue
            return text
        except urllib.error.HTTPError as exc:
            last_err = exc
            if exc.code in (429, 500, 502, 503, 504):     # too many requests / server-side errors: worth retrying
                retry_after = exc.headers.get("Retry-After") if exc.headers else None
                if retry_after and str(retry_after).isdigit():
                    wait = max(wait, int(retry_after))     # the provider's own advice wins when it is longer
                print(f"[audit] HTTP {exc.code} (attempt {attempt + 1}); waiting {wait}s")
                time.sleep(wait)
                continue
            raise                                          # any other HTTP error (e.g. 401 bad key) is a real fault
        except (urllib.error.URLError, TimeoutError) as exc:
            last_err = exc                                 # network hiccup: retry
            print(f"[audit] network error (attempt {attempt + 1}): {exc}; waiting {wait}s")
            time.sleep(wait)
    raise RuntimeError(f"API call failed after retries: {last_err}")


def _extract_json_array(text: str) -> list[dict]:
    """Pull a JSON array of verdict objects out of a strategy A reply.

    Strategy 1: try to decode from every "[" in the text (tolerates trailing prose).
    Strategy 2: if no array decodes, salvage the individual {...} objects that
    carry a constraint_id, de-duplicated by id, keeping the first occurrence.
    """
    decoder = json.JSONDecoder()
    for m in re.finditer(r"\[", text):
        try:
            obj, _ = decoder.raw_decode(text, m.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
            return obj
    salvaged = []
    for m in re.finditer(r"\{", text):
        try:
            obj, end = decoder.raw_decode(text, m.start())
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "constraint_id" in obj:
            salvaged.append(obj)
    if salvaged:
        # de-duplicate by constraint_id, keeping first occurrence
        seen, out = set(), []
        for o in salvaged:
            if o["constraint_id"] not in seen:
                seen.add(o["constraint_id"])
                out.append(o)
        return out
    raise ValueError(f"No parseable JSON in model output: {text[:200]!r}")


def _mock_findings(constraints: list[Constraint]) -> list[dict]:
    """Placeholder verdicts for SCALA_MOCK=1 runs (plumbing tests only)."""
    return [
        {"constraint_id": c.constraint_id, "status": "not_applicable",
         "severity": c.default_severity, "rationale": "MOCK MODE",
         "recommendation": "MOCK MODE"}
        for c in constraints
    ]


# --------------------------------------------------------------- entry --

def audit_playbook(pb: ParsedPlaybook, kb: PolicyKB, k: int = 8) -> AuditReport:
    """Audit one parsed playbook and return a typed report.

    k is how many constraints to retrieve from the knowledge base; the
    evaluation and corpus scripts pass 12 so every constraint is judged.
    """
    summary = pb.structural_summary()                    # the text the model reads
    constraints = kb.retrieve(summary, k=k)              # the rules to judge against

    # Dispatch on the configured strategy. Each branch returns a list of raw
    # verdict dictionaries (not yet validated) and a provenance string.
    if os.environ.get("SCALA_MOCK") == "1":
        raw = _mock_findings(constraints)
        model_name = "MOCK"
    elif AUDIT_MODE == "per_constraint":
        raw = _audit_per_constraint(summary, constraints)
        model_name = f"{MODEL}@{BACKEND}"
    elif AUDIT_MODE == "per_constraint_v4":
        raw = _audit_per_constraint_v4(summary, constraints,
                                       task_ids={t.task_id for t in pb.tasks})
        model_name = f"{MODEL}@{BACKEND}"
    elif AUDIT_MODE == "per_constraint_cot":
        raw = _audit_per_constraint_cot(summary, constraints,
                                        task_ids={t.task_id for t in pb.tasks})
        model_name = f"{MODEL}@{BACKEND}"
    elif AUDIT_MODE == "per_constraint_sc":
        raw = _audit_per_constraint_sc(summary, constraints,
                                       task_ids={t.task_id for t in pb.tasks})
        model_name = f"{MODEL}@{BACKEND}"
    elif AUDIT_MODE == "per_constraint_gate":
        raw = _audit_per_constraint_gate(summary, constraints,
                                         task_ids={t.task_id for t in pb.tasks})
        model_name = f"{MODEL}@{BACKEND}"
    else:
        # Strategy A (batched): one request for all constraints, with the same
        # three-attempt retry pattern as the per-constraint strategies.
        base = _PROMPT.format(summary=summary,
                              constraints=_format_constraints(constraints),
                              n=len(constraints))
        raw = None
        last_err = None
        for attempt, temp in enumerate((0.0, 0.1, 0.2)):
            prompt = base if attempt == 0 else base + _RETRY_SUFFIX
            try:
                raw = _extract_json_array(_call_ollama(prompt, temperature=temp))
                asked = {c.constraint_id for c in constraints}
                if not any(isinstance(x, dict) and x.get("constraint_id") in asked for x in raw):
                    # brackets were found but not a single verdict for a constraint we asked about
                    raise ValueError("reply contained no verdict for any requested constraint")
                break
            except (ValueError, json.JSONDecodeError) as exc:
                last_err = exc
                print(f"[audit] parse attempt {attempt + 1} failed for "
                      f"{pb.source_file}: {exc}")
        if raw is None:
            raise RuntimeError(
                f"Model output unparseable after 3 attempts for {pb.source_file}"
            ) from last_err
        model_name = f"{MODEL}@{BACKEND}"

    # Validate every raw verdict against the Finding form. Extra keys the model
    # invented are dropped; a verdict that fails validation (e.g. an unknown
    # status word) is skipped; a verdict for a constraint that was not asked
    # about is ignored.
    valid_ids = {c.constraint_id for c in constraints}
    findings = []
    for item in raw:
        try:
            f = Finding(**{k_: v for k_, v in item.items()
                           if k_ in Finding.model_fields})
        except Exception:
            continue
        if f.constraint_id in valid_ids:
            findings.append(f)

    # Report, but do not invent, any constraint the model failed to answer.
    missing = valid_ids - {f.constraint_id for f in findings}
    if missing:
        print(f"[audit] note: no verdict returned for {sorted(missing)} "
              f"on {pb.source_file}")

    return AuditReport(
        playbook_file=pb.source_file,
        playbook_name=pb.name,
        model_name=model_name,                            # provenance: which model, which back end
        retrieved_constraint_ids=sorted(valid_ids),
        findings=findings,
    )
