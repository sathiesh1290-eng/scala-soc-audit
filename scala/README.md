# SCALA: Security Compliance and Audit via LLM Agents

SCALA audits SOAR playbooks (Cortex XSOAR, Microsoft Sentinel Logic Apps, BPMN 2.0)
against incident-response governance constraints derived from NIST SP 800-61r3,
ISO/IEC 27001:2022 Annex A and CIS Controls v8, using locally hostable or
open-weights language models.

## How it works

SCALA has three parts, and one rule connects them: anything that can be computed
by ordinary code is computed by ordinary code; the language model is used only
for judgements about meaning.

1. **Constraints** (`standards/constraints.json`). Twelve audit rules translated by
   hand from the three standards. Each record holds the rule, the yes/no audit
   question, every supporting clause, a default severity, whether the rule is
   stated directly in the standard or derived by an interpretation step, and the
   written derivation. The file is data; no code writes rules.

2. **Parser** (`scala/parser.py`). Reads a playbook file and extracts only its
   structure: which tasks exist and what each calls, what order they run in,
   which steps are decisions and whether a person makes them, and where each
   branch leads. Three formats are supported. A file that merely resembles a
   supported format is rejected rather than misread.

3. **Auditor** (`scala/audit.py`). Renders the structure as a short text, retrieves
   the constraints from the knowledge base (`scala/kb.py`), asks the model for a
   verdict under one of six prompting strategies, parses the JSON reply
   defensively, checks for satisfied verdicts that the evidence the model cites
   exists in the playbook, and returns a typed report (`scala/models.py`).

Every module opens with a plain-language description, every function has a
docstring, and the reason for each imported library is stated where it is imported.

## Files

| Path | What it is |
|---|---|
| `standards/constraints.json` | The twelve constraints (data) |
| `scala/models.py` | The record types: task, playbook, constraint, finding, report; the structural summary the model reads |
| `scala/parser.py` | Format detection and the XSOAR, Sentinel and BPMN walkers |
| `scala/kb.py` | Loads the constraints, embeds them, returns the ones relevant to a playbook |
| `scala/audit.py` | The auditor: six strategies, two model back ends, reply parsing, evidence check |
| `evaluate.py` | Scores the auditor against a labelled set, decision by decision; resumable |
| `corpus_audit.py` | Applies the auditor to every playbook in a folder tree, with checkpoints |
| `parser_verify.py` | Checks every parse against its raw file: action counts (Sentinel), identifier sets and reference integrity (XSOAR), type vocabulary, name well-formedness, non-empty BPMN parses |
| `rview.py` | Renders a playbook, or a whole corpus, for a human reader under the four questions R1 to R4 |
| `run_audit.py` | Audits one playbook from the command line |
| `kappa.py` | Cohen's kappa between two labellings of the same decisions (used for the expert-rating check described as future work) |
| `corpus_stats.py` | Recomputes the corpus disposition and structural figures from a clone of the public collection, under stated definitions |
| `baseline.py` | The two no-model baselines of Section 6.1 (flag everything; the containment keyword rule), scored against the reference labels |
| `bootstrap.py` | Seeded bootstrap of the F1 intervals from the saved reports (Section 6.8 of the write-up) |
| `rescore.py` | Re-scores every evaluation cell from its saved reports against the current ground truth (no model calls) |
| `seeded/` | Development set: six synthetic playbooks and their labels (used only to develop prompts) |
| `real_derived/` | Reference set: ten real playbooks, their labels (`ground_truth.json`) and the record of modifications (`MODIFICATION_LOG.md`) |
| `outputs/` | Where every script writes its results (created on first run) |

## Running

1. Python 3.11 or newer. `pip install -r requirements.txt` (each dependency is
   explained in that file). For local models install Ollama and pull the models
   you want, for example `mistral`, `llama3.1`, `qwen2.5:14b`.
2. Local run: set `SCALA_BACKEND=ollama`, `SCALA_MODEL=mistral`,
   `SCALA_AUDIT_MODE=batched`, then `python evaluate.py --dir real_derived`.
   See `RUN_LOCAL.md`.
3. Remote open-weights run: set `SCALA_BACKEND=openai_compat`, `SCALA_API_BASE`,
   `SCALA_API_KEY` and `SCALA_MODEL` (for example `z-ai/glm-4.5`), then the same
   command. See `RUN_REMOTE.md`.
4. Strategies (`SCALA_AUDIT_MODE`): `batched` (A, all constraints at once),
   `per_constraint` (B, one at a time), `per_constraint_v4` (C, calibrated with
   worked examples and an evidence citation), `per_constraint_cot` (D, reasoning
   first), `per_constraint_sc` (E, plurality of three samples), `per_constraint_gate`
   (F, applicability asked first).
5. Corpus audit: `python corpus_audit.py <playbook directory>`.
6. Parser checks: `python parser_verify.py <playbook directory>`; readable
   rendering: `python rview.py <file or directory>`.

Results are written to `outputs/` with the set, model and strategy in the file
name, so runs of different sets, models and strategies do not overwrite each other
(a repeated run of the same cell resumes from its progress file), and every number
can be traced to the run that produced it. Resume identity is the set, model and prompt
version only: if the playbooks, labels, backend or mock setting change under the same tag,
delete the progress file first, or the old records will be reused.

## Retrieval depth

Every script calls the auditor with `k=12`, so all twelve constraints are always supplied to the model; the retrieval backend (ChromaDB when available, lexical otherwise) affects only the order in which they are listed. The saved reference-set cells do not record the backend, which is why `kb_backend` is null in those files.

## The Sentinel walker and rescoring

The Sentinel walker separates the true and else branches of Logic App conditions, walks switch cases and default cases, and treats a Teams step that holds the workflow until a person responds as a human decision point (approval and options e-mails are counted by `corpus_stats.py` from the raw template). `rescore.py` recomputes every cell from the saved reports without a model call.

## Reproducibility

Temperature 0 on the first attempt of every deterministic strategy, with a reply that could not be parsed retried at 0.1 and then 0.2; local model builds pinned;
remote model identifiers recorded in every report (`model_name` reads
`<model>@<backend>`); prompts and the constraint file are versioned; prompt wording was developed on
the synthetic development set. `SCALA_MOCK=1` runs the
pipeline without a model for plumbing checks only; its output is never a result.
