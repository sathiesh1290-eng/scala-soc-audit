# SCALA: Security Compliance and Audit via LLM Agents

Master readme for the software and data that accompany the MSc dissertation
"Security Compliance and Audit via LLM Agents (SCALA)". Two packages belong together:

| Package | Folder | Content |
|---|---|---|
| Code bundle | `scala/` | The source code, the constraint knowledge base, the two labelled evaluation sets, and the instructions to run everything |
| Data companion | `SCALA_data/` | What the code produced: evaluation results and audit reports for all 17 evaluation cells, the progress files they are scored from, the rendered playbooks used for labelling, the corpus inventory and statistics, and the corpus provenance |

## What SCALA does

SCALA audits SOAR playbooks (Cortex XSOAR, Microsoft Sentinel Logic Apps, BPMN 2.0)
against twelve incident-response governance constraints derived from NIST SP 800-61r3,
ISO/IEC 27001:2022 Annex A and CIS Controls v8, using open-weights language models
that an organisation can host itself. It has three parts:

1. **Constraints** (`scala/standards/constraints.json`): the twelve rules, each with its
   audit question, sources, severity, inference type and derivation record. The file is
   data; no code writes rules.
2. **Parser** (`scala/scala/parser.py`): reads a playbook file and extracts only its
   structure, which tasks exist and what each calls, in what order, which steps are
   decisions and whether a person makes them, and where each branch leads. Every parse
   is checked against the raw file by `scala/parser_verify.py` (counts, identifiers,
   reference integrity, type vocabulary and name well-formedness; see its docstring).
3. **Auditor** (`scala/scala/audit.py`): renders the structure as a short text, retrieves
   the constraints, asks the model for a verdict under one of six prompting strategies,
   checks for satisfied verdicts that the evidence the model cites exists in the playbook, and returns a
   typed report.

One rule connects them: anything that ordinary code can compute is computed by code;
the model is used only for judgements about meaning.

## Where to start

- To read the code: `scala/README.md` maps every file to its purpose and to the
  section of the dissertation that describes it.
- To run an audit: `scala/RUN_LOCAL.md` (small models on a laptop through Ollama)
  and `scala/RUN_REMOTE.md` (large open-weights models through an API).
- To see the results without running anything: `SCALA_data/evaluation_results/`
  (one file per cell) and `SCALA_data/audit_reports/` (every finding of every cell).
- To regenerate the results from the saved reports without a model call: copy
  `SCALA_data/eval_progress/` into `scala/outputs/` and run `python rescore.py`.
- To regenerate the corpus figures: clone the public playbook collection at the commit
  named in `SCALA_data/CORPUS_SOURCE.txt` and run `python corpus_stats.py <clone>/playbooks`.

## Correspondence with the dissertation

| Dissertation | Package |
|---|---|
| Chapter 3, Section 3.2 and Appendix A (the constraints) | `scala/standards/constraints.json` |
| Sections 3.3 and 4.3 (representation and parser) | `scala/scala/models.py`, `scala/scala/parser.py`, `scala/rview.py` |
| Section 4.4 and Appendix D (auditor and prompts) | `scala/scala/audit.py`, `scala/scala/kb.py` |
| Section 3.4 and Appendix E (evaluation sets and labels) | `scala/seeded/`, `scala/real_derived/` |
| Chapter 5 (corpus) | `scala/corpus_stats.py`, `SCALA_data/inventory/`, `SCALA_data/CORPUS_SOURCE.txt` |
| Chapter 6 (results) | `SCALA_data/evaluation_results/`, `SCALA_data/audit_reports/`, `scala/rescore.py` |
| Section 6.10 (extraction fidelity) | `scala/parser_verify.py` |
| Appendix F (code and data listing) | this file and `scala/README.md` |

## Requirements

Python 3.11 or newer; `pip install -r scala/requirements.txt` (each dependency is
explained in that file). Ollama for local models; an API key for remote models, as
described in `scala/RUN_REMOTE.md`. No playbook ever leaves the machine when a local
model is used.

## Provenance

The playbook corpus is the public collection assembled by Schlette et al. (2024); it is
not redistributed here, and `SCALA_data/CORPUS_SOURCE.txt` records the commit that
reproduces the exact set of files. The ten reference playbooks in `scala/real_derived/`
are copies of files from that collection, three of them with documented modifications
listed in `scala/real_derived/MODIFICATION_LOG.md`. All reference labels were assigned
by the author as domain expert under the conventions stated in
`scala/real_derived/ground_truth.json`.

## Licence

The code, the constraint file, the labels and the results are released under the MIT Licence (see LICENSE). The ten reference playbooks are copies of files from the public collection of Schlette et al. (2024) and remain under their source terms, with the three documented modifications listed in `scala/real_derived/MODIFICATION_LOG.md`.
