# SCALA data companion

Data and run outputs that accompany the SCALA code bundle. The code bundle holds the
code, the constraints and the two labelled sets; this companion holds what the code
produced and the inventory of the corpus. Keep the two together.

## Contents

| Folder or file | Content |
|---|---|
| `evaluation_results/` | One JSON per evaluated cell (set x model x strategy): micro precision, recall and F1, the true-positive, false-positive and false-negative counts they are computed from, and per-playbook predicted and actual violations. 17 reference-set cells (all seven models under Strategy A; six under Strategy C; DeepSeek-V3 under all six strategies) and the development-set cells. |
| `audit_reports/` | Full per-playbook findings (verdict, reason, evidence and severity for every constraint) for all 17 reference-set cells. |
| `eval_progress/` | The per-playbook progress files written by `evaluate.py`, from which every evaluation_results file is scored; `rescore.py` in the code bundle recomputes any cell from them without a model call. |
| `rviews/` | The analyst-readable R1 to R4 rendering of each of the 16 evaluation playbooks (6 development, 10 reference), as used for labelling. |
| `inventory/SCALA_Playbook_Inventory_472.xlsx` | One row per parsed playbook of the corpus (472): format, size, the extracted structure summarised under R1 to R4, the counts used in the corpus chapter, and the indicative functional class and threat domain of each vendor playbook (tasks, human decision points under the stated definition, decision points, containment keyword flag); sheet "How to read" explains the columns. |
| `inventory/corpus_stats_bc0f606.json` | The output of `corpus_stats.py` on the public collection at commit bc0f606: file counts per directory, the verification tallies, and one record per parsed playbook. |
| `CORPUS_SOURCE.txt` | Where the corpus comes from, the commit used, and why the files themselves are not redistributed. |

File names carry the set, the model id and the prompt version, for example
`evaluation_results_real_derived_z-ai-glm-4.5_v2-batched.json` is GLM-4.5 under
Strategy A on the reference set. Prompt versions map to strategies as
v2-batched = A, v3-perconstraint = B, v4-perconstraint-calibrated = C,
v5-perconstraint-reason-then-verdict = D, v6-perconstraint-selfconsistency-k3 = E,
v7.1-perconstraint-gate-then-judge = F.

## Regenerating the figures in the write-up

- Any evaluation cell: `python rescore.py` in the code bundle, with this companion's
  `eval_progress/` files copied into the bundle's `outputs/` folder.
- The corpus figures: `python corpus_stats.py <clone>/playbooks` on a clone of the
  collection at the commit named in `CORPUS_SOURCE.txt`.
- The verification tallies: `python parser_verify.py <clone>/playbooks`.

## Not for results

Files whose `model` field reads `MOCK` come from `SCALA_MOCK=1` plumbing checks and
must not be reported.
