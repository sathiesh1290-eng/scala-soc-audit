# SCALA: running with local models (Windows PowerShell shown; the same commands work on macOS and Linux with `export` instead of `$env:`)

## 1. One-time set-up

Unzip the bundle somewhere simple, for example `C:\scala`, then:

```powershell
cd C:\scala
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If activation is blocked: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, answer Y, retry.

Install Ollama (https://ollama.com) and pull the models you want:

```powershell
ollama pull mistral
ollama pull llama3.1
ollama pull qwen2.5:14b
```

The first real run downloads the sentence-embedding model (about 80 MB) automatically.
If the vector database cannot initialise, SCALA prints a warning and falls back to a
word-overlap ranking; the run still completes. A run intended as a result should show
`KB backend: chromadb+all-MiniLM-L6-v2`.

## 2. Try one playbook

With the Ollama app running:

```powershell
$env:SCALA_BACKEND="ollama"
$env:SCALA_MODEL="mistral"
$env:SCALA_AUDIT_MODE="batched"
python run_audit.py seeded\pb2_ransomware_no_hitl.yml
```

Expected: the playbook's name, format and task count (7 tasks), then one line per constraint. Exact verdicts
depend on the model.

## 3. Evaluate against a labelled set

```powershell
python evaluate.py --dir seeded          # development set (6 synthetic playbooks)
python evaluate.py --dir real_derived    # reference set (10 real playbooks, 120 decisions)
```

Each run writes to `outputs\`:
- `evaluation_results_<set>_<model>_<prompt>.json`: precision, recall, F1 and the counts they come from
- `audit_reports_<set>_<model>_<prompt>.json`: every finding for every playbook
- `eval_progress_<set>_<model>_<prompt>.json`: the checkpoint file; delete it to start that configuration afresh

Progress is saved after each playbook, so an interrupted run resumes when started again.

## 4. Switching model or strategy

- `$env:SCALA_MODEL` selects the Ollama model tag.
- `$env:SCALA_AUDIT_MODE` selects the strategy: `batched`, `per_constraint`,
  `per_constraint_v4`, `per_constraint_cot`, `per_constraint_sc`, `per_constraint_gate`.
- `$env:SCALA_MOCK="1"` runs the whole pipeline without a model. Use it only to check
  that files parse and scripts run; never report its output.
