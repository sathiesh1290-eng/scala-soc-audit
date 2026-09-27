Every SCALA script writes its results into this folder:

  report_<playbook>.json                         run_audit.py
  eval_progress_<set>_<model>_<prompt>.json      evaluate.py checkpoint (resumable)
  evaluation_results_<set>_<model>_<prompt>.json evaluate.py scores
  audit_reports_<set>_<model>_<prompt>.json      evaluate.py full findings
  corpus_progress_<model>_<prompt>.jsonl         corpus_audit.py checkpoint (one record per line)
  corpus_summary_<model>_<prompt>.json           corpus_audit.py summary
  parser_verification.json                       parser_verify.py
  rviews/                                        rview.py (one text file per playbook plus _index.txt)
  chroma/                                        the persisted constraint vector store
