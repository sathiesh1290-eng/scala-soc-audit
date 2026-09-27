# SCALA: running the large open-weights models through an OpenAI-compatible API

The large open-weights models (Llama-3.3 70B, Qwen2.5 72B, DeepSeek-V3, GLM-4.5,
Kimi K2) are too big for a workstation. They can be reached through any
OpenAI-compatible endpoint; OpenRouter is one provider that serves all five. The
prompts, the labelled sets and the scoring are exactly the same as for local runs;
only the back end changes. Because the weights are open, the same models could be
hosted by an organisation on its own server-class hardware.

## Set-up (PowerShell, from the SCALA folder, virtual environment active)

```powershell
$env:SCALA_BACKEND="openai_compat"
$env:SCALA_API_BASE="https://openrouter.ai/api/v1"
$env:SCALA_API_KEY="sk-or-...your key..."
```

## Running every model under two strategies on both sets

```powershell
foreach ($m in @("meta-llama/llama-3.3-70b-instruct","qwen/qwen-2.5-72b-instruct","deepseek/deepseek-chat","z-ai/glm-4.5","moonshotai/kimi-k2")) {
  $env:SCALA_MODEL=$m
  $env:SCALA_AUDIT_MODE="batched";           python evaluate.py --dir seeded; python evaluate.py --dir real_derived
  $env:SCALA_AUDIT_MODE="per_constraint_v4"; python evaluate.py --dir seeded; python evaluate.py --dir real_derived
}
```

Add `per_constraint`, `per_constraint_cot`, `per_constraint_sc` and
`per_constraint_gate` lines in the same pattern to run the other strategies.
Each configuration takes a few minutes; results land in `outputs\` tagged by set,
model id and prompt version, and every report records `<model>@openai_compat` so
provenance is self-describing.

## Notes

- Temperature 0 is used on the first attempt, as for local runs, with a reply that could not be parsed retried at 0.1 and then 0.2; remote providers may still show slight
  non-determinism between calls.
- Rate limits and transient provider errors are retried up to eight times with
  increasing waits; a run that still fails stops on the current playbook, keeping the
  playbooks already completed, and can be resumed from its progress file.
- Reasoning models that emit thinking text before the JSON are handled: the reply
  parser salvages the JSON from surrounding text.
