"""SCALA core package.

SCALA (Security Compliance and Audit via LLM Agents) checks SOAR playbooks
(Cortex XSOAR, Microsoft Sentinel Logic Apps, BPMN 2.0) against
incident-response governance constraints using a language model.

The package is split into four modules, each with one job:

  models.py   The "shapes" of the data: what a parsed playbook looks like, what
              a constraint looks like, and what an audit finding looks like.
              Also renders a playbook as the short text the language model reads.

  parser.py   Turns a raw playbook file (YAML, JSON or XML) into the normalised
              representation defined in models.py. Pure structure extraction:
              which tasks exist, what they call, what order they run in, which
              steps are decisions, and where each branch leads. No opinion about
              compliance is formed here.

  kb.py       The constraint knowledge base. Loads the twelve constraints from
              standards/constraints.json, turns their text into vectors
              (embeddings) and returns the constraints most relevant to a given
              playbook. This is the "retrieval" half of retrieval-augmented
              generation.

  audit.py    The auditor. Builds the prompt for the chosen strategy, sends it to
              a local or remote language model, reads the model's JSON reply
              carefully, checks that any evidence the model cites really exists
              in the playbook, and returns a typed report.

Design rule that runs through every module: everything that can be computed by
ordinary code (parsing, counting, retrieval, validation, scoring) is computed by
ordinary code, and is therefore testable and deterministic. Judgement about
meaning (is this task destructive? is this condition a human approval?) lives
only in the constraint texts and in the language model.
"""
