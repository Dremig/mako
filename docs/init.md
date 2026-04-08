# Init: Iteration Baseline

## Why this exists
This file captures the practical starting point after removing `sync/`.
It records the key ideas that matter for the current agent iteration.

## Most important takeaways from previous sync notes

1. State management is the real core, not RAG itself.
- RAG helps recall knowledge.
- Stability comes from explicit state: phase, facts, hypotheses, reflection constraints, and action history.

2. The architecture should stay split into interpreter + solver + shared runtime.
- Interpreter provides priors and route ordering.
- Solver executes step-by-step actions.
- Shared memory is the control surface across steps.

3. Reflection must be a mechanism, not just prompt text.
- Failures need structured reasons.
- Reflection outputs must be persisted.
- Next-step planner must consume reflection constraints.

4. Hypothesis lifecycle is mandatory.
- Candidate / confirmed / rejected / stale should be explicit.
- Strategy drift happens when hypotheses are implicit.

5. Execution reliability is a first-class problem.
- Strategy can be correct while shell execution fails.
- Structured actions and validator/executor layers are needed for critical chains.

6. Information gain should gate actions.
- Avoid repeating commands with low new evidence.
- Force action-family changes after repeated low-gain or timeout loops.

7. Entry-point extraction must remain conservative.
- False parameters pollute memory and break downstream planning.
- Precision-first extraction is safer than wide noisy extraction.

## Current direction in this repo
- Keep `rag/` focused on retrieval utilities.
- Keep `web_agent/` focused on interpreter, solver, validation, reflection, and runtime memory.
- Continue moving from free-form shell toward typed structured actions for high-value flows.

## Immediate guardrails
- Preserve reason/cluster canonical mapping.
- Keep controller validation rules modular and testable.
- Prefer module-based execution entrypoints (`python -m ...`) for import stability.
