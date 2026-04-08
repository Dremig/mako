# Pentagi Notes

## Purpose
This file is reserved for PentAGI-driven design input and integration notes.

## What to track here
- Flow-level orchestration ideas we want to absorb.
- Provider/tool-call reliability patterns.
- Structured execution contracts (action schemas, validators, executors).
- Runtime observability and state models useful for `web_agent/`.
- Any migration decisions from experimental code to stable modules.

## Initial integration goals
1. Align failure semantics between reasoning and execution layers.
2. Expand structured actions for brittle exploit chains.
3. Keep deterministic parsing for deterministic artifacts (tokens, forms, upload actions).
4. Define promotion rules from free-form probing to programmatic flow execution.
