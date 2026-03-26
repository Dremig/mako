# Agent Execution Architecture Summary

## Problem

The current agent is reasonably good at high-level strategy:

- identifying the likely challenge family
- selecting plausible exploit routes
- maintaining useful facts and reflections

The main instability is in the last mile:

- the model still emits free-form shell commands
- helper scripts are invoked with inconsistent flag names
- multi-step exploit chains lose stable paths, cookies, or exact action URLs
- execution failures are often caused by command syntax or argument drift, not wrong strategy

In short:

- thinking is often correct
- execution is too unconstrained

## Core Conclusion

The main architectural gap is the missing bridge between:

1. strategy-level reasoning
2. deterministic execution

`task_interpreter` helps with direction, but it does not guarantee exact command correctness.

For complex chains like:

- Tomcat Manager GUI upload
- Flask debug traceback harvesting
- helper-script-based exploitation

free-form shell generation is too fragile.

## Recommended General Improvements

### 1. Move from free-form shell to structured actions

Instead of:

- model emits arbitrary shell

Prefer:

- model emits an action name + structured args
- program validates and executes that action

Examples:

- `http_probe`
- `basic_auth_probe`
- `build_jsp_war`
- `tomcat_manager_read_file`
- `multipart_upload`
- `fetch_with_cookiejar`

### 2. Add a helper invocation layer

Known helper scripts should not rely on the model remembering exact CLI syntax.

The system should maintain metadata for each helper:

- canonical flags
- alias flags
- required flags
- default values derivable from memory

Then repair or reject malformed helper invocations before execution.

### 3. Maintain a working-set, not just facts

Besides facts/hypotheses, the agent should persist reusable execution assets:

- valid credentials
- cookie jar path
- csrf nonce
- exact upload action
- stable artifact directory
- generated WAR path
- deployed app path

These are execution objects, not just observations.

### 4. Use deterministic parsers for deterministic data

Do not rely on the model to re-derive:

- form actions
- hidden inputs
- upload endpoints
- CSRF tokens
- debug pages
- exact helper paths

These should be parsed directly and exposed as memory facts.

### 5. Promote certain exploit chains to programmatic flows

When the system already knows enough, it should stop improvising shell.

Example:

- Tomcat detected
- Basic Auth valid
- Manager upload action known

At that point, a fixed programmatic flow is preferable to further free-form command generation.

## What Was Implemented Now

This round added practical steps in that direction:

- dedicated helper scripts for JSP WAR generation and Tomcat Manager file read
- stable artifact directory handling
- command-family crash hardening
- helper command repair for known scripts
  - flag alias normalization
  - auto-filling missing values from memory

This is not yet a full structured-action architecture, but it is the first useful step away from raw shell-only execution.

## Next Recommended Step

The next meaningful refactor is:

1. introduce a small typed action schema
2. add validator/executor support for 3-5 high-value actions
3. keep LLM reasoning at strategy level
4. reserve raw shell for fallback only

That change would improve stability across many challenge classes, not only Tomcat.
