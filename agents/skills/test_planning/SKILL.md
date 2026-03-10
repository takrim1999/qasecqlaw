---
name: qasecclaw-test-planning
description: Produce QASecClaw scope plans (UI/API/Sec/Logs) from a target application and dataset configuration. Use this skill when the Test Planning Agent needs to output explicit coverage boundaries and test scenarios for downstream agents.
---

# QASecClaw Test Planning Skill

## Outputs

- UI scope (routes, workflows, credentials requirements)
- API scope (endpoints, auth modes, negative test ideas)
- Security scope (static + dynamic targets; baseline tools to run)
- Log scope (log sources/paths, expected signals, correlation keys)

## Guardrails

- Do not execute tests; only produce plans.
- Prefer explicit, machine-consumable lists (tables/JSON-like blocks).

