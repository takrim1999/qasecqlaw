---
name: playwright-adapter
description: Sandboxed tool adapter to execute Playwright scripts for web browser automation. Use this skill when the UI Automation Agent requires interacting with web applications via Playwright scripts to extract traces, screenshots, and validate DOM states.
---

# Playwright Adapter Skill

This skill allows agents to author and execute Playwright tests in a sandboxed environment.

## Usage Guidelines
1. Tests must be placed in `scripts/` or a designated `tests/` directory natively.
2. The agent executes tests using `npx playwright test`.
3. Capture outputs, including screenshots and traces, to the evidence directory.
4. Do not make any deployment or remediation decisions based on test results.

## Sandboxing Notice
Playwright operations are sandboxed and must not modify underlying host files outside the execution payload directory.
