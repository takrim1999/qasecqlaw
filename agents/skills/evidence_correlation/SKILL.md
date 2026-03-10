---
name: qasecclaw-evidence-correlation
description: Normalize and correlate evidence across UI, API, security scans, and logs into a causal chain explanation and unified evidence bundle.
---

# Evidence Correlation Skill

## Inputs (expected)

- UI failures: screenshots, traces, console/network logs
- API failures: raw request/response pairs, auth context, rate-limit signals
- Security findings: Semgrep/ZAP/Snyk outputs (normalized)
- System logs: parsed events, anomaly clusters, timestamps, request IDs

## Outputs

- Correlation graph / causal chain (human-readable + JSON export)
- Deduplicated issue list with supporting evidence references
- Link map across artifacts (file paths under `artifacts/`)

## Guardrails

- Never “fix” issues; only explain and link evidence.

