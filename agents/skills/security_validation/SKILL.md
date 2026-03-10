---
name: security-scanner-adapter
description: Pluggable scanner adapter. Wraps execution of Semgrep, ZAP, or similar vulnerability scanners. Use this skill for static and dependency scanning as well as baseline DAST scanning via the Security Validation Agent.
---

# Security Scanner Adapter Skill

This skill wraps standardized security tools to provide vulnerability signals to the log and correlation flows.

## Core Adapters
- **Semgrep:** Used for static analysis and dependency checks. `semgrep scan --json`
- **ZAP:** Used for active HTTP scanning (DAST).

## Usage Guidelines
1. Output results as JSON for the Evidence Correlation Agent to consume.
2. Do not attempt exploits. Gather the reports and findings only.
