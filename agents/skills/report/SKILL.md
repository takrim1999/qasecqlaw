---
name: report-generator
description: Generates reproducing reports and audit trails from correlated QA/Sec evidence. Use this skill via the Report Agent to compile findings into markdown, HTML, or PDF formats.
---

# Report Generator Skill

Synthesize evidence from multiple test vectors into a human-readable QA/Sec Bench report.

## Usage Guidelines
1. Ingest JSON outputs from the Evidence Correlation Agent.
2. Template the results using standard markdown files.
3. Attach screenshots, HTTP payloads, and log stack traces verbatim.
4. Include steps to reproduce derived from the Orchestrator's execution log.
5. Create QASecClaw-Bench specific evaluation metrics (issue discovery rate, false positives, etc.).
