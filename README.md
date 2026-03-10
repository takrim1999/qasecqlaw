# QASecClaw (QASecClaw-Bench)

QASecClaw is a multi-agent framework built on top of **OpenClaw** for automated:

- software QA testing
- security validation
- log intelligence analysis

It evaluates these layers together and correlates failures across them to produce an immutable, human-reviewable audit trail and report artifacts.

## Architecture

QASecClaw is coordinated by a **Mission Orchestrator** which delegates to seven specialized agents:

- **Test Planning**
- **UI Testing**
- **API Testing**
- **Security Validation**
- **Log Intelligence**
- **Evidence Correlation**
- **Report**

The implementation brief lives at `research/notes/idea/qa_sec_claw_idea0.pdf`.

## Repository layout

- `agents/`: OpenClaw-native workspaces and skills for each agent
- `framework/`: QASecClaw glue code (TypeScript). It is designed to integrate with `openclaw` (installed separately).
- `datasets/`: dataset configs + sampling utilities (no dataset blobs committed)
- `experiments/`: experiment pipelines, baselines, metrics, Python tooling
- `artifacts/`: run outputs (gitignored)
- `research/`: paper writing (notes/figures/bib/manuscript)

## Getting started (high-level)

1. Install Node 22+ and Python 3.10+.
2. Install JS deps (repo root): `pnpm install`.
3. Use the workspace definitions in `agents/workspaces/` from within an OpenClaw runtime.

## OpenClaw dependency

This repo intentionally does not vendor the upstream OpenClaw source tree.
Install OpenClaw separately (for example via npm/pnpm) in the environment where you run the agents.

