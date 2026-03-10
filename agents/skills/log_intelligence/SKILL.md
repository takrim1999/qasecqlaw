---
name: log-parser
description: Sandboxed log parser tool. Ingests and triages large, noisy app, server, and network logs. Use this skill when the Log Intelligence Agent needs to extract stack traces, timestamps, and error codes matching the test execution timeframe.
---

# Log Parser Skill

Parse raw backend and application logs to identify errors during a testing run.

## Usage Guidelines
1. Filter logs temporally utilizing the timestamps of the UI/API test executions.
2. Extract critical errors, exceptions, and stack traces.
3. Discard noise and structure the output in JSON format mapping `timestamp -> error_signature`.

## Requirements
Designed to handle large scale files using streams or grep-like primitives. output must be structured.
