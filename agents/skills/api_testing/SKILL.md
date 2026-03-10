---
name: api-testing-layer
description: Adapter for executing raw HTTP requests and API validation (REST, GraphQL, gRPC). Use this skill when the API Testing Agent needs to execute positive/negative tests against an endpoint and capture raw request/response payloads.
---

# API Testing Layer Skill

Execute HTTP requests with predefined payloads for backend validation.

## Usage Guidelines
1. Execute requests using native libraries or packaged scripts (`curl`, fetch).
2. Store raw payloads and status codes in the unified evidence format.
3. Handle authentication correctly by injecting tokens from the sandboxed environment variables, not local storage.

## Negative Testing
Inject malformed parameters, invalid types, and boundary values based on Test Planning output.
