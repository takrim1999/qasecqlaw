import type { APITestResult, APITestingOutput, HttpMethod } from "../index.js"
import chalk from "chalk"

/**
 * Inputs for the API Testing Agent (per PDF Section 3.3).
 */
export interface APITestingInputs {
  readonly baseUrl: string
  readonly endpoints?: readonly string[]
}

/**
 * API Testing Agent.
 * Simulates REST testing to generate valid calls, malformed requests,
 * and test authentication and rate limits.
 */
export class APITestingAgent {
  constructor(private readonly inputs: APITestingInputs) {}

  /**
   * Execute the agent and return APITestingOutput for the Orchestrator.
   */
  async execute(): Promise<APITestingOutput> {
    console.log(chalk.cyan.bold("[API Testing Agent]"))
    console.log(chalk.gray("  Initializing HTTP client..."))

    const results: APITestResult[] = []

    console.log(chalk.gray("  Sending valid API calls..."))
    results.push(...this.mockValidCalls())

    console.log(chalk.gray("  Sending malformed requests (fuzzing)..."))
    results.push(...this.mockMalformedRequests())

    console.log(chalk.gray("  Testing authentication flows..."))
    results.push(...this.mockAuthTests())

    console.log(chalk.gray("  Testing rate limits..."))
    results.push(...this.mockRateLimitTests())

    console.log(chalk.green(`  API testing complete. ${results.length} results. Handing off to Orchestrator.`))
    return { results }
  }

  private mockValidCalls(): APITestResult[] {
    const endpoints = this.inputs.endpoints ?? [
      "/api/benchmark/BenchmarkTest00001",
      "/api/login",
      "/api/user/profile",
    ]
    const results: APITestResult[] = endpoints.map((ep, i) => ({
      id: `api-valid-${String(i + 1).padStart(3, "0")}`,
      endpoint: `${this.inputs.baseUrl}${ep}`,
      method: (i === 0 ? "GET" : i === 1 ? "POST" : "GET") as HttpMethod,
      statusCode: 200,
      expectedStatusCodes: [200],
      payloadKind: "valid" as const,
      isUnexpected: false,
    }))
    console.log(chalk.dim(`    Valid calls: ${results.length} (all 200)`))
    return results
  }

  private mockMalformedRequests(): APITestResult[] {
    const results: APITestResult[] = [
      {
        id: "api-mal-001",
        endpoint: `${this.inputs.baseUrl}/api/benchmark/BenchmarkTest00001`,
        method: "GET" as HttpMethod,
        statusCode: 500,
        expectedStatusCodes: [200, 400],
        payloadKind: "malformed",
        isUnexpected: true,
        description: "SQL injection payload in id param; server returned 500",
      },
      {
        id: "api-mal-002",
        endpoint: `${this.inputs.baseUrl}/api/benchmark/BenchmarkTest00002`,
        method: "POST" as HttpMethod,
        statusCode: 400,
        expectedStatusCodes: [200, 400],
        payloadKind: "malformed",
        isUnexpected: false,
        description: "Invalid JSON body; expected 400",
      },
      {
        id: "api-mal-003",
        endpoint: `${this.inputs.baseUrl}/api/user/profile`,
        method: "GET" as HttpMethod,
        statusCode: 500,
        expectedStatusCodes: [200, 401],
        payloadKind: "fuzz",
        isUnexpected: true,
        description: "XSS in header; triggered server error",
      },
    ]
    console.log(chalk.dim(`    Malformed/fuzz: ${results.length} (WebGoat-style)`))
    return results
  }

  private mockAuthTests(): APITestResult[] {
    const results: APITestResult[] = [
      {
        id: "api-auth-001",
        endpoint: `${this.inputs.baseUrl}/api/admin/users`,
        method: "GET" as HttpMethod,
        statusCode: 401,
        expectedStatusCodes: [401],
        payloadKind: "auth-variant",
        isUnexpected: false,
        description: "No token; expected 401",
      },
      {
        id: "api-auth-002",
        endpoint: `${this.inputs.baseUrl}/api/admin/users`,
        method: "GET" as HttpMethod,
        statusCode: 200,
        expectedStatusCodes: [401],
        payloadKind: "auth-variant",
        isUnexpected: true,
        description: "Expired token accepted; auth bypass",
      },
    ]
    console.log(chalk.dim(`    Auth tests: ${results.length}`))
    return results
  }

  private mockRateLimitTests(): APITestResult[] {
    const results: APITestResult[] = [
      {
        id: "api-rate-001",
        endpoint: `${this.inputs.baseUrl}/api/search`,
        method: "GET" as HttpMethod,
        statusCode: 429,
        expectedStatusCodes: [200, 429],
        payloadKind: "boundary",
        isUnexpected: false,
        description: "Rate limit exceeded; 429 as expected",
      },
      {
        id: "api-rate-002",
        endpoint: `${this.inputs.baseUrl}/api/search`,
        method: "GET" as HttpMethod,
        statusCode: 200,
        expectedStatusCodes: [429],
        payloadKind: "boundary",
        isUnexpected: true,
        description: "Rate limit not enforced; 200 when 429 expected",
      },
    ]
    console.log(chalk.dim(`    Rate limit tests: ${results.length}`))
    return results
  }
}
