import type { TestPlanningOutput } from "../index.js"
import chalk from "chalk"
import * as fs from "node:fs"
import * as path from "node:path"

/**
 * Inputs for the Test Planning Agent (per PDF Section 3.1).
 */
export interface TestPlanningInputs {
  readonly sourceCodePath: string
  readonly apiSpecPath?: string
  readonly datasetDescription?: string
}

/**
 * Test Planning Agent.
 * Parses project structure, identifies endpoints, generates test scenarios.
 * Returns a strictly typed TestPlan compatible with the Orchestrator.
 */
export class TestPlanningAgent {
  constructor(private readonly inputs: TestPlanningInputs) {}

  /**
   * Execute the agent and return a TestPlan for the Orchestrator.
   */
  async execute(): Promise<TestPlanningOutput> {
    console.log(chalk.cyan.bold("[Test Planning Agent]"))
    console.log(chalk.gray("  Parsing project structure..."))

    const coveragePlan = await this.mockParseProjectStructure(this.inputs.sourceCodePath)
    console.log(chalk.gray("  Identifying endpoints from API spec..."))
    const apiEndpoints = await this.mockParseOpenApiSpec(this.inputs.apiSpecPath)
    console.log(chalk.gray("  Generating test scenarios..."))
    const { testCases, vulnerabilityTestingPlan } = this.mockGenerateTestScenarios(
      coveragePlan,
      apiEndpoints,
    )

    const plan: TestPlanningOutput = {
      coveragePlan: {
        uiAreas: coveragePlan.uiAreas,
        apiEndpoints,
        securitySurfaces: coveragePlan.securitySurfaces,
      },
      testCases,
      vulnerabilityTestingPlan,
    }

    console.log(chalk.green("  Plan generated successfully. Handing off to Orchestrator."))
    return plan
  }

  /**
   * Mock: simulate scanning directory structure (OWASP Benchmark layout).
   */
  private async mockParseProjectStructure(sourcePath: string): Promise<{
    uiAreas: string[]
    securitySurfaces: string[]
  }> {
    const uiAreas: string[] = []
    const securitySurfaces: string[] = []

    const owaspBenchmarkPaths = [
      "src/main/java/org/owasp/benchmark/testcode",
      "src/main/java/org/owasp/benchmark/helpers",
      "src/main/webapp",
      "testcases",
    ]

    for (const p of owaspBenchmarkPaths) {
      const fullPath = path.join(sourcePath, p)
      if (fs.existsSync(fullPath)) {
        const entries = fs.readdirSync(fullPath, { withFileTypes: true })
        for (const e of entries) {
          if (e.isDirectory()) {
            uiAreas.push(path.join(p, e.name))
            securitySurfaces.push(path.join(p, e.name))
          } else if (e.name.endsWith(".jsp") || e.name.endsWith(".java")) {
            securitySurfaces.push(path.join(p, e.name))
          }
        }
      } else {
        uiAreas.push(p)
        securitySurfaces.push(p)
      }
    }

    if (uiAreas.length === 0) {
      uiAreas.push("/benchmark/", "/login", "/admin")
    }
    if (securitySurfaces.length === 0) {
      securitySurfaces.push(
        "BenchmarkTest00001.java",
        "BenchmarkTest00002.java",
        "BenchmarkTest02143.jsp",
      )
    }

    console.log(
      chalk.dim(
        `    Discovered ${uiAreas.length} UI areas, ${securitySurfaces.length} security surfaces`,
      ),
    )
    return { uiAreas, securitySurfaces }
  }

  /**
   * Mock: simulate parsing OpenAPI/REST schema.
   */
  private async mockParseOpenApiSpec(apiSpecPath?: string): Promise<string[]> {
    const defaultEndpoints = [
      "/api/benchmark/BenchmarkTest00001",
      "/api/benchmark/BenchmarkTest00002",
      "/api/benchmark/BenchmarkTest02143",
      "/api/login",
      "/api/logout",
      "/api/user/profile",
      "/api/admin/users",
    ]

    if (apiSpecPath && fs.existsSync(apiSpecPath)) {
      const content = fs.readFileSync(apiSpecPath, "utf-8")
      const paths = content.match(/["']\/[^"']+["']/g) ?? []
      if (paths.length > 0) {
        const endpoints = paths.map((p) => p.replace(/["']/g, ""))
        console.log(chalk.dim(`    Parsed ${endpoints.length} endpoints from spec`))
        return endpoints
      }
    }

    console.log(chalk.dim(`    Using ${defaultEndpoints.length} mock OWASP Benchmark endpoints`))
    return defaultEndpoints
  }

  /**
   * Mock: generate test scenarios for OWASP Benchmark (CWE categories).
   */
  private mockGenerateTestScenarios(
    coveragePlan: { uiAreas: string[]; securitySurfaces: string[] },
    apiEndpoints: string[],
  ): {
    testCases: TestPlanningOutput["testCases"]
    vulnerabilityTestingPlan: TestPlanningOutput["vulnerabilityTestingPlan"]
  } {
    const cweCategories = [
      "CWE-78", // OS Command Injection
      "CWE-79", // XSS
      "CWE-89", // SQL Injection
      "CWE-90", // LDAP Injection
      "CWE-22", // Path Traversal
      "CWE-352", // CSRF
    ]

    const testCases: TestPlanningOutput["testCases"] = []
    let id = 1

    for (const ep of apiEndpoints.slice(0, 6)) {
      const cwe = cweCategories[(id - 1) % cweCategories.length]
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `Test ${ep} for ${cwe}`,
        tags: [cwe, "owasp-benchmark", "security"],
        ownerAgent: "security",
      })
      id++
    }

    for (const area of coveragePlan.uiAreas.slice(0, 3)) {
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `UI flow: ${area}`,
        tags: ["ui", "owasp-benchmark"],
        ownerAgent: "ui",
      })
      id++
    }

    for (const ep of apiEndpoints.slice(0, 4)) {
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `API validation: ${ep}`,
        tags: ["api", "rest"],
        ownerAgent: "api",
      })
      id++
    }

    const highRiskEndpoints = apiEndpoints.filter(
      (e) => e.includes("BenchmarkTest") || e.includes("admin"),
    )
    const authFlows = ["/api/login", "/api/logout", "/api/user/profile"]
    const dataFlows = apiEndpoints.filter((e) => e.includes("BenchmarkTest"))

    return {
      testCases,
      vulnerabilityTestingPlan: {
        highRiskEndpoints:
          highRiskEndpoints.length > 0 ? highRiskEndpoints : apiEndpoints.slice(0, 3),
        authFlows,
        dataFlows: dataFlows.length > 0 ? dataFlows : apiEndpoints.slice(0, 2),
      },
    }
  }
}
