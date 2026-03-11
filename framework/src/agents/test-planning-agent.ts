import type { TestPlanningOutput } from "../index.js"
import { generateQwenResponse } from "../llm/qwen-client.js"
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

const TEST_PLAN_JSON_SCHEMA = `
Return a strict JSON object only (no markdown, no code blocks) with this exact structure:
{
  "coveragePlan": {
    "uiAreas": ["string"],
    "apiEndpoints": ["string"],
    "securitySurfaces": ["string"]
  },
  "testCases": [
    { "id": "string", "description": "string", "tags": ["string"], "ownerAgent": "ui" | "api" | "security" | "logs" }
  ],
  "vulnerabilityTestingPlan": {
    "highRiskEndpoints": ["string"],
    "authFlows": ["string"],
    "dataFlows": ["string"]
  }
}`

/**
 * Test Planning Agent.
 * Uses Qwen LLM to generate test plans from source context.
 * Falls back to mock parsing if LLM is unavailable or returns invalid JSON.
 */
export class TestPlanningAgent {
  constructor(private readonly inputs: TestPlanningInputs) {}

  /**
   * Execute the agent and return a TestPlan for the Orchestrator.
   */
  async execute(): Promise<TestPlanningOutput> {
    console.log(chalk.cyan.bold("[Test Planning Agent]"))
    console.log(chalk.gray("  Gathering context (file tree, API spec)..."))

    const apiSpecContent = this.readApiSpec()
    const fileTree = this.buildFileTree(this.inputs.sourceCodePath)
    const datasetDesc = this.inputs.datasetDescription ?? "web application"

    const userMessage = this.buildUserMessage(apiSpecContent, fileTree, datasetDesc)
    const systemPrompt = this.buildSystemPrompt()

    console.log(chalk.gray("  Querying Qwen LLM for Test Plan..."))

    const start = Date.now()
    let plan: TestPlanningOutput

    try {
      const text = await generateQwenResponse(systemPrompt, userMessage, true)
      console.log(chalk.dim(`    Qwen API call succeeded in ${Date.now() - start}ms`))

      const parsed = this.parseLlmResponse(text)
      if (parsed) {
        plan = parsed
        console.log(chalk.green("  Plan generated from LLM. Handing off to Orchestrator."))
      } else {
        plan = await this.fallbackMockPlan()
        console.log(chalk.yellow("  LLM response invalid; using fallback mock plan. Handing off to Orchestrator."))
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      console.log(chalk.yellow(`    Qwen API failed (${Date.now() - start}ms): ${errMsg}`))
      plan = await this.fallbackMockPlan()
      console.log(chalk.yellow("  Using fallback mock plan. Handing off to Orchestrator."))
    }

    return plan
  }

  private readApiSpec(): string {
    if (!this.inputs.apiSpecPath || !fs.existsSync(this.inputs.apiSpecPath)) {
      return ""
    }
    try {
      return fs.readFileSync(this.inputs.apiSpecPath, "utf-8")
    } catch {
      return ""
    }
  }

  private buildFileTree(dirPath: string, prefix = "", maxDepth = 4, depth = 0): string {
    if (depth >= maxDepth) return ""
    if (!fs.existsSync(dirPath) || !fs.statSync(dirPath).isDirectory()) {
      return ""
    }

    const lines: string[] = []
    const entries = fs.readdirSync(dirPath, { withFileTypes: true }).slice(0, 50)

    for (const e of entries) {
      const name = e.name
      const fullPath = path.join(dirPath, name)
      if (e.isDirectory()) {
        lines.push(`${prefix}${name}/`)
        lines.push(this.buildFileTree(fullPath, `${prefix}  `, maxDepth, depth + 1))
      } else {
        lines.push(`${prefix}${name}`)
      }
    }
    return lines.filter(Boolean).join("\n")
  }

  private buildSystemPrompt(): string {
    return `You are a senior QA and Security Test Planner. Your job is to analyze source code structure and API specifications, then produce a comprehensive test plan for a multi-agent QA and security validation framework.

Output requirements:
${TEST_PLAN_JSON_SCHEMA}

Rules:
- ownerAgent must be exactly one of: "ui", "api", "security", "logs"
- Extract real endpoints from OpenAPI/JSON if provided
- Identify UI routes, forms, and workflows from the file tree
- Flag high-risk surfaces (auth, admin, user input handlers) for security testing
- Generate 5-15 test cases covering UI, API, and security`
  }

  private buildUserMessage(
    apiSpecContent: string,
    fileTree: string,
    datasetDesc: string,
  ): string {
    const parts: string[] = [
      `Dataset: ${datasetDesc}`,
      "",
      "File tree (source code structure):",
      fileTree || "(no directory or empty)",
      "",
    ]
    if (apiSpecContent) {
      parts.push("API specification (OpenAPI/JSON):")
      parts.push(apiSpecContent.slice(0, 8000))
      parts.push("")
    }
    parts.push("Generate the test plan JSON:")
    return parts.join("\n")
  }

  private parseLlmResponse(text: string): TestPlanningOutput | null {
    const trimmed = text.trim().replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "")
    try {
      const raw = JSON.parse(trimmed) as unknown
      if (!raw || typeof raw !== "object") return null

      const r = raw as Record<string, unknown>
      const coveragePlan = r.coveragePlan as Record<string, unknown> | undefined
      const testCases = Array.isArray(r.testCases) ? r.testCases : []
      const vulnPlan = r.vulnerabilityTestingPlan as Record<string, unknown> | undefined

      const plan: TestPlanningOutput = {
        coveragePlan: {
          uiAreas: Array.isArray(coveragePlan?.uiAreas)
            ? coveragePlan.uiAreas.filter((x): x is string => typeof x === "string")
            : [],
          apiEndpoints: Array.isArray(coveragePlan?.apiEndpoints)
            ? coveragePlan.apiEndpoints.filter((x): x is string => typeof x === "string")
            : [],
          securitySurfaces: Array.isArray(coveragePlan?.securitySurfaces)
            ? coveragePlan.securitySurfaces.filter((x): x is string => typeof x === "string")
            : [],
        },
        testCases: testCases
          .filter((tc): tc is Record<string, unknown> => tc && typeof tc === "object")
          .map((tc, i) => ({
            id: typeof tc.id === "string" ? tc.id : `tp-${String(i + 1).padStart(4, "0")}`,
            description: typeof tc.description === "string" ? tc.description : "Generated test case",
            tags: Array.isArray(tc.tags) ? tc.tags.filter((x): x is string => typeof x === "string") : [],
            ownerAgent: ["ui", "api", "security", "logs"].includes(tc.ownerAgent as string)
              ? (tc.ownerAgent as "ui" | "api" | "security" | "logs")
              : "api",
          })),
        vulnerabilityTestingPlan: {
          highRiskEndpoints: Array.isArray(vulnPlan?.highRiskEndpoints)
            ? vulnPlan.highRiskEndpoints.filter((x): x is string => typeof x === "string")
            : [],
          authFlows: Array.isArray(vulnPlan?.authFlows)
            ? vulnPlan.authFlows.filter((x): x is string => typeof x === "string")
            : [],
          dataFlows: Array.isArray(vulnPlan?.dataFlows)
            ? vulnPlan.dataFlows.filter((x): x is string => typeof x === "string")
            : [],
        },
      }
      return plan
    } catch {
      return null
    }
  }

  private async fallbackMockPlan(): Promise<TestPlanningOutput> {
    const coveragePlan = await this.mockParseProjectStructure(this.inputs.sourceCodePath)
    const apiEndpoints = await this.mockParseOpenApiSpec(this.inputs.apiSpecPath)
    const { testCases, vulnerabilityTestingPlan } = this.mockGenerateTestScenarios(
      coveragePlan,
      apiEndpoints,
    )
    return {
      coveragePlan: {
        uiAreas: coveragePlan.uiAreas,
        apiEndpoints,
        securitySurfaces: coveragePlan.securitySurfaces,
      },
      testCases,
      vulnerabilityTestingPlan,
    }
  }

  private async mockParseProjectStructure(sourcePath: string): Promise<{
    uiAreas: string[]
    securitySurfaces: string[]
  }> {
    const uiAreas: string[] = []
    const securitySurfaces: string[] = []
    const owaspBenchmarkPaths = [
      "src/main/java/org/owasp/benchmark/testcode",
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
    if (uiAreas.length === 0) uiAreas.push("/benchmark/", "/login", "/admin")
    if (securitySurfaces.length === 0) {
      securitySurfaces.push("BenchmarkTest00001.java", "BenchmarkTest00002.java")
    }
    return { uiAreas, securitySurfaces }
  }

  private async mockParseOpenApiSpec(apiSpecPath?: string): Promise<string[]> {
    const defaultEndpoints = [
      "/api/benchmark/BenchmarkTest00001",
      "/api/login",
      "/api/user/profile",
      "/api/admin/users",
    ]
    if (apiSpecPath && fs.existsSync(apiSpecPath)) {
      const content = fs.readFileSync(apiSpecPath, "utf-8")
      const paths = content.match(/["']\/[^"']+["']/g) ?? []
      if (paths.length > 0) {
        return paths.map((p) => p.replace(/["']/g, ""))
      }
    }
    return defaultEndpoints
  }

  private mockGenerateTestScenarios(
    coveragePlan: { uiAreas: string[]; securitySurfaces: string[] },
    apiEndpoints: string[],
  ): {
    testCases: TestPlanningOutput["testCases"]
    vulnerabilityTestingPlan: TestPlanningOutput["vulnerabilityTestingPlan"]
  } {
    const cweCategories = ["CWE-78", "CWE-79", "CWE-89", "CWE-22", "CWE-352"]
    const testCases: TestPlanningOutput["testCases"] = []
    let id = 1
    for (const ep of apiEndpoints.slice(0, 6)) {
      const cwe = cweCategories[(id - 1) % cweCategories.length]
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `Test ${ep} for ${cwe}`,
        tags: [cwe, "security"],
        ownerAgent: "security",
      })
      id++
    }
    for (const area of coveragePlan.uiAreas.slice(0, 3)) {
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `UI flow: ${area}`,
        tags: ["ui"],
        ownerAgent: "ui",
      })
      id++
    }
    for (const ep of apiEndpoints.slice(0, 4)) {
      testCases.push({
        id: `tp-${String(id).padStart(4, "0")}`,
        description: `API validation: ${ep}`,
        tags: ["api"],
        ownerAgent: "api",
      })
      id++
    }
    const highRiskEndpoints = apiEndpoints.filter(
      (e) => e.includes("BenchmarkTest") || e.includes("admin"),
    )
    return {
      testCases,
      vulnerabilityTestingPlan: {
        highRiskEndpoints: highRiskEndpoints.length > 0 ? highRiskEndpoints : apiEndpoints.slice(0, 3),
        authFlows: ["/api/login", "/api/logout", "/api/user/profile"],
        dataFlows:
          apiEndpoints.filter((e) => e.includes("BenchmarkTest")).length > 0
            ? apiEndpoints.filter((e) => e.includes("BenchmarkTest")).slice(0, 2)
            : apiEndpoints.slice(0, 2),
      },
    }
  }
}
