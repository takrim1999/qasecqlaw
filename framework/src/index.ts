import { fileURLToPath } from "url"
import { dirname, resolve } from "path"
import { writeFile } from "node:fs/promises"
import { parseArgs } from "node:util"

export type QASecClawRunRequest = {
  target: {
    name: string
    kind: "source_zip" | "repo_path" | "url"
    value: string
  }
  apiSpecPath?: string
}

export type QASecClawRunResult = {
  runId: string
  artifactsDir: string
}

/**
 * RFC3339-ish, filesystem-friendly run identifier.
 */
export function createRunId(now: Date = new Date()): string {
  return now.toISOString().replaceAll(":", "").replaceAll(".", "-")
}

/**
 * Mission phases for the orchestrator state machine.
 */
export enum MissionPhase {
  INITIALIZATION = "INITIALIZATION",
  TEST_PLANNING = "TEST_PLANNING",
  ACTIVE_TESTING = "ACTIVE_TESTING",
  LOG_ANALYSIS = "LOG_ANALYSIS",
  EVIDENCE_CORRELATION = "EVIDENCE_CORRELATION",
  REPORT_GENERATION = "REPORT_GENERATION",
  COMPLETED = "COMPLETED",
  FAILED = "FAILED",
}

/**
 * ---- Agent output types ----
 */

/**
 * Test Planning Agent
 * - outputs test coverage and vulnerability plans
 */
export interface TestPlanningOutput {
  readonly coveragePlan: {
    readonly uiAreas: string[]
    readonly apiEndpoints: string[]
    readonly securitySurfaces: string[]
  }
  readonly testCases: {
    readonly id: string
    readonly description: string
    readonly tags: string[]
    readonly ownerAgent: "ui" | "api" | "security" | "logs"
  }[]
  readonly vulnerabilityTestingPlan: {
    readonly highRiskEndpoints: string[]
    readonly authFlows: string[]
    readonly dataFlows: string[]
  }
}

/**
 * UI Testing Agent
 * - outputs traces, failure logs, and screenshots
 */
export interface UITestFailureTrace {
  readonly id: string
  readonly route: string
  readonly scenarioId: string
  readonly steps: string[]
  readonly errorMessage?: string
}

export interface UITestingOutput {
  readonly traces: UITestFailureTrace[]
  readonly failureLogs: {
    readonly id: string
    readonly traceId: string
    readonly rawLogPath: string
  }[]
  readonly screenshots: {
    readonly id: string
    readonly traceId: string
    readonly path: string
  }[]
}

/**
 * API Testing Agent
 * - outputs payload types, status codes, unexpected responses
 */
export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"

export interface APITestResult {
  readonly id: string
  readonly endpoint: string
  readonly method: HttpMethod
  readonly statusCode: number
  readonly expectedStatusCodes: number[]
  readonly payloadKind: "valid" | "malformed" | "boundary" | "auth-variant" | "fuzz"
  readonly isUnexpected: boolean
  readonly description?: string
}

export interface APITestingOutput {
  readonly results: APITestResult[]
}

/**
 * Security Validation Agent
 * - outputs tool used [Semgrep/ZAP/Snyk], vulnerability type, severity
 */
export type SecurityTool = "semgrep" | "zap" | "snyk"

export type VulnerabilitySeverity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"

export interface SecurityFinding {
  readonly id: string
  readonly tool: SecurityTool
  readonly vulnerabilityType: string
  readonly severity: VulnerabilitySeverity
  readonly location?: string
  readonly description?: string
  readonly cweId?: string
}

export interface SecurityValidationOutput {
  readonly findings: SecurityFinding[]
}

/**
 * Log Intelligence Agent
 * - outputs clustered anomalies and root cause estimations
 */
export interface LogCluster {
  readonly id: string
  readonly source: string
  readonly signature: string
  readonly size: number
  readonly anomalyScore: number
}

export interface SystemAnomaly {
  readonly id: string
  readonly timestamp: string
  readonly service: string
  readonly severity: string
  readonly message: string
  readonly stackTrace?: string
}

export interface LogAnalysisOutput {
  readonly systemAnomalies: readonly SystemAnomaly[]
}

export interface RootCauseEstimation {
  readonly id: string
  readonly clusterId: string
  readonly hypothesis: string
  readonly confidence: number
}

export interface LogIntelligenceOutput {
  readonly clusters: LogCluster[]
  readonly rootCauses: RootCauseEstimation[]
  readonly systemAnomalies: readonly SystemAnomaly[]
}

/**
 * Evidence Correlation Agent
 * - outputs CausalChain linking UI, API, and Log IDs
 */
export interface CausalChainStep {
  readonly description: string
  readonly uiTraceId?: string
  readonly apiResultId?: string
  readonly logClusterId?: string
  readonly securityFindingId?: string
}

export interface CausalChain {
  readonly id: string
  readonly summary: string
  readonly primaryFailureId?: string
  readonly linkedEvidenceIds?: readonly string[]
  readonly correlationExplanation?: string
  readonly steps: CausalChainStep[]
}

export interface EvidenceCorrelationOutput {
  readonly chains: CausalChain[]
}

/**
 * Report Agent
 * - consumes final state to generate the benchmark report
 */
export interface ReportOutput {
  readonly reportPath: string
  readonly summary: string
  readonly tablesPath?: string
  readonly figuresDir?: string
}

/**
 * ---- Mission state ----
 */
export interface MissionState {
  readonly runId: string
  readonly phase: MissionPhase
  readonly startedAt: Date
  readonly updatedAt: Date
  readonly request: QASecClawRunRequest

  readonly testPlanning?: TestPlanningOutput
  readonly uiTesting?: UITestingOutput
  readonly apiTesting?: APITestingOutput
  readonly securityValidation?: SecurityValidationOutput
  readonly logIntelligence?: LogIntelligenceOutput
  readonly evidenceCorrelation?: EvidenceCorrelationOutput
  readonly report?: ReportOutput

  readonly errors: readonly string[]
}

/**
 * Options for the Mission Orchestrator.
 */
export interface MissionOrchestratorOptions {
  readonly enableColor?: boolean
  readonly tickDelayMs?: number
}

/**
 * Terminal dashboard using chalk.
 */
import chalk from "chalk"

/**
 * Mission Orchestrator
 * - wires phases into a simple, observable state machine
 * - downstream agents are placeholders; only logging + state transitions for now
 */
export class MissionOrchestrator {
  private state: MissionState
  private readonly opts: Required<MissionOrchestratorOptions>

  constructor(request: QASecClawRunRequest, options: MissionOrchestratorOptions = {}) {
    const now = new Date()
    this.state = {
      runId: createRunId(now),
      phase: MissionPhase.INITIALIZATION,
      startedAt: now,
      updatedAt: now,
      request,
      errors: [],
    }

    this.opts = {
      enableColor: options.enableColor ?? true,
      tickDelayMs: options.tickDelayMs ?? 200,
    }
  }

  /**
   * Main orchestrator entrypoint.
   */
  async run(): Promise<MissionState> {
    this.logBanner()

    try {
      await this.transitionTo(MissionPhase.TEST_PLANNING, async () => {
        this.logHandoff("Mission Orchestrator", "Test Planning Agent")
        this.state = await this.runTestPlanning(this.state)
      })

      await this.transitionTo(MissionPhase.ACTIVE_TESTING, async () => {
        this.logHandoff("Mission Orchestrator", "UI/API/Security Agents")
        this.state = await this.runActiveTesting(this.state)
      })

      await this.transitionTo(MissionPhase.LOG_ANALYSIS, async () => {
        this.logHandoff("Mission Orchestrator", "Log Intelligence Agent")
        this.state = await this.runLogAnalysis(this.state)
      })

      await this.transitionTo(MissionPhase.EVIDENCE_CORRELATION, async () => {
        this.logHandoff("Mission Orchestrator", "Evidence Correlation Agent")
        this.state = await this.runEvidenceCorrelation(this.state)
      })

      await this.transitionTo(MissionPhase.REPORT_GENERATION, async () => {
        this.logHandoff("Mission Orchestrator", "Report Agent")
        this.state = await this.runReportGeneration(this.state)
      })

      this.state = {
        ...this.state,
        phase: MissionPhase.COMPLETED,
        updatedAt: new Date(),
      }

      this.logDashboard("Mission completed successfully.")
      return this.state
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err)
      this.state = {
        ...this.state,
        phase: MissionPhase.FAILED,
        updatedAt: new Date(),
        errors: [...this.state.errors, errorMessage],
      }
      this.logDashboard(`Mission failed: ${errorMessage}`)
      return this.state
    }
  }

  /**
   * Current immutable snapshot.
   */
  getState(): MissionState {
    return this.state
  }

  private async transitionTo(
    phase: MissionPhase,
    fn: () => Promise<void> | void,
  ): Promise<void> {
    this.state = {
      ...this.state,
      phase,
      updatedAt: new Date(),
    }
    this.logDashboard(`Entering phase: ${phase}`)
    await Promise.resolve(fn())
    await this.sleep(this.opts.tickDelayMs)
  }

  /**
   * Placeholder implementations for each phase.
   * These only stub out structure and dashboard logs for now.
   */

  private async runTestPlanning(prev: MissionState): Promise<MissionState> {
    this.logPhaseDetail("Test Planning", "Synthesizing coverage and vulnerability plans...")
    const sourcePath = prev.request.target.value || "/tmp/owasp-benchmark"
    const apiSpecPath =
      prev.request.apiSpecPath ??
      (prev.request.target.kind === "repo_path"
        ? `${prev.request.target.value}/openapi.json`
        : undefined)
    const agent = new (await import("./agents/test-planning-agent.js")).TestPlanningAgent({
      sourceCodePath: sourcePath,
      apiSpecPath,
      datasetDescription: prev.request.target.name || "OWASP Benchmark",
    })
    const output = await agent.execute()
    return {
      ...prev,
      testPlanning: output,
      updatedAt: new Date(),
    }
  }

  private async runActiveTesting(prev: MissionState): Promise<MissionState> {
    this.logPhaseDetail(
      "Active Testing",
      "Simulating parallel UI, API, and Security test execution...",
    )

    const sourcePath = prev.request.target.value || "/tmp/owasp-benchmark"
    const baseUrl = prev.request.target.kind === "url"
      ? prev.request.target.value
      : `http://localhost:8080`

    const [ui, api, sec] = await Promise.all([
      new (await import("./agents/ui-testing-agent.js")).UITestingAgent({
        baseUrl,
        uiAreas: prev.testPlanning?.coveragePlan.uiAreas,
      }).execute(),
      new (await import("./agents/api-testing-agent.js")).APITestingAgent({
        baseUrl,
        endpoints: prev.testPlanning?.coveragePlan.apiEndpoints,
      }).execute(),
      new (await import("./agents/security-validation-agent.js")).SecurityValidationAgent({
        sourcePath,
        highRiskSurfaces: prev.testPlanning?.vulnerabilityTestingPlan.highRiskEndpoints ?? [],
      }).execute(),
    ])

    return {
      ...prev,
      uiTesting: ui,
      apiTesting: api,
      securityValidation: sec,
      updatedAt: new Date(),
    }
  }

  private async runLogAnalysis(prev: MissionState): Promise<MissionState> {
    this.logPhaseDetail("Log Analysis", "Parsing logs and clustering anomalies...")
    const mockRawLogs = `2024-03-10T14:32:01.123Z [postgresql] ERROR: connection timeout after 30000ms
  at ConnectionPool.acquire (node_modules/pg/lib/connection-pool.js:45:12)
  at Client.query (node_modules/pg/lib/client.js:89:7)
  at Database.getUser (/app/services/db.js:112:5)
  at async UserService.findById (/app/services/user.js:23:11)
Caused by: ECONNREFUSED 127.0.0.1:5432

2024-03-10T14:32:02.456Z [nginx] 500 Internal Server Error - upstream timed out
  client: 192.168.1.100
  request: "GET /api/users/123 HTTP/1.1"
  upstream: "http://127.0.0.1:8080/api/users/123"
  host: "api.example.com"`

    const agent = new (await import("./agents/log-intelligence-agent.js")).LogIntelligenceAgent({
      rawLogs: mockRawLogs,
    })
    const analysis = await agent.execute()
    const logs: LogIntelligenceOutput = {
      clusters: [],
      rootCauses: [],
      systemAnomalies: analysis.systemAnomalies,
    }
    return {
      ...prev,
      logIntelligence: logs,
      updatedAt: new Date(),
    }
  }

  private async runEvidenceCorrelation(prev: MissionState): Promise<MissionState> {
    this.logPhaseDetail("Evidence Correlation", "Linking UI, API, Security, and Logs...")
    const artifacts = {
      uiTraces: prev.uiTesting?.traces ?? [],
      apiLogs: prev.apiTesting?.results ?? [],
      vulnerabilities: prev.securityValidation?.findings ?? [],
      systemAnomalies: prev.logIntelligence?.systemAnomalies ?? [],
      rootCauseEstimations: prev.logIntelligence?.rootCauses,
    }
    const agent = new (await import("./agents/evidence-correlation-agent.js")).EvidenceCorrelationAgent({
      artifacts,
    })
    const evidence = await agent.execute()

    // ── QASECCLAW CORE VALUE: The False Positive Filter ──
    const linkedIds = new Set(
      evidence.chains.flatMap((c) => c.linkedEvidenceIds || [])
    )
    
    let allFindings = prev.securityValidation?.findings ?? []
    const dynamicallyVerified = allFindings.filter((finding) => linkedIds.has(finding.id))
    const uncorrelated = allFindings.filter((finding) => !linkedIds.has(finding.id))
    
    let finalFindings = [...dynamicallyVerified]
    
    // For findings without dynamic execution context (e.g., pure static benchmarks),
    // we use the LLM SastFilterAgent to do a deep code review to recover True Positives.
    const sourcePath = prev.request.target.value || "/tmp/owasp-benchmark"
    if (uncorrelated.length > 0) {
      this.logPhaseDetail("Evidence Correlation", `Running deep LLM SAST filter on ${uncorrelated.length} uncorrelated findings...`)
      
      const SastFilterAgent = (await import("./agents/sast-filter-agent.js")).SastFilterAgent
      const filterAgent = new SastFilterAgent(sourcePath, uncorrelated)
      const llmVerified = await filterAgent.execute()
      
      finalFindings.push(...llmVerified)
    }

    const dropped = allFindings.length - finalFindings.length
    this.logPhaseDetail("Evidence Correlation", `Filtered out ${dropped} False Positives. Kept ${finalFindings.length} verified findings.`)

    return {
      ...prev,
      evidenceCorrelation: evidence,
      securityValidation: prev.securityValidation ? {
        ...prev.securityValidation,
        findings: finalFindings
      } : undefined,
      updatedAt: new Date(),
    }
  }

  private async runReportGeneration(prev: MissionState): Promise<MissionState> {
    this.logPhaseDetail("Report Generation", "Assembling benchmark report artifacts...")
    const agent = new (await import("./agents/report-agent.js")).ReportAgent({
      testPlan: prev.testPlanning,
      uiTesting: prev.uiTesting,
      apiTesting: prev.apiTesting,
      securityValidation: prev.securityValidation,
      logIntelligence: prev.logIntelligence,
      causalChains: prev.evidenceCorrelation?.chains,
    })
    const markdown = await agent.execute()
    const __dirname = dirname(fileURLToPath(import.meta.url))
    const reportPath = resolve(__dirname, "..", "qasecclaw-report.md")
    await writeFile(reportPath, markdown, "utf-8")
    console.log(chalk.green(`Report written to ${reportPath}`))
    
    // Also export raw security findings to JSON for benchmark scoring
    const rawFindingsPath = resolve(__dirname, "..", "qasecclaw-raw-findings.json")
    const rawFindings = prev.securityValidation?.findings || []
    await writeFile(rawFindingsPath, JSON.stringify(rawFindings, null, 2), "utf-8")
    console.log(chalk.green(`Raw security findings written to ${rawFindingsPath}`))

    const report: ReportOutput = {
      reportPath,
      summary: markdown.slice(0, 200) + (markdown.length > 200 ? "..." : ""),
    }
    return {
      ...prev,
      report,
      updatedAt: new Date(),
    }
  }

  /**
   * ---- Terminal dashboard logging ----
   */

  private logBanner(): void {
    const title = chalk.cyan.bold("QASecClaw Mission Orchestrator")
    const runId = chalk.magenta(this.state.runId)
    const target = chalk.yellow(this.state.request.target.name)

    // eslint-disable-next-line no-console
    console.log(
      [
        "",
        title,
        chalk.gray(`  runId: ${runId}`),
        chalk.gray(`  target: ${target} (${this.state.request.target.kind})`),
        "",
      ].join("\n"),
    )
  }

  private logDashboard(message: string): void {
    const ts = new Date().toISOString()
    const prefix = chalk.gray(`[${ts}]`)
    const msg = chalk.green(message)
    const phaseLines = this.renderPhaseLines()

    // eslint-disable-next-line no-console
    console.log(
      [
        "",
        chalk.bold("Mission Phases"),
        ...phaseLines,
        "",
        `${prefix} ${msg}`,
        "",
      ].join("\n"),
    )
  }

  private logPhaseDetail(phaseLabel: string, detail: string): void {
    const label = chalk.yellow.bold(`[${phaseLabel}]`)
    const text = chalk.dim(detail)
    // eslint-disable-next-line no-console
    console.log(`${label} ${text}`)
  }

  private logHandoff(from: string, to: string): void {
    const arrow = chalk.cyan("⇒")
    const fromStr = chalk.bold(from)
    const toStr = chalk.bold(to)
    // eslint-disable-next-line no-console
    console.log(chalk.magenta(`[handoff] ${fromStr} ${arrow} ${toStr}`))
  }

  private renderPhaseLines(): string[] {
    const current = this.state.phase

    const phases: MissionPhase[] = [
      MissionPhase.INITIALIZATION,
      MissionPhase.TEST_PLANNING,
      MissionPhase.ACTIVE_TESTING,
      MissionPhase.LOG_ANALYSIS,
      MissionPhase.EVIDENCE_CORRELATION,
      MissionPhase.REPORT_GENERATION,
      MissionPhase.COMPLETED,
      MissionPhase.FAILED,
    ]

    return phases.map((p) => {
      const isCurrent = p === current
      const marker = isCurrent ? chalk.cyan.bold(">") : " "
      const label = p

      if (p === MissionPhase.COMPLETED) {
        return `${marker} ${chalk.green(label)}`
      }
      if (p === MissionPhase.FAILED) {
        return `${marker} ${chalk.red(label)}`
      }
      if (isCurrent) {
        return `${marker} ${chalk.cyan.bold(label)}`
      }
      return `${marker} ${chalk.gray(label)}`
    })
  }

  private async sleep(ms: number): Promise<void> {
    if (ms <= 0) return
    await new Promise<void>((resolve) => setTimeout(resolve, ms))
  }
}

/**
 * Execution block: run orchestrator when this file is executed directly.
 */
const __filename = fileURLToPath(import.meta.url)
const isMain = process.argv[1] === __filename

if (isMain) {
  ;(async () => {
    // `tsx` and package managers sometimes inject a literal `--` to
    // separate their own flags from script flags. `parseArgs` will treat
    // anything after that as positionals, so we strip it for robustness.
    const args = process.argv.slice(2).filter((a) => a !== "--")
    const { values } = parseArgs({
      args,
      options: {
        name: { type: "string" },
        source: { type: "string" },
        api: { type: "string" },
      },
    })

    const name = values.name ?? "OWASP Benchmark"
    const source = values.source ?? "/tmp/owasp-benchmark"
    const apiSpecPath = values.api ?? (values.source ? `${source}/openapi.json` : undefined)
    const kind: QASecClawRunRequest["target"]["kind"] =
      source.startsWith("http://") || source.startsWith("https://") ? "url" : "repo_path"

    const request: QASecClawRunRequest = {
      target: {
        name,
        kind,
        value: source,
      },
      apiSpecPath,
    }
    const orchestrator = new MissionOrchestrator(request)
    try {
      await orchestrator.run()
    } catch (err) {
      console.error("Fatal error:", err instanceof Error ? err.message : String(err))
      process.exit(1)
    }
  })()
}
