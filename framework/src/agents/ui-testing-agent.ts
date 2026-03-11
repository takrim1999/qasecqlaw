import type {
  UITestFailureTrace,
  UITestingOutput,
} from "../index.js"
import chalk from "chalk"

/**
 * Inputs for the UI Testing Agent (per PDF Section 3.2).
 */
export interface UITestingInputs {
  readonly baseUrl: string
  readonly uiAreas?: readonly string[]
}

/**
 * UI Testing Agent.
 * Simulates Playwright/Selenium to automate browser interactions,
 * test login systems, forms, and user workflows.
 */
export class UITestingAgent {
  constructor(private readonly inputs: UITestingInputs) {}

  /**
   * Execute the agent and return UITestingOutput for the Orchestrator.
   */
  async execute(): Promise<UITestingOutput> {
    console.log(chalk.cyan.bold("[UI Testing Agent]"))
    console.log(chalk.gray("  Launching Playwright browser..."))

    const traces: UITestFailureTrace[] = []
    const failureLogs: UITestingOutput["failureLogs"] = []
    const screenshots: UITestingOutput["screenshots"] = []

    console.log(chalk.gray("  Running login flow tests..."))
    const loginTrace = this.mockLoginFlow()
    traces.push(loginTrace.trace)
    if (loginTrace.failureLog) failureLogs.push(loginTrace.failureLog)
    screenshots.push(...loginTrace.screenshots)

    console.log(chalk.gray("  Running form filling workflow..."))
    const formTrace = this.mockFormWorkflow()
    traces.push(formTrace.trace)
    if (formTrace.failureLog) failureLogs.push(formTrace.failureLog)
    screenshots.push(...formTrace.screenshots)

    console.log(chalk.gray("  Running multi-step navigation workflow..."))
    const navTrace = this.mockNavigationWorkflow()
    traces.push(navTrace.trace)
    if (navTrace.failureLog) failureLogs.push(navTrace.failureLog)
    screenshots.push(...navTrace.screenshots)

    console.log(chalk.green(`  UI testing complete. ${traces.length} traces, ${screenshots.length} screenshots. Handing off to Orchestrator.`))
    return { traces, failureLogs, screenshots }
  }

  private mockLoginFlow(): {
    trace: UITestFailureTrace
    failureLog?: UITestingOutput["failureLogs"][number]
    screenshots: UITestingOutput["screenshots"]
  } {
    const trace: UITestFailureTrace = {
      id: "ui-trace-001",
      route: "/login",
      scenarioId: "webarena-login-001",
      steps: [
        "navigate to /login",
        "fill username input",
        "fill password input",
        "click submit",
        "assert redirect to /dashboard",
      ],
      errorMessage: "Expected redirect to /dashboard; got 401 Unauthorized",
    }
    const failureLog = {
      id: "fl-001",
      traceId: trace.id,
      rawLogPath: "artifacts/runs/ui/login-failure-001.log",
    }
    const screenshots = [
      { id: "ss-001", traceId: trace.id, path: "artifacts/runs/ui/login-step-2.png" },
      { id: "ss-002", traceId: trace.id, path: "artifacts/runs/ui/login-failure.png" },
    ]
    console.log(chalk.dim(`    Login flow: 1 trace, 2 screenshots (failure captured)`))
    return { trace, failureLog, screenshots }
  }

  private mockFormWorkflow(): {
    trace: UITestFailureTrace
    failureLog?: UITestingOutput["failureLogs"][number]
    screenshots: UITestingOutput["screenshots"]
  } {
    const trace: UITestFailureTrace = {
      id: "ui-trace-002",
      route: "/search",
      scenarioId: "webarena-form-001",
      steps: [
        "navigate to /search",
        "fill search input with query",
        "submit form",
        "assert results rendered",
      ],
    }
    const screenshots = [
      { id: "ss-003", traceId: trace.id, path: "artifacts/runs/ui/form-filled.png" },
      { id: "ss-004", traceId: trace.id, path: "artifacts/runs/ui/form-results.png" },
    ]
    console.log(chalk.dim(`    Form workflow: 1 trace, 2 screenshots (passed)`))
    return { trace, failureLog: undefined, screenshots }
  }

  private mockNavigationWorkflow(): {
    trace: UITestFailureTrace
    failureLog?: UITestingOutput["failureLogs"][number]
    screenshots: UITestingOutput["screenshots"]
  } {
    const trace: UITestFailureTrace = {
      id: "ui-trace-003",
      route: "/admin/users",
      scenarioId: "webarena-nav-001",
      steps: [
        "navigate to /",
        "click Admin menu",
        "navigate to /admin/users",
        "assert user table visible",
      ],
      errorMessage: "Element .admin-users-table not found within 5s",
    }
    const failureLog = {
      id: "fl-002",
      traceId: trace.id,
      rawLogPath: "artifacts/runs/ui/nav-failure-001.log",
    }
    const screenshots = [
      { id: "ss-005", traceId: trace.id, path: "artifacts/runs/ui/nav-admin.png" },
      { id: "ss-006", traceId: trace.id, path: "artifacts/runs/ui/nav-failure.png" },
    ]
    console.log(chalk.dim(`    Navigation workflow: 1 trace, 2 screenshots (failure captured)`))
    return { trace, failureLog, screenshots }
  }
}
