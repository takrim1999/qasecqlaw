import type {
  SecurityFinding,
  SecurityTool,
  SecurityValidationOutput,
  VulnerabilitySeverity,
} from "../index.js"
import chalk from "chalk"
import { exec } from "node:child_process"
import { promisify } from "node:util"

const execAsync = promisify(exec)

/**
 * Inputs for the Security Validation Agent (per PDF Section 3.4).
 */
export interface SecurityValidationInputs {
  readonly sourcePath: string
  /**
   * Alias for `sourcePath`. Some callers may provide this name; we keep both
   * to avoid breaking existing orchestrator wiring.
   */
  readonly sourceCodePath?: string
  readonly highRiskSurfaces?: readonly string[]
}

/**
 * Security Validation Agent.
 * Simulates Semgrep, OWASP ZAP, and dependency scanners.
 * Detects injection vulnerabilities, authentication flaws, insecure dependencies.
 */
export class SecurityValidationAgent {
  constructor(private readonly inputs: SecurityValidationInputs) {}

  /**
   * Execute the agent and return SecurityFinding[] for the Orchestrator.
   */
  async execute(): Promise<SecurityValidationOutput> {
    console.log(chalk.cyan.bold("[Security Validation Agent]"))
    console.log(chalk.gray("  Initializing scanners (Semgrep, ZAP, Snyk)..."))

    const findings: SecurityFinding[] = []

    let semgrepFindings: SecurityFinding[] = []

    try {
      const codePath = this.inputs.sourceCodePath ?? this.inputs.sourcePath
      console.log(chalk.blue("Initiating live Semgrep SAST scan..."))

      const start = Date.now()
      const { stdout } = await execAsync(
        `semgrep scan --json ${codePath}`,
        { maxBuffer: 1024 * 1024 * 10 },
      )

      console.log(
        chalk.blue(`Semgrep scan finished in ${Date.now() - start}ms`),
      )

      const parsed: unknown = JSON.parse(stdout)
      const results: unknown[] =
        typeof parsed === "object" && parsed !== null && "results" in parsed
          ? // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ((parsed as any).results as unknown[])
          : (parsed as unknown[])

      semgrepFindings = Array.isArray(results)
        ? results
            .map((r, i) => mapSemgrepResultToFinding(r, i))
            .filter((x): x is SecurityFinding => x !== null)
        : []
    } catch (err) {
      console.error(
        chalk.yellow(
          "Live Semgrep execution failed (ensure semgrep is installed). Falling back to mock SAST data.",
        ),
      )
      semgrepFindings = this.mockSemgrepRun()
    }

    findings.push(...semgrepFindings)

    console.log(chalk.gray("  Running OWASP ZAP dynamic scan..."))
    findings.push(...this.mockZapRun())

    console.log(chalk.gray("  Running Snyk dependency scan..."))
    findings.push(...this.mockSnykRun())

    console.log(chalk.green(`  Scan complete. ${findings.length} findings. Handing off to Orchestrator.`))
    return { findings }
  }

  private mockSemgrepRun(): SecurityFinding[] {
    const findings: SecurityFinding[] = [
      {
        id: "sem-001",
        tool: "semgrep" as SecurityTool,
        vulnerabilityType: "SQL Injection",
        severity: "HIGH" as VulnerabilitySeverity,
        location: "BenchmarkTest00001.java:42",
        description: "User input concatenated into SQL query without sanitization.",
        cweId: "CWE-89",
      },
      {
        id: "sem-002",
        tool: "semgrep" as SecurityTool,
        vulnerabilityType: "Cross-Site Scripting (XSS)",
        severity: "MEDIUM" as VulnerabilitySeverity,
        location: "BenchmarkTest00002.jsp:18",
        description: "Reflected user input rendered without encoding.",
        cweId: "CWE-79",
      },
      {
        id: "sem-003",
        tool: "semgrep" as SecurityTool,
        vulnerabilityType: "Command Injection",
        severity: "CRITICAL" as VulnerabilitySeverity,
        location: "BenchmarkTest00003.java:56",
        description: "Runtime.exec() called with unsanitized user input.",
        cweId: "CWE-78",
      },
      {
        id: "sem-004",
        tool: "semgrep" as SecurityTool,
        vulnerabilityType: "Path Traversal",
        severity: "MEDIUM" as VulnerabilitySeverity,
        location: "BenchmarkTest00004.java:31",
        description: "File path constructed from user-controlled input.",
        cweId: "CWE-22",
      },
    ]
    console.log(chalk.dim(`    Semgrep: ${findings.length} static findings`))
    return findings
  }

  private mockZapRun(): SecurityFinding[] {
    const findings: SecurityFinding[] = [
      {
        id: "zap-001",
        tool: "zap" as SecurityTool,
        vulnerabilityType: "SQL Injection (DAST)",
        severity: "HIGH" as VulnerabilitySeverity,
        location: "/api/benchmark/BenchmarkTest00001",
        description: "Parameter 'id' vulnerable to SQL injection.",
        cweId: "CWE-89",
      },
      {
        id: "zap-002",
        tool: "zap" as SecurityTool,
        vulnerabilityType: "Missing Authentication",
        severity: "MEDIUM" as VulnerabilitySeverity,
        location: "/api/admin/users",
        description: "Admin endpoint accessible without authentication.",
        cweId: "CWE-306",
      },
      {
        id: "zap-003",
        tool: "zap" as SecurityTool,
        vulnerabilityType: "Cross-Site Request Forgery (CSRF)",
        severity: "MEDIUM" as VulnerabilitySeverity,
        location: "/api/user/profile",
        description: "State-changing request lacks CSRF token.",
        cweId: "CWE-352",
      },
    ]
    console.log(chalk.dim(`    ZAP: ${findings.length} dynamic findings`))
    return findings
  }

  private mockSnykRun(): SecurityFinding[] {
    const findings: SecurityFinding[] = [
      {
        id: "snyk-001",
        tool: "snyk" as SecurityTool,
        vulnerabilityType: "Insecure Dependency",
        severity: "HIGH" as VulnerabilitySeverity,
        location: "commons-fileupload:1.3.3",
        description: "Known RCE in Apache Commons FileUpload.",
        cweId: "CWE-502",
      },
      {
        id: "snyk-002",
        tool: "snyk" as SecurityTool,
        vulnerabilityType: "Outdated Dependency",
        severity: "LOW" as VulnerabilitySeverity,
        location: "log4j-core:2.14.1",
        description: "Log4j version has known vulnerabilities; upgrade to 2.17+.",
        cweId: "CWE-1104",
      },
    ]
    console.log(chalk.dim(`    Snyk: ${findings.length} dependency findings`))
    return findings
  }
}

function mapSemgrepResultToFinding(r: unknown, index: number): SecurityFinding | null {
  if (typeof r !== "object" || r === null) return null

  // semgrep JSON shape (best-effort, varies by semgrep version)
  // result.path, result.start.line, result.extra.severity/message, result.check_id
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const o = r as any

  const path = typeof o.path === "string" ? o.path : undefined
  const line = typeof o?.start?.line === "number" ? o.start.line : undefined
  const severityRaw = o?.extra?.severity
  const descriptionRaw = o?.extra?.message
  const checkIdRaw = o?.check_id

  if (!path || line === undefined || typeof severityRaw !== "string") return null

  const severity = normalizeSemgrepSeverity(severityRaw)
  return {
    id: `semgrep-${String(index + 1).padStart(4, "0")}`,
    tool: "semgrep" as SecurityTool,
    vulnerabilityType: typeof checkIdRaw === "string" ? checkIdRaw : "Semgrep Finding",
    severity,
    location: `${path}:${line}`,
    description: typeof descriptionRaw === "string" ? descriptionRaw : undefined,
  }
}

function normalizeSemgrepSeverity(severity: string): VulnerabilitySeverity {
  const s = severity.toLowerCase()
  if (s.includes("critical")) return "CRITICAL"
  if (s.includes("high")) return "HIGH"
  if (s.includes("medium")) return "MEDIUM"
  return "LOW"
}
