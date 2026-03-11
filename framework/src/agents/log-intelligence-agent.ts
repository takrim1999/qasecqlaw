import type { LogAnalysisOutput, SystemAnomaly } from "../index.js"
import { generateQwenResponse } from "../llm/qwen-client.js"
import chalk from "chalk"

export interface LogIntelligenceInputs {
  readonly rawLogs: string | readonly string[]
}

/**
 * Raw SystemAnomaly shape returned by the LLM.
 */
interface SystemAnomalyResponse {
  readonly id: string
  readonly timestamp: string
  readonly service: string
  readonly severity: string
  readonly message: string
  readonly stackTrace?: string
}

/**
 * Log Intelligence Agent.
 * Uses Qwen LLM (qwen3.5-plus) to parse raw unstructured logs and identify
 * stack traces, database crash events, rate-limit triggers, and other anomalies.
 */
export class LogIntelligenceAgent {
  constructor(private readonly inputs: LogIntelligenceInputs) {}

  async execute(): Promise<LogAnalysisOutput> {
    const rawLogs = Array.isArray(this.inputs.rawLogs)
      ? this.inputs.rawLogs.join("\n")
      : this.inputs.rawLogs

    const systemPrompt = `You are a Server Log Analysis AI. Your task is to parse raw unstructured server logs and identify anomalies such as:
- Stack traces (Java, Node.js, Python, etc.)
- Database connection timeouts or crash events
- Rate-limit triggers (429, 503)
- Application errors (5xx, exceptions)
- Security-related events

You MUST output ONLY a valid JSON object with a single key "systemAnomalies" whose value is an array of anomaly objects. Each anomaly must have exactly these keys:
- id: string (unique identifier, e.g. "anomaly-1")
- timestamp: string (ISO or log timestamp)
- service: string (e.g. "postgresql", "nginx", "app")
- severity: string (e.g. "ERROR", "WARN", "CRITICAL")
- message: string (brief description)
- stackTrace: string (optional, full stack trace if present)

Do not include markdown, code blocks, or conversational text. Output valid JSON only.`

    const userPrompt = `Analyze the following raw server logs and extract system anomalies:

\`\`\`
${rawLogs}
\`\`\``

    console.log(chalk.cyan("Querying qwen3.5-plus for log analysis..."))
    const start = Date.now()

    let rawText: string
    try {
      rawText = await generateQwenResponse(systemPrompt, userPrompt, true, "qwen3.5-plus")
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      console.error(chalk.red(`Qwen API failed: ${errMsg}`))
      return { systemAnomalies: [] }
    }

    console.log(chalk.cyan(`Log analysis completed in ${Date.now() - start}ms`))

    let parsed: { systemAnomalies?: unknown }
    try {
      parsed = JSON.parse(rawText) as { systemAnomalies?: unknown }
    } catch {
      console.error("Failed to parse LLM response as JSON. Raw text:", rawText)
      return { systemAnomalies: [] }
    }

    const rawAnomalies = Array.isArray(parsed.systemAnomalies)
      ? parsed.systemAnomalies
      : []
    const systemAnomalies: SystemAnomaly[] = rawAnomalies
      .filter((a): a is SystemAnomalyResponse => isSystemAnomalyResponse(a))
      .map((a) => ({
        id: a.id,
        timestamp: a.timestamp,
        service: a.service,
        severity: a.severity,
        message: a.message,
        stackTrace: a.stackTrace,
      }))

    return { systemAnomalies }
  }
}

function isSystemAnomalyResponse(a: unknown): a is SystemAnomalyResponse {
  if (typeof a !== "object" || a === null) return false
  const o = a as Record<string, unknown>
  return (
    typeof o.id === "string" &&
    typeof o.timestamp === "string" &&
    typeof o.service === "string" &&
    typeof o.severity === "string" &&
    typeof o.message === "string"
  )
}
