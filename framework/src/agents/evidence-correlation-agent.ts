import type {
  APITestResult,
  CausalChain,
  EvidenceCorrelationOutput,
  RootCauseEstimation,
  SecurityFinding,
  SystemAnomaly,
  UITestFailureTrace,
} from "../index.js"
import { generateQwenResponse } from "../llm/qwen-client.js"
import chalk from "chalk"

/**
 * Artifacts collected from prior agents for root cause correlation.
 */
export interface EvidenceCorrelationArtifacts {
  readonly uiTraces: readonly UITestFailureTrace[]
  readonly apiLogs: readonly APITestResult[]
  readonly vulnerabilities: readonly SecurityFinding[]
  readonly systemAnomalies: readonly SystemAnomaly[]
  readonly rootCauseEstimations?: readonly RootCauseEstimation[]
}

export interface EvidenceCorrelationInputs {
  readonly artifacts: EvidenceCorrelationArtifacts
}

/**
 * Raw CausalChain shape returned by the LLM.
 */
interface CausalChainResponse {
  readonly id: string
  readonly primaryFailureId: string
  readonly linkedEvidenceIds: readonly string[]
  readonly correlationExplanation: string
}

/**
 * Evidence Correlation Agent.
 * Uses Qwen LLM (qwen3.5-plus) to correlate UI failures, API errors,
 * security vulnerabilities, and log anomalies into causal chains.
 */
export class EvidenceCorrelationAgent {
  constructor(private readonly inputs: EvidenceCorrelationInputs) {}

  async execute(): Promise<EvidenceCorrelationOutput> {
    const { uiTraces, apiLogs, vulnerabilities, systemAnomalies } =
      this.inputs.artifacts

    const systemPrompt = `You are a Root Cause Analysis Expert. Your task is to correlate frontend UI failures, backend API errors, security vulnerabilities, and log anomalies into causal chains.

You MUST output ONLY a valid JSON object with a single key "chains" whose value is an array of CausalChain objects. Each CausalChain must have exactly these keys:
- id: string (unique chain identifier)
- primaryFailureId: string (the ID of the primary failure that triggered the chain)
- linkedEvidenceIds: string[] (array of IDs from uiTraces, apiLogs, vulnerabilities, or systemAnomalies that are causally linked)
- correlationExplanation: string (brief explanation of how these pieces of evidence are causally related)

Do not include markdown, code blocks, or conversational text. Output valid JSON only.`

    const userPrompt = `Correlate the following evidence into causal chains:

## UI Traces (frontend failures)
${JSON.stringify(uiTraces, null, 2)}

## API Logs (backend errors)
${JSON.stringify(apiLogs, null, 2)}

## Security Vulnerabilities
${JSON.stringify(vulnerabilities, null, 2)}

## System Anomalies (log clusters)
${JSON.stringify(systemAnomalies, null, 2)}`

    console.log(chalk.blue("Querying qwen3.5-plus for root cause correlation..."))
    const start = Date.now()

    let rawText: string
    try {
      rawText = await generateQwenResponse(systemPrompt, userPrompt, true, "qwen3.5-plus")
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err)
      console.error(chalk.red(`Qwen API failed: ${errMsg}`))
      return { chains: [] }
    }

    console.log(chalk.blue(`Root cause correlation completed in ${Date.now() - start}ms`))

    let parsed: { chains?: unknown }
    try {
      parsed = JSON.parse(rawText) as { chains?: unknown }
    } catch {
      console.error("Failed to parse LLM response as JSON. Raw text:", rawText)
      return { chains: [] }
    }

    const rawChains = Array.isArray(parsed.chains) ? parsed.chains : []
    const chains: CausalChain[] = rawChains
      .filter((c): c is CausalChainResponse => isCausalChainResponse(c))
      .map((c) => ({
        id: c.id,
        summary: c.correlationExplanation,
        primaryFailureId: c.primaryFailureId,
        linkedEvidenceIds: c.linkedEvidenceIds,
        correlationExplanation: c.correlationExplanation,
        steps: [],
      }))

    return { chains }
  }
}

function isCausalChainResponse(
  c: unknown,
): c is CausalChainResponse {
  if (typeof c !== "object" || c === null) return false
  const o = c as Record<string, unknown>
  return (
    typeof o.id === "string" &&
    typeof o.primaryFailureId === "string" &&
    Array.isArray(o.linkedEvidenceIds) &&
    typeof o.correlationExplanation === "string"
  )
}
