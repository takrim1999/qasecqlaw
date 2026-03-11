import type {
  APITestingOutput,
  CausalChain,
  LogIntelligenceOutput,
  SecurityValidationOutput,
  TestPlanningOutput,
  UITestingOutput,
} from "../index.js"
import { generateQwenResponse } from "../llm/qwen-client.js"
import chalk from "chalk"

export interface ReportAgentInputs {
  readonly testPlan?: TestPlanningOutput
  readonly uiTesting?: UITestingOutput
  readonly apiTesting?: APITestingOutput
  readonly securityValidation?: SecurityValidationOutput
  readonly logIntelligence?: LogIntelligenceOutput
  readonly causalChains?: readonly CausalChain[]
}

/**
 * Report Agent.
 * Uses Qwen LLM (qwen3.5-plus) to synthesize testing data, vulnerabilities,
 * anomalies, and causal chains into a comprehensive Markdown executive report.
 */
export class ReportAgent {
  constructor(private readonly inputs: ReportAgentInputs) {}

  async execute(): Promise<string> {
    const systemPrompt = `You are a Senior QA & Security Executive. Your task is to synthesize all testing data, vulnerabilities, anomalies, and causal chains into a comprehensive, professional Markdown report.

You MUST output ONLY valid Markdown text. Include the following sections:
1. **Executive Summary** - High-level overview of findings and risk posture
2. **Key Vulnerabilities** - Security findings with severity and remediation guidance
3. **Root Cause Analysis** - Synthesize causal chains to explain failure propagation
4. **Actionable Recommendations** - Prioritized next steps for engineering and security teams

Do not include JSON, code blocks around the report, or conversational preamble. Output raw Markdown only.`

    const userPrompt = `Synthesize the following accumulated mission state into an executive report:

${JSON.stringify(
  {
    testPlan: this.inputs.testPlan,
    uiTesting: this.inputs.uiTesting,
    apiTesting: this.inputs.apiTesting,
    securityValidation: this.inputs.securityValidation,
    logIntelligence: this.inputs.logIntelligence,
    causalChains: this.inputs.causalChains,
  },
  null,
  2,
)}`

    console.log(chalk.magenta("Synthesizing final executive report via qwen3.5-plus..."))
    const start = Date.now()

    const markdown = await generateQwenResponse(systemPrompt, userPrompt, false, "qwen3.5-plus")

    console.log(chalk.magenta(`Report synthesis completed in ${Date.now() - start}ms`))

    return markdown
  }
}
