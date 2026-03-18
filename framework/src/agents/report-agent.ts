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

You MUST structure the '2. Key Vulnerabilities' section EXACTLY using the following markdown headers. You must create a separate markdown table under each header. Do not combine them into a single table.

### Critical Severity
| ID | Vulnerability Type | Location | Description |
|---|---|---|---|

### High Severity
| ID | Vulnerability Type | Location | Description |
|---|---|---|---|

### Medium Severity
| ID | Vulnerability Type | Location | Description |
|---|---|---|---|

### Low Severity
| ID | Vulnerability Type | Location | Description |
|---|---|---|---|

If there are no vulnerabilities for a specific severity, output the header and write 'No vulnerabilities found in this category.' instead of a table.

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
