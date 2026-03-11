import OpenAI from "openai"
import chalk from "chalk"
import { config } from "dotenv"
import { resolve, dirname } from "path"
import { fileURLToPath } from "url"

// Load .env from framework root (works regardless of process cwd)
const __dirname = dirname(fileURLToPath(import.meta.url))
config({ path: resolve(__dirname, "../../.env") })

const baseURL = "https://dashscope-intl.aliyuncs.com/compatible-mode/v1"

const client = new OpenAI({
  baseURL,
  apiKey: process.env.DASHSCOPE_API_KEY ?? "",
})

/**
 * Generate a completion from Qwen via OpenAI-compatible DashScope endpoint.
 * @param modelOverride - Optional model name (e.g. "qwen3.5-plus"). Uses QWEN_MODEL_NAME env var if not provided.
 */
export async function generateQwenResponse(
  systemPrompt: string,
  userPrompt: string,
  jsonMode: boolean = false,
  modelOverride?: string,
): Promise<string> {
  const apiKey = process.env.DASHSCOPE_API_KEY
  if (!apiKey) {
    const msg = "DASHSCOPE_API_KEY environment variable is required"
    console.error(chalk.red(msg))
    throw new Error(msg)
  }

  const model = modelOverride ?? process.env.QWEN_MODEL_NAME ?? "qwen-max"

  try {
    const completion = await client.chat.completions.create({
      model,
      messages: [
        { role: "system", content: systemPrompt },
        {
          role: "user",
          content: jsonMode
            ? `${userPrompt}\n\nRespond with valid JSON only, no markdown or code blocks.`
            : userPrompt,
        },
      ],
      ...(jsonMode && {
        response_format: { type: "json_object" as const },
      }),
    })

    const content = completion.choices[0]?.message?.content ?? ""
    return content
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.error(chalk.red(`Qwen API error: ${msg}`))
    throw err
  }
}
