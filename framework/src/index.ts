export type QASecClawRunRequest = {
  target: {
    name: string
    kind: "source_zip" | "repo_path" | "url"
    value: string
  }
}

export type QASecClawRunResult = {
  runId: string
  artifactsDir: string
}

export function createRunId(now: Date = new Date()): string {
  // RFC3339-ish, filesystem friendly.
  return now.toISOString().replaceAll(":", "").replaceAll(".", "-")
}

