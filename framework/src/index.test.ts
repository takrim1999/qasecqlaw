import { describe, expect, it } from "vitest"

import { createRunId } from "./index.js"

describe("createRunId", () => {
  it("is filesystem-friendly", () => {
    const runId = createRunId(new Date("2026-03-10T12:34:56.789Z"))
    expect(runId).toBe("2026-03-10T123456-789Z")
  })
})

