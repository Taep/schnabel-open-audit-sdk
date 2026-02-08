import { describe, it, expect } from "vitest";

import { normalize } from "../src/normalizer/normalize.js";
import { scanSignals } from "../src/signals/scan.js";

import { ToolResultContradictionScanner } from "../src/signals/scanners/detect/tool_result_contradiction.js";

describe("ToolResultContradictionScanner", () => {
  it("flags high risk when tool failed but response claims success", async () => {
    const n = normalize({
      requestId: "r-trc-1",
      timestamp: 1,
      prompt: "user prompt",
      toolResults: [{ toolName: "web.search", ok: false, result: { error: "timeout" } }],
      responseText: "Done. I successfully retrieved the results.",
    });

    const { findings } = await scanSignals(n, [ToolResultContradictionScanner], { mode: "audit", failFast: false });

    expect(findings.length).toBe(1);
    expect(findings[0]!.scanner).toBe("tool_result_contradiction");
    expect(findings[0]!.risk).toBe("high");
  });

  it("flags medium risk when tool succeeded but response claims failure", async () => {
    const n = normalize({
      requestId: "r-trc-2",
      timestamp: 1,
      prompt: "user prompt",
      toolResults: [{ toolName: "db.query", ok: true, result: { rows: [1] } }],
      responseText: "It failed. I couldn't do it.",
    });

    const { findings } = await scanSignals(n, [ToolResultContradictionScanner], { mode: "audit", failFast: false });

    expect(findings.length).toBe(1);
    expect(findings[0]!.risk).toBe("medium");
  });

  it("does nothing when responseText is missing", async () => {
    const n = normalize({
      requestId: "r-trc-3",
      timestamp: 1,
      prompt: "user prompt",
      toolResults: [{ toolName: "db.query", ok: false, result: {} }],
    });

    const { findings } = await scanSignals(n, [ToolResultContradictionScanner], { mode: "audit", failFast: false });
    expect(findings.length).toBe(0);
  });
});
