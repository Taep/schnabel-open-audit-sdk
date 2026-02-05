import { describe, it, expect } from "vitest";

import { normalize } from "../src/normalizer/normalize.js";
import { scanSignals } from "../src/signals/scan.js";

import { ToolResultFactMismatchScanner } from "../src/signals/scanners/detect/tool_result_fact_mismatch.js";

describe("ToolResultFactMismatchScanner", () => {
  it("flags high when numeric fact differs (balance)", async () => {
    const n = normalize({
      requestId: "tm-1",
      timestamp: 1,
      prompt: "Hello",
      toolResults: [{ toolName: "wallet.getBalance", ok: true, result: { balance: 0 } }],
      responseText: "Balance is 100.",
    });

    const { findings } = await scanSignals(n, [ToolResultFactMismatchScanner], { mode: "audit" });
    expect(findings.some(f => f.scanner === "tool_result_fact_mismatch" && f.risk === "high")).toBe(true);
  });

  it("flags high when count differs (array length vs response)", async () => {
    const n = normalize({
      requestId: "tm-2",
      timestamp: 1,
      prompt: "Hello",
      toolResults: [{ toolName: "db.list", ok: true, result: [1, 2] }], // count=2
      responseText: "Found 5 results.",
    });

    const { findings } = await scanSignals(n, [ToolResultFactMismatchScanner], { mode: "audit" });
    expect(findings.some(f => f.scanner === "tool_result_fact_mismatch" && f.risk === "high")).toBe(true);
  });

  it("flags high when boolean found=false but response claims found", async () => {
    const n = normalize({
      requestId: "tm-3",
      timestamp: 1,
      prompt: "Hello",
      toolResults: [{ toolName: "search.find", ok: true, result: { found: false } }],
      responseText: "I found it.",
    });

    const { findings } = await scanSignals(n, [ToolResultFactMismatchScanner], { mode: "audit" });
    expect(findings.some(f => f.scanner === "tool_result_fact_mismatch" && f.risk === "high")).toBe(true);
  });

  it("does nothing if response does not make a clear claim", async () => {
    const n = normalize({
      requestId: "tm-4",
      timestamp: 1,
      prompt: "Hello",
      toolResults: [{ toolName: "wallet.getBalance", ok: true, result: { balance: 0 } }],
      responseText: "Here are the results.",
    });

    const { findings } = await scanSignals(n, [ToolResultFactMismatchScanner], { mode: "audit" });
    expect(findings.length).toBe(0);
  });
});
