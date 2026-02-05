import { describe, it, expect } from "vitest";

import { runAudit } from "../src/core/run_audit.js";
import { InMemoryHistoryStore } from "../src/core/history_store.js";

import { ToolResultFactMismatchScanner } from "../src/signals/scanners/detect/tool_result_fact_mismatch.js";
import { createHistoryContradictionScanner } from "../src/signals/scanners/detect/history_contradiction.js";

import type { Scanner } from "../src/signals/scanners/scanner.js";

describe("Policy escalations (immediate + history)", () => {
  it("immediately BLOCKs on tool_result_fact_mismatch high", async () => {
    const scanners: Scanner[] = [ToolResultFactMismatchScanner];

    const res = await runAudit(
      {
        requestId: "escal-1",
        timestamp: 1,
        prompt: "Hello",
        toolResults: [{ toolName: "wallet.getBalance", ok: true, result: { balance: 0 } }],
        responseText: "Balance is 100.",
      },
      { scanners }
    );

    expect(res.decision.action).toBe("block");
    expect(res.decision.risk).toBe("critical");
  });

  it("escalates repeated medium contradictions to CHALLENGE via history", async () => {
    const store = new InMemoryHistoryStore({ maxTurns: 50 });
    const sessionId = "sess-esc-1";

    const hc = createHistoryContradictionScanner(store, { window: 10 });
    const scanners: Scanner[] = [hc];

    // Turn 1: create history baseline (failed tool)
    await runAudit(
      {
        requestId: "t1",
        timestamp: 1,
        prompt: "Hello",
        toolResults: [{ toolName: "db.query", ok: false, result: { error: "timeout" } }],
        responseText: "It failed. I couldn't do it.",
      },
      { scanners, history: { store, sessionId } }
    );

    // Turn 2: medium contradiction (no escalation yet)
    const r2 = await runAudit(
      {
        requestId: "t2",
        timestamp: 2,
        prompt: "Hello",
        responseText: "I already completed it successfully earlier.",
      },
      { scanners, history: { store, sessionId } }
    );

    // Turn 3: repeated contradiction => should escalate to CHALLENGE at least
    const r3 = await runAudit(
      {
        requestId: "t3",
        timestamp: 3,
        prompt: "Hello",
        responseText: "I already completed it successfully earlier.",
      },
      { scanners, history: { store, sessionId } }
    );

    // r2 may be warn; r3 should be escalated to challenge (or block if thresholds changed)
    expect(["challenge", "block"].includes(r3.decision.action)).toBe(true);
  });
});
