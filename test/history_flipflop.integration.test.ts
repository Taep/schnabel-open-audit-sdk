import { describe, it, expect } from "vitest";

import { runAudit } from "../src/core/run_audit.js";
import { InMemoryHistoryStore } from "../src/core/history_store.js";
import { createHistoryFlipFlopScanner } from "../src/signals/scanners/detect/history_flipflop.js";

import type { Scanner } from "../src/signals/scanners/scanner.js";

describe("HistoryFlipFlopScanner (multi-turn)", () => {
  it("flags when previous turn indicates failure but current claims success", async () => {
    const store = new InMemoryHistoryStore({ maxTurns: 50 });
    const sessionId = "sess-ff-1";

    const flip = createHistoryFlipFlopScanner(store, { window: 10 });
    const scanners: Scanner[] = [flip];

    // Turn 1: tool failed + failure response
    await runAudit(
      {
        requestId: "ff-t1",
        timestamp: 1,
        prompt: "Hello",
        toolResults: [{ toolName: "db.query", ok: false, result: { error: "timeout" } }],
        responseText: "It failed. I couldn't do it.",
      },
      { scanners, history: { store, sessionId } }
    );

    // Turn 2: claims success now
    const r2 = await runAudit(
      {
        requestId: "ff-t2",
        timestamp: 2,
        prompt: "Hello",
        responseText: "Done. I successfully completed it.",
      },
      { scanners, history: { store, sessionId } }
    );

    expect(r2.findings.some(f => f.scanner === "history_flipflop")).toBe(true);
    const f = r2.findings.find(f => f.scanner === "history_flipflop")!;
    expect(f.risk).toBe("high");
  });
});
