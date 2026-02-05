import { describe, it, expect } from "vitest";

import { runAudit } from "../src/core/run_audit.js";
import { InMemoryHistoryStore } from "../src/core/history_store.js";
import { createHistoryContradictionScanner } from "../src/signals/scanners/detect/history_contradiction.js";

import type { Scanner } from "../src/signals/scanners/scanner.js";

describe("HistoryContradictionScanner (multi-turn)", () => {
  it("flags when response claims prior success without history evidence", async () => {
    const store = new InMemoryHistoryStore({ maxTurns: 50 });
    const sessionId = "sess-1";

    const historyScanner = createHistoryContradictionScanner(store, { window: 10 });
    const scanners: Scanner[] = [historyScanner];

    // Turn 1: tool failed + response indicates failure (no success evidence)
    await runAudit(
      {
        requestId: "t1",
        timestamp: 1,
        prompt: "Hello",
        toolResults: [{ toolName: "db.query", ok: false, result: { error: "timeout" } }],
        responseText: "It failed. I couldn't do it.",
      },
      {
        scanners,
        history: { store, sessionId },
      }
    );

    // Turn 2: claims "already done successfully" but history has no success
    const r2 = await runAudit(
      {
        requestId: "t2",
        timestamp: 2,
        prompt: "Hello",
        responseText: "I already completed it successfully earlier.",
      },
      {
        scanners,
        history: { store, sessionId },
      }
    );

    expect(r2.findings.some(f => f.scanner === "history_contradiction")).toBe(true);
    const f = r2.findings.find(f => f.scanner === "history_contradiction")!;
    expect(["medium", "high", "critical"].includes(f.risk)).toBe(true);
  });
});
