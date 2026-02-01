import { describe, it, expect } from "vitest";
import { fromAgentIngressEvent } from "../src/adapters/generic_agent.js";
import { normalize } from "../src/normalizer/normalize.js";
import { scanSignals } from "../src/signals/scan.js";
import { Uts39ConfusablesScanner } from "../src/signals/scanners/detect/uts39_confusables.js";

describe("UTS#39 confusables scanner", () => {
  it("flags mixed-script / homograph-like text", async () => {
    // "PayPal" with Cyrillic 'а' (U+0430) instead of Latin 'a'
    const homograph = "PayP\u0430l";

    const req = fromAgentIngressEvent({
      requestId: "r-uts39-1",
      timestamp: 1,
      userPrompt: homograph,
    });

    const n = normalize(req);

    const { findings } = await scanSignals(n, [Uts39ConfusablesScanner], {
      mode: "audit",
      failFast: false,
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.scanner === "uts39_confusables")).toBe(true);
  });
});
