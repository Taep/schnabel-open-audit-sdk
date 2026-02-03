import { describe, it, expect } from "vitest";
import { decideDumpPolicy } from "../src/core/dump_policy.js";

describe("DumpPolicy", () => {
  it("dumps on challenge by default", () => {
    const dd = decideDumpPolicy({
      requestId: "r1",
      action: "challenge",
      risk: "high",
      findings: [],
    });

    expect(dd.dump).toBe(true);
    expect(dd.dumpEvidence).toBe(true);
  });

  it("does not dump on allow by default", () => {
    const dd = decideDumpPolicy({
      requestId: "r2",
      action: "allow",
      risk: "none",
      findings: [],
    });

    expect(dd.dump).toBe(false);
  });

  it("can sample allow traffic", () => {
    const dd = decideDumpPolicy(
      { requestId: "r3", action: "allow", risk: "none", findings: [] },
      { sampleAllowRate: 1.0 } // force sample
    );

    expect(dd.dump).toBe(true);
  });
});
