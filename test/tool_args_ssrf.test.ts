import { describe, it, expect } from "vitest";
import { normalize } from "../src/normalizer/normalize.js";
import { scanSignals } from "../src/signals/scan.js";
import { ToolArgsSSRFScanner } from "../src/signals/scanners/detect/tool_args_ssrf.js";


describe("ToolArgsSSRFScanner", () => {
  it("flags metadata IP SSRF", async () => {
    const n = normalize({
      requestId: "ssrf-1",
      timestamp: 1,
      prompt: "Hello",
      toolCalls: [{
        toolName: "http.fetch",
        args: { url: "http://169.254.169.254/latest/meta-data/" }
      }],
    });

    const { findings } = await scanSignals(n, [ToolArgsSSRFScanner], { mode: "audit", failFast: false });
    expect(findings.some(f => f.scanner === "tool_args_ssrf" && f.risk === "high")).toBe(true);
  });

  it("flags dangerous scheme (file://)", async () => {
    const n = normalize({
      requestId: "ssrf-2",
      timestamp: 1,
      prompt: "Hello",
      toolCalls: [{ toolName: "read", args: { path: "file:///etc/passwd" } }],
    });

    const { findings } = await scanSignals(n, [ToolArgsSSRFScanner], { mode: "audit", failFast: false });
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.scanner === "tool_args_ssrf" && f.tags?.includes("dangerous_scheme"))).toBe(true);
  });
});
