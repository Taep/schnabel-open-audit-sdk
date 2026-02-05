import { describe, it, expect } from "vitest";
import { normalize } from "../src/normalizer/normalize.js";
import { scanSignals } from "../src/signals/scan.js";
import { ToolArgsPathTraversalScanner } from "../src/signals/scanners/detect/tool_args_path_traversal.js";

describe("ToolArgsPathTraversalScanner", () => {
  it("flags traversal patterns", async () => {
    const n = normalize({
      requestId: "path-1",
      timestamp: 1,
      prompt: "Hello",
      toolCalls: [{
        toolName: "fs.readFile",
        args: { path: "../../etc/passwd" }
      }],
    });

    const { findings } = await scanSignals(n, [ToolArgsPathTraversalScanner], { mode: "audit", failFast: false });
    expect(findings.some(f => f.scanner === "tool_args_path_traversal")).toBe(true);
  });
});

