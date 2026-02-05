import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

function walkStrings(x: unknown, cb: (value: string, path: string) => void, path = "$"): void {
  if (typeof x === "string") return cb(x, path);
  if (Array.isArray(x)) {
    for (let i = 0; i < x.length; i++) walkStrings(x[i], cb, `${path}[${i}]`);
    return;
  }
  if (x && typeof x === "object") {
    for (const [k, v] of Object.entries(x as Record<string, unknown>)) {
      walkStrings(v, cb, `${path}.${k}`);
    }
  }
}

function looksLikePath(s: string): boolean {
  const t = s.trim();
  return t.includes("/") || t.includes("\\") || t.startsWith("~") || t.startsWith(".");
}

function hasTraversal(s: string): boolean {
  const t = s.toLowerCase();
  return (
    /(^|[\\/])\.\.([\\/]|$)/.test(t) ||
    /%2e%2e/i.test(t) ||
    /%2f|%5c/i.test(t)
  );
}

function isSensitiveFile(s: string): boolean {
  const t = s.toLowerCase();
  const patterns = [
    "/etc/passwd", "/etc/shadow", "/proc/", "/sys/", "/root/",
    ".ssh", "id_rsa", ".env",
    "c:\\windows\\system32", "c:\\users\\", "c:\\windows\\",
  ];
  return patterns.some(p => t.includes(p));
}

/**
 * Detect traversal/sensitive paths in toolCalls args.
 */
export const ToolArgsPathTraversalScanner: Scanner = {
  name: "tool_args_path_traversal",
  kind: "detect",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];
    const toolCalls = input.raw.toolCalls ?? [];
    if (!toolCalls.length) return { input, findings };

    for (let i = 0; i < toolCalls.length; i++) {
      const tc: any = toolCalls[i];
      const toolName = String(tc?.toolName ?? "unknown_tool");
      const args = tc?.args;

      walkStrings(args, (val, p) => {
        if (!looksLikePath(val)) return;

        const traversal = hasTraversal(val);
        const sensitive = isSensitiveFile(val);

        if (!traversal && !sensitive) return;

        const risk = sensitive ? "high" : "medium";
        const score = sensitive ? 0.8 : 0.6;

        findings.push({
          id: makeFindingId("tool_args_path_traversal", input.requestId, `${toolName}:${i}:${p}`),
          kind: "detect",
          scanner: "tool_args_path_traversal",
          score,
          risk,
          tags: ["tool", "path", traversal ? "traversal" : "sensitive_path"],
          summary: sensitive
            ? "Sensitive file path reference detected in tool args."
            : "Path traversal pattern detected in tool args.",
          target: { field: "promptChunk", view: "raw", source: "tool", chunkIndex: i },
          evidence: {
            toolName,
            argPath: p,
            value: val,
            traversal,
            sensitive,
          },
        });
      });
    }

    return { input, findings };
  },
};
