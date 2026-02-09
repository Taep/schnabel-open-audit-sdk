import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

interface ToolCallEntry { toolName: string; args: unknown; }

function getToolCalls(input: NormalizedInput): ToolCallEntry[] {
  try {
    const x: unknown = JSON.parse(input.canonical.toolCallsJson);
    if (Array.isArray(x)) return x as ToolCallEntry[];
  } catch {
    /* canonical parse failed; fall back to raw */
  }
  return input.raw.toolCalls ?? [];
}

const WALK_MAX_DEPTH = 32;

function walkStrings(
  x: unknown,
  cb: (value: string, path: string) => void,
  path = "$",
  depth = 0
): void {
  if (depth > WALK_MAX_DEPTH) return;
  if (typeof x === "string") return cb(x, path);
  if (Array.isArray(x)) {
    for (let i = 0; i < x.length; i++) walkStrings(x[i], cb, `${path}[${i}]`, depth + 1);
    return;
  }
  if (x && typeof x === "object") {
    for (const [k, v] of Object.entries(x as Record<string, unknown>)) {
      walkStrings(v, cb, `${path}.${k}`, depth + 1);
    }
  }
}

function looksLikePath(s: string): boolean {
  const t = s.trim();
  return t.includes("/") || t.includes("\\") || t.startsWith("~") || t.startsWith(".");
}

function hasTraversal(s: string): boolean {
  // Double URL-decode to catch encoded variants like %252e%252e
  let decoded = s;
  try { decoded = decodeURIComponent(decoded); } catch { /* not encoded */ }
  try { decoded = decodeURIComponent(decoded); } catch { /* not double-encoded */ }

  // Normalize backslash → forward slash for Windows path support
  const normalized = decoded.replace(/\\/g, "/").toLowerCase();

  return (
    /(^|\/)\.\.(\/|$)/.test(normalized) ||
    /%2e%2e/i.test(s) ||
    /%2f|%5c/i.test(s)
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
    const toolCalls = getToolCalls(input);
    if (!toolCalls.length) return { input, findings };

    for (let i = 0; i < toolCalls.length; i++) {
      const tc = toolCalls[i]!;
      const toolName = String(tc.toolName ?? "unknown_tool");
      const args = tc.args;

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
