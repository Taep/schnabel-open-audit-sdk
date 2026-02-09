import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

import net from "node:net";

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
  if (typeof x === "string") {
    cb(x, path);
    return;
  }
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

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(x => Number(x));
  if (parts.length !== 4 || parts.some(n => !Number.isFinite(n))) return false;

  const a = parts[0];
  const b = parts[1];
  if (a === undefined || b === undefined) return false;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const s = ip.toLowerCase();
  if (s === "::1" || s === "::") return true;
  if (s.startsWith("fe80:")) return true; // link-local
  if (s.startsWith("fc") || s.startsWith("fd")) return true; // ULA fc00::/7
  return false;
}

function isSuspiciousHostname(host: string): boolean {
  const h = host.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local")) return true;
  if (h === "metadata.google.internal") return true;
  if (h === "169.254.169.254") return true;
  return false;
}

/** Schemes we consider for SSRF / internal access. Includes dangerous schemes. */
const URL_SCHEMES = [
  "http://",
  "https://",
  "file://",
  "gopher://",
  "dict://",
  "ftp://",
  "sftp://",
  "ldap://",
  "ldaps://",
  "data:",
  "netdoc://",
];

function looksLikeUrl(s: string): boolean {
  const t = s.trim().toLowerCase();
  return URL_SCHEMES.some((scheme) => t.startsWith(scheme));
}

function isDangerousScheme(urlStr: string): { hit: boolean; reason: string } {
  const t = urlStr.trim().toLowerCase();
  if (t.startsWith("file://")) return { hit: true, reason: "file:// scheme (local file access)" };
  if (t.startsWith("gopher://")) return { hit: true, reason: "gopher:// scheme (internal network)" };
  if (t.startsWith("dict://")) return { hit: true, reason: "dict:// scheme (internal network)" };
  if (t.startsWith("ldap://") || t.startsWith("ldaps://")) return { hit: true, reason: "ldap(s):// scheme (directory injection)" };
  if (t.startsWith("data:")) return { hit: true, reason: "data: scheme (embedded payload)" };
  if (t.startsWith("netdoc://")) return { hit: true, reason: "netdoc:// scheme (internal resource)" };
  return { hit: false, reason: "" };
}

export const ToolArgsSSRFScanner: Scanner = {
  name: "tool_args_ssrf",
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
        if (!looksLikeUrl(val)) return;

        const schemeCheck = isDangerousScheme(val);
        if (schemeCheck.hit) {
          findings.push({
            id: makeFindingId(this.name, input.requestId, `${toolName}:${i}:${p}`),
            kind: "detect",
            scanner: this.name,
            score: 0.9,
            risk: "high",
            tags: ["tool", "ssrf", "dangerous_scheme"],
            summary: "Dangerous URL scheme in tool args (e.g. file/gopher/dict).",
            target: { field: "promptChunk", view: "raw", source: "tool", chunkIndex: i },
            evidence: {
              toolName,
              argPath: p,
              url: val,
              reason: schemeCheck.reason,
            },
          });
          return;
        }

        let u: URL;
        try {
          u = new URL(val);
        } catch {
          return;
        }

        const host = u.hostname;
        const ipKind = net.isIP(host);

        let hit = false;
        let reason = "";

        if (ipKind === 4 && isPrivateIPv4(host)) {
          hit = true;
          reason = "private/loopback/link-local IPv4";
        } else if (ipKind === 6 && isPrivateIPv6(host)) {
          hit = true;
          reason = "private/loopback/link-local IPv6";
        } else if (isSuspiciousHostname(host)) {
          hit = true;
          reason = "suspicious internal hostname/metadata";
        }

        if (hit) {
          findings.push({
            id: makeFindingId(this.name, input.requestId, `${toolName}:${i}:${p}`),
            kind: "detect",
            scanner: this.name,
            score: 0.85,
            risk: "high",
            tags: ["tool", "ssrf", "network"],
            summary: "Potential SSRF / internal network access via tool args URL.",
            target: { field: "promptChunk", view: "raw", source: "tool", chunkIndex: i },
            evidence: {
              toolName,
              argPath: p,
              url: val,
              host,
              reason,
            },
          });
        }
      });
    }

    return { input, findings };
  },
};
