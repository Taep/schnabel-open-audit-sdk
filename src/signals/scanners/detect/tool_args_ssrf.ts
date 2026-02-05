import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

import net from "node:net";

function walkStrings(x: unknown, cb: (value: string, path: string) => void, path = "$"): void {
  if (typeof x === "string") {
    cb(x, path);
    return;
  }
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

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(x => Number(x));
  if (parts.length !== 4 || parts.some(n => !Number.isFinite(n))) return false;

  const [a, b] = parts;

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

function looksLikeUrl(s: string): boolean {
  const t = s.trim().toLowerCase();
  return t.startsWith("http://") || t.startsWith("https://");
}

export const ToolArgsSSRFScanner: Scanner = {
  name: "tool_args_ssrf",
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
        if (!looksLikeUrl(val)) return;

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
