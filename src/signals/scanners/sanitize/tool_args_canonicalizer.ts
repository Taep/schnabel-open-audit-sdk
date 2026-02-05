import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

const INVISIBLE_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g;
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

function cleanText(s: string): { text: string; changed: boolean; removedInvisible: number; removedBidi: number; nfkc: boolean } {
  const before = s;
  const nfkcText = s.normalize("NFKC");
  const nfkc = nfkcText !== s;

  const beforeInv = nfkcText;
  const noInv = nfkcText.replace(INVISIBLE_REGEX, "");
  const removedInvisible = beforeInv.length - noInv.length;

  const beforeBidi = noInv;
  const noBidi = noInv.replace(BIDI_REGEX, "");
  const removedBidi = beforeBidi.length - noBidi.length;

  const text = noBidi.trim();
  const changed = text !== before.trim() || nfkc || removedInvisible > 0 || removedBidi > 0;

  return { text, changed, removedInvisible, removedBidi, nfkc };
}

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

export const ToolArgsCanonicalizerScanner: Scanner = {
  name: "tool_args_canonicalizer",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];
    const toolCalls = input.raw.toolCalls ?? [];
    if (!toolCalls.length) return { input, findings };

    let totalChanged = 0;
    let totalInv = 0;
    let totalBidi = 0;
    let anyNfkc = false;

    for (let i = 0; i < toolCalls.length; i++) {
      const tc: any = toolCalls[i];
      const args = tc?.args;

      walkStrings(args, (val) => {
        const res = cleanText(val);
        if (res.changed) {
          totalChanged++;
          totalInv += res.removedInvisible;
          totalBidi += res.removedBidi;
          anyNfkc = anyNfkc || res.nfkc;
        }
      });
    }

    if (totalChanged > 0) {
      findings.push({
        id: makeFindingId(this.name, input.requestId, "tool_args_cleaned"),
        kind: "sanitize",
        scanner: this.name,
        score: totalInv > 0 || totalBidi > 0 ? 0.45 : 0.2,
        risk: totalInv > 0 || totalBidi > 0 ? "medium" : "low",
        tags: ["tool", "canonicalization", "obfuscation"],
        summary: "Tool args contain obfuscation patterns (NFKC/zero-width/bidi). Consider scanning on a canonicalized view.",
        target: { field: "promptChunk", view: "raw", source: "tool", chunkIndex: 0 },
        evidence: {
          toolCalls: toolCalls.length,
          changedStrings: totalChanged,
          removedInvisible: totalInv,
          removedBidi: totalBidi,
          nfkcApplied: anyNfkc,
        },
      });
    }

    return { input, findings };
  },
};
