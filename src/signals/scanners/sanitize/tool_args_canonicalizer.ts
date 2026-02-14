import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { canonicalizeJson } from "../../../normalizer/canonicalize.js";
import { makeFindingId } from "../../util.js";

const INVISIBLE_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g;
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

function cleanText(s: string): {
  text: string;
  changed: boolean;
  removedInvisible: number;
  removedBidi: number;
  nfkc: boolean;
} {
  const before = s;

  const nfkcText = s.normalize("NFKC");
  const nfkc = nfkcText !== s;

  const beforeInv = nfkcText;
  const noInv = nfkcText.replace(INVISIBLE_REGEX, "");
  const removedInvisible = beforeInv.length - noInv.length;

  const beforeBidi = noInv;
  const noBidi = noInv.replace(BIDI_REGEX, "");
  const removedBidi = beforeBidi.length - noBidi.length;

  // NOTE: Do not trim. Tool args may be sensitive to whitespace.
  const text = noBidi;
  const changed = text !== before || nfkc || removedInvisible > 0 || removedBidi > 0;

  return { text, changed, removedInvisible, removedBidi, nfkc };
}

type Agg = {
  changedStrings: number;
  removedInvisible: number;
  removedBidi: number;
  nfkcApplied: boolean;
  changed: boolean;
};

function emptyAgg(): Agg {
  return { changedStrings: 0, removedInvisible: 0, removedBidi: 0, nfkcApplied: false, changed: false };
}

function mergeAgg(a: Agg, b: Agg): Agg {
  return {
    changedStrings: a.changedStrings + b.changedStrings,
    removedInvisible: a.removedInvisible + b.removedInvisible,
    removedBidi: a.removedBidi + b.removedBidi,
    nfkcApplied: a.nfkcApplied || b.nfkcApplied,
    changed: a.changed || b.changed,
  };
}

function sanitizeDeep(x: unknown): { value: unknown; agg: Agg } {
  if (typeof x === "string") {
    const r = cleanText(x);
    return {
      value: r.text,
      agg: {
        changedStrings: r.changed ? 1 : 0,
        removedInvisible: r.removedInvisible,
        removedBidi: r.removedBidi,
        nfkcApplied: r.nfkc,
        changed: r.changed,
      },
    };
  }

  if (Array.isArray(x)) {
    let agg = emptyAgg();
    let changed = false;
    const out = x.map((v) => {
      const r = sanitizeDeep(v);
      agg = mergeAgg(agg, r.agg);
      changed = changed || r.agg.changed;
      return r.value;
    });
    return { value: changed ? out : x, agg };
  }

  if (x && typeof x === "object") {
    let agg = emptyAgg();
    let changed = false;
    const obj = x as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(obj)) {
      const r = sanitizeDeep(v);
      agg = mergeAgg(agg, r.agg);
      changed = changed || r.agg.changed;
      out[k] = r.value;
    }
    return { value: changed ? out : x, agg };
  }

  return { value: x, agg: emptyAgg() };
}

function parseToolCallsJson(jsonText: string): Record<string, unknown>[] {
  try {
    const x: unknown = JSON.parse(jsonText);
    return Array.isArray(x) ? x as Record<string, unknown>[] : [];
  } catch {
    return [];
  }
}

export const ToolArgsCanonicalizerScanner: Scanner = {
  name: "tool_args_canonicalizer",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    if (!input.features.hasToolCalls) return { input, findings };

    const toolCalls = parseToolCallsJson(input.canonical.toolCallsJson);
    if (!toolCalls.length) return { input, findings };

    let total = emptyAgg();
    let anyToolArgsChanged = false;

    const outCalls = toolCalls.map((tc) => {
      const r = sanitizeDeep(tc["args"]);
      total = mergeAgg(total, r.agg);

      if (r.agg.changed) {
        anyToolArgsChanged = true;
        return { ...tc, args: r.value };
      }
      return tc;
    });

    if (anyToolArgsChanged) {
      const next: NormalizedInput = {
        ...input,
        canonical: { ...input.canonical, toolCallsJson: canonicalizeJson(outCalls) },
      };

      findings.push({
        id: makeFindingId(this.name, input.requestId, "tool_args_canonicalized"),
        kind: "sanitize",
        scanner: this.name,
        score: total.removedInvisible > 0 || total.removedBidi > 0 ? 0.45 : 0.2,
        risk: total.removedInvisible > 0 || total.removedBidi > 0 ? "medium" : "low",
        tags: ["tool", "canonicalization", "obfuscation"],
        summary:
          "Tool args were canonicalized (NFKC / zero-width / bidi) for downstream tool-boundary detectors.",
        target: { field: "promptChunk", view: "raw", source: "tool", chunkIndex: 0 },
        evidence: {
          toolCalls: toolCalls.length,
          changedStrings: total.changedStrings,
          removedInvisible: total.removedInvisible,
          removedBidi: total.removedBidi,
          nfkcApplied: total.nfkcApplied,
          outputField: "canonical.toolCallsJson",
        },
      });

      return { input: next, findings };
    }

    return { input, findings };
  },
};
