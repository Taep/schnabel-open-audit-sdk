import type { Scanner } from "../scanner.js";
import type { Finding, RiskLevel } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";
import { ensureViews } from "../../views.js";

/**
 * Zero-width / invisible chars commonly used for obfuscation.
 */
const INVISIBLE_REGEX = /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/g;

/**
 * Bidirectional controls used for visual spoofing.
 */
const BIDI_REGEX = /[\u202A-\u202E\u2066-\u2069]/g;

type SanitizeStats = {
  nfkcApplied: boolean;
  removedInvisibleCount: number;
  removedBidiCount: number;
  changed: boolean;
};

function sanitizeText(raw: string): { text: string; stats: SanitizeStats } {
  const before = raw;

  const nfkc = raw.normalize("NFKC");
  const nfkcApplied = nfkc !== raw;

  const beforeInv = nfkc;
  const noInv = nfkc.replace(INVISIBLE_REGEX, "");
  const removedInvisibleCount = beforeInv.length - noInv.length;

  const beforeBidi = noInv;
  const noBidi = noInv.replace(BIDI_REGEX, "");
  const removedBidiCount = beforeBidi.length - noBidi.length;

  const text = noBidi.trim();
  const changed =
    text !== before.trim() ||
    nfkcApplied ||
    removedInvisibleCount > 0 ||
    removedBidiCount > 0;

  return { text, stats: { nfkcApplied, removedInvisibleCount, removedBidiCount, changed } };
}

function riskFrom(stats: SanitizeStats): { risk: RiskLevel; score: number } {
  if (stats.removedBidiCount > 0) return { risk: "medium", score: 0.6 };
  if (stats.removedInvisibleCount > 0) return { risk: "medium", score: 0.5 };
  if (stats.nfkcApplied) return { risk: "low", score: 0.2 };
  return { risk: "none", score: 0.0 };
}

/**
 * UnicodeSanitizerScanner
 * - Updates canonical + views.sanitized/revealed
 * - Keeps views.raw unchanged
 */
export const UnicodeSanitizerScanner: Scanner = {
  name: "unicode_sanitizer",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const base = ensureViews(input);
    const views = base.views!;
    const findings: Finding[] = [];

    let changed = false;

    // Prompt
    const p0 = base.canonical.prompt;
    const p = sanitizeText(p0);
    if (p.stats.changed) {
      changed = true;

      // Update canonical to sanitized baseline (so detectors without views still benefit)
      // Also update views.sanitized and views.revealed
      views.prompt.sanitized = p.text;
      views.prompt.revealed = p.text;
    }

    // Chunks
    const chunks = base.canonical.promptChunksCanonical ?? [];
    const outChunks = chunks.map((ch, i) => {
      const res = sanitizeText(ch.text);
      if (res.stats.changed) {
        changed = true;
        const cv = views.chunks?.[i];
        if (cv) {
          cv.views.sanitized = res.text;
          cv.views.revealed = res.text;
        }
      }
      return { ...ch, text: res.text };
    });

    // Findings (only if suspicious)
    const pr = riskFrom(p.stats);
    if (p.stats.changed && pr.risk !== "none") {
      findings.push({
        id: makeFindingId(this.name, base.requestId, "prompt"),
        kind: this.kind,
        scanner: this.name,
        score: pr.score,
        risk: pr.risk,
        tags: ["unicode", "sanitization", "obfuscation"],
        summary: "Unicode sanitization applied (NFKC / zero-width / bidi).",
        target: { field: "prompt", view: "sanitized" },
        evidence: p.stats,
      });
    }

    for (let i = 0; i < chunks.length; i++) {
      const ch = chunks[i];
      if (!ch) continue;
      const res = sanitizeText(ch.text);
      const rr = riskFrom(res.stats);
      if (res.stats.changed && rr.risk !== "none") {
        findings.push({
          id: makeFindingId(this.name, base.requestId, `chunk:${i}:${ch.source}`),
          kind: this.kind,
          scanner: this.name,
          score: rr.score,
          risk: rr.risk,
          tags: ["unicode", "sanitization", "obfuscation"],
          summary: "Unicode sanitization applied to chunk (NFKC / zero-width / bidi).",
          target: { field: "promptChunk", view: "sanitized", source: ch.source, chunkIndex: i },
          evidence: res.stats,
        });
      }
    }

    if (!changed) return { input: base, findings };

    const updated: NormalizedInput = {
      ...base,
      canonical: {
        ...base.canonical,
        prompt: views.prompt.sanitized,
        ...(outChunks.length ? { promptChunksCanonical: outChunks } : {}),
      },
      features: {
        ...base.features,
        promptLength: views.prompt.revealed.length,
      },
      views,
    };

    return { input: updated, findings };
  },
};
