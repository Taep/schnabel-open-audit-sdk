import type { Scanner } from "../scanner.js";
import type { Finding, RiskLevel } from "../../types.js";
import type { NormalizedInput, SourcedText } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

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
  let s = raw;
  const before = s;

  // 1) NFKC normalization
  const nfkc = s.normalize("NFKC");
  const nfkcApplied = nfkc !== s;
  s = nfkc;

  // 2) Remove invisible/zero-width chars
  const beforeInv = s;
  s = s.replace(INVISIBLE_REGEX, "");
  const removedInvisibleCount = beforeInv.length - s.length;

  // 3) Remove bidi controls
  const beforeBidi = s;
  s = s.replace(BIDI_REGEX, "");
  const removedBidiCount = beforeBidi.length - s.length;

  // 4) Final trim to avoid accidental leading/trailing whitespace after removals
  s = s.trim();

  const changed =
    s !== before ||
    nfkcApplied ||
    removedInvisibleCount > 0 ||
    removedBidiCount > 0;

  return {
    text: s,
    stats: {
      nfkcApplied,
      removedInvisibleCount,
      removedBidiCount,
      changed,
    },
  };
}

function riskFrom(stats: SanitizeStats): { risk: RiskLevel; score: number } {
  // Conservative defaults: obfuscation signals are suspicious, but not always "high".
  if (stats.removedBidiCount > 0) return { risk: "medium", score: 0.6 };
  if (stats.removedInvisibleCount > 0) return { risk: "medium", score: 0.5 };
  if (stats.nfkcApplied) return { risk: "low", score: 0.2 };
  return { risk: "none", score: 0.0 };
}

/**
 * UnicodeSanitizerScanner
 * - Mutates canonical prompt + promptChunksCanonical (if present) by applying:
 *   - NFKC normalization
 *   - removal of common invisible/zero-width chars
 *   - removal of bidi controls
 * - Emits Findings only when changes are made (or suspicious transforms detected).
 */
export const UnicodeSanitizerScanner: Scanner = {
  name: "unicode_sanitizer",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    // Sanitize canonical prompt
    const p = sanitizeText(input.canonical.prompt);
    const pRisk = riskFrom(p.stats);

    if (p.stats.changed && pRisk.risk !== "none") {
      findings.push({
        id: makeFindingId(this.name, input.requestId, `prompt`),
        kind: this.kind,
        scanner: this.name,
        score: pRisk.score,
        risk: pRisk.risk,
        tags: ["unicode", "sanitization", "obfuscation"],
        summary: "Unicode sanitization applied to canonical prompt.",
        target: { field: "prompt" },
        evidence: {
          nfkcApplied: p.stats.nfkcApplied,
          removedInvisibleCount: p.stats.removedInvisibleCount,
          removedBidiCount: p.stats.removedBidiCount,
        },
      });
    }

    // Sanitize provenance chunks if present
    const inChunks = input.canonical.promptChunksCanonical ?? [];
    const outChunks: SourcedText[] = [];
    let anyChunkChanged = false;

    for (let i = 0; i < inChunks.length; i++) {
      const ch = inChunks[i];
      const s = sanitizeText(ch.text);
      const r = riskFrom(s.stats);

      outChunks.push({ source: ch.source, text: s.text });

      if (s.stats.changed) anyChunkChanged = true;

      if (s.stats.changed && r.risk !== "none") {
        findings.push({
          id: makeFindingId(this.name, input.requestId, `chunk:${i}:${ch.source}`),
          kind: this.kind,
          scanner: this.name,
          score: r.score,
          risk: r.risk,
          tags: ["unicode", "sanitization", "obfuscation"],
          summary: "Unicode sanitization applied to provenance chunk.",
          target: { field: "promptChunk", source: ch.source, chunkIndex: i },
          evidence: {
            nfkcApplied: s.stats.nfkcApplied,
            removedInvisibleCount: s.stats.removedInvisibleCount,
            removedBidiCount: s.stats.removedBidiCount,
          },
        });
      }
    }

    // Build updated input if anything changed; otherwise keep original reference.
    const promptChanged = p.text !== input.canonical.prompt;
    const chunksChanged = anyChunkChanged;

    if (!promptChanged && !chunksChanged) {
      return { input, findings };
    }

    const updated: NormalizedInput = {
      ...input,
      canonical: {
        ...input.canonical,
        prompt: p.text,
        promptChunksCanonical: inChunks.length ? outChunks : undefined,
      },
      features: {
        ...input.features,
        // Keep features consistent with the new canonical prompt
        promptLength: p.text.length,
      },
    };

    return { input: updated, findings };
  },
};
