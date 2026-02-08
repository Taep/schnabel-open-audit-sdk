import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { ensureViews } from "../../views.js";
import { makeFindingId } from "../../util.js";

/**
 * SeparatorCollapseScanner
 * - Collapses common separators used to split keywords:
 *   | . _ - +
 * - Applies to views.sanitized and views.revealed (raw remains unchanged)
 * - Optionally updates canonical prompt/chunks to the collapsed text so non-view scanners also benefit.
 *
 * Design goal:
 * - Make obfuscated keywords detectable (e.g., "s.y.s.t.e.m" -> "system")
 * - Keep it conservative: only remove separators around letters/digits.
 */

const SEP_CLASS = `[|._\\-\\+]`;

// Remove separators between letters/digits (including Hangul via \p{L})
const BETWEEN = new RegExp(`(?<=[\\p{L}\\p{N}])${SEP_CLASS}+(?=[\\p{L}\\p{N}])`, "gu");
// Remove leading separators right before letters/digits at token start
const LEADING = new RegExp(`(?:(?<=\\s)|^)${SEP_CLASS}+(?=[\\p{L}\\p{N}])`, "gu");
// Remove trailing separators right after letters/digits at token end
const TRAILING = new RegExp(`(?<=[\\p{L}\\p{N}])${SEP_CLASS}+(?=\\s|$)`, "gu");

type CollapseStats = {
  removedBetween: number;
  removedLeading: number;
  removedTrailing: number;
  changed: boolean;
};

function sumMatchLengths(s: string, re: RegExp): number {
  const m = s.match(re);
  return m ? m.reduce((acc, x) => acc + x.length, 0) : 0;
}


function collapseSeparators(text: string): { text: string; stats: CollapseStats } {
  let s = (text ?? "").toString();

  const removedBetween = sumMatchLengths(s, BETWEEN);
  s = s.replace(BETWEEN, "");

  const removedLeading = sumMatchLengths(s, LEADING);
  s = s.replace(LEADING, "");

  const removedTrailing = sumMatchLengths(s, TRAILING);
  s = s.replace(TRAILING, "");

  // Normalize whitespace after collapsing
  const beforeTrim = s;
  s = s.replace(/\s{2,}/g, " ").trim();

  const changed = (s !== (text ?? "").toString().trim()) || (beforeTrim !== s);
  return {
    text: s,
    stats: { removedBetween, removedLeading, removedTrailing, changed },
  };
}

function riskScore(stats: CollapseStats): { risk: Finding["risk"]; score: number } {
  const removed = stats.removedBetween + stats.removedLeading + stats.removedTrailing;
  if (removed >= 6) return { risk: "medium", score: 0.55 };
  if (removed >= 2) return { risk: "low", score: 0.25 };
  if (removed >= 1) return { risk: "low", score: 0.2 };
  return { risk: "none", score: 0.0 };
}

export const SeparatorCollapseScanner: Scanner = {
  name: "separator_collapse",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const base = ensureViews(input);
    const findings: Finding[] = [];

    let anyChanged = false;

    // 1) Prompt views
    {
      const v = base.views!.prompt;

      const s1 = collapseSeparators(v.sanitized);
      const s2 = collapseSeparators(v.revealed);

      if (s1.stats.changed || s2.stats.changed) {
        anyChanged = true;
        v.sanitized = s1.text;
        v.revealed = s2.text;

        const rs = riskScore({
          removedBetween: s1.stats.removedBetween + s2.stats.removedBetween,
          removedLeading: s1.stats.removedLeading + s2.stats.removedLeading,
          removedTrailing: s1.stats.removedTrailing + s2.stats.removedTrailing,
          changed: true,
        });

        if (rs.risk !== "none") {
          findings.push({
            id: makeFindingId(this.name, base.requestId, "prompt"),
            kind: this.kind,
            scanner: this.name,
            score: rs.score,
            risk: rs.risk,
            tags: ["obfuscation", "separator_collapse"],
            summary: "Collapsed separator-based obfuscation in prompt (e.g., dots/pipes between letters).",
            target: { field: "prompt", view: "sanitized" },
            evidence: {
              removedBetween: s1.stats.removedBetween + s2.stats.removedBetween,
              removedLeading: s1.stats.removedLeading + s2.stats.removedLeading,
              removedTrailing: s1.stats.removedTrailing + s2.stats.removedTrailing,
            },
          });
        }
      }
    }

    // 2) Chunk views
    const chunkViews = base.views!.chunks ?? [];
    for (let i = 0; i < chunkViews.length; i++) {
      const cv = chunkViews[i];
      if (!cv) continue;
      const v = cv.views;

      const s1 = collapseSeparators(v.sanitized);
      const s2 = collapseSeparators(v.revealed);

      if (s1.stats.changed || s2.stats.changed) {
        anyChanged = true;
        v.sanitized = s1.text;
        v.revealed = s2.text;

        const rs = riskScore({
          removedBetween: s1.stats.removedBetween + s2.stats.removedBetween,
          removedLeading: s1.stats.removedLeading + s2.stats.removedLeading,
          removedTrailing: s1.stats.removedTrailing + s2.stats.removedTrailing,
          changed: true,
        });

        if (rs.risk !== "none") {
          findings.push({
            id: makeFindingId(this.name, base.requestId, `chunk:${i}:${cv.source}`),
            kind: this.kind,
            scanner: this.name,
            score: rs.score,
            risk: rs.risk,
            tags: ["obfuscation", "separator_collapse"],
            summary: "Collapsed separator-based obfuscation in chunk (e.g., dots/pipes between letters).",
            target: { field: "promptChunk", view: "sanitized", source: cv.source, chunkIndex: i },
            evidence: {
              removedBetween: s1.stats.removedBetween + s2.stats.removedBetween,
              removedLeading: s1.stats.removedLeading + s2.stats.removedLeading,
              removedTrailing: s1.stats.removedTrailing + s2.stats.removedTrailing,
            },
          });
        }
      }
    }

    // 3) Optionally update canonical fields to match revealed text
    // This helps any detector that still uses canonical instead of views.
    if (anyChanged) {
      const promptCollapsed = base.views!.prompt.revealed;

      const canonicalChunks = base.canonical.promptChunksCanonical ?? [];
      const updatedChunks = canonicalChunks.length
        ? canonicalChunks.map((ch, i) => {
            const cv = base.views!.chunks?.[i];
            const nextText = cv?.views?.revealed ?? ch.text;
            return { ...ch, text: nextText };
          })
        : undefined;

      const updated: NormalizedInput = {
        ...base,
        canonical: {
          ...base.canonical,
          prompt: promptCollapsed,
          ...(updatedChunks !== undefined && updatedChunks.length > 0 ? { promptChunksCanonical: updatedChunks } : {}),
        },
        features: {
          ...base.features,
          promptLength: promptCollapsed.length,
        },
      };

      return { input: updated, findings };
    }

    return { input: base, findings };
  },
};
