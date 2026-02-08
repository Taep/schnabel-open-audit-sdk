import type { NormalizedInput, TextView, TextViewSet, InputViews } from "../normalizer/types.js";

// Scan all views, skeleton last
export const VIEW_SCAN_ORDER: TextView[] = ["raw", "sanitized", "revealed", "skeleton"];

// Prefer human-readable views first; skeleton is a fallback for confusables
export const VIEW_PREFERENCE: TextView[] = ["revealed", "sanitized", "raw", "skeleton"];

function initViewSet(text: string): TextViewSet {
  return {
    raw: text,
    sanitized: text,
    revealed: text,
    // Default skeleton starts as raw; a skeleton-view scanner can later replace it.
    skeleton: text,
  };
}

/**
 * Ensure input.views exists.
 * - raw view is initialized from L1 canonical baseline (prompt + chunks)
 * - sanitized/revealed/skeleton start equal to raw and get updated by sanitizers/enrichers
 */
export function ensureViews(input: NormalizedInput): NormalizedInput {
  if (input.views) return input;

  const chunks = input.canonical.promptChunksCanonical ?? [];
  const views: InputViews = {
    prompt: initViewSet(input.canonical.prompt),
    ...(chunks.length
      ? { chunks: chunks.map(ch => ({ source: ch.source, views: initViewSet(ch.text) })) }
      : {}),
  };

  return { ...input, views };
}

export function pickPreferredView(matched: TextView[]): TextView {
  const s = new Set(matched);
  for (const v of VIEW_PREFERENCE) {
    if (s.has(v)) return v;
  }
  return "raw";
}
