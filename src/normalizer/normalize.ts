import type { AuditRequest, NormalizedInput, SourcedText } from "./types.js";
import { canonicalizeJson } from "./canonicalize.js";

/**
 * Very lightweight language hint.
 * This is NOT a full language detector; it's just a cheap heuristic.
 */
function guessLang(text: string): "ko" | "en" | "unknown" {
  if (/[가-힣]/.test(text)) return "ko";
  if (/[a-zA-Z]/.test(text)) return "en";
  return "unknown";
}

/**
 * normalize()
 * - Converts raw AuditRequest into deterministic NormalizedInput.
 * - Preserves provenance if promptChunks exists (trim-only cleanup at this stage).
 */
export function normalize(req: AuditRequest): NormalizedInput {
  const toolCalls = req.toolCalls ?? [];
  const toolResults = req.toolResults ?? [];

  // Deterministic set of tool names
  const toolNames = Array.from(
    new Set([
      ...toolCalls.map(t => t.toolName),
      ...toolResults.map(t => t.toolName),
    ])
  ).sort();

  const prompt = req.prompt.trim();
  const responseText = req.responseText?.trim();

  // Preserve provenance if provided, while applying minimal cleanup (trim + drop empty)
  const chunks: SourcedText[] | undefined = req.promptChunks
    ? req.promptChunks
        .map(ch => ({ source: ch.source, text: ch.text.trim() }))
        .filter(ch => ch.text.length > 0)
    : undefined;

  return {
    requestId: req.requestId,
    canonical: {
      prompt,

      // Important: pass provenance forward if it exists
      ...(chunks && chunks.length ? { promptChunksCanonical: chunks } : {}),

      toolCallsJson: canonicalizeJson(toolCalls),
      toolResultsJson: canonicalizeJson(toolResults),
      ...(responseText !== undefined ? { responseText } : {}),
    },
    features: {
      hasToolCalls: toolCalls.length > 0,
      hasToolResults: toolResults.length > 0,
      toolNames,
      languageHint: guessLang(prompt),
      promptLength: prompt.length,
    },
    raw: req,
  };
}
