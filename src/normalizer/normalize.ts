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
const MAX_REQUEST_ID_LEN = 255;
const MAX_PROMPT_LEN = 1_048_576; // 1 MB

function validateRequest(req: AuditRequest): void {
  if (!req || typeof req !== "object") {
    throw new Error("normalize: request must be a non-null object");
  }
  if (typeof req.requestId !== "string" || req.requestId.length === 0) {
    throw new Error("normalize: requestId must be a non-empty string");
  }
  if (req.requestId.length > MAX_REQUEST_ID_LEN) {
    throw new Error(`normalize: requestId exceeds max length (${MAX_REQUEST_ID_LEN})`);
  }
  if (typeof req.timestamp !== "number" || !Number.isFinite(req.timestamp) || req.timestamp < 0) {
    throw new Error("normalize: timestamp must be a finite non-negative number");
  }
  if (typeof req.prompt !== "string") {
    throw new Error("normalize: prompt must be a string");
  }
  if (req.prompt.length > MAX_PROMPT_LEN) {
    throw new Error(`normalize: prompt exceeds max length (${MAX_PROMPT_LEN})`);
  }
}

export function normalize(req: AuditRequest): NormalizedInput {
  validateRequest(req);

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
