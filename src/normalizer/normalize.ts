import type { AuditRequest, NormalizedInput } from "./types.js";
import { canonicalizeJson } from "./canonicalize.js";

function guessLang(text: string): "ko" | "en" | "unknown" {
  if (/[가-힣]/.test(text)) return "ko";
  if (/[a-zA-Z]/.test(text)) return "en";
  return "unknown";
}

export function normalize(req: AuditRequest): NormalizedInput {
  const toolCalls = req.toolCalls ?? [];
  const toolResults = req.toolResults ?? [];

  const toolNames = Array.from(
    new Set([
      ...toolCalls.map(t => t.toolName),
      ...toolResults.map(t => t.toolName),
    ])
  ).sort(); // 결정론 위해 sort

  const prompt = req.prompt.trim();
  const responseText = req.responseText?.trim();

  return {
    requestId: req.requestId,
    canonical: {
      prompt,
      toolCallsJson: canonicalizeJson(toolCalls),
      toolResultsJson: canonicalizeJson(toolResults),
      responseText,
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
