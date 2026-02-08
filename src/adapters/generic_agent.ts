import type { AuditRequest, InputSource, SourcedText } from "../normalizer/types.js";

/**
 * AgentIngressEvent
 * - A generic example schema of an external agent/runtime event.
 * - L0 Adapter converts this into the SDK's internal AuditRequest.
 *
 * NOTE:
 * - Adjust this interface to match your real upstream payload when you integrate.
 * - This file is intentionally generic to avoid confusion with any specific vendor/runtime.
 */
export interface AgentIngressEvent {
  requestId: string;
  timestamp: number; // epoch ms

  actor?: { userId?: string; sessionId?: string; ip?: string };
  model?: { name?: string; provider?: string };

  /**
   * Primary user prompt text.
   * Keep raw-ish here; L1 normalize will handle deterministic trimming/canonicalization.
   */
  userPrompt: string;

  /** Optional higher-priority instruction texts */
  systemPrompt?: string;
  developerPrompt?: string;

  /**
   * Optional retrieval/RAG documents.
   * Provenance (source="retrieval") is preserved for indirect-injection defenses.
   */
  retrievalDocs?: Array<{
    text: string;
    docId?: string;
    url?: string;
    score?: number;
  }>;

  toolCalls?: Array<{
    toolName: string;
    args: unknown;
  }>;

  toolResults?: Array<{
    toolName: string;
    ok: boolean;
    result: unknown;
    latencyMs?: number;
  }>;

  responseText?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Build provenance-aware chunks with minimal assumptions.
 * - Keeps sources separated (system/developer/user/retrieval)
 * - Avoids heavy mutation at L0; L1 normalize performs deterministic cleanup.
 */
function buildPromptChunks(e: AgentIngressEvent): SourcedText[] | undefined {
  const chunks: SourcedText[] = [];

  const push = (source: InputSource, text?: string) => {
    if (typeof text !== "string") return;

    // Keep text mostly raw at L0; only drop chunks that are effectively empty.
    if (text.trim().length === 0) return;

    chunks.push({ source, text });
  };

  // Typical priority order: system -> developer -> user -> retrieval
  push("system", e.systemPrompt);
  push("developer", e.developerPrompt);
  push("user", e.userPrompt);

  for (const d of e.retrievalDocs ?? []) {
    push("retrieval", d.text);
  }

  return chunks.length ? chunks : undefined;
}

/**
 * L0 Adapter: Convert AgentIngressEvent -> AuditRequest
 * - Preserves provenance via promptChunks
 * - Keeps compat `prompt` as the raw userPrompt
 * - Passes toolCalls/toolResults through without mutation
 */
export function fromAgentIngressEvent(e: AgentIngressEvent): AuditRequest {
  return {
    requestId: e.requestId,
    timestamp: e.timestamp,
    ...(e.actor !== undefined ? { actor: e.actor } : {}),
    ...(e.model !== undefined ? { model: e.model } : {}),

    // Compat prompt: keep the user's raw prompt string.
    prompt: e.userPrompt,

    // Provenance-preserving chunks: system/developer/user/retrieval separated.
    ...((): { promptChunks?: SourcedText[] } => {
      const chunks = buildPromptChunks(e);
      return chunks ? { promptChunks: chunks } : {};
    })(),

    ...(e.toolCalls !== undefined ? { toolCalls: e.toolCalls } : {}),
    ...(e.toolResults !== undefined ? { toolResults: e.toolResults } : {}),
    ...(e.responseText !== undefined ? { responseText: e.responseText } : {}),

    // Keep upstream metadata. Put retrieval doc meta here (not the full text).
    metadata: {
      ...(e.metadata ?? {}),
      retrievalDocsMeta: (e.retrievalDocs ?? []).map(d => ({
        docId: d.docId,
        url: d.url,
        score: d.score,
      })),
    },
  };
}
