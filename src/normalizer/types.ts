export type InputSource =
  | "user"
  | "system"
  | "developer"
  | "retrieval"
  | "tool"
  | "assistant"
  | "unknown";

export interface SourcedText {
  text: string;
  source: InputSource;
}

/**
 * Multi-view text representation:
 * - raw: L1 canonical baseline (pre-sanitize)
 * - sanitized: after normalization/cleanup (unicode/zero-width/bidi)
 * - revealed: sanitized + any revealed content (e.g., TAG decode)
 */
export type TextView = "raw" | "sanitized" | "revealed" | "skeleton";

export interface TextViewSet {
  raw: string;
  sanitized: string;
  revealed: string;
  skeleton: string;
}

export interface ChunkViews {
  source: InputSource;
  views: TextViewSet;
}

export interface InputViews {
  prompt: TextViewSet;
  chunks?: ChunkViews[] | undefined;
}

/**
 * AuditRequest
 * - Raw input schema coming from outside the SDK (apps/agents/services).
 */
export interface AuditRequest {
  requestId: string;
  timestamp: number; // epoch milliseconds
  actor?: { userId?: string; sessionId?: string; ip?: string } | undefined;
  model?: { name?: string; provider?: string } | undefined;

  /**
   * Primary prompt text (compat path).
   * Provenance-aware input should also provide promptChunks.
   */
  prompt: string;

  /**
   * Provenance-preserving chunks.
   * Keeps user/system/retrieval/tool sources separated for indirect-injection defenses.
   */
  promptChunks?: SourcedText[];

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
 * NormalizedInput
 * - Deterministic, comparison-friendly representation used by downstream layers.
 */
export interface NormalizedInput {
  requestId: string;

  canonical: {
    /**
     * Trimmed prompt string used for most rules/features.
     */
    prompt: string;

    /**
     * Optional: provenance-preserving canonical chunks.
     */
    promptChunksCanonical?: SourcedText[] | undefined;

    /**
     * Deterministic JSON strings for tool calls/results.
     */
    toolCallsJson: string;
    toolResultsJson: string;

    responseText?: string | undefined;
  };

  /**
   * Optional multi-view texts maintained by L2 sanitizers/detectors.
   * L1 normalize does not need to populate this.
   */
  views?: InputViews | undefined;

  features: {
    hasToolCalls: boolean;
    hasToolResults: boolean;
    toolNames: string[];
    languageHint: "ko" | "en" | "unknown";
    promptLength: number;
  };

  /**
   * Raw input is preserved for evidence/debugging.
   * Do NOT mutate this object downstream.
   */
  raw: AuditRequest;
}
