export interface AuditRequest {
  requestId: string;
  timestamp: number; // epoch ms
  actor?: { userId?: string; sessionId?: string; ip?: string };
  model?: { name?: string; provider?: string };

  prompt: string;

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

export interface NormalizedInput {
  requestId: string;
  canonical: {
    prompt: string;
    toolCallsJson: string;     // stable JSON string
    toolResultsJson: string;   // stable JSON string
    responseText?: string;
  };
  features: {
    hasToolCalls: boolean;
    hasToolResults: boolean;
    toolNames: string[];
    languageHint: "ko" | "en" | "unknown";
    promptLength: number;
  };
  raw: AuditRequest;
}
