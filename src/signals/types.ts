import type { InputSource, TextView } from "../normalizer/types.js";

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
export type ScannerKind = "sanitize" | "detect" | "enrich";

export interface FindingTarget {
  field: "prompt" | "promptChunk" | "response";
  view: TextView;            // NEW: raw/sanitized/revealed
  source?: InputSource;
  chunkIndex?: number;
}

export interface ScannerMetric {
  scanner: string;
  kind: ScannerKind;
  durationMs: number;
  findingCount: number;
  error?: string | undefined;
}

export interface Finding {
  id: string;
  kind: ScannerKind;
  scanner: string;

  // 0..1, higher means more suspicious
  score: number;

  risk: RiskLevel;
  tags: string[];
  summary: string;

  // Where the signal came from
  target: FindingTarget;

  // Minimal structured evidence (avoid dumping full text here)
  evidence?: Record<string, unknown>;
}

// ── Shared constants & helpers ──────────────────────────────────────

export const RISK_ORDER: readonly RiskLevel[] = ["none", "low", "medium", "high", "critical"];

export function riskAtOrAbove(a: RiskLevel, b: RiskLevel): boolean {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b);
}
