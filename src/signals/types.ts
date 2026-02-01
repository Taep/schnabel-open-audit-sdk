import type { InputSource } from "../normalizer/types.js";

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export type ScannerKind = "sanitize" | "detect" | "enrich";

export interface FindingTarget {
  field: "prompt" | "promptChunk";
  source?: InputSource;
  chunkIndex?: number;
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
