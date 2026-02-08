import type { Finding, RiskLevel } from "../signals/types.js";

export type VerdictAction =
  | "allow"
  | "allow_with_warning"
  | "challenge"
  | "block";

export interface PolicyDecision {
  policyId: string;
  action: VerdictAction;
  risk: RiskLevel;
  confidence: number; // 0..1
  reasons: string[];
  findingIds: string[];
  stats: {
    totalFindings: number;
    maxScore: number;
    scoreSum: number;
    byRisk: Record<RiskLevel, number>;
  };
}

export interface PolicyConfig {
  policyId: string;
  blockAt: RiskLevel;     // default: critical
  challengeAt: RiskLevel; // default: high
  challengeScoreSumAt: number; // default: 0.9
  warnScoreSumAt: number;      // default: 0.4
  maxReasons: number;          // default: 5
}

const DEFAULT_CONFIG: PolicyConfig = {
  policyId: "policy-v0",
  blockAt: "critical",
  challengeAt: "high",
  challengeScoreSumAt: 0.9,
  warnScoreSumAt: 0.4,
  maxReasons: 5,
};

const RISK_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

function maxRisk(findings: Finding[]): RiskLevel {
  let maxIdx = 0;
  for (const f of findings) {
    const idx = RISK_ORDER.indexOf(f.risk);
    if (idx > maxIdx) maxIdx = idx;
  }
  return RISK_ORDER[maxIdx] ?? "none";
}

function riskMeetsOrExceeds(risk: RiskLevel, threshold: RiskLevel): boolean {
  return RISK_ORDER.indexOf(risk) >= RISK_ORDER.indexOf(threshold);
}

function buildStats(findings: Finding[]) {
  const byRisk: Record<RiskLevel, number> = {
    none: 0,
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  };

  let maxScore = 0;
  let scoreSum = 0;

  for (const f of findings) {
    byRisk[f.risk] += 1;
    if (f.score > maxScore) maxScore = f.score;
    scoreSum += f.score;
  }

  return {
    totalFindings: findings.length,
    maxScore,
    scoreSum,
    byRisk,
  };
}

function defaultConfidence(risk: RiskLevel): number {
  switch (risk) {
    case "critical": return 0.9;
    case "high":     return 0.75;
    case "medium":   return 0.6;
    case "low":      return 0.55;
    case "none":     return 0.7;
  }
}

/**
 * Named export is important:
 * run_audit.ts imports it via: import { evaluatePolicy } from "../policy/evaluate.js"
 */
export function evaluatePolicy(
  findings: Finding[],
  partial?: Partial<PolicyConfig>
): PolicyDecision {
  const cfg: PolicyConfig = { ...DEFAULT_CONFIG, ...(partial ?? {}) };

  const stats = buildStats(findings);
  const risk = maxRisk(findings);

  const sorted = [...findings].sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    return RISK_ORDER.indexOf(b.risk) - RISK_ORDER.indexOf(a.risk);
  });

  const reasons = sorted.slice(0, cfg.maxReasons).map(f => {
    const where =
  f.target.field === "prompt"
    ? `prompt@${f.target.view}`
    : `chunk(${f.target.source ?? "unknown"}#${f.target.chunkIndex ?? -1})@${f.target.view}`;


    return `[${f.risk.toUpperCase()}|${f.scanner}] ${where}: ${f.summary}`;
  });

  const findingIds = findings.map(f => f.id);

  let action: VerdictAction = "allow";

  if (riskMeetsOrExceeds(risk, cfg.blockAt)) {
    action = "block";
  } else if (riskMeetsOrExceeds(risk, cfg.challengeAt) || stats.scoreSum >= cfg.challengeScoreSumAt) {
    action = "challenge";
  } else if (stats.scoreSum >= cfg.warnScoreSumAt) {
    action = "allow_with_warning";
  }

  return {
    policyId: cfg.policyId,
    action,
    risk,
    confidence: defaultConfidence(risk),
    reasons,
    findingIds,
    stats,
  };
}
