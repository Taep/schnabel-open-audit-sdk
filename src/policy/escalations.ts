import type { PolicyDecision } from "./evaluate.js";
import type { Finding, RiskLevel } from "../signals/types.js";
import type { HistoryTurnV0 } from "../core/history_store.js";

const RISK_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

function riskAtOrAbove(a: RiskLevel, b: RiskLevel): boolean {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b);
}

function cloneDecision(d: PolicyDecision): PolicyDecision {
  return {
    ...d,
    reasons: [...(d.reasons ?? [])],
    findingIds: [...(d.findingIds ?? [])],
    stats: { ...(d.stats as any) },
  };
}

function hasDetectFinding(findings: Finding[], scannerName: string, minRisk: RiskLevel): boolean {
  return findings.some(
    f => f.kind === "detect" && f.scanner === scannerName && riskAtOrAbove(f.risk, minRisk)
  );
}

function countRecentScannerHits(
  recent: HistoryTurnV0[],
  scannerName: string,
  window: number
): number {
  const turns = recent.slice(Math.max(0, recent.length - window));
  let c = 0;
  for (const t of turns) {
    if (t.detectScanners?.includes(scannerName)) c += 1;
  }
  return c;
}

function countRecentAnyScannerHits(
  recent: HistoryTurnV0[],
  scannerNames: string[],
  window: number
): number {
  const turns = recent.slice(Math.max(0, recent.length - window));
  let c = 0;
  for (const t of turns) {
    if (!t.detectScanners?.length) continue;
    if (scannerNames.some(s => t.detectScanners!.includes(s))) c += 1;
  }
  return c;
}

/**
 * Policy escalations:
 * (1) Immediate: tool_result_fact_mismatch(high) => BLOCK
 * (2) History-based repetition:
 *     - if contradiction-related detectors appear repeatedly in session, escalate:
 *         >=2 occurrences in window => CHALLENGE (at least)
 *         >=3 occurrences in window => BLOCK
 */
export function applyPolicyEscalations(args: {
  base: PolicyDecision;
  findings: Finding[];
  recentHistory?: HistoryTurnV0[];

  repetition?: {
    window?: number; // default 5
    challengeAt?: number; // default 2
    blockAt?: number; // default 3
  };
}): PolicyDecision {
  const decision = cloneDecision(args.base);

  const recent = args.recentHistory ?? [];
  const repWindow = args.repetition?.window ?? 5;
  const repChallengeAt = args.repetition?.challengeAt ?? 2;
  const repBlockAt = args.repetition?.blockAt ?? 3;

  // ---------- (1) Immediate: fact mismatch => block ----------
  // Tool-result fact mismatch is considered high-confidence verification.
  if (hasDetectFinding(args.findings, "tool_result_fact_mismatch", "high")) {
    if (decision.action !== "block") {
      decision.action = "block";
      decision.risk = "critical";
      decision.confidence = Math.max(decision.confidence ?? 0, 0.9);
      decision.reasons.unshift("[CRITICAL|policy] Tool fact mismatch detected (verified tool output vs response). Escalated to BLOCK.");
    }
    return decision;
  }

  // ---------- (2) Repetition-based escalation ----------
  const CONTRA_SCANNERS = [
    "history_contradiction",
    "history_flipflop",
    "tool_result_contradiction",
    "tool_result_fact_mismatch",
  ];

  // Count occurrences from history
  const histHits = countRecentAnyScannerHits(recent, CONTRA_SCANNERS, repWindow);

  // Also count current turn if it contains any contradiction scanner finding
  const currentHasContra = args.findings.some(
    f => f.kind === "detect" && CONTRA_SCANNERS.includes(f.scanner) && riskAtOrAbove(f.risk, "medium")
  );
  const totalHits = histHits + (currentHasContra ? 1 : 0);

  if (totalHits >= repBlockAt) {
    // Escalate to BLOCK
    if (decision.action !== "block") {
      decision.action = "block";
      decision.risk = "critical";
      decision.confidence = Math.max(decision.confidence ?? 0, 0.85);
      decision.reasons.unshift(
        `[CRITICAL|policy] Repeated contradictions across session (hits=${totalHits}/${repWindow}). Escalated to BLOCK.`
      );
    }
  } else if (totalHits >= repChallengeAt) {
    // Escalate to CHALLENGE if lower
    const actionRank = (a: string) => (a === "allow" ? 0 : a === "allow_with_warning" ? 1 : a === "challenge" ? 2 : 3);
    if (actionRank(decision.action) < actionRank("challenge")) {
      decision.action = "challenge";
      decision.risk = riskAtOrAbove(decision.risk, "high") ? decision.risk : "high";
      decision.confidence = Math.max(decision.confidence ?? 0, 0.75);
      decision.reasons.unshift(
        `[HIGH|policy] Repeated contradictions across session (hits=${totalHits}/${repWindow}). Escalated to CHALLENGE.`
      );
    }
  }

  return decision;
}
