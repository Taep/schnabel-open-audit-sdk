import { type Finding, type RiskLevel, RISK_ORDER, riskAtOrAbove } from "../signals/types.js";
import type { InputSource, TextView } from "../normalizer/types.js";
import { sha256Hex } from "../signals/util.js";

export type VerdictAction = "allow" | "allow_with_warning" | "challenge" | "block";

export interface DumpPolicyInput {
  requestId: string;
  action: VerdictAction;
  risk: RiskLevel;
  findings: Finding[];
}

export interface DumpPolicyConfig {
  // Output toggles when dumping is decided
  dumpEvidence: boolean;     // default true
  dumpReport: boolean;       // default true

  // Strong triggers
  dumpOnActions: VerdictAction[];    // default ["challenge","block"]
  minRiskToDump: RiskLevel;          // default "high"
  dumpIfViewsInclude: TextView[];    // default ["revealed","skeleton"]
  dumpIfSourcesInclude: InputSource[]; // default ["retrieval"]

  // Sampling for non-incident traffic
  sampleAllowRate: number;          // default 0.0
  sampleWarnRate: number;           // default 0.0
  sampleSeed: string;               // default "schnabel"
}

export interface DumpDecision {
  dumpEvidence: boolean;
  dumpReport: boolean;
  dump: boolean;
  reasons: string[];
}

const DEFAULT_CFG: DumpPolicyConfig = {
  dumpEvidence: true,
  dumpReport: true,

  dumpOnActions: ["challenge", "block"],
  minRiskToDump: "high",
  dumpIfViewsInclude: ["revealed", "skeleton"],
  dumpIfSourcesInclude: ["retrieval"],

  sampleAllowRate: 0.0,
  sampleWarnRate: 0.0,
  sampleSeed: "schnabel",
};

function maxFindingRisk(findings: Finding[]): RiskLevel {
  let max: RiskLevel = "none";
  for (const f of findings) {
    if (riskAtOrAbove(f.risk, max)) max = f.risk;
  }
  return max;
}

function stableRand01(seed: string): number {
  // Use first 8 hex digits as a 32-bit integer
  const h = sha256Hex(seed).slice(0, 8);
  const n = parseInt(h, 16);
  return n / 0x100000000;
}

/**
 * Decide whether to dump evidence/report based on action/risk/findings/views/sources and sampling.
 */
export function decideDumpPolicy(
  input: DumpPolicyInput,
  partial?: Partial<DumpPolicyConfig>
): DumpDecision {
  const cfg: DumpPolicyConfig = { ...DEFAULT_CFG, ...(partial ?? {}) };

  const reasons: string[] = [];
  let dump = false;

  // 1) Action trigger
  if (cfg.dumpOnActions.includes(input.action)) {
    dump = true;
    reasons.push(`action=${input.action}`);
  }

  // 2) Risk trigger
  if (riskAtOrAbove(input.risk, cfg.minRiskToDump)) {
    dump = true;
    reasons.push(`decisionRisk>=${cfg.minRiskToDump} (${input.risk})`);
  }

  const maxR = maxFindingRisk(input.findings);
  if (riskAtOrAbove(maxR, cfg.minRiskToDump)) {
    dump = true;
    reasons.push(`maxFindingRisk>=${cfg.minRiskToDump} (${maxR})`);
  }

  // 3) View trigger (revealed/skeleton are usually "attack surface" signals)
  const viewSet = new Set<TextView>();
  for (const f of input.findings) {
    viewSet.add(f.target.view);
    const mv = f.evidence?.["matchedViews"];
    if (Array.isArray(mv)) {
      for (const v of mv) viewSet.add(v);
    }
  }
  for (const v of cfg.dumpIfViewsInclude) {
    if (viewSet.has(v)) {
      dump = true;
      reasons.push(`view=${v}`);
      break;
    }
  }

  // 4) Source trigger (retrieval is high-value to keep)
  const srcSet = new Set<InputSource>();
  for (const f of input.findings) {
    if (f.target.field === "promptChunk" && f.target.source) srcSet.add(f.target.source);
  }
  for (const s of cfg.dumpIfSourcesInclude) {
    if (srcSet.has(s)) {
      dump = true;
      reasons.push(`source=${s}`);
      break;
    }
  }

  // 5) Sampling for allow / warn
  if (!dump) {
    if (input.action === "allow" && cfg.sampleAllowRate > 0) {
      const r = stableRand01(`${cfg.sampleSeed}:${input.requestId}:allow`);
      if (r < cfg.sampleAllowRate) {
        dump = true;
        reasons.push(`sampled_allow(rate=${cfg.sampleAllowRate})`);
      }
    }
    if (input.action === "allow_with_warning" && cfg.sampleWarnRate > 0) {
      const r = stableRand01(`${cfg.sampleSeed}:${input.requestId}:warn`);
      if (r < cfg.sampleWarnRate) {
        dump = true;
        reasons.push(`sampled_warn(rate=${cfg.sampleWarnRate})`);
      }
    }
  }

  return {
    dump,
    dumpEvidence: dump && cfg.dumpEvidence,
    dumpReport: dump && cfg.dumpReport,
    reasons,
  };
}
