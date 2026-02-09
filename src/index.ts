// --- L0: adapters / ingress helpers ---
export { fromAgentIngressEvent } from "./adapters/generic_agent.js";
export type { AgentIngressEvent } from "./adapters/generic_agent.js";

// --- L1: normalize ---
export { normalize } from "./normalizer/normalize.js";
export { canonicalizeJson } from "./normalizer/canonicalize.js";
export type {
  InputSource,
  SourcedText,
  TextView,
  TextViewSet,
  ChunkViews,
  InputViews,
  AuditRequest,
  NormalizedInput,
} from "./normalizer/types.js";

// --- L2: signals (scanner chain + core types) ---
export { scanSignals } from "./signals/scan.js";
export type { ScanOptions } from "./signals/scan.js";
export type { RiskLevel, ScannerKind, FindingTarget, Finding, ScannerMetric } from "./signals/types.js";
export type { Scanner, ScannerContext, ScannerOutput } from "./signals/scanners/scanner.js";
export { ensureViews, initViewSet, VIEW_SCAN_ORDER, VIEW_PREFERENCE, pickPreferredView } from "./signals/views.js";
export { makeFindingId } from "./signals/util.js";
export { defineScanner } from "./signals/define_scanner.js";
export type { DefineScannerOptions } from "./signals/define_scanner.js";

// Built-in scanners (sanitize / enrich / detect)
export { UnicodeSanitizerScanner } from "./signals/scanners/sanitize/unicode_sanitizer.js";
export { HiddenAsciiTagsScanner } from "./signals/scanners/sanitize/hidden_ascii_tags.js";
export { SeparatorCollapseScanner } from "./signals/scanners/sanitize/separator_collapse.js";
export { ToolArgsCanonicalizerScanner } from "./signals/scanners/sanitize/tool_args_canonicalizer.js";

export { Uts39SkeletonViewScanner } from "./signals/scanners/enrich/uts39_skeleton_view.js";

export { createRulePackScanner } from "./signals/scanners/detect/rulepack_scanner.js";
export type { RulePackScannerOptions } from "./signals/scanners/detect/rulepack_scanner.js";
export { KeywordInjectionScanner } from "./signals/scanners/detect/keyword_injection.js";
export { ToolResultContradictionScanner } from "./signals/scanners/detect/tool_result_contradiction.js";
export { ToolResultFactMismatchScanner } from "./signals/scanners/detect/tool_result_fact_mismatch.js";
export { ToolArgsSSRFScanner } from "./signals/scanners/detect/tool_args_ssrf.js";
export { ToolArgsPathTraversalScanner } from "./signals/scanners/detect/tool_args_path_traversal.js";
export { Uts39ConfusablesScanner } from "./signals/scanners/detect/uts39_confusables.js";
export { createHistoryContradictionScanner } from "./signals/scanners/detect/history_contradiction.js";
export { createHistoryFlipFlopScanner } from "./signals/scanners/detect/history_flipflop.js";

// --- L3: policy ---
export { evaluatePolicy } from "./policy/evaluate.js";
export type { PolicyConfig, PolicyDecision, VerdictAction } from "./policy/evaluate.js";
export { applyPolicyEscalations } from "./policy/escalations.js";

// --- L5: evidence (package + dumps) ---
export { buildEvidencePackageV0 } from "./core/evidence_package.js";
export type { EvidencePackageV0, EvidenceOptions } from "./core/evidence_package.js";

export { decideDumpPolicy } from "./core/dump_policy.js";
export type { DumpPolicyInput, DumpPolicyConfig, DumpDecision } from "./core/dump_policy.js";

export { saveEvidencePackage } from "./core/evidence_dump.js";
export type { SaveEvidenceOptions } from "./core/evidence_dump.js";

export { renderEvidenceReportEN } from "./core/evidence_report_en.js";
export type { ReportOptions } from "./core/evidence_report_en.js";
export { renderEvidenceReportKR } from "./core/evidence_report_kr.js";

export {
  saveEvidenceReportMarkdown,
  saveEvidenceReportEN,
  saveEvidenceReportKR,
} from "./core/evidence_report_dump.js";
export type { SaveEvidenceReportOptions } from "./core/evidence_report_dump.js";

export { dumpEvidenceToSessionLayout } from "./core/session_store.js";
export type { SessionDumpOptions, SessionStateV0 } from "./core/session_store.js";
export { SessionAggregator } from "./core/session_aggregator.js";
export type { TurnRecord, SessionSummary } from "./core/session_aggregator.js";

// --- Orchestration (runAudit) + presets ---
export { runAudit } from "./core/run_audit.js";
export type { AuditRunOptions, AuditResult } from "./core/run_audit.js";

export {
  createPreLLMScannerChain,
  createToolBoundaryScannerChain,
  createPostLLMScannerChain,
} from "./core/presets.js";

// --- History store (multiturn) ---
export { InMemoryHistoryStore } from "./core/history_store.js";
export type { HistoryStore, HistoryTurnV0 } from "./core/history_store.js";
