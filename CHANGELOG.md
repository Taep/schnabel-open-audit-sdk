# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-08

### Added

- **L0 Ingress**: Generic agent adapter (`fromAgentIngressEvent`) turning external events into `AuditRequest` with provenance (`promptChunks`).
- **L1 Normalize**: Deterministic canonicalization (`canonicalizeJson`, `normalize`), feature extraction, provenance preserved in `NormalizedInput`.
- **L2 Signals**: Scanner chain runner `scanSignals` (sanitize → enrich → detect), failFast/audit modes, multi-view (raw/sanitized/revealed/skeleton).
- **Sanitize scanners**: UnicodeSanitizer, HiddenAsciiTags, SeparatorCollapse, ToolArgsCanonicalizer.
- **Enrich**: Uts39SkeletonViewScanner.
- **Detect scanners**: KeywordInjection, RulePack (JSON rulepack, hotReload), ToolArgsSSRF (including dangerous schemes), ToolArgsPathTraversal (with maxDepth guard), ToolResultContradiction, ToolResultFactMismatch, Uts39Confusables, HistoryContradiction, HistoryFlipFlop.
- **L3 Policy**: `evaluatePolicy` (allow / allow_with_warning / challenge / block), `applyPolicyEscalations` (fact-mismatch block, session repetition escalation).
- **L5 Evidence**: `EvidencePackageV0`, integrity hash chain, `saveEvidencePackage`, `saveEvidenceReportEN`/`KR`, `dumpEvidenceToSessionLayout`, `decideDumpPolicy`.
- **Orchestration**: `runAudit`, presets (`createPreLLMScannerChain`, `createToolBoundaryScannerChain`, `createPostLLMScannerChain`).
- **History**: `InMemoryHistoryStore`, `HistoryTurnV0` (session escalation).
- **Red team**: `npm run redteam`, scenario-driven runner and encodings.
- **Build**: tsup ESM/CJS + d.ts, `copy-assets` to `dist/assets`, `resolveAssetPath` for dev and packaged builds.

### Security / robustness

- RulePack: pattern length limit (400), no backreferences, nested-quantifier heuristic to reduce ReDoS risk.
- Tool-args walk: maxDepth limit (32) in SSRF and path-traversal scanners to avoid deep recursion.
- Optional `maxPromptLength` in `AuditRunOptions` to reject or cap oversized prompts.

### Documentation

- README: architecture (L0–L5), full scanner list, Quickstart with minimal example and checkpoints, EvidenceOptions (preview/privacy), presets, red team, build.
- LICENSE (ISC), CHANGELOG.

[1.0.0]: https://github.com/schnabel-open-audit/schnabel-open-audit-sdk/releases/tag/v1.0.0
