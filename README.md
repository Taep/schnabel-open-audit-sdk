#  ____   ____  _   _ _   _    _    ____  _____ _
# / ___| / ___|| | | | \ | |  / \  | __ )| ____| |
# \___ \| |    | |_| |  \| | / _ \ |  _ \|  _| | |
#  ___) | |___ |  _  | |\  |/ ___ \| |_) | |___| |___
# |____/ \____||_| |_|_| \_/_/   \_\____/|_____|_____|
#
# Schnabel Open Audit SDK
# Evidence-first • Provenance-aware • Obfuscation-resistant • Benchmark-driven (planned)

Schnabel is a **Node.js/TypeScript Open Audit SDK** for LLM/agent runtimes.
It standardizes raw inputs, runs a **chain of scanners** (sanitizers + detectors), and produces **structured Findings**
that later drive policy decisions and evidence packages.

This repository is in active development. Current implementation covers **L0–L2** with passing tests.

---

## Why Schnabel

Modern prompt injection and agent abuse often relies on:

- **Obfuscation** (zero-width characters, bidi controls, invisible Unicode TAG payloads)
- **Provenance confusion** (user vs retrieval/RAG vs system/developer instructions)
- **Evasion drift** (variants that slip past naive keyword filters)
- **Over-defense** (blocking benign content due to keyword bias)

Schnabel is built around two principles:

1) **Don’t just “block”—explain.**  
   Every signal becomes a **Finding** with structured evidence and target metadata
   (prompt vs retrieval chunk, etc).

2) **Make defenses extensible and testable.**  
   Defense logic is a **scanner chain**. Add a scanner, and the pipeline automatically aggregates results
   and preserves traceability.

---

## Architecture (6-Layer Model)

Schnabel follows a clear audit-friendly flow:

- **L0. Ingress/Adapter**  
  Converts upstream events → `AuditRequest` while preserving role/source context.

- **L1. Normalize**  
  Produces deterministic `NormalizedInput` (stable JSON canonicalization + trim) and preserves provenance.

- **L2. Signals**  
  Runs a **scanner chain** (sanitize/detect/enrich) → `Findings`.

- **L3. Policy** *(planned)*  
  Calibrated decisioning with over-defense control (hard negatives / NotInject-style evaluation).

- **L4. Verdict** *(planned)*  
  Actionable outcome: allow / challenge / block / redact / rate-limit.

- **L5. Evidence** *(planned)*  
  Integrity-protected, replayable audit packages.

---

## Current Status (Implemented)

### L0 — Ingress / Adapter ✅
- Generic adapter converts external agent/runtime events into `AuditRequest`
- Preserves **provenance** via `promptChunks` (system / developer / user / retrieval)

Files:
- `src/adapters/generic_agent.ts`

### L1 — Normalize ✅
- Deterministic canonicalization for tool payloads (`canonicalizeJson`)
- Minimal cleanup (`trim`) + feature extraction (`toolNames`, language hint)
- Provenance preserved in `promptChunksCanonical`

Files:
- `src/normalizer/types.ts`
- `src/normalizer/canonicalize.ts`
- `src/normalizer/normalize.ts`

### L2 — Signals (Scanner Chain) ✅
- Sequential scanner chain runner (`scanSignals`)
- Supports:
  - **Input mutation** by sanitizers (sanitize → detect improves detection)
  - **failFast** (runtime mode) vs **full scan** (audit mode)
- Standard output as **Findings**:
  - `risk`, `score`, `tags`, `summary`
  - `target` (prompt vs chunk + source + index)
  - minimal `evidence`

Files:
- `src/signals/scan.ts`
- `src/signals/types.ts`
- `src/signals/scanners/scanner.ts`

#### Implemented Scanners
Sanitize:
- `UnicodeSanitizerScanner`  
  NFKC normalization + zero-width/invisible removal + bidi control removal  
  `src/signals/scanners/sanitize/unicode_sanitizer.ts`
- `HiddenAsciiTagsScanner`  
  Decodes invisible Unicode TAG payloads (U+E0000..U+E007F) to reveal hidden ASCII  
  `src/signals/scanners/sanitize/hidden_ascii_tags.ts`

Detect:
- `KeywordInjectionScanner`  
  Minimal rule-based injection patterns across prompt + provenance chunks  
  `src/signals/scanners/detect/keyword_injection.ts`

---

## Quickstart

### Install
```bash
npm install
