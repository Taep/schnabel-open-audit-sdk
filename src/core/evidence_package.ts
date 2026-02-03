import type { AuditRequest, NormalizedInput, InputViews } from "../normalizer/types.js";
import type { Finding } from "../signals/types.js";
import type { PolicyDecision } from "../policy/evaluate.js";
import type { Scanner } from "../signals/scanners/scanner.js";

import { canonicalizeJson } from "../normalizer/canonicalize.js";
import { sha256Hex } from "../signals/util.js";

/**
 * EvidencePackage v0
 * - Minimal audit artifact for reproducibility + explainability
 * - Avoids storing full raw text by default (stores hashes + short previews)
 */
export interface EvidencePackageV0 {
  schema: "schnabel-evidence-v0";
  requestId: string;

  // These timestamps are for logging only; integrity hash does NOT include generatedAt.
  generatedAtMs: number;

  request: {
    timestamp: number;
    actor?: AuditRequest["actor"];
    model?: AuditRequest["model"];
  };

  // Raw digest: keep only hashes and short previews to reduce sensitive leakage.
  rawDigest: {
    prompt: { hash: string; preview?: string; length: number };
    promptChunks?: Array<{ source: string; hash: string; preview?: string; length: number }>;
    toolCallsHash?: string;
    toolResultsHash?: string;
    responseTextHash?: string;
  };

  // L1 output (before L2 sanitizers mutate anything)
  normalized: {
    canonical: NormalizedInput["canonical"];
  };

  // L2 output (after sanitizers/enrichers)
  scanned: {
    canonical: NormalizedInput["canonical"];
    views?: InputViews;
  };

  scanners: Array<{ name: string; kind: string }>;

  findings: Finding[];
  decision: PolicyDecision;

  // Deterministic integrity proof
  integrity: {
    algo: "sha256";
    items: Array<{ name: string; hash: string }>;
    rootHash: string;
  };

  // Derived metadata helpful for audit/reporting
  meta: {
    rulePackVersions?: string[]; // extracted from findings evidence if present
  };
}

export interface EvidenceOptions {
  previewChars?: number;            // default 160
  includeRawPreviews?: boolean;     // default true
}

/**
 * Build a short preview safely.
 */
function previewText(s: unknown, n: number): string | undefined {
  if (typeof s !== "string") return undefined;
  const t = s.trim();
  if (!t) return undefined;
  if (t.length <= n) return t;
  return t.slice(0, n) + "…";
}

function hashOf(obj: unknown): string {
  return sha256Hex(canonicalizeJson(obj));
}

function computeHashChain(items: Array<{ name: string; hash: string }>): string {
  let acc = "root";
  for (const it of items) {
    acc = sha256Hex(`${acc}:${it.name}:${it.hash}`);
  }
  return acc;
}

function extractRulePackVersions(findings: Finding[]): string[] | undefined {
  const versions = new Set<string>();

  for (const f of findings) {
    const ev: any = f.evidence ?? {};
    if (typeof ev.rulePackVersion === "string") versions.add(ev.rulePackVersion);
  }

  const arr = Array.from(versions);
  return arr.length ? arr.sort() : undefined;
}

/**
 * buildEvidencePackageV0()
 * - Constructs a minimal audit package
 * - Produces a deterministic integrity hash chain for key sections
 */
export function buildEvidencePackageV0(args: {
  req: AuditRequest;
  normalized: NormalizedInput;
  scanned: NormalizedInput;
  scanners: Scanner[];
  findings: Finding[];
  decision: PolicyDecision;
  options?: EvidenceOptions;
}): EvidencePackageV0 {
  const { req, normalized, scanned, scanners, findings, decision } = args;
  const opts: Required<EvidenceOptions> = {
    previewChars: args.options?.previewChars ?? 160,
    includeRawPreviews: args.options?.includeRawPreviews ?? true,
  };

  // Raw digest section (hashes + previews)
  const rawPrompt = req.prompt ?? "";
  const rawChunks = req.promptChunks ?? [];

  const rawDigest: EvidencePackageV0["rawDigest"] = {
    prompt: {
      hash: sha256Hex(rawPrompt),
      preview: opts.includeRawPreviews ? previewText(rawPrompt, opts.previewChars) : undefined,
      length: rawPrompt.length,
    },
    promptChunks: rawChunks.length
      ? rawChunks.map(ch => ({
          source: String(ch.source),
          hash: sha256Hex(ch.text ?? ""),
          preview: opts.includeRawPreviews ? previewText(ch.text ?? "", opts.previewChars) : undefined,
          length: (ch.text ?? "").length,
        }))
      : undefined,
    toolCallsHash: req.toolCalls ? hashOf(req.toolCalls) : undefined,
    toolResultsHash: req.toolResults ? hashOf(req.toolResults) : undefined,
    responseTextHash: req.responseText ? sha256Hex(req.responseText) : undefined,
  };

  const scannerMeta = scanners.map(s => ({ name: s.name, kind: s.kind }));

  // Build integrity items (deterministic; exclude generatedAtMs)
  const items: Array<{ name: string; hash: string }> = [
    { name: "request", hash: hashOf({ requestId: req.requestId, timestamp: req.timestamp, actor: req.actor, model: req.model }) },
    { name: "rawDigest", hash: hashOf(rawDigest) },
    { name: "normalized.canonical", hash: hashOf(normalized.canonical) },
    { name: "scanned.canonical", hash: hashOf(scanned.canonical) },
    { name: "scanned.views", hash: hashOf(scanned.views ?? null) },
    { name: "findings", hash: hashOf(findings) },
    { name: "decision", hash: hashOf(decision) },
    { name: "scanners", hash: hashOf(scannerMeta) },
  ];

  const rootHash = computeHashChain(items);

  return {
    schema: "schnabel-evidence-v0",
    requestId: req.requestId,
    generatedAtMs: Date.now(),
    request: {
      timestamp: req.timestamp,
      actor: req.actor,
      model: req.model,
    },
    rawDigest,
    normalized: { canonical: normalized.canonical },
    scanned: { canonical: scanned.canonical, views: scanned.views },
    scanners: scannerMeta,
    findings,
    decision,
    integrity: {
      algo: "sha256",
      items,
      rootHash,
    },
    meta: {
      rulePackVersions: extractRulePackVersions(findings),
    },
  };
}
