import type { AuditRequest, NormalizedInput } from "../normalizer/types.js";
import type { Finding } from "../signals/types.js";
import type { Scanner } from "../signals/scanners/scanner.js";
import type { ScanOptions } from "../signals/scan.js";
import type { PolicyConfig, PolicyDecision } from "../policy/evaluate.js";

import { normalize } from "../normalizer/normalize.js";
import { scanSignals } from "../signals/scan.js";
import { evaluatePolicy } from "../policy/evaluate.js";

import { buildEvidencePackageV0, type EvidencePackageV0 } from "./evidence_package.js";
import { saveEvidencePackage, type SaveEvidenceOptions } from "./evidence_dump.js";
import { saveEvidenceReportKR, type SaveEvidenceReportOptions } from "./evidence_report_dump.js";
import { decideDumpPolicy, type DumpPolicyConfig, type DumpDecision } from "./dump_policy.js";

export interface AuditRunOptions {
  scanners: Scanner[];
  scanOptions?: ScanOptions;
  policyConfig?: Partial<PolicyConfig>;

  /**
   * Direct dumping (always dumps when enabled).
   * - true: dump to defaults
   * - object: custom dump options
   */
  dumpEvidence?: boolean | SaveEvidenceOptions;
  dumpEvidenceReport?: boolean | SaveEvidenceReportOptions;

  /**
   * Policy-based dumping (recommended for production).
   * - true: enable with default policy
   * - object: customize policy
   *
   * When dumpPolicy is provided, dumping occurs only if policy decides to dump.
   * dumpEvidence/dumpEvidenceReport options are used as output settings (outDir/fileName).
   */
  dumpPolicy?: boolean | Partial<DumpPolicyConfig>;

  /**
   * Convenience: close scanners that expose close() after runAudit finishes.
   * Default: false (safe for scanner reuse)
   */
  autoCloseScanners?: boolean;
}

export interface AuditResult {
  requestId: string;
  createdAt: number;

  normalized: NormalizedInput;
  scanned: NormalizedInput;

  findings: Finding[];
  decision: PolicyDecision;

  integrity: {
    algo: "sha256";
    rootHash: string;
  };

  evidence: EvidencePackageV0;

  evidenceFilePath?: string;
  evidenceReportFilePath?: string;

  dumpDecision?: DumpDecision;
}

function tryCloseScanners(scanners: Scanner[]) {
  for (const s of scanners as any[]) {
    if (s && typeof s.close === "function") {
      try { s.close(); } catch {}
    }
  }
}

export async function runAudit(req: AuditRequest, opts: AuditRunOptions): Promise<AuditResult> {
  const createdAt = Date.now();

  // L1
  const normalized = normalize(req);

  // L2
  const { input: scanned, findings } = await scanSignals(
    normalized,
    opts.scanners,
    opts.scanOptions ?? { mode: "audit", failFast: false }
  );

  // L3
  const decision = evaluatePolicy(findings, opts.policyConfig);

  // Evidence package (L5 v0)
  const evidence = buildEvidencePackageV0({
    req,
    normalized,
    scanned,
    scanners: opts.scanners,
    findings,
    decision,
  });

  let evidenceFilePath: string | undefined;
  let evidenceReportFilePath: string | undefined;
  let dumpDecision: DumpDecision | undefined;

  // --- Dumping strategy ---
  if (opts.dumpPolicy) {
    // Policy-based dumping
    const cfg = opts.dumpPolicy === true ? {} : opts.dumpPolicy;

    dumpDecision = decideDumpPolicy({
      requestId: req.requestId,
      action: decision.action,
      risk: decision.risk,
      findings,
    }, cfg);

    if (dumpDecision.dumpEvidence) {
      const dumpOpts: SaveEvidenceOptions =
        typeof opts.dumpEvidence === "object" ? opts.dumpEvidence : {};
      evidenceFilePath = await saveEvidencePackage(evidence, dumpOpts);
    }

    if (dumpDecision.dumpReport) {
      const reportOpts: SaveEvidenceReportOptions =
        typeof opts.dumpEvidenceReport === "object" ? opts.dumpEvidenceReport : {};
      evidenceReportFilePath = await saveEvidenceReportKR(evidence, reportOpts);
    }
  } else {
    // Direct dumping (always)
    if (opts.dumpEvidence) {
      const dumpOpts: SaveEvidenceOptions =
        opts.dumpEvidence === true ? {} : opts.dumpEvidence;
      evidenceFilePath = await saveEvidencePackage(evidence, dumpOpts);
    }

    if (opts.dumpEvidenceReport) {
      const reportOpts: SaveEvidenceReportOptions =
        opts.dumpEvidenceReport === true ? {} : opts.dumpEvidenceReport;
      evidenceReportFilePath = await saveEvidenceReportKR(evidence, reportOpts);
    }
  }

  if (opts.autoCloseScanners) {
    tryCloseScanners(opts.scanners);
  }

  return {
    requestId: req.requestId,
    createdAt,
    normalized,
    scanned,
    findings,
    decision,
    integrity: { algo: "sha256", rootHash: evidence.integrity.rootHash },
    evidence,
    evidenceFilePath,
    evidenceReportFilePath,
    dumpDecision,
  };
}
