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
import { saveEvidenceReportEN, type SaveEvidenceReportOptions } from "./evidence_report_dump.js";
import { decideDumpPolicy, type DumpPolicyConfig, type DumpDecision } from "./dump_policy.js";
import { dumpEvidenceToSessionLayout, type SessionDumpOptions } from "./session_store.js";

import type { HistoryStore, HistoryTurnV0 } from "./history_store.js";
import { applyPolicyEscalations } from "../policy/escalations.js";

export interface AuditRunOptions {
  scanners: Scanner[];
  scanOptions?: ScanOptions;
  policyConfig?: Partial<PolicyConfig>;

  dumpEvidence?: boolean | SaveEvidenceOptions;
  dumpEvidenceReport?: boolean | SaveEvidenceReportOptions;

  dumpPolicy?: boolean | Partial<DumpPolicyConfig>;
  dumpSession?: SessionDumpOptions;

  history?: {
    store: HistoryStore;
    sessionId: string;
    window?: number;                 // how many past turns used for escalation
    maxResponseSnippetChars?: number;
  };

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

  evidenceFilePath?: string | undefined;
  evidenceReportFilePath?: string | undefined;

  sessionRootDir?: string | undefined;
  turnDir?: string | undefined;
  sessionSummaryPath?: string | undefined;

  dumpDecision?: DumpDecision | undefined;
}

function tryCloseScanners(scanners: Scanner[]) {
  for (const s of scanners as any[]) {
    if (s && typeof s.close === "function") {
      try { s.close(); } catch {}
    }
  }
}

function uniqueStrings(xs: unknown[]): string[] {
  return Array.from(new Set(xs.filter(x => typeof x === "string") as string[]));
}

export async function runAudit(req: AuditRequest, opts: AuditRunOptions): Promise<AuditResult> {
  const createdAt = Date.now();

  // Inject sessionId into actor
  const reqEffective: AuditRequest = opts.history
    ? { ...req, actor: { ...(req.actor ?? {}), sessionId: opts.history.sessionId } }
    : req;

  // L1
  const normalized = normalize(reqEffective);

  // L2
  const { input: scanned, findings } = await scanSignals(
    normalized,
    opts.scanners,
    opts.scanOptions ?? { mode: "audit", failFast: false }
  );

  // L3 base
  let decision = evaluatePolicy(findings, opts.policyConfig);

  // --- Escalations (immediate + history-based) ---
  if (opts.history) {
    const w = opts.history.window ?? 20;
    const recent = await opts.history.store.getRecent(opts.history.sessionId, w);

    decision = applyPolicyEscalations({
      base: decision,
      findings,
      recentHistory: recent,
      repetition: { window: 5, challengeAt: 2, blockAt: 3 },
    });
  } else {
    // immediate escalation without history (fact mismatch => block)
    decision = applyPolicyEscalations({ base: decision, findings });
  }

  // Evidence (after escalation)
  const evidence = buildEvidencePackageV0({
    req: reqEffective,
    normalized,
    scanned,
    scanners: opts.scanners,
    findings,
    decision,
  });

  let evidenceFilePath: string | undefined;
  let evidenceReportFilePath: string | undefined;
  let sessionRootDir: string | undefined;
  let turnDir: string | undefined;
  let sessionSummaryPath: string | undefined;
  let dumpDecision: DumpDecision | undefined;

  const dumpToSessionLayout = async () => {
    if (!opts.dumpSession) return;
    const out = await dumpEvidenceToSessionLayout(evidence, opts.dumpSession);
    sessionRootDir = out.sessionRoot;
    turnDir = out.turnDir;
    evidenceFilePath = out.evidencePath;
    evidenceReportFilePath = out.reportPath;
    sessionSummaryPath = out.summaryPath;
  };

  const dumpFlat = async (doEvidence: boolean, doReport: boolean) => {
    if (doEvidence) {
      const dumpOpts: SaveEvidenceOptions = typeof opts.dumpEvidence === "object" ? opts.dumpEvidence : {};
      evidenceFilePath = await saveEvidencePackage(evidence, dumpOpts);
    }
    if (doReport) {
      const reportOpts: SaveEvidenceReportOptions = typeof opts.dumpEvidenceReport === "object" ? opts.dumpEvidenceReport : {};
      evidenceReportFilePath = await saveEvidenceReportEN(evidence, reportOpts);
    }
  };

  // Dumping strategy
  if (opts.dumpPolicy) {
    const cfg = opts.dumpPolicy === true ? {} : opts.dumpPolicy;

    dumpDecision = decideDumpPolicy(
      { requestId: reqEffective.requestId, action: decision.action, risk: decision.risk, findings },
      cfg
    );

    if (dumpDecision.dump) {
      if (opts.dumpSession) await dumpToSessionLayout();
      else await dumpFlat(dumpDecision.dumpEvidence, dumpDecision.dumpReport);
    }
  } else {
    const wantEvidence = Boolean(opts.dumpEvidence);
    const wantReport = Boolean(opts.dumpEvidenceReport);
    if (wantEvidence || wantReport) {
      if (opts.dumpSession) await dumpToSessionLayout();
      else await dumpFlat(wantEvidence, wantReport);
    }
  }

  // Append to history AFTER final decision (so session sees escalated action)
  if (opts.history) {
    const maxN = opts.history.maxResponseSnippetChars ?? 240;
    const responseText = (reqEffective.responseText ?? "").toString();
    const responseSnippet = responseText ? responseText.replace(/\s+/g, " ").trim().slice(0, maxN) : undefined;

    const toolResults = reqEffective.toolResults ?? [];
    const succeededTools = toolResults.filter(t => t?.ok === true).map(t => t.toolName);
    const failedTools = toolResults.filter(t => t?.ok === false).map(t => t.toolName);

    const detectFindings = (findings ?? []).filter(f => f.kind === "detect");

    const ruleIds = uniqueStrings(detectFindings.map(f => (f.evidence as any)?.ruleId));
    const categories = uniqueStrings(detectFindings.map(f => (f.evidence as any)?.category));

    const detectScanners = uniqueStrings(detectFindings.map(f => f.scanner));
    const detectTags = uniqueStrings(detectFindings.flatMap(f => f.tags ?? []));

    const turn: HistoryTurnV0 = {
      requestId: reqEffective.requestId,
      createdAtMs: createdAt,
      action: decision.action,
      risk: decision.risk,
      succeededTools,
      failedTools,
      responseSnippet,
      ruleIds,
      categories,
      detectScanners,
      detectTags,
    };

    await opts.history.store.append(opts.history.sessionId, turn);
  }

  if (opts.autoCloseScanners) {
    tryCloseScanners(opts.scanners);
  }

  return {
    requestId: reqEffective.requestId,
    createdAt,
    normalized,
    scanned,
    findings,
    decision,
    integrity: { algo: "sha256", rootHash: evidence.integrity.rootHash },
    evidence,
    evidenceFilePath,
    evidenceReportFilePath,
    sessionRootDir,
    turnDir,
    sessionSummaryPath,
    dumpDecision,
  };
}
