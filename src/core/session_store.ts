import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";

import type { EvidencePackageV0 } from "./evidence_package.js";
import type { RiskLevel } from "../signals/types.js";
import type { TextView } from "../normalizer/types.js";

import { saveEvidencePackage } from "./evidence_dump.js";
import { saveEvidenceReportEN } from "./evidence_report_dump.js";

export interface SessionDumpOptions {
  baseDir?: string;          // default: artifacts/audit
  sessionId: string;         // required
  updateSessionSummary?: boolean; // default true
  maxTimeline?: number;      // default 20
}

type VerdictAction = "allow" | "allow_with_warning" | "challenge" | "block";

export interface SessionStateV0 {
  schema: "schnabel-session-state-v0";
  sessionId: string;
  createdAtMs: number;
  updatedAtMs: number;

  turns: number;

  actions: Record<string, number>;
  risks: Record<RiskLevel, number>;

  findingsTotal: number;
  findingsByView: Record<TextView, number>;
  findingsBySource: Record<string, number>;

  ruleCounts: Record<string, number>;
  categoryCounts: Record<string, number>;

  timeline: Array<{
    requestId: string;
    generatedAtMs: number;
    action: VerdictAction;
    risk: RiskLevel;
    evidencePath: string;
    reportPath: string;
  }>;
}

const RISK_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

function safeName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

function initRiskCounts(): Record<RiskLevel, number> {
  return { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function initViewCounts(): Record<TextView, number> {
  return { raw: 0, sanitized: 0, revealed: 0, skeleton: 0 };
}

function countViewsForFinding(f: any): Set<TextView> {
  const out = new Set<TextView>();
  if (f.target?.view) out.add(f.target.view);
  const mv = f.evidence?.matchedViews;
  if (Array.isArray(mv)) for (const v of mv) if (v in initViewCounts()) out.add(v);
  return out;
}

function renderSessionSummaryEN(state: SessionStateV0): string {
  const lines: string[] = [];
  lines.push(`# Schnabel Session Summary`);
  lines.push(`- sessionId: \`${state.sessionId}\``);
  lines.push(`- turns: \`${state.turns}\``);
  lines.push(`- window: \`${new Date(state.createdAtMs).toISOString()} ~ ${new Date(state.updatedAtMs).toISOString()}\``);
  lines.push("");

  lines.push(`## A) Actions`);
  for (const [k, v] of Object.entries(state.actions).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${k}: ${v}`);
  }
  lines.push("");

  lines.push(`## B) Risks (per turn)`);
  for (const r of [...RISK_ORDER].reverse()) {
    lines.push(`- ${r}: ${state.risks[r] ?? 0}`);
  }
  lines.push("");

  lines.push(`## C) Findings`);
  lines.push(`- totalFindings: ${state.findingsTotal}`);
  lines.push(`- byView: raw=${state.findingsByView.raw}, sanitized=${state.findingsByView.sanitized}, revealed=${state.findingsByView.revealed}, skeleton=${state.findingsByView.skeleton}`);
  lines.push(`- bySource: ${Object.entries(state.findingsBySource).sort((a,b)=>b[1]-a[1]).map(([k,v])=>`${k}=${v}`).join(", ") || "N/A"}`);
  lines.push("");

  const topRules = Object.entries(state.ruleCounts).sort((a,b)=>b[1]-a[1]).slice(0, 8);
  lines.push(`## D) Top Rules`);
  if (!topRules.length) lines.push(`- (none)`);
  for (const [k, v] of topRules) lines.push(`- ${k}: ${v}`);
  lines.push("");

  const topCats = Object.entries(state.categoryCounts).sort((a,b)=>b[1]-a[1]).slice(0, 8);
  lines.push(`## E) Top Categories`);
  if (!topCats.length) lines.push(`- (none)`);
  for (const [k, v] of topCats) lines.push(`- ${k}: ${v}`);
  lines.push("");

  lines.push(`## F) Timeline (latest first)`);
  const recent = [...state.timeline].slice(-20).reverse();
  for (const t of recent) {
    lines.push(`- ${new Date(t.generatedAtMs).toISOString()} | ${t.action.toUpperCase()} | risk=${t.risk} | req=${t.requestId}`);
    lines.push(`  - evidence: ${t.evidencePath}`);
    lines.push(`  - report: ${t.reportPath}`);
  }

  lines.push("");
  return lines.join("\n");
}

async function loadState(sessionRoot: string, sessionId: string): Promise<SessionStateV0> {
  const statePath = path.join(sessionRoot, "session_state.json");
  if (!fs.existsSync(statePath)) {
    const now = Date.now();
    return {
      schema: "schnabel-session-state-v0",
      sessionId,
      createdAtMs: now,
      updatedAtMs: now,
      turns: 0,
      actions: {},
      risks: initRiskCounts(),
      findingsTotal: 0,
      findingsByView: initViewCounts(),
      findingsBySource: {},
      ruleCounts: {},
      categoryCounts: {},
      timeline: [],
    };
  }

  const raw = await fsp.readFile(statePath, "utf8");
  return JSON.parse(raw) as SessionStateV0;
}

async function saveState(sessionRoot: string, state: SessionStateV0): Promise<void> {
  const statePath = path.join(sessionRoot, "session_state.json");
  await fsp.writeFile(statePath, JSON.stringify(state, null, 2), "utf8");
}

export async function dumpEvidenceToSessionLayout(
  evidence: EvidencePackageV0,
  opts: SessionDumpOptions
): Promise<{ sessionRoot: string; turnDir: string; evidencePath: string; reportPath: string; summaryPath?: string | undefined }> {
  const baseDir = opts.baseDir ?? "artifacts/audit";
  const sessionId = safeName(opts.sessionId);
  const sessionRoot = path.resolve(baseDir, sessionId);

  const turnDirName = `${safeName(evidence.requestId)}.${evidence.generatedAtMs}`;
  const turnDir = path.join(sessionRoot, "turns", turnDirName);

  // Save files inside per-turn directory
  const evidencePath = await saveEvidencePackage(evidence, { outDir: turnDir, fileName: "evidence.json", pretty: true });
  const reportPath = await saveEvidenceReportEN(evidence, { outDir: turnDir, fileName: "report.en.md" });

  // Update session summary (incremental state)
  let summaryPath: string | undefined;
  if (opts.updateSessionSummary ?? true) {
    const state = await loadState(sessionRoot, sessionId);

    state.updatedAtMs = Date.now();
    state.turns += 1;

    const action = evidence.decision.action as VerdictAction;
    state.actions[action] = (state.actions[action] ?? 0) + 1;
    state.risks[evidence.decision.risk] = (state.risks[evidence.decision.risk] ?? 0) + 1;

    // Aggregate findings counts
    const findings = evidence.findings ?? [];
    state.findingsTotal += findings.length;

    for (const f of findings as any[]) {
      // views
      for (const v of countViewsForFinding(f)) state.findingsByView[v] += 1;

      // source
      if (f.target?.field === "prompt") state.findingsBySource.prompt = (state.findingsBySource.prompt ?? 0) + 1;
      else {
        const s = f.target?.source ?? "unknown";
        state.findingsBySource[s] = (state.findingsBySource[s] ?? 0) + 1;
      }

      // rule/category
      const ruleId = f.evidence?.ruleId;
      const cat = f.evidence?.category;
      if (typeof ruleId === "string") state.ruleCounts[ruleId] = (state.ruleCounts[ruleId] ?? 0) + 1;
      if (typeof cat === "string") state.categoryCounts[cat] = (state.categoryCounts[cat] ?? 0) + 1;
    }

    // timeline append
    state.timeline.push({
      requestId: evidence.requestId,
      generatedAtMs: evidence.generatedAtMs,
      action,
      risk: evidence.decision.risk,
      evidencePath: path.relative(sessionRoot, evidencePath),
      reportPath: path.relative(sessionRoot, reportPath),
    });

    // trim timeline
    const maxTimeline = opts.maxTimeline ?? 20;
    if (state.timeline.length > maxTimeline) state.timeline = state.timeline.slice(-maxTimeline);

    await fsp.mkdir(sessionRoot, { recursive: true });
    await saveState(sessionRoot, state);

    const md = renderSessionSummaryEN(state);
    summaryPath = path.join(sessionRoot, "session_summary.en.md");
    await fsp.writeFile(summaryPath, md, "utf8");
  }

  return { sessionRoot, turnDir, evidencePath, reportPath, summaryPath };
}
