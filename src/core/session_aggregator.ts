import type { RiskLevel, Finding } from "../signals/types.js";
import type { InputSource, TextView } from "../normalizer/types.js";
import type { VerdictAction } from "./dump_policy.js";

export interface TurnRecord {
  requestId: string;
  createdAt: number;
  action: VerdictAction;
  risk: RiskLevel;

  totalFindings: number;
  detectFindings: number;

  byRisk: Record<RiskLevel, number>;
  byView: Record<TextView, number>;
  bySource: Record<string, number>; // includes "prompt" and chunk sources

  topRules: Array<{ ruleId: string; count: number }>;
  topCategories: Array<{ category: string; count: number }>;

  evidenceFilePath?: string;
  reportFilePath?: string;
}

export interface SessionSummary {
  sessionId: string;
  startedAtMs: number;
  endedAtMs: number;
  turns: number;

  actions: Record<string, number>;
  risks: Record<RiskLevel, number>;

  findingsTotal: number;
  findingsByView: Record<TextView, number>;
  findingsBySource: Record<string, number>;

  topRules: Array<{ ruleId: string; count: number }>;
  topCategories: Array<{ category: string; count: number }>;
}

const RISK_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

function initRiskCounts(): Record<RiskLevel, number> {
  return { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
}

function initViewCounts(): Record<TextView, number> {
  return { raw: 0, sanitized: 0, revealed: 0, skeleton: 0 };
}

function inc<K extends string>(obj: Record<K, number>, key: K, by = 1) {
  obj[key] = (obj[key] ?? 0) + by;
}

function countFindingsByRisk(findings: Finding[]): Record<RiskLevel, number> {
  const out = initRiskCounts();
  for (const f of findings) out[f.risk] += 1;
  return out;
}

function countByView(findings: Finding[]): Record<TextView, number> {
  const out = initViewCounts();
  for (const f of findings) {
    out[f.target.view] += 1;
    const mv = (f.evidence as any)?.matchedViews;
    if (Array.isArray(mv)) {
      for (const v of mv) {
        if (v in out) out[v as TextView] += 1;
      }
    }
  }
  return out;
}

function countBySource(findings: Finding[]): Record<string, number> {
  const out: Record<string, number> = { prompt: 0 };

  for (const f of findings) {
    if (f.target.field === "prompt") {
      out.prompt += 1;
    } else {
      const s = f.target.source ?? "unknown";
      out[s] = (out[s] ?? 0) + 1;
    }
  }
  return out;
}

function topN(map: Map<string, number>, n = 5): Array<{ key: string; count: number }> {
  return Array.from(map.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([key, count]) => ({ key, count }));
}

function extractRuleAndCategoryCounts(findings: Finding[]) {
  const ruleCounts = new Map<string, number>();
  const catCounts = new Map<string, number>();

  for (const f of findings) {
    const ev: any = f.evidence ?? {};
    if (typeof ev.ruleId === "string") ruleCounts.set(ev.ruleId, (ruleCounts.get(ev.ruleId) ?? 0) + 1);
    if (typeof ev.category === "string") catCounts.set(ev.category, (catCounts.get(ev.category) ?? 0) + 1);
  }

  return { ruleCounts, catCounts };
}

export class SessionAggregator {
  readonly sessionId: string;
  readonly startedAtMs: number;

  private endedAtMs: number;
  private turnRecords: TurnRecord[] = [];

  // session-wide accumulators
  private actionCounts: Record<string, number> = {};
  private riskCounts: Record<RiskLevel, number> = initRiskCounts();
  private findingsTotal = 0;
  private findingsByView: Record<TextView, number> = initViewCounts();
  private findingsBySource: Record<string, number> = {};
  private ruleCounts = new Map<string, number>();
  private catCounts = new Map<string, number>();

  constructor(sessionId: string) {
    this.sessionId = sessionId;
    this.startedAtMs = Date.now();
    this.endedAtMs = this.startedAtMs;
  }

  addTurn(args: {
    requestId: string;
    createdAt: number;
    action: VerdictAction;
    risk: RiskLevel;
    findings: Finding[];
    evidenceFilePath?: string;
    reportFilePath?: string;
  }): void {
    this.endedAtMs = Math.max(this.endedAtMs, args.createdAt);

    const findings = args.findings ?? [];
    const byRisk = countFindingsByRisk(findings);
    const byView = countByView(findings);
    const bySource = countBySource(findings);

    const detectFindings = findings.filter(f => f.kind === "detect").length;

    // Update session accumulators
    inc(this.actionCounts, args.action, 1);
    this.riskCounts[args.risk] += 1;

    this.findingsTotal += findings.length;

    for (const v of Object.keys(byView) as TextView[]) this.findingsByView[v] += byView[v];
    for (const k of Object.keys(bySource)) this.findingsBySource[k] = (this.findingsBySource[k] ?? 0) + bySource[k];

    const { ruleCounts, catCounts } = extractRuleAndCategoryCounts(findings);
    for (const [k, c] of ruleCounts.entries()) this.ruleCounts.set(k, (this.ruleCounts.get(k) ?? 0) + c);
    for (const [k, c] of catCounts.entries()) this.catCounts.set(k, (this.catCounts.get(k) ?? 0) + c);

    const topRules = topN(ruleCounts, 3).map(x => ({ ruleId: x.key, count: x.count }));
    const topCategories = topN(catCounts, 3).map(x => ({ category: x.key, count: x.count }));

    this.turnRecords.push({
      requestId: args.requestId,
      createdAt: args.createdAt,
      action: args.action,
      risk: args.risk,
      totalFindings: findings.length,
      detectFindings,
      byRisk,
      byView,
      bySource,
      topRules,
      topCategories,
      evidenceFilePath: args.evidenceFilePath,
      reportFilePath: args.reportFilePath,
    });
  }

  getTurnRecords(): TurnRecord[] {
    return [...this.turnRecords];
  }

  summary(): SessionSummary {
    const topRules = topN(this.ruleCounts, 8).map(x => ({ ruleId: x.key, count: x.count }));
    const topCategories = topN(this.catCounts, 8).map(x => ({ category: x.key, count: x.count }));

    return {
      sessionId: this.sessionId,
      startedAtMs: this.startedAtMs,
      endedAtMs: this.endedAtMs,
      turns: this.turnRecords.length,
      actions: { ...this.actionCounts },
      risks: { ...this.riskCounts },
      findingsTotal: this.findingsTotal,
      findingsByView: { ...this.findingsByView },
      findingsBySource: { ...this.findingsBySource },
      topRules,
      topCategories,
    };
  }

  renderSummaryKR(): string {
    const s = this.summary();

    const lines: string[] = [];
    lines.push(`# Schnabel Session Summary`);
    lines.push(`- sessionId: \`${s.sessionId}\``);
    lines.push(`- turns: \`${s.turns}\``);
    lines.push(`- window: \`${new Date(s.startedAtMs).toISOString()} ~ ${new Date(s.endedAtMs).toISOString()}\``);
    lines.push("");

    lines.push(`## A. Action 분포`);
    for (const [k, v] of Object.entries(s.actions).sort((a, b) => b[1] - a[1])) {
      lines.push(`- ${k}: ${v}`);
    }
    lines.push("");

    lines.push(`## B. Risk 분포(턴 기준)`);
    for (const r of [...RISK_ORDER].reverse()) {
      lines.push(`- ${r}: ${s.risks[r] ?? 0}`);
    }
    lines.push("");

    lines.push(`## C. Findings 요약`);
    lines.push(`- total findings: ${s.findingsTotal}`);
    lines.push(`- by view: raw=${s.findingsByView.raw}, sanitized=${s.findingsByView.sanitized}, revealed=${s.findingsByView.revealed}, skeleton=${s.findingsByView.skeleton}`);
    lines.push("");

    lines.push(`## D. Source별 Findings`);
    for (const [k, v] of Object.entries(s.findingsBySource).sort((a, b) => b[1] - a[1])) {
      lines.push(`- ${k}: ${v}`);
    }
    lines.push("");

    lines.push(`## E. Top Rule IDs`);
    if (!s.topRules.length) lines.push(`- (none)`);
    for (const x of s.topRules) lines.push(`- ${x.ruleId}: ${x.count}`);
    lines.push("");

    lines.push(`## F. Top Categories`);
    if (!s.topCategories.length) lines.push(`- (none)`);
    for (const x of s.topCategories) lines.push(`- ${x.category}: ${x.count}`);
    lines.push("");

    lines.push(`## G. Timeline (최근 순)`);
    const recent = [...this.turnRecords].slice(-12).reverse();
    for (const t of recent) {
      lines.push(`- ${new Date(t.createdAt).toISOString()} | ${t.action.toUpperCase()} | risk=${t.risk} | detect=${t.detectFindings} | req=${t.requestId}`);
      if (t.topRules.length) lines.push(`  - top rules: ${t.topRules.map(x => `${x.ruleId}(${x.count})`).join(", ")}`);
      if (t.reportFilePath) lines.push(`  - report: ${t.reportFilePath}`);
      if (t.evidenceFilePath) lines.push(`  - evidence: ${t.evidenceFilePath}`);
    }

    lines.push("");
    return lines.join("\n");
  }
}
