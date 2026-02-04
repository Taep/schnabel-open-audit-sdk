import type { EvidencePackageV0 } from "./evidence_package.js";

type RiskLevel = "none" | "low" | "medium" | "high" | "critical";
type VerdictAction = "allow" | "allow_with_warning" | "challenge" | "block";

export interface ReportOptions {
  maxPreviewChars?: number;        // default 120
  includeNotes?: boolean;          // default true
  includeDetails?: boolean;        // default false
}

const RISK_ORDER: RiskLevel[] = ["none", "low", "medium", "high", "critical"];

function clip(s: string, n: number): string {
  const t = (s ?? "").toString().replace(/\s+/g, " ").trim();
  if (t.length <= n) return t;
  return t.slice(0, n) + "…";
}

function badgeForAction(action: VerdictAction): string {
  switch (action) {
    case "allow": return "✅ ALLOW";
    case "allow_with_warning": return "🟡 WARN";
    case "challenge": return "🟠 CHALLENGE";
    case "block": return "⛔ BLOCK";
  }
}

function pickPrimaryDetectFinding(e: EvidencePackageV0) {
  const detect = (e.findings ?? []).filter((f: any) => f.kind === "detect");
  if (!detect.length) return null;

  detect.sort((a: any, b: any) => {
    const ra = RISK_ORDER.indexOf(a.risk);
    const rb = RISK_ORDER.indexOf(b.risk);
    if (rb !== ra) return rb - ra;
    return (b.score ?? 0) - (a.score ?? 0);
  });

  return detect[0];
}

function summarizeSources(e: EvidencePackageV0): string {
  const chunks = e.normalized?.canonical?.promptChunksCanonical ?? [];
  const sources = new Set<string>();

  // prompt always exists logically (user prompt)
  sources.add("user");

  for (const ch of chunks as any[]) {
    if (ch?.source) sources.add(String(ch.source));
  }

  return Array.from(sources).sort().join(", ");
}

function inputOneLiner(e: EvidencePackageV0, maxN: number): string {
  const prompt = e.rawDigest?.prompt?.preview ?? "";
  const chunks = e.normalized?.canonical?.promptChunksCanonical ?? [];

  const retrieval = (chunks as any[])
    .map((ch, i) => ({ ...ch, i }))
    .filter(x => x.source === "retrieval");

  if (!retrieval.length) return `userPrompt="${clip(prompt, maxN)}"`;

  const r0 = retrieval[0];
  return `userPrompt="${clip(prompt, maxN)}" | retrieval#${r0.i}="${clip(r0.text ?? "", maxN)}"`;
}

function obfuscationBadges(e: EvidencePackageV0): string {
  const tags = new Set<string>();

  for (const f of e.findings ?? []) {
    if (f.kind === "sanitize" && f.scanner === "unicode_sanitizer") tags.add("🧩 unicode");
    if (f.kind === "sanitize" && f.scanner === "hidden_ascii_tags") tags.add("🏷️ tags");

    const mv = (f.evidence as any)?.matchedViews;
    if (Array.isArray(mv)) {
      if (mv.includes("revealed")) tags.add("👀 revealed");
      if (mv.includes("skeleton")) tags.add("🦴 skeleton");
    }

    if (f.target?.view === "revealed") tags.add("👀 revealed");
    if (f.target?.view === "skeleton") tags.add("🦴 skeleton");
  }

  const arr = Array.from(tags);
  return arr.length ? arr.join(" · ") : "none";
}

function whereOf(f: any): string {
  if (!f?.target) return "N/A";
  if (f.target.field === "prompt") return `prompt@${f.target.view}`;
  return `chunk(${f.target.source ?? "unknown"}#${f.target.chunkIndex ?? -1})@${f.target.view}`;
}

function ruleLine(primary: any): string {
  if (!primary) return "N/A";
  const ev: any = primary.evidence ?? {};
  const ruleId = ev.ruleId ? `ruleId=${ev.ruleId}` : "ruleId=N/A";
  const cat = ev.category ? `category=${ev.category}` : "category=N/A";
  return `${ruleId} | ${cat}`;
}

function matchedViewsLine(primary: any): string {
  if (!primary) return "matchedViews=[]";
  const mv = (primary.evidence as any)?.matchedViews;
  if (!Array.isArray(mv)) return "matchedViews=[]";
  return `matchedViews=[${mv.join(", ")}]`;
}

function topReason(e: EvidencePackageV0, maxN: number): string {
  const r = (e.decision?.reasons ?? [])[0] ?? "";
  return r ? clip(r, maxN) : "(none)";
}

function detailsBlock(e: EvidencePackageV0, maxN: number): string {
  const list = (e.findings ?? []).map((f: any) => {
    const ev: any = f.evidence ?? {};
    const mv = Array.isArray(ev.matchedViews) ? ` matchedViews=[${ev.matchedViews.join(", ")}]` : "";
    const ruleId = ev.ruleId ? ` ruleId=${ev.ruleId}` : "";
    const cat = ev.category ? ` category=${ev.category}` : "";
    const snip = ev.snippet ? ` snippet="${clip(ev.snippet, maxN)}"` : "";
    return `- ${f.kind}/${f.scanner} (${f.risk}, score=${f.score}) @ ${whereOf(f)} — ${f.summary}${ruleId}${cat}${mv}${snip}`;
  }).join("\n") || "- (none)";

  return `
<details>
<summary><strong>Technical details (optional)</strong></summary>

### Findings
${list}

### Root hash
- ${e.integrity?.rootHash}

</details>
`.trim();
}

/**
 * RedTeam-like markdown report:
 * - Main summary in a text block (terminal style)
 * - Minimal notes for humans
 * - Optional technical details hidden
 */
export function renderEvidenceReportEN(e: EvidencePackageV0, opts: ReportOptions = {}): string {
  const maxN = opts.maxPreviewChars ?? 120;
  const includeNotes = opts.includeNotes ?? true;
  const includeDetails = opts.includeDetails ?? false;

  const action = e.decision.action as VerdictAction;
  const badge = badgeForAction(action);

  const detectFindings = (e.findings ?? []).filter((f: any) => f.kind === "detect");
  const primary = pickPrimaryDetectFinding(e);

  const sources = summarizeSources(e);
  const indicators = obfuscationBadges(e);

  const primaryLine = primary
    ? `Primary: ${primary.scanner} | risk=${primary.risk} | view=${primary.target.view} | ${matchedViewsLine(primary)}`
    : `Primary: N/A`;

  const decisionLine = `Decision: ${action} | DetectFindings: ${detectFindings.length} | TotalFindings: ${(e.findings ?? []).length}`;

  const reportHeader = `# ${badge} Schnabel Audit (RedTeam-style)

\`\`\`text
⚔️  Audit Turn (${e.requestId})
Source=${sources}
${decisionLine}
${primaryLine}
Rule: ${ruleLine(primary)}
Indicators: ${indicators}
RootHash: ${e.integrity?.rootHash}
--------------------------------------------------
\`\`\`
`;

  const notes = includeNotes ? `## Notes
- Input: ${inputOneLiner(e, maxN)}
- Top reason: ${topReason(e, maxN)}
- Recommendation: Treat retrieval as untrusted; drop suspicious chunks and re-run retrieval if needed.
` : "";

  const details = includeDetails ? `\n${detailsBlock(e, maxN)}\n` : "";

  return `${reportHeader}\n${notes}\n${details}`.trim() + "\n";
}
