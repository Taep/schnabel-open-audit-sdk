import type { EvidencePackageV0 } from "./evidence_package.js";

export interface ReportOptions {
  maxPreviewChars?: number;  // default 180
  includeIntegrityItems?: boolean; // default true
}

function clip(s: string, n: number): string {
  const t = (s ?? "").toString();
  if (t.length <= n) return t;
  return t.slice(0, n) + "…";
}

function fmtList(items: string[]): string {
  return items.map(x => `- ${x}`).join("\n");
}

function getTopFindings(e: EvidencePackageV0, n = 5) {
  const order = ["none", "low", "medium", "high", "critical"];
  return [...(e.findings ?? [])].sort((a, b) => {
    const ra = order.indexOf(a.risk);
    const rb = order.indexOf(b.risk);
    if (rb !== ra) return rb - ra;
    return (b.score ?? 0) - (a.score ?? 0);
  }).slice(0, n);
}

function findingWhere(f: any): string {
  if (f.target?.field === "prompt") return `prompt@${f.target.view}`;
  return `chunk(${f.target.source ?? "unknown"}#${f.target.chunkIndex ?? -1})@${f.target.view}`;
}

export function renderEvidenceReportKR(e: EvidencePackageV0, opts: ReportOptions = {}): string {
  const maxN = opts.maxPreviewChars ?? 180;
  const includeIntegrity = opts.includeIntegrityItems ?? true;

  const rulepackVersions = e.meta?.rulePackVersions?.length ? e.meta.rulePackVersions.join(", ") : "N/A";
  const decision = e.decision;
  const topFindings = getTopFindings(e, 5);

  const reasons = (decision?.reasons ?? []).map(r => `1) ${r}`).join("\n");
  const scanners = (e.scanners ?? []).map(s => `- ${s.name} (${s.kind})`).join("\n");

  // Provenance summary
  const chunks = e.normalized?.canonical?.promptChunksCanonical ?? [];
  const chunkSummary = chunks.length
    ? chunks.map((ch, i) => `- Chunk #${i} (source=${ch.source}): ${clip(ch.text ?? "", maxN)}`).join("\n")
    : "- (none)";

  // Multi-view summary for changed chunks (basic heuristic: if any view differs)
  const viewLines: string[] = [];
  const vchunks = e.scanned?.views?.chunks ?? [];
  for (let i = 0; i < vchunks.length; i++) {
    const vc = vchunks[i];
    const v = vc.views;
    const diff =
      v.raw !== v.sanitized || v.sanitized !== v.revealed || v.revealed !== v.skeleton;

    if (!diff) continue;

    viewLines.push(`### Chunk #${i} (source=${vc.source}) views`);
    viewLines.push(`- raw: \`${clip(v.raw, maxN)}\``);
    viewLines.push(`- sanitized: \`${clip(v.sanitized, maxN)}\``);
    viewLines.push(`- revealed: \`${clip(v.revealed, maxN)}\``);
    viewLines.push(`- skeleton: \`${clip(v.skeleton, maxN)}\``);
    viewLines.push("");
  }
  const viewsSection = viewLines.length ? viewLines.join("\n") : "_(의미 있는 view 변화 없음)_";

  // Findings table-ish
  const findingsMd = (e.findings ?? []).map(f => {
    const ev: any = f.evidence ?? {};
    const rulePart = ev.ruleId ? ` ruleId=${ev.ruleId}` : "";
    const mv = Array.isArray(ev.matchedViews) ? ` matchedViews=[${ev.matchedViews.join(", ")}]` : "";
    const snip = ev.snippet ? ` snippet="${clip(ev.snippet, maxN)}"` : "";
    return `- **${f.kind}/${f.scanner}** (${f.risk}, score=${f.score}) @ ${findingWhere(f)}${rulePart}${mv}${snip}`;
  }).join("\n");

  const integrityItems = includeIntegrity
    ? (e.integrity?.items ?? []).map(it => `- ${it.name}: \`${it.hash}\``).join("\n")
    : "_(hidden)_";

  const topFindingMd = topFindings.map(f => {
    return `- [${f.risk.toUpperCase()}|${f.scanner}] ${findingWhere(f)}: ${f.summary}`;
  }).join("\n");

  return `# Schnabel Audit Summary (Evidence v0)

## A. 실행 정보
- **Request ID**: \`${e.requestId}\`
- **Schema**: \`${e.schema}\`
- **GeneratedAt(ms)**: \`${e.generatedAtMs}\`
- **Integrity Root Hash (sha256)**: \`${e.integrity?.rootHash}\`
- **RulePack Version(s)**: \`${rulepackVersions}\`

## B. 최종 판단(Policy Decision)
- **Action**: \`${decision?.action}\`
- **Risk**: \`${decision?.risk}\`
- **Confidence**: \`${decision?.confidence}\`

### Decision Reasons
${reasons || "_(none)_"}

## C. 입력 요약(Provenance)
### Prompt
- preview: \`${clip(e.rawDigest?.prompt?.preview ?? "", maxN)}\`
- length: \`${e.rawDigest?.prompt?.length}\`
- hash: \`${e.rawDigest?.prompt?.hash}\`

### Prompt Chunks (canonical)
${chunkSummary}

## D. Multi-View 변화(핵심 관측값)
${viewsSection}

## E. 스캐너 체인(실행 순서)
${scanners || "_(none)_"}

## F. Findings (전체)
${findingsMd || "_(none)_"}

## G. Top Findings (요약)
${topFindingMd || "_(none)_"}

## H. 무결성(Integrity)
${integrityItems}

`;
}
