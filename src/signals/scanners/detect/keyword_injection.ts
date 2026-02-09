import type { Scanner } from "../scanner.js";
import type { Finding, RiskLevel } from "../../types.js";
import type { NormalizedInput, TextView, TextViewSet } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";
import { ensureViews, VIEW_SCAN_ORDER, pickPreferredView } from "../../views.js";

type PatternSpec = {
  key: string;
  re: RegExp;
  risk: RiskLevel;
  score: number;
  tags: string[];
  summary: string;
};

const PATTERNS: PatternSpec[] = [
  {
    key: "ignore_previous_instructions",
    re: /ignore\s+(all|any|previous)\s+instructions/i,
    risk: "high",
    score: 0.8,
    tags: ["prompt_injection", "override"],
    summary: "Instruction override pattern detected.",
  },
  {
    key: "reveal_system_prompt",
    re: /system\s+prompt|reveal\s+.*system/i,
    risk: "high",
    score: 0.8,
    tags: ["prompt_exfil", "system_disclosure"],
    summary: "System prompt disclosure attempt detected.",
  },
];

function matchViews(re: RegExp, viewMap: TextViewSet): TextView[] {
  const matched: TextView[] = [];
  for (const v of VIEW_SCAN_ORDER) {
    const text = viewMap[v as keyof typeof viewMap] ?? "";
    if (re.test(text)) matched.push(v);
  }
  return matched;
}

/**
 * KeywordInjectionScanner
 * - Scans multiple views (raw/sanitized/revealed) without double-counting
 * - Emits a single Finding per (pattern, target), with matchedViews evidence
 */
export const KeywordInjectionScanner: Scanner = {
  name: "keyword_injection",
  kind: "detect",

  async run(input: NormalizedInput) {
    const base = ensureViews(input);
    const views = base.views!;
    const findings: Finding[] = [];

    // 1) Prompt
    for (const p of PATTERNS) {
      const matchedViews = matchViews(p.re, views.prompt);
      if (!matchedViews.length) continue;

      const view = pickPreferredView(matchedViews);
      findings.push({
        id: makeFindingId(this.name, base.requestId, `${p.key}:prompt`),
        kind: this.kind,
        scanner: this.name,
        score: p.score,
        risk: p.risk,
        tags: p.tags,
        summary: p.summary,
        target: { field: "prompt", view },
        evidence: {
          pattern: p.key,
          matchedViews,
        },
      });
    }

    // 2) Chunks
    const chunks = views.chunks ?? [];
    for (let i = 0; i < chunks.length; i++) {
      const ch = chunks[i];
      if (!ch) continue;
      const viewMap = ch.views;

      for (const p of PATTERNS) {
        const matchedViews = matchViews(p.re, viewMap);
        if (!matchedViews.length) continue;

        const view = pickPreferredView(matchedViews);
        findings.push({
          id: makeFindingId(this.name, base.requestId, `${p.key}:chunk:${i}:${ch.source}`),
          kind: this.kind,
          scanner: this.name,
          score: p.score,
          risk: p.risk,
          tags: p.tags,
          summary: p.summary,
          target: { field: "promptChunk", view, source: ch.source, chunkIndex: i },
          evidence: {
            pattern: p.key,
            matchedViews,
          },
        });
      }
    }

    return { input: base, findings };
  },
};
