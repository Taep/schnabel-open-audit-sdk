import type { Scanner } from "../scanner.js";
import type { Finding, RiskLevel } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

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

/**
 * KeywordInjectionScanner
 * - Minimal demo scanner:
 *   - scans canonical prompt
 *   - scans provenance chunks (if present)
 * - Produces Findings with target info (prompt vs retrieval/system/user chunk)
 */
export const KeywordInjectionScanner: Scanner = {
  name: "keyword_injection",
  kind: "detect",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    const check = (text: string, target: Finding["target"], requestId: string) => {
      for (const p of PATTERNS) {
        if (p.re.test(text)) {
          findings.push({
            id: makeFindingId(
              this.name,
              requestId,
              `${p.key}:${target.field}:${target.source ?? "n/a"}:${target.chunkIndex ?? -1}`
            ),
            kind: this.kind,
            scanner: this.name,
            score: p.score,
            risk: p.risk,
            tags: p.tags,
            summary: p.summary,
            target,
            evidence: { pattern: p.key },
          });
        }
      }
    };

    // 1) Scan canonical prompt
    check(input.canonical.prompt, { field: "prompt" }, input.requestId);

    // 2) Scan provenance chunks if provided
    const chunks = input.canonical.promptChunksCanonical ?? [];
    for (let i = 0; i < chunks.length; i++) {
      const ch = chunks[i];
      check(ch.text, { field: "promptChunk", source: ch.source, chunkIndex: i }, input.requestId);
    }

    return { input, findings };
  },
};
