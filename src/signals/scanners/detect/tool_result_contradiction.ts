import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

function looksLikeSuccessClaim(text: string): boolean {
  const t = text.toLowerCase();

  const en =
    /\b(success|successful|completed|done|finished|created|updated|deleted|sent|executed|connected|retrieved)\b/.test(t) ||
    /\b(it is|it's)\s+(done|complete|successful)\b/.test(t);

  const ko =
    /(성공|완료|처리(되었|됐|했습니다)|끝났(습니다)?|완료했(습니다)?|정상(적으로)?\s*처리)/.test(text);

  return en || ko;
}

function looksLikeFailureClaim(text: string): boolean {
  const t = text.toLowerCase();

  const en =
    /\b(fail|failed|failure|error|unable|cannot|can't|could not)\b/.test(t) ||
    /\b(not possible|not able)\b/.test(t);

  const ko =
    /(실패|오류|에러|불가능|할 수 없|못했|문제가 발생)/.test(text);

  return en || ko;
}

function snippet(text: string, max = 160): string {
  const t = (text ?? "").toString().replace(/\s+/g, " ").trim();
  return t.length <= max ? t : t.slice(0, max) + "…";
}

/**
 * Named export is critical. (import { ToolResultContradictionScanner } ...)
 */
export const ToolResultContradictionScanner: Scanner = {
  name: "tool_result_contradiction",
  kind: "detect",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    const toolResults = input.raw.toolResults ?? [];
    const response = input.raw.responseText ?? input.canonical.responseText ?? "";

    if (!toolResults.length || !response.trim()) {
      return { input, findings };
    }

    const hasSuccessClaim = looksLikeSuccessClaim(response);
    const hasFailureClaim = looksLikeFailureClaim(response);

    const failed = toolResults.filter(t => t && t.ok === false);
    const succeeded = toolResults.filter(t => t && t.ok === true);

    // A) tool failed but response claims success => high
    if (failed.length > 0 && hasSuccessClaim) {
      findings.push({
        id: makeFindingId(this.name, input.requestId, "fail_but_success_claim"),
        kind: this.kind,
        scanner: this.name,
        score: 0.85,
        risk: "high",
        tags: ["tool", "contradiction", "gaslighting", "post_llm"],
        summary: "Tool result indicates failure, but the response appears to claim success.",
        target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
        evidence: {
          failedTools: failed.map(x => x.toolName),
          responseSnippet: snippet(response),
        },
      });
    }

    // B) tool succeeded but response claims failure => medium
    if (succeeded.length > 0 && hasFailureClaim && !hasSuccessClaim) {
      findings.push({
        id: makeFindingId(this.name, input.requestId, "success_but_failure_claim"),
        kind: this.kind,
        scanner: this.name,
        score: 0.55,
        risk: "medium",
        tags: ["tool", "contradiction", "post_llm"],
        summary: "Tool result indicates success, but the response appears to claim failure.",
        target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
        evidence: {
          succeededTools: succeeded.map(x => x.toolName),
          responseSnippet: snippet(response),
        },
      });
    }

    return { input, findings };
  },
};
