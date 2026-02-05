import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";
import type { HistoryStore, HistoryTurnV0 } from "../../../core/history_store.js";

type Options = {
  window?: number;
};

function snippet(text: string, max = 160): string {
  const t = (text ?? "").toString().replace(/\s+/g, " ").trim();
  return t.length <= max ? t : t.slice(0, max) + "…";
}

function looksLikeSuccessClaim(text: string): boolean {
  const t = text.toLowerCase();
  const en =
    /\b(success|successful|completed|done|finished|retrieved|created|updated|deleted)\b/.test(t) ||
    /\b(i (did|have done|completed|finished) (it|that))\b/.test(t);
  const ko =
    /(성공|완료|처리(했|했습니다|됐습니다)|끝냈(습니다)?|정상(적으로)?\s*처리)/.test(text);
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

function lastTurn(turns: HistoryTurnV0[]): HistoryTurnV0 | undefined {
  return turns.length ? turns[turns.length - 1] : undefined;
}

/**
 * Flip-Flop detector:
 * - Prior turn indicates failure (failed tools OR failure-claim snippet)
 * - Current response claims success
 * => medium/high risk, because the assistant is inconsistent across turns.
 */
export function createHistoryFlipFlopScanner(store: HistoryStore, opts: Options = {}): Scanner {
  const window = opts.window ?? 10;

  return {
    name: "history_flipflop",
    kind: "detect",

    async run(input: NormalizedInput) {
      const findings: Finding[] = [];

      const sessionId = input.raw.actor?.sessionId;
      if (!sessionId) return { input, findings };

      const response = input.raw.responseText ?? input.canonical.responseText ?? "";
      if (!response.trim()) return { input, findings };

      const history = await store.getRecent(sessionId, window);
      if (!history.length) return { input, findings };

      const prev = lastTurn(history);
      if (!prev) return { input, findings };

      const prevHadFailureEvidence =
        (prev.failedTools?.length ?? 0) > 0 ||
        (prev.responseSnippet ? looksLikeFailureClaim(prev.responseSnippet) : false);

      const currClaimsSuccess = looksLikeSuccessClaim(response);

      // If previous had failure evidence and current claims success => flip-flop.
      if (prevHadFailureEvidence && currClaimsSuccess) {
        findings.push({
          id: makeFindingId("history_flipflop", input.requestId, "prev_fail_now_success"),
          kind: "detect",
          scanner: "history_flipflop",
          score: 0.7,
          risk: "high",
          tags: ["history", "contradiction", "flipflop", "gaslighting", "post_llm"],
          summary: "Assistant appears inconsistent: previous turn indicates failure, but current response claims success.",
          target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
          evidence: {
            window,
            prevTurn: {
              requestId: prev.requestId,
              action: prev.action,
              risk: prev.risk,
              failedTools: prev.failedTools,
              responseSnippet: prev.responseSnippet ? snippet(prev.responseSnippet) : undefined,
            },
            currResponseSnippet: snippet(response),
          },
        });
      }

      return { input, findings };
    },
  };
}
