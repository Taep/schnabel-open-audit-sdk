import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";
import type { HistoryStore, HistoryTurnV0 } from "../../../core/history_store.js";

type Options = {
  window?: number;   // how many recent turns to look at
};

function snippet(text: string, max = 160): string {
  const t = (text ?? "").toString().replace(/\s+/g, " ").trim();
  return t.length <= max ? t : t.slice(0, max) + "…";
}

// "I already did it" kind of claim (EN + KR)
function looksLikePriorActionClaim(text: string): boolean {
  const t = text.toLowerCase();

  const en =
    /\b(already|earlier|previously|as i (said|mentioned)|i have already|i already)\b/.test(t) ||
    /\b(i (did|have done|completed|finished) (it|that))\b/.test(t);

  const ko =
    /(이미|아까|전에|앞서|말씀드린|방금|처리(했|했습니다)|완료(했|했습니다)|끝냈(습니다)?)/.test(text);

  return en || ko;
}

// success-ish claim (EN + KR)
function looksLikeSuccessClaim(text: string): boolean {
  const t = text.toLowerCase();

  const en =
    /\b(success|successful|completed|done|finished|retrieved|created|updated|deleted)\b/.test(t) ||
    /\b(it is|it's)\s+(done|complete|successful)\b/.test(t);

  const ko =
    /(성공|완료|처리(되었|됐|했습니다)|끝났(습니다)?|정상(적으로)?\s*처리)/.test(text);

  return en || ko;
}

function countHistoryToolSuccess(turns: HistoryTurnV0[]): number {
  let n = 0;
  for (const t of turns) {
    if (t.succeededTools && t.succeededTools.length) n += t.succeededTools.length;
  }
  return n;
}

function lastTurn(turns: HistoryTurnV0[]): HistoryTurnV0 | undefined {
  return turns.length ? turns[turns.length - 1] : undefined;
}

/**
 * Create a multi-turn contradiction scanner.
 * - Requires a shared HistoryStore instance.
 * - Uses actor.sessionId as the key.
 */
export function createHistoryContradictionScanner(store: HistoryStore, opts: Options = {}): Scanner {
  const window = opts.window ?? 20;

  return {
    name: "history_contradiction",
    kind: "detect",

    async run(input: NormalizedInput) {
      const findings: Finding[] = [];

      const sessionId = input.raw.actor?.sessionId;
      if (!sessionId) return { input, findings };

      const response = input.raw.responseText ?? input.canonical.responseText ?? "";
      if (!response.trim()) return { input, findings };

      const history = await store.getRecent(sessionId, window);
      if (!history.length) return { input, findings };

      const priorClaim = looksLikePriorActionClaim(response);
      const successClaim = looksLikeSuccessClaim(response);

      const successCount = countHistoryToolSuccess(history);
      const prev = lastTurn(history);

      // Heuristic A:
      // - The response claims "already did it" + success, but history shows no successful tool evidence.
      if (priorClaim && successClaim && successCount === 0) {
        findings.push({
          id: makeFindingId("history_contradiction", input.requestId, "prior_success_no_evidence"),
          kind: "detect",
          scanner: "history_contradiction",
          score: 0.6,
          risk: "medium",
          tags: ["history", "contradiction", "gaslighting", "post_llm"],
          summary: "Response claims prior success, but session history has no evidence of successful tool outcomes.",
          target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
          evidence: {
            window,
            historyTurns: history.length,
            historySuccessToolCount: successCount,
            lastTurn: prev ? { requestId: prev.requestId, action: prev.action, risk: prev.risk } : null,
            responseSnippet: snippet(response),
          },
        });
      }

      return { input, findings };
    },
  };
}
