import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

/**
 * ToolResultFactMismatchScanner (POST-LLM)
 * - Detects "fact mismatch" between toolResults.result and responseText.
 * - Conservative MVP:
 *   - Only checks a small allowlist of keys (balance/total/count/found/exists/success).
 *   - Only checks primitive values (number/boolean).
 *   - Requires response to include explicit claim patterns.
 */

type Fact =
  | { kind: "number"; toolName: string; key: string; value: number; aliases: string[] }
  | { kind: "boolean"; toolName: string; key: string; value: boolean; aliases: string[] };

const KEY_ALIASES: Record<string, string[]> = {
  // numeric
  balance: ["balance", "account balance", "잔액"],
  total: ["total", "sum", "총액", "합계"],
  count: ["count", "results", "items", "개수", "건수", "수량", "결과"],
  amount: ["amount", "금액"],
  score: ["score", "점수"],

  // boolean-ish
  found: ["found", "exists", "located", "존재", "찾음", "발견"],
  exists: ["exists", "present", "존재"],
  success: ["success", "succeeded", "ok", "성공", "정상"],
};

function snippet(text: string, index: number, max = 140): string {
  const t = (text ?? "").toString();
  const start = Math.max(0, index - 30);
  const end = Math.min(t.length, start + max);
  const s = t.slice(start, end).replace(/\s+/g, " ").trim();
  return s.length < t.length ? s + "…" : s;
}

function getResponse(input: NormalizedInput): string {
  return (input.raw.responseText ?? input.canonical.responseText ?? "").toString();
}

function isPrimitiveNumber(x: unknown): x is number {
  return typeof x === "number" && Number.isFinite(x);
}

function isPrimitiveBoolean(x: unknown): x is boolean {
  return typeof x === "boolean";
}

function normalizeKey(k: string): string {
  return k.trim().toLowerCase();
}

function buildAliases(key: string): string[] {
  const k = normalizeKey(key);
  const fromMap = KEY_ALIASES[k] ?? [k];

  // Also add snake_case -> spaced alias
  const spaced = k.includes("_") ? k.replace(/_/g, " ") : null;
  const arr = [...fromMap, ...(spaced ? [spaced] : [])];

  return Array.from(new Set(arr));
}

function extractFacts(toolName: string, result: unknown): Fact[] {
  const facts: Fact[] = [];

  if (result && typeof result === "object" && !Array.isArray(result)) {
    const obj = result as Record<string, unknown>;

    for (const [k0, v] of Object.entries(obj)) {
      const k = normalizeKey(k0);

      // only allowlist keys (conservative)
      if (!(k in KEY_ALIASES)) continue;

      if (isPrimitiveNumber(v)) {
        facts.push({ kind: "number", toolName, key: k, value: v, aliases: buildAliases(k) });
      } else if (isPrimitiveBoolean(v)) {
        facts.push({ kind: "boolean", toolName, key: k, value: v, aliases: buildAliases(k) });
      }
    }

    return facts;
  }

  // If result is an array, treat its length as "count" (optional, conservative)
  if (Array.isArray(result)) {
    facts.push({ kind: "number", toolName, key: "count", value: result.length, aliases: buildAliases("count") });
  }

  return facts;
}

function findNumberClaim(response: string, alias: string): { claimed: number; index: number; match: string } | null {
  // Patterns like: "balance is 100", "balance: 100", "잔액 100", "count=5"
  const a = alias.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`\\b${a}\\b\\s*(?:is|=|:)?\\s*\\$?(-?\\d+(?:\\.\\d+)?)`, "i");

  const m = re.exec(response);
  if (!m) return null;

  const num = Number(m[1]);
  if (!Number.isFinite(num)) return null;

  return { claimed: num, index: m.index, match: m[0] };
}

function findCountClaim(response: string): { claimed: number; index: number; match: string } | null {
  // Patterns like: "Found 5 results", "5 results", "결과 5개"
  const patterns = [
    /\bfound\s+(\d+)\s+(results|items)\b/i,
    /\b(\d+)\s+(results|items)\b/i,
    /(결과|총)\s*(\d+)\s*(개|건)/,
    /(\d+)\s*(개|건)\s*(결과)?/,
  ];

  for (const re of patterns) {
    const m = re.exec(response);
    if (!m) continue;

    const num = Number(m[1] ?? m[2]);
    if (!Number.isFinite(num)) continue;

    return { claimed: num, index: m.index, match: m[0] };
  }

  return null;
}

function looksLikeFoundPositive(response: string, aliases: string[]): boolean {
  const t = response.toLowerCase();

  // explicit negatives to avoid false positives
  const neg = /\b(not found|no results|doesn't exist|cannot find)\b/i;
  if (neg.test(response) || /(없(음|습니다)|찾지 못|발견 못|존재하지 않)/.test(response)) return false;

  for (const a of aliases) {
    const ax = a.toLowerCase();
    if (t.includes(ax)) return true;
  }

  // also accept generic success words
  if (/\bfound\b|\bexists\b|\blocated\b/i.test(response)) return true;
  if (/(찾았|발견|존재)/.test(response)) return true;

  return false;
}

function looksLikeFoundNegative(response: string): boolean {
  return /\b(not found|no results|doesn't exist|cannot find)\b/i.test(response) ||
    /(없(음|습니다)|찾지 못|발견 못|존재하지 않)/.test(response);
}

export const ToolResultFactMismatchScanner: Scanner = {
  name: "tool_result_fact_mismatch",
  kind: "detect",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    const response = getResponse(input);
    const toolResults = input.raw.toolResults ?? [];

    if (!response.trim() || !toolResults.length) return { input, findings };

    for (const tr of toolResults as any[]) {
      if (!tr) continue;

      const toolName = String(tr.toolName ?? "unknown_tool");
      const ok = tr.ok === true;

      // We mostly care about ok=true results for fact mismatch,
      // because ok=false is already handled by ToolResultContradictionScanner.
      if (!ok) continue;

      const facts = extractFacts(toolName, tr.result);

      for (const fact of facts) {
        if (fact.kind === "number") {
          let claim = null as { claimed: number; index: number; match: string } | null;

          if (fact.key === "count") {
            claim = findCountClaim(response);
          } else {
            for (const alias of fact.aliases) {
              claim = findNumberClaim(response, alias);
              if (claim) break;
            }
          }

          if (!claim) continue;

          if (claim.claimed !== fact.value) {
            findings.push({
              id: makeFindingId(this.name, input.requestId, `${toolName}:${fact.key}:number_mismatch`),
              kind: this.kind,
              scanner: this.name,
              score: 0.75,
              risk: "high",
              tags: ["tool", "fact_mismatch", "post_llm"],
              summary: `Response appears to claim ${fact.key}=${claim.claimed}, but tool returned ${fact.value}.`,
              target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
              evidence: {
                toolName,
                key: fact.key,
                toolValue: fact.value,
                claimedValue: claim.claimed,
                responseSnippet: snippet(response, claim.index),
              },
            });
          }
        }

        if (fact.kind === "boolean") {
          // found/exists/success booleans
          // if tool says false but response looks positive -> mismatch
          if (fact.value === false && looksLikeFoundPositive(response, fact.aliases)) {
            findings.push({
              id: makeFindingId(this.name, input.requestId, `${toolName}:${fact.key}:bool_mismatch_pos`),
              kind: this.kind,
              scanner: this.name,
              score: 0.7,
              risk: "high",
              tags: ["tool", "fact_mismatch", "post_llm"],
              summary: `Response appears to claim ${fact.key}=true, but tool returned false.`,
              target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
              evidence: {
                toolName,
                key: fact.key,
                toolValue: false,
                responseSnippet: snippet(response, 0),
              },
            });
          }

          // if tool says true but response looks negative -> medium (could be partial)
          if (fact.value === true && looksLikeFoundNegative(response)) {
            findings.push({
              id: makeFindingId(this.name, input.requestId, `${toolName}:${fact.key}:bool_mismatch_neg`),
              kind: this.kind,
              scanner: this.name,
              score: 0.5,
              risk: "medium",
              tags: ["tool", "fact_mismatch", "post_llm"],
              summary: `Response appears to claim ${fact.key}=false, but tool returned true.`,
              target: { field: "promptChunk", view: "raw", source: "assistant", chunkIndex: 0 },
              evidence: {
                toolName,
                key: fact.key,
                toolValue: true,
                responseSnippet: snippet(response, 0),
              },
            });
          }
        }
      }
    }

    return { input, findings };
  },
};
