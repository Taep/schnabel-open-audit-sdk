import type { RiskLevel } from "../signals/types.js";

export type VerdictAction = "allow" | "allow_with_warning" | "challenge" | "block";

export interface HistoryTurnV0 {
  requestId: string;
  createdAtMs: number;
  action: VerdictAction;
  risk: RiskLevel;

  // Tool outcome snapshot (useful for gaslighting checks)
  succeededTools: string[];
  failedTools: string[];

  // Short response snippet (for light heuristic comparisons)
  responseSnippet?: string;

  // Optional: signal digest (rule ids / categories)
  ruleIds?: string[];
  categories?: string[];
}

export interface HistoryStore {
  getRecent(sessionId: string, limit: number): Promise<HistoryTurnV0[]>;
  append(sessionId: string, turn: HistoryTurnV0): Promise<void>;
}

/**
 * In-memory history store (good for dev/testing and app-level integration).
 * You can replace this with Redis/DB later without changing scanner logic.
 */
export class InMemoryHistoryStore implements HistoryStore {
  private maxTurns: number;
  private map = new Map<string, HistoryTurnV0[]>();

  constructor(opts?: { maxTurns?: number }) {
    this.maxTurns = opts?.maxTurns ?? 200;
  }

  async getRecent(sessionId: string, limit: number): Promise<HistoryTurnV0[]> {
    const arr = this.map.get(sessionId) ?? [];
    if (limit <= 0) return [];
    return arr.slice(Math.max(0, arr.length - limit));
  }

  async append(sessionId: string, turn: HistoryTurnV0): Promise<void> {
    const arr = this.map.get(sessionId) ?? [];
    arr.push(turn);
    if (arr.length > this.maxTurns) {
      arr.splice(0, arr.length - this.maxTurns);
    }
    this.map.set(sessionId, arr);
  }
}
