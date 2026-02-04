// examples/red-team/scenarios.ts

export interface AttackExpectedResult {
  shouldDetect: boolean;
  expectedMatchedViewsInclude?: string[];
}

export interface AttackScenario {
  id?: string;
  name: string;
  description?: string;
  source: "user" | "retrieval" | "system";
  basePayload: string;  // <-- 옛날엔 payload였음
  encoding?: string;
  
  // [여기가 중요!] 이 expected 객체가 정의되어 있어야 합니다.
  expected: AttackExpectedResult;
}

export const ATTACK_SCENARIOS: AttackScenario[] = [];