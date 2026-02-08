/**
 * Red-team scenario types. Each scenario must define expected.shouldDetect.
 */

export interface AttackExpectedResult {
  shouldDetect: boolean;
  expectedMatchedViewsInclude?: string[];
}

export interface AttackScenario {
  id?: string;
  name: string;
  description?: string;
  source: "user" | "retrieval" | "system";
  basePayload: string;
  encoding?: string;
  expected: AttackExpectedResult;
}

export const ATTACK_SCENARIOS: AttackScenario[] = [];