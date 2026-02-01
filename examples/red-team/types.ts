export type ScenarioSource = "user" | "retrieval" | "system";
export type TextView = "raw" | "sanitized" | "revealed" | "skeleton";
export type VerdictAction = "allow" | "allow_with_warning" | "challenge" | "block";

export type PayloadEncoding =
  | "plain"
  | "zero_width"
  | "tags"
  | "fullwidth"
  | "cyrillic_a";

export interface AttackScenario {
  id: string;
  name: string;
  description: string;

  source: ScenarioSource;
  basePayload: string;
  encoding: PayloadEncoding;

  expected: {
    /**
     * If true: require at least one detect finding.
     * If false: require zero detect findings.
     */
    shouldDetect: boolean;

    /**
     * Optional: constrain expected policy decision actions.
     * Example: ["allow", "allow_with_warning"]
     */
    expectedActions?: VerdictAction[];

    /**
     * Optional: expect primary detect finding to have this target.view
     */
    expectedPrimaryView?: TextView;

    /**
     * Optional: expect evidence.matchedViews includes these
     */
    expectedMatchedViewsInclude?: TextView[];

    /**
     * Optional: if set, require at least one detect finding with evidence.ruleId == this value
     */
    expectedRuleId?: string;
  };

  tags?: string[];
}
