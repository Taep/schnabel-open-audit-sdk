import type { NormalizedInput } from "../../normalizer/types.js";
import type { Finding, ScannerKind } from "../types.js";

export interface ScannerContext {
  mode: "runtime" | "audit";
  nowMs: number;
}

/**
 * ScannerOutput
 * - input: potentially updated NormalizedInput (sanitizers may modify canonical fields)
 * - findings: zero or more findings produced by the scanner
 */
export interface ScannerOutput {
  input: NormalizedInput;
  findings: Finding[];
}

export interface Scanner {
  name: string;
  kind: ScannerKind;

  /**
   * Run scanner on a normalized input.
   * Scanners may optionally transform the input (e.g., sanitizers).
   */
  run(input: NormalizedInput, ctx: ScannerContext): Promise<ScannerOutput>;
}
