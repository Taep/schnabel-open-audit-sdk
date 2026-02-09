import type { NormalizedInput } from "../normalizer/types.js";
import type { Finding } from "./types.js";
import type { Scanner, ScannerContext, ScannerOutput } from "./scanners/scanner.js";
import { ensureViews } from "./views.js";

export interface ScanOptions {
  mode?: "runtime" | "audit";
  failFast?: boolean;

  /**
   * If failFast is enabled, stop scanning when a finding meets/overrides this threshold.
   * Default: "high"
   */
  failFastRisk?: "high" | "critical";

  /**
   * Per-scanner execution timeout in milliseconds.
   * If a scanner exceeds this limit, it is aborted and an error is thrown.
   * Default: 30 000 (30 s)
   */
  scannerTimeoutMs?: number;
}

function isFailFastHit(
  risk: Finding["risk"],
  threshold: NonNullable<ScanOptions["failFastRisk"]>
): boolean {
  if (threshold === "critical") return risk === "critical";
  return risk === "high" || risk === "critical";
}

/**
 * scanSignals()
 * - Runs scanners sequentially (chain).
 * - Allows scanners to mutate the working input (sanitizers/enrichers).
 * - Aggregates findings.
 * - Optionally stops early (failFast).
 * - Ensures multi-view (raw/sanitized/revealed/skeleton) is initialized at chain start.
 *
 * Added safety:
 * - Validates scanner objects to avoid "Cannot read properties of undefined (reading 'run')".
 */
export async function scanSignals(
  input: NormalizedInput,
  scanners: Scanner[],
  options: ScanOptions = {}
): Promise<{ input: NormalizedInput; findings: Finding[] }> {
  const ctx: ScannerContext = {
    mode: options.mode ?? "runtime",
    nowMs: Date.now(),
  };

  const findings: Finding[] = [];
  const failFast = options.failFast ?? false;
  const failFastRisk = options.failFastRisk ?? "high";

  // Working input that can be updated by sanitizers/enrichers
  let current = ensureViews(input);

  const timeoutMs = options.scannerTimeoutMs ?? 30_000;

  for (let i = 0; i < scanners.length; i++) {
    const scanner = scanners[i];

    // Defensive validation (helps debug wrong imports/exports)
    if (!scanner || typeof scanner.run !== "function") {
      const name = scanner?.name ?? "(unknown)";
      throw new Error(
        `scanSignals: invalid scanner at index ${i}. ` +
        `Expected object with .run(), got: ${String(scanner)} (name=${name})`
      );
    }

    const out: ScannerOutput = await Promise.race([
      scanner.run(current, ctx),
      new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error(`scanSignals: scanner "${scanner.name}" timed out after ${timeoutMs}ms`)),
          timeoutMs,
        ),
      ),
    ]);

    if (!out || !out.input || !Array.isArray(out.findings)) {
      throw new Error(
        `scanSignals: scanner "${scanner.name}" returned invalid output. ` +
        `Expected { input, findings[] }.`
      );
    }

    // Preserve views across scanners (in case a scanner forgets to carry it)
    const next = out.input.views ? out.input : { ...out.input, views: current.views };
    current = ensureViews(next);

    if (out.findings.length) findings.push(...out.findings);

    if (failFast && out.findings.some((f: Finding) => isFailFastHit(f.risk, failFastRisk))) {
      break;
    }
  }

  return { input: current, findings };
}
