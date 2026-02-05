import type { Scanner } from "../signals/scanners/scanner.js";

// --- L2 sanitize / enrich / detect (prompt + retrieval) ---
import { UnicodeSanitizerScanner } from "../signals/scanners/sanitize/unicode_sanitizer.js";
import { HiddenAsciiTagsScanner } from "../signals/scanners/sanitize/hidden_ascii_tags.js";
import { SeparatorCollapseScanner } from "../signals/scanners/sanitize/separator_collapse.js";
import { Uts39SkeletonViewScanner } from "../signals/scanners/enrich/uts39_skeleton_view.js";
import { createRulePackScanner } from "../signals/scanners/detect/rulepack_scanner.js";

// --- Tool boundary guards (toolCalls args) ---
import { ToolArgsCanonicalizerScanner } from "../signals/scanners/sanitize/tool_args_canonicalizer.js";
import { ToolArgsSSRFScanner } from "../signals/scanners/detect/tool_args_ssrf.js";
import { ToolArgsPathTraversalScanner } from "../signals/scanners/detect/tool_args_path_traversal.js";

// --- Post-LLM contradiction detectors (toolResults vs responseText) ---
import { ToolResultContradictionScanner } from "../signals/scanners/detect/tool_result_contradiction.js";
import { ToolResultFactMismatchScanner } from "../signals/scanners/detect/tool_result_fact_mismatch.js";

export interface PresetOptions {
  // RulePack
  rulepackHotReload?: boolean;
  rulepackLogger?: (
    level: "info" | "warn" | "error",
    message: string,
    meta?: Record<string, unknown>
  ) => void;

  // Pre-LLM extras
  includeSeparatorCollapse?: boolean; // default true
  includeSkeletonView?: boolean;      // default true

  // Tool boundary guards
  includeToolArgsCanonicalizer?: boolean; // default true
  includeToolArgsGuards?: boolean;        // default true

  // Post-LLM contradiction detectors
  includeToolContradiction?: boolean; // default true
  includeToolFactMismatch?: boolean;  // default true
}

function makeRulepack(opts: PresetOptions) {
  return createRulePackScanner({
    hotReload: opts.rulepackHotReload ?? false,
    logger: opts.rulepackLogger ?? (() => {}),
  });
}

/**
 * Pre-LLM chain (before sending prompt to the model):
 * sanitize(prompt/retrieval) -> enrich(skeleton) -> detect(rulepack)
 */
export function createPreLLMScannerChain(opts: PresetOptions = {}): Scanner[] {
  const rulepack = makeRulepack(opts);

  const chain: Scanner[] = [
    UnicodeSanitizerScanner,
    HiddenAsciiTagsScanner,
  ];

  if (opts.includeSeparatorCollapse ?? true) {
    chain.push(SeparatorCollapseScanner);
  }

  if (opts.includeSkeletonView ?? true) {
    chain.push(Uts39SkeletonViewScanner);
  }

  chain.push(rulepack);

  return chain;
}

/**
 * Tool-boundary chain (run right before executing a tool call):
 * sanitize(tool args) -> detect(SSRF/path traversal)
 *
 * Note: This does NOT include rulepack/prompt scanners by default.
 */
export function createToolBoundaryScannerChain(opts: PresetOptions = {}): Scanner[] {
  const chain: Scanner[] = [];

  if (opts.includeToolArgsCanonicalizer ?? true) {
    chain.push(ToolArgsCanonicalizerScanner);
  }

  chain.push(ToolArgsSSRFScanner);
  chain.push(ToolArgsPathTraversalScanner);

  return chain;
}

/**
 * Post-LLM chain (after tool execution / after response generation):
 * pre-LLM chain + tool-boundary guards (optional) + post-LLM contradiction detectors
 */
export function createPostLLMScannerChain(opts: PresetOptions = {}): Scanner[] {
  const chain: Scanner[] = [];

  // Reuse pre-LLM protections (they will still work even post-LLM)
  chain.push(...createPreLLMScannerChain(opts));

  // Optional: also run tool args guards in post phase (useful if toolCalls are present in the same request)
  if (opts.includeToolArgsGuards ?? true) {
    chain.push(...createToolBoundaryScannerChain(opts));
  }

  // Post-LLM contradiction detectors
  if (opts.includeToolContradiction ?? true) {
    chain.push(ToolResultContradictionScanner);
  }

  if (opts.includeToolFactMismatch ?? true) {
    chain.push(ToolResultFactMismatchScanner);
  }

  return chain;
}
