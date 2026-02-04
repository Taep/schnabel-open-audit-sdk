import type { Scanner } from "../signals/scanners/scanner.js";

import { UnicodeSanitizerScanner } from "../signals/scanners/sanitize/unicode_sanitizer.js";
import { HiddenAsciiTagsScanner } from "../signals/scanners/sanitize/hidden_ascii_tags.js";
import { Uts39SkeletonViewScanner } from "../signals/scanners/enrich/uts39_skeleton_view.js";
import { createRulePackScanner } from "../signals/scanners/detect/rulepack_scanner.js";
import { ToolResultContradictionScanner } from "../signals/scanners/detect/tool_result_contradiction.js";
import { SeparatorCollapseScanner } from "../signals/scanners/sanitize/separator_collapse.js";

export interface PresetOptions {
  rulepackHotReload?: boolean;
  rulepackLogger?: (level: "info" | "warn" | "error", message: string, meta?: Record<string, unknown>) => void;

  /**
   * If true, include post-LLM contradiction scanner (toolResults vs responseText).
   * This should be enabled for POST-LLM checks.
   */
  includeToolContradiction?: boolean;
}

/**
 * Pre-LLM chain:
 * - sanitize: unicode obfuscation, TAG hidden channel
 * - enrich: skeleton view (UTS#39)
 * - detect: rulepack (multi-view scan)
 */
export function createPreLLMScannerChain(opts: PresetOptions = {}): Scanner[] {
  const rulepack = createRulePackScanner({
    hotReload: opts.rulepackHotReload ?? false,
    logger: opts.rulepackLogger ?? (() => {}),
  });

  return [
    UnicodeSanitizerScanner,
    HiddenAsciiTagsScanner,
    SeparatorCollapseScanner,
    Uts39SkeletonViewScanner,
    rulepack,
  ];
}

/**
 * Post-LLM chain:
 * - everything in pre-LLM
 * - plus tool/result contradiction detector (gaslighting / hallucinated success)
 */
export function createPostLLMScannerChain(opts: PresetOptions = {}): Scanner[] {
  const chain = createPreLLMScannerChain(opts);

  if (opts.includeToolContradiction ?? true) {
    chain.push(ToolResultContradictionScanner);
  }

  return chain;
}
