import fs from "node:fs";
import { fileURLToPath } from "node:url";
import type { InputSource } from "../../normalizer/types.js";
import type { RiskLevel } from "../types.js";

export type RuleScope = "prompt" | "chunks" | "response";
export type PatternType = "regex" | "keyword";

export interface RuleSpec {
  id: string;
  category: string;

  patternType: PatternType;
  pattern: string;

  // For regex
  flags?: string;

  // Optional exclusion (false positive reduction)
  // If positive pattern matches but negativePattern also matches, we skip emitting a finding.
  negativePattern?: string;
  negativeFlags?: string;

  risk: RiskLevel;
  score: number;

  tags?: string[];
  summary?: string;

  // Optional targeting controls
  scopes?: RuleScope[];        // default: ["prompt","chunks"]
  sources?: InputSource[];     // only for chunks
}

export interface RulePack {
  version: string;
  rules: RuleSpec[];
}

export interface CompiledRule extends RuleSpec {
  _scopes: RuleScope[];
  _sources?: Set<InputSource>;
  _re?: RegExp;               // compiled regex (if patternType=regex)
  _negRe?: RegExp;            // compiled negative regex (optional)
  _keywordLower?: string;     // normalized keyword (if patternType=keyword)
  _signature: string;         // used for dedup
}

export interface CompiledRulePack {
  version: string;
  rules: CompiledRule[];
}

const CACHE = new Map<string, CompiledRulePack>();

const MAX_PATTERN_LEN = 400;

/**
 * Very small perf-guard heuristics for regex safety.
 * This does not fully prevent ReDoS but helps catch obvious footguns.
 */
function perfGuardRegex(ruleId: string, pattern: string, label: "pattern" | "negativePattern" = "pattern"): void {
  if (pattern.length > MAX_PATTERN_LEN) {
    throw new Error(`RulePack: regex too long (>${MAX_PATTERN_LEN}) for ${label} in rule: ${ruleId}`);
  }

  // Disallow backreferences (\1..\9) which can be expensive and tricky
  if (/(\\[1-9])/.test(pattern)) {
    throw new Error(`RulePack: backreferences are not allowed for ${label} in rule: ${ruleId}`);
  }

  // Basic nested quantifier heuristic: ( ... + )+ , ( ... * )+ , etc.
  if (/\([^)]*[*+][^)]*\)\s*[*+]/.test(pattern)) {
    throw new Error(`RulePack: potential nested quantifier (ReDoS risk) for ${label} in rule: ${ruleId}`);
  }

  // Disallow greedy .\s+.* which can cause catastrophic backtracking.
  // Non-greedy [\s\S]*? or .+? are accepted.
  if (/\\s[+*]\.(\*|\+)(?!\?)/.test(pattern)) {
    throw new Error(`RulePack: greedy \\s+.* pattern (ReDoS risk) for ${label} in rule: ${ruleId}. Use non-greedy .*? instead.`);
  }
}

const DEFAULT_SCOPES: RuleScope[] = ["prompt", "chunks"];

function normalizeScopes(scopes?: RuleScope[]): RuleScope[] {
  const s = scopes && scopes.length ? scopes : DEFAULT_SCOPES;
  const uniq = Array.from(new Set(s));
  // keep stable ordering
  return uniq.sort();
}

function normalizeFlags(flags?: string): string {
  const raw = (flags ?? "").trim();

  // Remove dangerous/stateful flags that make repeated tests tricky
  // - g (global): stateful lastIndex
  // - y (sticky): stateful
  const stripped = raw.replace(/[gy]/g, "");

  // Allow only i, m, s, u
  const allowed = stripped.split("").filter(ch => "imsu".includes(ch));
  // Dedup and stable sort
  return Array.from(new Set(allowed)).sort().join("");
}

function validateRule(rule: RuleSpec): void {
  if (!rule.id || typeof rule.id !== "string") throw new Error("RulePack: rule.id is required");
  if (!rule.category || typeof rule.category !== "string") throw new Error(`RulePack: category missing for ${rule.id}`);

  if (rule.patternType !== "regex" && rule.patternType !== "keyword") {
    throw new Error(`RulePack: invalid patternType for ${rule.id}`);
  }

  if (!rule.pattern || typeof rule.pattern !== "string") {
    throw new Error(`RulePack: pattern missing for ${rule.id}`);
  }

  if (typeof rule.score !== "number" || rule.score < 0 || rule.score > 1) {
    throw new Error(`RulePack: score must be 0..1 for ${rule.id}`);
  }

  const risk: RiskLevel = rule.risk;
  if (!["none", "low", "medium", "high", "critical"].includes(risk)) {
    throw new Error(`RulePack: invalid risk for ${rule.id}`);
  }

  if (rule.scopes) {
    for (const sc of rule.scopes) {
      if (sc !== "prompt" && sc !== "chunks" && sc !== "response") {
        throw new Error(`RulePack: invalid scope "${sc}" for ${rule.id}`);
      }
    }
  }

  if (rule.sources) {
    for (const src of rule.sources) {
      if (typeof src !== "string") throw new Error(`RulePack: invalid source for ${rule.id}`);
    }
  }

  if (rule.negativePattern && typeof rule.negativePattern !== "string") {
    throw new Error(`RulePack: negativePattern must be a string for ${rule.id}`);
  }
}

function compileRule(rule: RuleSpec): CompiledRule {
  validateRule(rule);

  const _scopes = normalizeScopes(rule.scopes);

  const compiled: CompiledRule = {
    ...rule,
    _scopes,
    _signature: "",
  };

  if (rule.sources?.length) {
    compiled._sources = new Set(rule.sources);
  }

  if (rule.patternType === "regex") {
    perfGuardRegex(rule.id, rule.pattern, "pattern");
    const flags = normalizeFlags(rule.flags);
    compiled.flags = flags;

    try {
      compiled._re = new RegExp(rule.pattern, flags);
    } catch (e) {
      throw new Error(`RulePack: regex compile failed for ${rule.id}: ${e instanceof Error ? e.message : String(e)}`);
    }
  } else {
    // keyword
    compiled._keywordLower = rule.pattern.toLowerCase();
  }

  // Optional negative regex
  if (rule.negativePattern) {
    perfGuardRegex(rule.id, rule.negativePattern, "negativePattern");
    const negFlags = normalizeFlags(rule.negativeFlags ?? rule.flags ?? "");
    compiled.negativeFlags = negFlags;

    try {
      compiled._negRe = new RegExp(rule.negativePattern, negFlags);
    } catch (e) {
      throw new Error(`RulePack: negative regex compile failed for ${rule.id}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  // signature for dedup across packs
  compiled._signature = [
    compiled.patternType,
    compiled.pattern,
    compiled.flags ?? "",
    compiled.negativePattern ?? "",
    compiled.negativeFlags ?? "",
    compiled.risk,
    String(compiled.score),
    compiled.category,
    compiled._scopes.join(","),
    compiled.sources?.join(",") ?? "",
  ].join("|");

  return compiled;
}

function compilePack(pack: RulePack): CompiledRulePack {
  if (!pack || typeof pack !== "object") throw new Error("RulePack: invalid pack object");
  if (!pack.version || typeof pack.version !== "string") throw new Error("RulePack: version is required");
  if (!Array.isArray(pack.rules)) throw new Error("RulePack: rules must be an array");

  // 1) enforce unique ids
  const ids = new Set<string>();
  for (const r of pack.rules) {
    if (ids.has(r.id)) throw new Error(`RulePack: duplicate rule id: ${r.id}`);
    ids.add(r.id);
  }

  // 2) compile
  const compiled = pack.rules.map(compileRule);

  // 3) dedup identical signatures (keep first occurrence; stable)
  const seenSig = new Set<string>();
  const deduped: CompiledRule[] = [];
  for (const r of compiled) {
    if (seenSig.has(r._signature)) continue;
    seenSig.add(r._signature);
    deduped.push(r);
  }

  // stable order by rule id
  deduped.sort((a, b) => a.id.localeCompare(b.id));

  return { version: pack.version, rules: deduped };
}

/**
 * Load a RulePack from a file URL (JSON only in v0).
 * The compiled pack is cached by file path.
 */
export function loadRulePackFromUrl(url: URL, opts?: { forceReload?: boolean }): CompiledRulePack {
  const path = fileURLToPath(url);

  if (!opts?.forceReload && CACHE.has(path)) {
    return CACHE.get(path)!;
  }

  if (!fs.existsSync(path)) {
    throw new Error(`RulePack: file not found: ${path}`);
  }

  const raw = fs.readFileSync(path, "utf8");
  let obj: unknown;

  try {
    obj = JSON.parse(raw);
  } catch (e) {
    throw new Error(`RulePack: JSON parse failed: ${path}: ${e instanceof Error ? e.message : String(e)}`);
  }

  const compiled = compilePack(obj as RulePack);
  CACHE.set(path, compiled);
  return compiled;
}
