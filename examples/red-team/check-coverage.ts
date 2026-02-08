/**
 * Checks whether each scenario payload (from scenarios.d) is matched by the current rulepack
 * (static pattern check) and whether the pipeline actually detects it. Use when debugging
 * failures after merging new rules.
 *
 * Usage: npm run redteam:check
 */

import path from "node:path";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { loadScenarios } from "./load_scenarios.js";
import type { AttackScenario, PayloadEncoding } from "./types.js";
import { fromAgentIngressEvent } from "../../src/adapters/generic_agent.js";
import { runAudit } from "../../src/core/run_audit.js";
import { UnicodeSanitizerScanner } from "../../src/signals/scanners/sanitize/unicode_sanitizer.js";
import { HiddenAsciiTagsScanner } from "../../src/signals/scanners/sanitize/hidden_ascii_tags.js";
import { SeparatorCollapseScanner } from "../../src/signals/scanners/sanitize/separator_collapse.js";
import { Uts39SkeletonViewScanner } from "../../src/signals/scanners/enrich/uts39_skeleton_view.js";
import { createRulePackScanner } from "../../src/signals/scanners/detect/rulepack_scanner.js";
import { loadRulePackFromUrl } from "../../src/signals/rules/rulepack.js";
import { resolveAssetPath } from "../../src/core/asset_path.js";
import type { CompiledRule } from "../../src/signals/rules/rulepack.js";

const c = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  gray: (s: string) => `\x1b[90m${s}\x1b[0m`,
};

function toFullwidth(s: string): string {
  let out = "";
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    if (code === 0x20) out += "\u3000";
    else if (code >= 0x21 && code <= 0x7e) out += String.fromCharCode(code + 0xfee0);
    else out += ch;
  }
  return out;
}
function addZeroWidth(s: string): string {
  return s.split("").join("\u200b");
}
function encodeToTags(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) out += String.fromCodePoint(0xe0000 + code);
  }
  return out;
}
function replaceCyrillicA(s: string): string {
  return s.replace(/a/g, "\u0430").replace(/A/g, "\u0410");
}
function applyEncoding(base: string, enc: PayloadEncoding): string {
  switch (enc) {
    case "plain":
      return base;
    case "zero_width":
      return addZeroWidth(base);
    case "tags":
      return encodeToTags(base);
    case "fullwidth":
      return toFullwidth(base);
    case "cyrillic_a":
      return replaceCyrillicA(base);
    default:
      return base;
  }
}

/** Whether the rule matches the payload string (same logic as rulepack, single text). */
function ruleMatchesText(rule: CompiledRule, text: string): boolean {
  if (rule.patternType === "keyword") {
    const hay = text.toLowerCase();
    const needle = rule._keywordLower!;
    if (hay.indexOf(needle) < 0) return false;
    if (rule._negRe && rule._negRe.test(text)) return false;
    return true;
  }
  if (!rule._re!.test(text)) return false;
  if (rule._negRe && rule._negRe.test(text)) return false;
  return true;
}

/** Rule ids that match this payload (static: only the payload string is considered). */
function rulesMatchingPayload(pack: { rules: CompiledRule[] }, payload: string): string[] {
  const ids: string[] = [];
  for (const r of pack.rules) {
    if (ruleMatchesText(r, payload)) ids.push(r.id);
  }
  return ids;
}

async function main() {
  const scenariosDir = path.resolve("examples/red-team/scenarios.d");
  let scenarios: AttackScenario[] = [];
  try {
    scenarios = loadScenarios(scenariosDir);
  } catch (e) {
    console.error(c.red("Failed to load scenarios: " + String(e)));
    process.exit(1);
  }
  if (scenarios.length === 0) {
    console.log("No scenarios in", scenariosDir);
    process.exit(0);
  }

  const packUrl = pathToFileURL(resolveAssetPath("rules/default.rulepack.json", import.meta.url));
  let pack: ReturnType<typeof loadRulePackFromUrl>;
  try {
    pack = loadRulePackFromUrl(packUrl, { forceReload: true });
  } catch (e: any) {
    console.error(c.red("Failed to load rulepack: " + (e?.message ?? e)));
    process.exit(1);
  }

  const rulepack = createRulePackScanner({ hotReload: false, logger: () => {} });
  const scanners = [
    UnicodeSanitizerScanner,
    HiddenAsciiTagsScanner,
    SeparatorCollapseScanner,
    Uts39SkeletonViewScanner,
    rulepack,
  ];

  console.log(c.gray("RulePack: " + packUrl.pathname));
  console.log(c.gray("Rules: " + pack.rules.length + "\n"));

  type Row = {
    id: string;
    name: string;
    expected: boolean;
    payloadSnippet: string;
    staticMatchIds: string[];
    actualDetect: boolean;
    ok: boolean;
  };
  const rows: Row[] = [];

  for (const s of scenarios) {
    const encoding = (s.encoding ?? "plain") as PayloadEncoding;
    const payload = applyEncoding(s.basePayload, encoding);

    const event = {
      requestId: `check-${s.id}-${Date.now()}`,
      timestamp: Date.now(),
      userPrompt: s.source === "user" ? payload : "Hello",
      systemPrompt: s.source === "system" ? payload : "You are a helpful assistant.",
      retrievalDocs: s.source === "retrieval" ? [{ text: payload, docId: "doc1" }] : [],
    };
    const req = fromAgentIngressEvent(event as any);

    let actualDetect = false;
    try {
      const result = await runAudit(req, {
        scanners,
        scanOptions: { mode: "audit", failFast: false },
      });
      actualDetect = result.findings.some((f) => f.kind === "detect");
    } catch (_) {
      actualDetect = false;
    }

    const staticMatchIds = rulesMatchingPayload(pack, payload);
    const expected = s.expected?.shouldDetect ?? true;
    const ok = actualDetect === expected;
    const snippet = payload.length > 50 ? payload.slice(0, 50) + "…" : payload;

    rows.push({
      id: s.id,
      name: s.name ?? "",
      expected,
      payloadSnippet: snippet,
      staticMatchIds,
      actualDetect,
      ok,
    });
  }

  if (typeof (rulepack as any).close === "function") (rulepack as any).close();

  const expectedDetect = rows.filter((r) => r.expected);
  const failed = rows.filter((r) => !r.ok);
  const missed = rows.filter((r) => r.expected && !r.actualDetect);
  const noStaticRule = missed.filter((r) => r.staticMatchIds.length === 0);
  const hasStaticRuleButNoDetect = missed.filter((r) => r.staticMatchIds.length > 0);

  console.log("Summary");
  console.log("   Scenarios: " + rows.length + ", expected detect: " + expectedDetect.length);
  console.log("   FAIL: " + failed.length + " (expected detect but missed: " + missed.length + ", expected no detect but fired: " + (failed.length - missed.length) + ")");
  console.log("");
  console.log("   Missed with no matching rule: " + c.yellow(String(noStaticRule.length)));
  console.log("   Missed with matching rule (view/scope etc.): " + c.yellow(String(hasStaticRuleButNoDetect.length)));
  console.log("");

  if (noStaticRule.length > 0) {
    console.log(c.gray("--- Missed scenarios with no rule match (add or strengthen rules) ---"));
    for (const r of noStaticRule) {
      console.log("  " + r.id + " | " + r.payloadSnippet);
    }
    console.log("");
  }
  if (hasStaticRuleButNoDetect.length > 0) {
    console.log(c.gray("--- Rule matches payload but pipeline did not detect (check view/scope) ---"));
    for (const r of hasStaticRuleButNoDetect) {
      console.log("  " + r.id + " | static rules: " + r.staticMatchIds.join(", ") + " | " + r.payloadSnippet);
    }
  }

  const outPath = path.resolve("examples/red-team/out/coverage-check.json");
  try {
    const outDir = path.dirname(outPath);
    if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(
      outPath,
      JSON.stringify(
        {
          summary: {
            total: rows.length,
            failed: failed.length,
            missed,
            noStaticRule: noStaticRule.length,
            hasStaticRuleButNoDetect: hasStaticRuleButNoDetect.length,
          },
          rows: rows.map((r) => ({
            id: r.id,
            expected: r.expected,
            staticMatchIds: r.staticMatchIds,
            actualDetect: r.actualDetect,
            ok: r.ok,
          })),
        },
        null,
        2
      ),
      "utf8"
    );
    console.log(c.gray("\nDetails: " + outPath));
  } catch (_) {}

  process.exit(failed.length > 0 ? 1 : 0);
}

main();
