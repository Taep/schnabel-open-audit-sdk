import path from "node:path";
import { loadScenarios } from "./load_scenarios.js";
import type { PayloadEncoding, TextView, AttackScenario } from "./types.js";

import { fromAgentIngressEvent, type AgentIngressEvent } from "../../src/adapters/generic_agent.js";
import { runAudit } from "../../src/core/run_audit.js";

import { UnicodeSanitizerScanner } from "../../src/signals/scanners/sanitize/unicode_sanitizer.js";
import { HiddenAsciiTagsScanner } from "../../src/signals/scanners/sanitize/hidden_ascii_tags.js";
import { Uts39SkeletonViewScanner } from "../../src/signals/scanners/enrich/uts39_skeleton_view.js";
import { createRulePackScanner } from "../../src/signals/scanners/detect/rulepack_scanner.js";

// Simple ANSI colors
const c = {
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  blue: (s: string) => `\x1b[34m${s}\x1b[0m`,
  gray: (s: string) => `\x1b[90m${s}\x1b[0m`,
};

function toFullwidth(s: string): string {
  let out = "";
  for (const ch of s) {
    const code = ch.charCodeAt(0);
    if (code === 0x20) out += "\u3000";
    else if (code >= 0x21 && code <= 0x7e) out += String.fromCharCode(code + 0xFEE0);
    else out += ch;
  }
  return out;
}

function addZeroWidth(s: string): string {
  return s.split("").join("\u200B");
}

function encodeToTags(s: string): string {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code >= 0x20 && code <= 0x7e) out += String.fromCodePoint(0xE0000 + code);
  }
  return out;
}

function replaceCyrillicA(s: string): string {
  return s.replace(/a/g, "\u0430").replace(/A/g, "\u0410");
}

function applyEncoding(base: string, enc: PayloadEncoding): string {
  switch (enc) {
    case "plain": return base;
    case "zero_width": return addZeroWidth(base);
    case "tags": return encodeToTags(base);
    case "fullwidth": return toFullwidth(base);
    case "cyrillic_a": return replaceCyrillicA(base);
  }
}

function buildEvent(source: "user" | "system" | "retrieval", payload: string): AgentIngressEvent {
  return {
    requestId: `rt-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    timestamp: Date.now(),
    userPrompt: source === "user" ? payload : "Hello",
    systemPrompt: source === "system" ? payload : "You are a helpful assistant.",
    retrievalDocs: source === "retrieval" ? [{ text: payload, docId: "doc1" }] : [],
  };
}

function pickPrimaryDetectFinding(findings: any[]) {
  const order = ["none", "low", "medium", "high", "critical"];
  const detect = findings.filter((f: any) => f.kind === "detect");

  if (!detect.length) return null;

  detect.sort((a: any, b: any) => {
    const ra = order.indexOf(a.risk);
    const rb = order.indexOf(b.risk);
    if (rb !== ra) return rb - ra;
    return (b.score ?? 0) - (a.score ?? 0);
  });

  return detect[0];
}

function matchesExpected(s: AttackScenario, result: any) {
  const detectFindings = result.findings.filter((f: any) => f.kind === "detect");
  const primary = pickPrimaryDetectFinding(result.findings);
  const action = result.decision.action;

  // 1) Detection expectation
  let ok = true;

  if (s.expected.shouldDetect) {
    if (detectFindings.length === 0) ok = false;
  } else {
    if (detectFindings.length > 0) ok = false;
  }

  // 2) Optional action expectation
  if (s.expected.expectedActions && s.expected.expectedActions.length) {
    if (!s.expected.expectedActions.includes(action)) ok = false;
  }

  // 3) Optional ruleId expectation
  if (s.expected.expectedRuleId) {
    const hasRule = detectFindings.some((f: any) => (f.evidence?.ruleId === s.expected.expectedRuleId));
    if (!hasRule) ok = false;
  }

  // 4) Optional view expectations
  if (s.expected.shouldDetect && primary) {
    const matchedViews = (primary.evidence?.matchedViews ?? []) as TextView[];
    const primaryView = primary.target?.view as TextView | undefined;

    if (s.expected.expectedMatchedViewsInclude) {
      for (const v of s.expected.expectedMatchedViewsInclude) {
        if (!matchedViews.includes(v)) ok = false;
      }
    }

    if (s.expected.expectedPrimaryView) {
      if (primaryView !== s.expected.expectedPrimaryView) ok = false;
    }
  }

  return { ok, detectFindings, primary, action };
}

async function runRedTeam() {
  const scenariosDir = path.resolve("examples/red-team/scenarios.d");
  const scenarios = loadScenarios(scenariosDir);

  console.log(c.yellow("🔥 Schnabel Red Team Suite"));
  console.log(c.gray(`Loaded ${scenarios.length} scenarios from ${scenariosDir}`));
  console.log(c.gray("==================================================\n"));

  // Scanner chain (sanitize -> enrich -> detect)
  const rulepack = createRulePackScanner({ hotReload: false, logger: () => {} });
  const scanners = [
    UnicodeSanitizerScanner,
    HiddenAsciiTagsScanner,
    Uts39SkeletonViewScanner,
    rulepack,
  ];

  let passed = 0;
  let failed = 0;

  for (const s of scenarios) {
    const payload = applyEncoding(s.basePayload, s.encoding);
    const event = buildEvent(s.source, payload);
    const req = fromAgentIngressEvent(event);

    console.log(`⚔️  ${c.blue(s.name)} (${c.gray(s.id)})`);
    console.log(c.gray(`   Desc: ${s.description}`));
    console.log(c.gray(`   Source=${s.source}, Encoding=${s.encoding}`));

    const result = await runAudit(req, {
      scanners,
      scanOptions: { mode: "audit", failFast: false },
    });

    const verdict = matchesExpected(s, result);

    if (verdict.primary) {
      const matchedViews = (verdict.primary.evidence?.matchedViews ?? []) as string[];
      console.log(`   Decision: ${c.yellow(verdict.action)} | DetectFindings: ${verdict.detectFindings.length}`);
      console.log(`   Primary: ${verdict.primary.scanner} | risk=${verdict.primary.risk} | view=${verdict.primary.target.view} | matchedViews=[${matchedViews.join(", ")}]`);
    } else {
      console.log(`   Decision: ${c.yellow(verdict.action)} | DetectFindings: ${verdict.detectFindings.length}`);
      console.log(`   Primary: N/A`);
    }

    if (verdict.ok) {
      console.log(`   ✅ ${c.green("PASS")}\n`);
      passed++;
    } else {
      console.log(`   ❌ ${c.red("FAIL")}\n`);
      failed++;
    }

    console.log(c.gray("--------------------------------------------------"));
  }

  console.log(`\n📊 Summary: ${c.green(String(passed) + " Passed")}, ${c.red(String(failed) + " Failed")}`);

  rulepack.close();
  if (failed > 0) process.exit(1);
}

runRedTeam().catch(e => {
  console.error(c.red(`Fatal error: ${String(e?.message ?? e)}`));
  process.exit(1);
});
