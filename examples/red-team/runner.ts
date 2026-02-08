import path from "node:path";
import fs from "node:fs";
import { loadScenarios } from "./load_scenarios.js";
import type { AttackScenario, PayloadEncoding, TextView } from "./types.js";

/** Missed scenario: expected detect but got none. Used to suggest new rulepack rules. */
export interface MissedScenario {
  scenarioId: string;
  name: string;
  description: string;
  source: string;
  encoding: string;
  basePayload: string;
}
import { fromAgentIngressEvent } from "../../src/adapters/generic_agent.js";
import { runAudit } from "../../src/core/run_audit.js";
import { UnicodeSanitizerScanner } from "../../src/signals/scanners/sanitize/unicode_sanitizer.js";
import { HiddenAsciiTagsScanner } from "../../src/signals/scanners/sanitize/hidden_ascii_tags.js";
import { SeparatorCollapseScanner } from "../../src/signals/scanners/sanitize/separator_collapse.js";
import { Uts39SkeletonViewScanner } from "../../src/signals/scanners/enrich/uts39_skeleton_view.js";
import { createRulePackScanner } from "../../src/signals/scanners/detect/rulepack_scanner.js";

// ANSI colors
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
    default: return base;
  }
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

async function runRedTeam() {
  const scenariosDir = path.resolve("examples/red-team/scenarios.d");
  let scenarios: AttackScenario[] = [];
  try {
      scenarios = loadScenarios(scenariosDir);
  } catch(e) {
      console.error(c.red(`Failed to load scenarios: ${e}`));
      process.exit(1);
  }

  console.log(c.yellow("🔥 Schnabel Red Team Suite"));
  console.log(c.gray(`Loaded ${scenarios.length} scenarios from ${scenariosDir}`));
  console.log(c.gray("==================================================\n"));

  // Scanner chain (sanitize -> enrich -> detect)
  const rulepack = createRulePackScanner({ hotReload: false, logger: () => {} });
  const scanners = [
    UnicodeSanitizerScanner,
    HiddenAsciiTagsScanner,
    SeparatorCollapseScanner,
    Uts39SkeletonViewScanner,
    rulepack,
  ];

  let passed = 0;
  let failed = 0;
  const missed: MissedScenario[] = [];

  for (const s of scenarios) {
    const encoding = (s.encoding ?? "plain") as PayloadEncoding;
    const payload = applyEncoding(s.basePayload, encoding);

    // Build ingress event (use adapter to keep provenance consistent)
    const event = {
      requestId: `rt-${s.id}-${Date.now()}`,
      timestamp: Date.now(),
      userPrompt: s.source === "user" ? payload : "Hello",
      systemPrompt: s.source === "system" ? payload : "You are a helpful assistant.",
      retrievalDocs: s.source === "retrieval" ? [{ text: payload, docId: "doc1" }] : [],
    };

    const req = fromAgentIngressEvent(event as any);

    console.log(`⚔️  ${c.blue(s.name)} (${c.gray(s.id || 'no-id')})`);
    console.log(c.gray(`   Desc: ${s.description}`));
    console.log(c.gray(`   Source=${s.source}, Encoding=${encoding}`));

    try {
      // ✅ IMPORTANT: runAudit MUST receive scanners via opts
      const result = await runAudit(req, {
        scanners,
        scanOptions: { mode: "audit", failFast: false },
      });

      const detectFindings = result.findings.filter(f => f.kind === "detect");
      const hasDetect = detectFindings.length > 0;

      const expectedDetect = s.expected?.shouldDetect ?? true;
      let ok = (hasDetect === expectedDetect);

      const primary = pickPrimaryDetectFinding(result.findings);
      let matchedViews: TextView[] = [];
      if (primary) {
        const mv = (primary.evidence as any)?.matchedViews;
        if (Array.isArray(mv)) matchedViews = mv;
        else if (primary.target?.view) matchedViews = [primary.target.view];
      }

      // Pass/fail is based only on shouldDetect vs hasDetect; which view matched is not used.
      console.log(`   Decision: ${c.yellow(result.decision.action)} | DetectFindings: ${detectFindings.length}`);

      if (primary) {
        console.log(`   Primary: ${primary.scanner} | risk=${primary.risk} | view=${primary.target.view} | matchedViews=[${matchedViews.join(", ")}]`);
      } else {
        console.log(`   Primary: N/A`);
      }

      if (ok) {
        console.log(`   ✅ ${c.green("PASS")}\n`);
        passed++;
      } else {
        console.log(`   ❌ ${c.red("FAIL")}`);
        console.log(c.gray(`      └─ Expected shouldDetect=${expectedDetect}, got=${hasDetect}`));
        console.log("");
        failed++;
        // Collect missed: we expected detection but got none → candidate for new rulepack rule
        if (expectedDetect && !hasDetect) {
          missed.push({
            scenarioId: s.id ?? "unknown",
            name: s.name ?? "",
            description: s.description ?? "",
            source: s.source,
            encoding,
            basePayload: s.basePayload,
          });
        }
      }
    } catch (e: any) {
      console.log(c.red("   ❌ CRASH"));
      console.log(c.red(`      └─ ${String(e?.message ?? e)}`));
      console.log("");
      failed++;
    }

    console.log(c.gray("--------------------------------------------------"));
  }

  console.log(`\n📊 Summary: ${c.green(String(passed) + " Passed")}, ${c.red(String(failed) + " Failed")}`);

  // Write missed scenarios (expected detect but got none) for rulepack suggestion
  const outDir = path.resolve("examples/red-team/out");
  if (missed.length > 0) {
    try {
      if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
      const missedPath = path.join(outDir, "missed.json");
      fs.writeFileSync(missedPath, JSON.stringify({ runAt: new Date().toISOString(), count: missed.length, scenarios: missed }, null, 2), "utf8");
      console.log(c.yellow(`\n📝 Missed ${missed.length} scenario(s) → ${missedPath}`));
      console.log(c.gray("   Run: npm run redteam:suggest  to generate rulepack rule candidates."));
    } catch (e: any) {
      console.log(c.gray(`   (Could not write missed.json: ${e?.message ?? e})`));
    }
  }

  if (typeof (rulepack as any).close === "function") (rulepack as any).close();

  if (failed > 0) process.exit(1);
}

runRedTeam();