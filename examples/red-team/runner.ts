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
import { renderEvidenceReportEN } from "../../src/core/evidence_report_en.js";
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

/** Run timestamp for file names: YYYYMMDD-HHmmss */
function runTimestamp(): string {
  const d = new Date();
  const y = d.getFullYear();
  const M = String(d.getMonth() + 1).padStart(2, "0");
  const D = String(d.getDate()).padStart(2, "0");
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${y}${M}${D}-${h}${m}${s}`;
}

async function runRedTeam() {
  const scenariosDir = path.resolve("examples/red-team/scenarios.d");
  const redTeamOutDir = path.resolve("examples/red-team/out");
  const ts = runTimestamp();
  let scenarios: AttackScenario[] = [];
  try {
    scenarios = loadScenarios(scenariosDir);
  } catch (e) {
    console.error(c.red(`Failed to load scenarios: ${e}`));
    process.exit(1);
  }

  if (!fs.existsSync(redTeamOutDir)) fs.mkdirSync(redTeamOutDir, { recursive: true });
  fs.mkdirSync(path.join(redTeamOutDir, "evidence"), { recursive: true });
  fs.mkdirSync(path.join(redTeamOutDir, "reports"), { recursive: true });

  console.log(c.yellow("🔥 Schnabel Red Team Suite"));
  console.log(c.gray(`Loaded ${scenarios.length} scenarios from ${scenariosDir}`));
  console.log(c.gray(`Run: ${ts} → ${redTeamOutDir}/evidence (one file), ${redTeamOutDir}/reports\n`));

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
  type RunEntry = { scenario: AttackScenario; encoding: string; result?: Awaited<ReturnType<typeof runAudit>>; ok?: boolean; error?: string };
  const runEntries: RunEntry[] = [];

  for (const s of scenarios) {
    const encoding = (s.encoding ?? "plain") as PayloadEncoding;
    const payload = applyEncoding(s.basePayload, encoding);

    const event = {
      requestId: `rt-${s.id}-${Date.now()}`,
      timestamp: Date.now(),
      userPrompt: s.source === "user" ? payload : "Hello",
      systemPrompt: s.source === "system" ? payload : "You are a helpful assistant.",
      retrievalDocs: s.source === "retrieval" ? [{ text: payload, docId: "doc1" }] : [],
    };

    const req = fromAgentIngressEvent(event as any);

    console.log(`⚔️  ${c.blue(s.name)} (${c.gray(s.id || "no-id")})`);
    console.log(c.gray(`   Desc: ${s.description}`));
    console.log(c.gray(`   Source=${s.source}, Encoding=${encoding}`));

    try {
      const result = await runAudit(req, {
        scanners,
        scanOptions: { mode: "audit", failFast: false },
      });

      const detectFindings = result.findings.filter(f => f.kind === "detect");
      const hasDetect = detectFindings.length > 0;
      const expectedDetect = s.expected?.shouldDetect ?? true;
      const ok = hasDetect === expectedDetect;

      const primary = pickPrimaryDetectFinding(result.findings);
      let matchedViews: TextView[] = [];
      if (primary) {
        const mv = (primary.evidence as any)?.matchedViews;
        if (Array.isArray(mv)) matchedViews = mv;
        else if (primary.target?.view) matchedViews = [primary.target.view];
      }

      runEntries.push({ scenario: s, encoding, result, ok });

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
      const errMsg = String(e?.message ?? e);
      runEntries.push({ scenario: s, encoding, ok: false, error: errMsg });
      console.log(c.red("   ❌ CRASH"));
      console.log(c.red(`      └─ ${errMsg}`));
      console.log("");
      failed++;
    }

    console.log(c.gray("--------------------------------------------------"));
  }

  const byAction: Record<string, number> = { allow: 0, allow_with_warning: 0, challenge: 0, block: 0 };
  const byRisk: Record<string, number> = { none: 0, low: 0, medium: 0, high: 0, critical: 0 };
  let crashCount = 0;
  for (const e of runEntries) {
    if (e.error) {
      crashCount++;
      continue;
    }
    if (e.result?.decision) {
      const a = e.result.decision.action ?? "allow";
      byAction[a] = (byAction[a] ?? 0) + 1;
      const r = e.result.decision.risk ?? "none";
      byRisk[r] = (byRisk[r] ?? 0) + 1;
    }
  }

  const singleEvidencePath = path.join(redTeamOutDir, "evidence", `${ts}.redteam.evidence.json`);
  const redTeamEvidence = {
    schema: "schnabel-redteam-evidence-v0",
    runId: ts,
    runAt: new Date().toISOString(),
    summary: { total: scenarios.length, passed, failed, crashed: crashCount },
    entries: runEntries.map((e) => {
      if (e.error) {
        return { scenarioId: e.scenario.id ?? null, scenarioName: e.scenario.name, encoding: e.encoding, ok: false, error: e.error };
      }
      return {
        scenarioId: e.scenario.id ?? null,
        scenarioName: e.scenario.name,
        encoding: e.encoding,
        ok: e.ok,
        evidence: e.result!.evidence,
      };
    }),
  };
  fs.writeFileSync(singleEvidencePath, JSON.stringify(redTeamEvidence, null, 2), "utf8");
  console.log(c.gray(`\n📦 Evidence: ${singleEvidencePath}`));

  const singleReportPath = path.join(redTeamOutDir, "reports", `${ts}.redteam.report.en.md`);
  const reportParts: string[] = [
    `# Red Team Run`,
    ``,
    `**Run:** \`${ts}\` · **Time:** ${new Date().toISOString()}`,
    ``,
    `## Summary`,
    ``,
    `| Metric | Count |`,
    `|--------|-------|`,
    `| **Scenarios audited** | ${scenarios.length} |`,
    `| ✅ Passed | ${passed} |`,
    `| ❌ Failed | ${failed} |`,
    `| ❌ Crashed | ${crashCount} |`,
    ``,
    `### By decision (action)`,
    ``,
    `| Action | Count |`,
    `|--------|-------|`,
    `| allow | ${byAction.allow} |`,
    `| allow_with_warning | ${byAction.allow_with_warning} |`,
    `| challenge | ${byAction.challenge} |`,
    `| block | ${byAction.block} |`,
    ``,
    `### By risk level`,
    ``,
    `| Risk | Count |`,
    `|------|-------|`,
    `| none | ${byRisk.none} |`,
    `| low | ${byRisk.low} |`,
    `| medium | ${byRisk.medium} |`,
    `| high | ${byRisk.high} |`,
    `| critical | ${byRisk.critical} |`,
    ``,
    `---`,
    ``,
    `## Scenario details`,
    ``,
  ];
  for (const entry of runEntries) {
    const { scenario: s, encoding, result, ok, error } = entry;
    const verdict = ok === true ? "✅ PASS" : ok === false && error ? "❌ CRASH" : "❌ FAIL";
    reportParts.push(`## ${verdict} · ${s.name} (\`${s.id ?? "n/a"}\`)`);
    reportParts.push(``);
    reportParts.push(`- **Source:** ${s.source} · **Encoding:** ${encoding}`);
    reportParts.push(``);
    if (result?.evidence) {
      reportParts.push(renderEvidenceReportEN(result.evidence, { maxPreviewChars: 100, includeNotes: true, includeDetails: false }));
    } else if (error) {
      reportParts.push("```text\n❌ CRASH\n   └─ " + error + "\n```");
    }
    reportParts.push(``);
    reportParts.push(`---`);
    reportParts.push(``);
  }
  fs.writeFileSync(singleReportPath, reportParts.join("\n"), "utf8");
  console.log(c.gray(`\n📄 Report: ${singleReportPath}`));

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