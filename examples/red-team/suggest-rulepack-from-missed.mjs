#!/usr/bin/env node
/**
 * Reads examples/red-team/out/missed.json (from a prior redteam run)
 * and outputs rulepack rule candidates to examples/red-team/out/suggested-rules.json.
 *
 * Usage: npm run redteam:suggest
 *        node examples/red-team/suggest-rulepack-from-missed.mjs [path-to-missed.json]
 *
 * Then manually merge rules from suggested-rules.json into src/assets/rules/default.rulepack.json
 * (or run with --merge to append; review before committing).
 */

import fs from "node:fs";
import path from "node:path";

const MAX_PATTERN_LEN = 400;
const DEFAULT_MISSED_PATH = "examples/red-team/out/missed.json";
const DEFAULT_OUT_PATH = "examples/red-team/out/suggested-rules.json";

function slug(id) {
  return String(id).replace(/[^a-z0-9_-]/gi, "_").replace(/_+/g, "_").slice(0, 60) || "unknown";
}

function main() {
  const args = process.argv.slice(2);
  const merge = args.includes("--merge");
  const missedPath = args.find((a) => !a.startsWith("--")) || DEFAULT_MISSED_PATH;
  const absMissed = path.resolve(process.cwd(), missedPath);

  if (!fs.existsSync(absMissed)) {
    console.error("Missing missed file:", absMissed);
    console.error("Run: npm run redteam  first (with some failing scenarios).");
    process.exit(1);
  }

  let data;
  try {
    data = JSON.parse(fs.readFileSync(absMissed, "utf8"));
  } catch (e) {
    console.error("Failed to read/parse missed.json:", e.message);
    process.exit(1);
  }

  const scenarios = data.scenarios ?? [];
  if (scenarios.length === 0) {
    console.log("No missed scenarios in", absMissed);
    process.exit(0);
  }

  const suggested = [];
  for (const s of scenarios) {
    const payload = String(s.basePayload ?? "").trim();
    if (!payload) continue;

    const pattern = payload.length > MAX_PATTERN_LEN ? payload.slice(0, MAX_PATTERN_LEN) : payload;
    const ruleId = `redteam.missed.${slug(s.scenarioId ?? s.name ?? suggested.length)}`;

    suggested.push({
      id: ruleId,
      category: "redteam_missed",
      patternType: "keyword",
      pattern,
      risk: "high",
      score: 0.75,
      tags: ["redteam", "missed"],
      summary: (s.name || s.description || ruleId).slice(0, 120),
    });
  }

  const outDir = path.dirname(path.resolve(process.cwd(), DEFAULT_OUT_PATH));
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.resolve(process.cwd(), DEFAULT_OUT_PATH);
  fs.writeFileSync(outPath, JSON.stringify({ suggested, count: suggested.length }, null, 2), "utf8");
  console.log("Suggested rules:", suggested.length, "→", outPath);

  if (merge) {
    const rulepackPath = path.resolve(process.cwd(), "src/assets/rules/default.rulepack.json");
    if (!fs.existsSync(rulepackPath)) {
      console.error("RulePack not found:", rulepackPath);
      process.exit(1);
    }
    const pack = JSON.parse(fs.readFileSync(rulepackPath, "utf8"));
    pack.rules = pack.rules || [];
    const existingIds = new Set(pack.rules.map((r) => r.id));
    let added = 0;
    for (const r of suggested) {
      if (!existingIds.has(r.id)) {
        pack.rules.push(r);
        existingIds.add(r.id);
        added++;
      }
    }
    fs.writeFileSync(rulepackPath, JSON.stringify(pack, null, 2), "utf8");
    console.log("Merged", added, "new rule(s) into", rulepackPath, "(review before commit).");
    if (added > 0) console.log("  → Run: npm run build  then  npm run redteam  to verify (runner loads rulepack from dist).");
  } else {
    console.log("To merge into default.rulepack.json run: npm run redteam:suggest -- --merge");
  }
}

main();
