import fs from "node:fs";
import path from "node:path";
import type { AttackScenario } from "./types.js";

function isObject(x: unknown): x is Record<string, unknown> {
  return typeof x === "object" && x !== null;
}

function assertScenario(o: any, file: string): AttackScenario {
  if (!isObject(o)) throw new Error(`Scenario file is not an object: ${file}`);

  const req = (k: string) => {
    if (!(k in o)) throw new Error(`Missing field "${k}" in ${file}`);
    return (o as any)[k];
  };

  // Required top-level fields
  req("id"); req("name"); req("description");
  req("source"); req("basePayload"); req("encoding");
  req("expected"); (o as any).expected.shouldDetect;

  // Minimal type checks (lightweight)
  if (typeof o.id !== "string") throw new Error(`id must be string: ${file}`);
  if (typeof o.name !== "string") throw new Error(`name must be string: ${file}`);
  if (typeof o.description !== "string") throw new Error(`description must be string: ${file}`);

  const allowedSource = new Set(["user", "retrieval", "system"]);
  if (!allowedSource.has(o.source)) throw new Error(`invalid source "${o.source}" in ${file}`);

  const allowedEncoding = new Set(["plain", "zero_width", "tags", "fullwidth", "cyrillic_a"]);
  if (!allowedEncoding.has(o.encoding)) throw new Error(`invalid encoding "${o.encoding}" in ${file}`);

  if (!isObject(o.expected)) throw new Error(`expected must be object: ${file}`);
  if (typeof o.expected.shouldDetect !== "boolean") throw new Error(`expected.shouldDetect must be boolean: ${file}`);

  return o as AttackScenario;
}

export function loadScenarios(dir: string): AttackScenario[] {
  const abs = path.resolve(dir);
  if (!fs.existsSync(abs)) {
    throw new Error(`Scenario directory not found: ${abs}`);
  }

  const files = fs.readdirSync(abs)
    .filter(f => f.endsWith(".scenario.json"))
    .sort();

  const scenarios: AttackScenario[] = [];
  for (const f of files) {
    const p = path.join(abs, f);
    const raw = fs.readFileSync(p, "utf8");
    let obj: any;
    try {
      obj = JSON.parse(raw);
    } catch (e: any) {
      throw new Error(`JSON parse failed: ${p}: ${String(e?.message ?? e)}`);
    }
    scenarios.push(assertScenario(obj, p));
  }

  // Ensure unique ids
  const ids = new Set<string>();
  for (const s of scenarios) {
    if (ids.has(s.id)) throw new Error(`Duplicate scenario id: ${s.id}`);
    ids.add(s.id);
  }

  return scenarios;
}
