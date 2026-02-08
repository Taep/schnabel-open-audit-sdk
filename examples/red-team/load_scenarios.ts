import * as fs from 'fs';
import * as path from 'path';
import type { AttackScenario } from "./types.js";

/**
 * Loads attack scenarios from JSON files in the given directory.
 * Each scenario may be a single object or an array; encoding defaults to "plain" if omitted.
 */
export function loadScenarios(dir: string): AttackScenario[] {
  if (!fs.existsSync(dir)) return [];

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  let allScenarios: AttackScenario[] = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(dir, file), 'utf-8');
      const loaded = JSON.parse(content);
      const list = Array.isArray(loaded) ? loaded : [loaded];

      list.forEach((s: any) => {
        if (!s.encoding) s.encoding = "plain";
      });

      allScenarios = [...allScenarios, ...list];
    } catch (e) {
      console.error(`Failed to load ${file}: ${e}`);
    }
  }
  return allScenarios;
}