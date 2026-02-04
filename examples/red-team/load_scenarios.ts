import * as fs from 'fs';
import * as path from 'path';
import type { AttackScenario } from "./types.js";

// [보조 함수] encoding 기본값 처리 포함
export function loadScenarios(dir: string): AttackScenario[] {
  if (!fs.existsSync(dir)) return [];
  
  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
  let allScenarios: AttackScenario[] = [];

  for (const file of files) {
    try {
      const content = fs.readFileSync(path.join(dir, file), 'utf-8');
      const loaded = JSON.parse(content);
      const list = Array.isArray(loaded) ? loaded : [loaded];
      
      // [수정] encoding이 없으면 'plain'으로 자동 설정
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