import fs from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput, TextView } from "../../../normalizer/types.js";

import { makeFindingId } from "../../util.js";
import { ensureViews, VIEW_SCAN_ORDER, pickPreferredView } from "../../views.js";
import { loadRulePackFromUrl, type CompiledRulePack, type CompiledRule } from "../../rules/rulepack.js";
import { resolveAssetPath } from "../../../core/asset_path.js";

const DEFAULT_PACK_URL = pathToFileURL(resolveAssetPath("rules/default.rulepack.json", import.meta.url));

export interface RulePackScannerOptions {
  packUrl?: URL;
  name?: string;
  hotReload?: boolean;
  watchDebounceMs?: number;
  logger?: (level: "info" | "warn" | "error", message: string, meta?: Record<string, unknown>) => void;
}

type MatchDetail = { view: TextView; index: number; match: string };

function snippet(text: string, index: number, size = 80): string {
  const start = Math.max(0, index - 20);
  const end = Math.min(text.length, start + size);
  const s = text.slice(start, end);
  return s.length < text.length ? s + "…" : s;
}

export function createRulePackScanner(opts: RulePackScannerOptions = {}): Scanner & { close: () => void } {
  const scannerName = opts.name ?? "rulepack";
  const packUrl = opts.packUrl ?? DEFAULT_PACK_URL;

  const log = opts.logger ?? (() => {});
  const packPath = fileURLToPath(packUrl);

  let pack: CompiledRulePack | null = null;
  let packMtimeMs = 0;

  let watcher: fs.FSWatcher | null = null;
  let reloadTimer: NodeJS.Timeout | null = null;
  const debounceMs = opts.watchDebounceMs ?? 100;

  const reload = () => {
    try {
      pack = loadRulePackFromUrl(packUrl, { forceReload: true });
      const st = fs.statSync(packPath);
      packMtimeMs = st.mtimeMs;
      log("info", `[${scannerName}] rulepack reloaded`, { version: pack.version });
    } catch (e: any) {
      log("error", `[${scannerName}] rulepack reload failed (keeping previous pack)`, { error: String(e?.message ?? e) });
    }
  };

  const scheduleReload = () => {
    if (reloadTimer) clearTimeout(reloadTimer);
    reloadTimer = setTimeout(reload, debounceMs);
  };

  const ensurePack = (): CompiledRulePack => {
    if (!pack) {
      pack = loadRulePackFromUrl(packUrl);
      const st = fs.statSync(packPath);
      packMtimeMs = st.mtimeMs;
    }

    if (opts.hotReload) {
      try {
        const st = fs.statSync(packPath);
        if (st.mtimeMs > packMtimeMs) reload();
      } catch {}
    }

    return pack!;
  };

  if (opts.hotReload) {
    try {
      watcher = fs.watch(packPath, { persistent: false }, () => scheduleReload());
      log("info", `[${scannerName}] hot reload enabled`, { path: packPath });
    } catch (e: any) {
      log("warn", `[${scannerName}] fs.watch failed; relying on mtime reload`, { error: String(e?.message ?? e) });
    }
  }

  const close = () => {
    if (reloadTimer) clearTimeout(reloadTimer);
    reloadTimer = null;
    if (watcher) watcher.close();
    watcher = null;
  };

  const matchInText = (rule: CompiledRule, text: string): { hit: boolean; index?: number; match?: string; negated?: boolean } => {
    // Positive match
    if (rule.patternType === "keyword") {
      const hay = text.toLowerCase();
      const needle = rule._keywordLower!;
      const idx = hay.indexOf(needle);
      if (idx < 0) return { hit: false };

      // Negative cancels
      if (rule._negRe && rule._negRe.test(text)) return { hit: false, negated: true };
      return { hit: true, index: idx, match: rule.pattern };
    }

    const re = rule._re!;
    const m = re.exec(text);
    if (!m) return { hit: false };

    if (rule._negRe && rule._negRe.test(text)) return { hit: false, negated: true };
    return { hit: true, index: m.index, match: m[0] };
  };

    const matchAcrossViews = (rule: CompiledRule, viewMap: { raw: string; sanitized: string; revealed: string; skeleton: string }) => {
    const matchedViews: TextView[] = [];
    const details: Record<string, MatchDetail> = {};

    for (const v of VIEW_SCAN_ORDER) {
      const t = (viewMap as any)[v] ?? "";
      const res = matchInText(rule, t);
      if (res.hit && typeof res.index === "number") {
        matchedViews.push(v);
        details[v] = { view: v, index: res.index, match: res.match ?? "" };
      }
    }

    if (!matchedViews.length) return null;
    const preferred = pickPreferredView(matchedViews);
    return { matchedViews, preferred, detail: details[preferred] };
  };

  return {
    name: scannerName,
    kind: "detect",
    close,

    async run(input: NormalizedInput) {
      const base = ensureViews(input);
      const p = ensurePack();
      const { rules, version } = p;

      const findings: Finding[] = [];

      // Prompt rules
      for (const rule of rules) {
        if (!rule._scopes.includes("prompt")) continue;

        const hit = matchAcrossViews(rule, base.views!.prompt);
        if (!hit) continue;

        const view = hit.preferred;
        const text = (base.views!.prompt as any)[view] ?? "";
        const idx = hit.detail?.index ?? -1;

        findings.push({
          id: makeFindingId(scannerName, base.requestId, `${rule.id}:prompt:${view}`),
          kind: "detect",
          scanner: scannerName,
          score: rule.score,
          risk: rule.risk,
          tags: rule.tags ?? [rule.category],
          summary: rule.summary ?? `Rule matched: ${rule.id}`,
          target: { field: "prompt", view },
          evidence: {
            ruleId: rule.id,
            category: rule.category,
            patternType: rule.patternType,
            rulePackVersion: version,
            matchedViews: hit.matchedViews,
            snippet: idx >= 0 ? snippet(text, idx) : undefined,
          },
        });
      }

      // Chunk rules
      const chunks = base.views!.chunks ?? [];
      for (let i = 0; i < chunks.length; i++) {
        const ch = chunks[i];
        if (!ch) continue;

        for (const rule of rules) {
          if (!rule._scopes.includes("chunks")) continue;
          if (rule._sources && !rule._sources.has(ch.source)) continue;

          const hit = matchAcrossViews(rule, ch.views);
          if (!hit) continue;

          const view = hit.preferred;
          const text = (ch.views as unknown as Record<string, string>)[view] ?? "";
          const idx = hit.detail?.index ?? -1;

          findings.push({
            id: makeFindingId(scannerName, base.requestId, `${rule.id}:chunk:${i}:${ch.source}:${view}`),
            kind: "detect",
            scanner: scannerName,
            score: rule.score,
            risk: rule.risk,
            tags: rule.tags ?? [rule.category],
            summary: rule.summary ?? `Rule matched: ${rule.id}`,
            target: { field: "promptChunk", view, source: ch.source, chunkIndex: i },
            evidence: {
              ruleId: rule.id,
              category: rule.category,
              patternType: rule.patternType,
              rulePackVersion: version,
              matchedViews: hit.matchedViews,
              snippet: idx >= 0 ? snippet(text, idx) : undefined,
            },
          });
        }
      }

      return { input: base, findings };
    },
  };
}
