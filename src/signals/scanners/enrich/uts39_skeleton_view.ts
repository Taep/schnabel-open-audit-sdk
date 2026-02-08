import fs from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { Scanner } from "../scanner.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { resolveAssetPath } from "../../../core/asset_path.js";
import { ensureViews } from "../../views.js";

/**
 * UTS#39 confusables.txt location in this repo:
 *   src/assets/uts39/confusables.txt
 */
const CONFUSABLES_URL = pathToFileURL(resolveAssetPath("uts39/confusables.txt", import.meta.url));

type ConfusablesData = {
  version: string;
  map: Map<string, number[]>;
  maxSrcLen: number;
};

let CACHE: ConfusablesData | null = null;

function parseHeaderVersion(lines: string[]): string {
  for (const line of lines.slice(0, 50)) {
    const m = line.match(/^#\s*Version:\s*([0-9.]+)/i);
    if (m && m[1]) return m[1];
  }
  return "unknown";
}

function parseHexSeq(s: string): number[] {
  return s.trim().split(/\s+/g).filter(Boolean).map(h => parseInt(h, 16));
}

function keyOf(seq: number[]): string {
  return seq.join("-");
}

function loadConfusables(): ConfusablesData {
  if (CACHE) return CACHE;

  const path = fileURLToPath(CONFUSABLES_URL);
  if (!fs.existsSync(path)) {
    throw new Error(
      `UTS#39 confusables.txt not found at: ${path}\n` +
      `Please place it at: src/assets/uts39/confusables.txt`
    );
  }

  const raw = fs.readFileSync(path, "utf8");
  const lines = raw.split(/\r?\n/);

  const version = parseHeaderVersion(lines);
  const map = new Map<string, number[]>();
  let maxSrcLen = 1;

  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;

    // Format: <src> ; <dst> ; <type> # comment
    const beforeHash = t.split("#")[0];
    if (beforeHash === undefined) continue;
    const parts = beforeHash.split(";").map(x => x.trim());
    if (parts.length < 2) continue;

    const p0 = parts[0];
    const p1 = parts[1];
    if (p0 === undefined || p1 === undefined) continue;

    const srcSeq = parseHexSeq(p0);
    const dstSeq = parseHexSeq(p1);
    if (!srcSeq.length || !dstSeq.length) continue;

    map.set(keyOf(srcSeq), dstSeq);
    if (srcSeq.length > maxSrcLen) maxSrcLen = srcSeq.length;
  }

  CACHE = { version, map, maxSrcLen };
  return CACHE;
}

function toCodePoints(s: string): number[] {
  const cps: number[] = [];
  for (const ch of s) cps.push(ch.codePointAt(0)!);
  return cps;
}

function fromCodePoints(cps: number[]): string {
  const CHUNK = 4096;
  let out = "";
  for (let i = 0; i < cps.length; i += CHUNK) {
    const chunk = cps.slice(i, i + CHUNK).filter((n): n is number => n !== undefined);
    out += String.fromCodePoint(...chunk);
  }
  return out;
}

/**
 * Compute UTS#39 skeleton:
 * - NFKC normalize first (UTS#39 compatible processing)
 * - Apply longest-match substitutions using confusables mapping
 */
function skeletonize(text: string, data: ConfusablesData): string {
  const nfkc = text.normalize("NFKC");
  const cps = toCodePoints(nfkc);

  const out: number[] = [];

  for (let i = 0; i < cps.length; ) {
    let matched = false;

    const max = Math.min(data.maxSrcLen, cps.length - i);
    for (let len = max; len >= 1; len--) {
      const key = keyOf(cps.slice(i, i + len));
      const dst = data.map.get(key);
      if (dst) {
        out.push(...dst);
        i += len;
        matched = true;
        break;
      }
    }

    if (!matched) {
      const cp = cps[i];
      if (cp !== undefined) out.push(cp);
      i += 1;
    }
  }

  return fromCodePoints(out);
}

/**
 * Uts39SkeletonViewScanner (enrich)
 * - Does NOT create findings; it enriches views.skeleton for prompt/chunks.
 * - We compute skeleton from the *revealed* view so hidden ASCII content is included.
 */
export const Uts39SkeletonViewScanner: Scanner = {
  name: "uts39_skeleton_view",
  kind: "enrich",

  async run(input: NormalizedInput) {
    const base = ensureViews(input);
    const views = base.views!;
    const data = loadConfusables();

    // Prompt skeleton from revealed
    const promptSkeleton = skeletonize(views.prompt.revealed, data);
    views.prompt.skeleton = promptSkeleton;

    // Chunk skeletons
    const chunks = views.chunks ?? [];
    for (const ch of chunks) {
      ch.views.skeleton = skeletonize(ch.views.revealed, data);
    }

    // No findings (pure enrichment)
    return { input: { ...base, views }, findings: [] };
  },
};
