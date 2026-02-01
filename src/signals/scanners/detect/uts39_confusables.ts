import fs from "node:fs";
import { fileURLToPath } from "node:url";

import type { Scanner } from "../scanner.js";
import type { Finding, RiskLevel } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

/**
 * We load UTS#39 confusables.txt from the repo asset path.
 * Expected location:
 *   src/assets/uts39/confusables.txt
 */
const CONFUSABLES_URL = new URL("../../../assets/uts39/confusables.txt", import.meta.url);

type ConfusablesData = {
  version: string;
  map: Map<string, number[]>;
  maxSrcLen: number;
};

let CONFUSABLES_CACHE: ConfusablesData | null = null;

function parseHeaderVersion(lines: string[]): string {
  // confusables.txt typically contains lines like:
  // # Version: 17.0.0
  for (const line of lines.slice(0, 40)) {
    const m = line.match(/^#\s*Version:\s*([0-9.]+)/i);
    if (m) return m[1];
  }
  return "unknown";
}

function parseHexSeq(s: string): number[] {
  const parts = s.trim().split(/\s+/g).filter(Boolean);
  return parts.map(h => parseInt(h, 16));
}

function keyOf(seq: number[]): string {
  // join with "-" to form a stable key
  return seq.join("-");
}

function loadConfusables(): ConfusablesData {
  if (CONFUSABLES_CACHE) return CONFUSABLES_CACHE;

  const path = fileURLToPath(CONFUSABLES_URL);
  if (!fs.existsSync(path)) {
    throw new Error(
      `UTS#39 confusables.txt not found at: ${path}\n` +
      `Please copy your confusables.txt to: src/assets/uts39/confusables.txt`
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

    // Format:
    // <src> ; <dst> ; <type> # comment
    const parts = t.split("#")[0].split(";").map(x => x.trim());
    if (parts.length < 2) continue;

    const srcSeq = parseHexSeq(parts[0]);
    const dstSeq = parseHexSeq(parts[1]);
    if (!srcSeq.length || !dstSeq.length) continue;

    map.set(keyOf(srcSeq), dstSeq);
    if (srcSeq.length > maxSrcLen) maxSrcLen = srcSeq.length;
  }

  CONFUSABLES_CACHE = { version, map, maxSrcLen };
  return CONFUSABLES_CACHE;
}

function toCodePoints(s: string): number[] {
  const cps: number[] = [];
  for (const ch of s) cps.push(ch.codePointAt(0)!);
  return cps;
}

function fromCodePoints(cps: number[]): string {
  // Avoid stack overflow with huge arrays by chunking
  const CHUNK = 4096;
  let out = "";
  for (let i = 0; i < cps.length; i += CHUNK) {
    out += String.fromCodePoint(...cps.slice(i, i + CHUNK));
  }
  return out;
}

function skeletonize(text: string, data: ConfusablesData): { nfkc: string; skeleton: string; replaced: number; changed: boolean } {
  const nfkc = text.normalize("NFKC");
  const cps = toCodePoints(nfkc);

  const out: number[] = [];
  let replaced = 0;

  for (let i = 0; i < cps.length; ) {
    let matched = false;

    const max = Math.min(data.maxSrcLen, cps.length - i);
    for (let len = max; len >= 1; len--) {
      const key = keyOf(cps.slice(i, i + len));
      const dst = data.map.get(key);
      if (dst) {
        out.push(...dst);
        i += len;
        replaced++;
        matched = true;
        break;
      }
    }

    if (!matched) {
      out.push(cps[i]);
      i += 1;
    }
  }

  const skeleton = fromCodePoints(out);
  const changed = skeleton !== nfkc;
  return { nfkc, skeleton, replaced, changed };
}

function detectMixedScripts(s: string): boolean {
  // Lightweight mixed-script heuristic (Latin + Cyrillic/Greek)
  const hasLatin = /[A-Za-z]/.test(s);
  const hasCyrillic = /[\u0400-\u04FF]/.test(s);
  const hasGreek = /[\u0370-\u03FF]/.test(s);
  const count = (hasLatin ? 1 : 0) + (hasCyrillic ? 1 : 0) + (hasGreek ? 1 : 0);
  return count >= 2;
}

function riskFor(changed: boolean, mixed: boolean): { risk: RiskLevel; score: number } {
  if (mixed) return { risk: "high", score: 0.75 };
  if (changed) return { risk: "medium", score: 0.5 };
  return { risk: "none", score: 0.0 };
}

function preview(s: string, max = 140): string {
  const t = s.trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/**
 * Uts39ConfusablesScanner
 * - Computes UTS#39 skeleton using confusables.txt
 * - Flags mixed-script and/or skeleton changes
 * - Does NOT mutate the input by default (detection + evidence)
 */
export const Uts39ConfusablesScanner: Scanner = {
  name: "uts39_confusables",
  kind: "detect",

  async run(input: NormalizedInput) {
    const data = loadConfusables();
    const findings: Finding[] = [];

    const check = (text: string, target: Finding["target"], requestId: string, key: string) => {
      const { nfkc, skeleton, replaced, changed } = skeletonize(text, data);
      const mixed = detectMixedScripts(nfkc);

      const { risk, score } = riskFor(changed, mixed);
      if (risk === "none") return;

      findings.push({
        id: makeFindingId(this.name, requestId, key),
        kind: this.kind,
        scanner: this.name,
        score,
        risk,
        tags: ["uts39", "confusables", mixed ? "mixed_script" : "skeleton_changed"],
        summary: mixed
          ? "Mixed-script text detected (potential homograph attack)."
          : "UTS#39 skeleton differs from NFKC text (potential confusable characters).",
        target,
        evidence: {
          uts39Version: data.version,
          replacedMappings: replaced,
          nfkcPreview: preview(nfkc),
          skeletonPreview: preview(skeleton),
          mixedScripts: mixed,
          changed,
        },
      });
    };

    // 1) Prompt
    check(input.canonical.prompt, { field: "prompt" }, input.requestId, "prompt");

    // 2) Provenance chunks
    const chunks = input.canonical.promptChunksCanonical ?? [];
    for (let i = 0; i < chunks.length; i++) {
      const ch = chunks[i];
      check(
        ch.text,
        { field: "promptChunk", source: ch.source, chunkIndex: i },
        input.requestId,
        `chunk:${i}:${ch.source}`
      );
    }

    // This scanner does not mutate input; it only emits findings.
    return { input, findings };
  },
};
