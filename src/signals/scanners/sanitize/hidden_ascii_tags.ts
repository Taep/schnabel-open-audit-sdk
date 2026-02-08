import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";
import { ensureViews } from "../../views.js";

/**
 * Unicode "TAG" characters block (invisible on most renderers):
 * - U+E0000..U+E007F
 * - U+E0020..U+E007E map to ASCII 0x20..0x7E ("hidden ASCII")
 */
const TAG_CHAR_REGEX = /[\u{E0000}-\u{E007F}]/gu;

function decodeTagChars(text: string): { removed: string; decoded: string; tagCount: number } {
  let decoded = "";
  let tagCount = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xE0000 && cp <= 0xE007F) {
      tagCount++;
      const ascii = cp - 0xE0000;
      if (ascii >= 0x20 && ascii <= 0x7e) decoded += String.fromCharCode(ascii);
    }
  }

  const removed = text.replace(TAG_CHAR_REGEX, "").trim();
  return { removed, decoded: decoded.trim(), tagCount };
}

function preview(s: string, max = 120): string {
  const t = s.trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

/**
 * HiddenAsciiTagsScanner
 * - Updates canonical + views.revealed (and views.sanitized without tags)
 * - Keeps views.raw unchanged
 */
export const HiddenAsciiTagsScanner: Scanner = {
  name: "hidden_ascii_tags",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const base = ensureViews(input);
    const views = base.views!;
    const findings: Finding[] = [];

    let changed = false;

    // Prompt
    const p0 = base.canonical.prompt;
    const p = decodeTagChars(p0);

    if (p.tagCount > 0) {
      changed = true;

      // sanitized view: tags removed
      views.prompt.sanitized = p.removed;

      // revealed view: tags removed + decoded (if any)
      views.prompt.revealed = p.decoded.length ? `${p.removed}\n${p.decoded}`.trim() : p.removed;

      findings.push({
        id: makeFindingId(this.name, base.requestId, "prompt"),
        kind: this.kind,
        scanner: this.name,
        score: 0.85,
        risk: "high",
        tags: ["obfuscation", "unicode_tags", "hidden_ascii"],
        summary: "Hidden ASCII TAG characters detected and decoded in prompt.",
        target: { field: "prompt", view: "revealed" },
        evidence: { tagCount: p.tagCount, decodedPreview: preview(p.decoded) },
      });
    }

    // Chunks
    const chunks = base.canonical.promptChunksCanonical ?? [];
    const outChunks = chunks.map((ch, i) => {
      const r = decodeTagChars(ch.text);
      if (r.tagCount > 0) {
        changed = true;

        const cv = views.chunks?.[i];
        if (cv) {
          cv.views.sanitized = r.removed;
          cv.views.revealed = r.decoded.length ? `${r.removed}\n${r.decoded}`.trim() : r.removed;
        }

        findings.push({
          id: makeFindingId(this.name, base.requestId, `chunk:${i}:${ch.source}`),
          kind: this.kind,
          scanner: this.name,
          score: 0.85,
          risk: "high",
          tags: ["obfuscation", "unicode_tags", "hidden_ascii"],
          summary: "Hidden ASCII TAG characters detected and decoded in chunk.",
          target: { field: "promptChunk", view: "revealed", source: ch.source, chunkIndex: i },
          evidence: { tagCount: r.tagCount, decodedPreview: preview(r.decoded) },
        });
      }
      const revealed = r.decoded.length ? `${r.removed}\n${r.decoded}`.trim() : r.removed;
      return { ...ch, text: revealed };
    });

    if (!changed) return { input: base, findings };

    const updated: NormalizedInput = {
      ...base,
      canonical: {
        ...base.canonical,
        prompt: views.prompt.revealed,
        ...(outChunks.length ? { promptChunksCanonical: outChunks } : {}),
      },
      features: {
        ...base.features,
        promptLength: views.prompt.revealed.length,
      },
      views,
    };

    return { input: updated, findings };
  },
};
