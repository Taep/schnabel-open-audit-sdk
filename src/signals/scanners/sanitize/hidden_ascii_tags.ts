import type { Scanner } from "../scanner.js";
import type { Finding } from "../../types.js";
import type { NormalizedInput, SourcedText } from "../../../normalizer/types.js";
import { makeFindingId } from "../../util.js";

/**
 * Unicode "TAG" characters block (invisible on most renderers):
 * - U+E0000..U+E007F
 * - U+E0020..U+E007E map to ASCII 0x20..0x7E ("hidden ASCII")
 */
const TAG_CHAR_REGEX = /[\u{E0000}-\u{E007F}]/gu;

type TagDecodeResult = {
  sanitized: string;
  decoded: string;
  tagCount: number;
  changed: boolean;
};

function decodeTagChars(text: string): TagDecodeResult {
  let decoded = "";
  let tagCount = 0;

  // Decode any TAG chars to ASCII (only printable range), preserving order.
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    if (cp >= 0xE0000 && cp <= 0xE007F) {
      tagCount++;
      const ascii = cp - 0xE0000;

      // Only keep printable ASCII (space..tilde). Ignore 0x00..0x1F and 0x7F.
      if (ascii >= 0x20 && ascii <= 0x7e) {
        decoded += String.fromCharCode(ascii);
      }
    }
  }

  // Remove tag chars from original text
  const removed = text.replace(TAG_CHAR_REGEX, "");

  // If we decoded meaningful content, append it (newline-separated) so downstream detectors can see it.
  // This is a scanning-time canonicalization; raw input is preserved elsewhere.
  let sanitized = removed;
  if (decoded.trim().length > 0) {
    sanitized = `${removed}\n${decoded}`;
  }

  sanitized = sanitized.trim();

  const changed = tagCount > 0 && sanitized !== text.trim();
  return { sanitized, decoded, tagCount, changed };
}

function makeEvidence(decoded: string, tagCount: number) {
  const preview = decoded.length > 120 ? decoded.slice(0, 120) + "…" : decoded;
  return {
    tagCount,
    decodedLength: decoded.length,
    decodedPreview: preview,
  };
}

/**
 * HiddenAsciiTagsScanner
 * - Detects and decodes invisible TAG characters (U+E0000..U+E007F).
 * - Mutates canonical prompt + promptChunksCanonical to reveal hidden ASCII content.
 * - Emits Findings when TAG chars are present.
 */
export const HiddenAsciiTagsScanner: Scanner = {
  name: "hidden_ascii_tags",
  kind: "sanitize",

  async run(input: NormalizedInput) {
    const findings: Finding[] = [];

    // 1) Sanitize canonical prompt
    const p = decodeTagChars(input.canonical.prompt);

    if (p.tagCount > 0) {
      findings.push({
        id: makeFindingId(this.name, input.requestId, "prompt"),
        kind: this.kind,
        scanner: this.name,
        score: 0.85,
        risk: "high",
        tags: ["obfuscation", "unicode_tags", "hidden_ascii"],
        summary: "Hidden ASCII TAG characters detected and decoded in canonical prompt.",
        target: { field: "prompt" },
        evidence: makeEvidence(p.decoded, p.tagCount),
      });
    }

    // 2) Sanitize provenance chunks (if any)
    const inChunks = input.canonical.promptChunksCanonical ?? [];
    const outChunks: SourcedText[] = [];
    let anyChunkChanged = false;

    for (let i = 0; i < inChunks.length; i++) {
      const ch = inChunks[i];
      const r = decodeTagChars(ch.text);

      outChunks.push({ source: ch.source, text: r.sanitized });

      if (r.tagCount > 0) {
        findings.push({
          id: makeFindingId(this.name, input.requestId, `chunk:${i}:${ch.source}`),
          kind: this.kind,
          scanner: this.name,
          score: 0.85,
          risk: "high",
          tags: ["obfuscation", "unicode_tags", "hidden_ascii"],
          summary: "Hidden ASCII TAG characters detected and decoded in provenance chunk.",
          target: { field: "promptChunk", source: ch.source, chunkIndex: i },
          evidence: makeEvidence(r.decoded, r.tagCount),
        });
      }

      if (r.changed) anyChunkChanged = true;
    }

    // If nothing changed, return original input
    const promptChanged = p.changed;

    if (!promptChanged && !anyChunkChanged) {
      return { input, findings };
    }

    const updated: NormalizedInput = {
      ...input,
      canonical: {
        ...input.canonical,
        prompt: p.sanitized,
        promptChunksCanonical: inChunks.length ? outChunks : undefined,
      },
      features: {
        ...input.features,
        promptLength: p.sanitized.length,
      },
    };

    return { input: updated, findings };
  },
};
