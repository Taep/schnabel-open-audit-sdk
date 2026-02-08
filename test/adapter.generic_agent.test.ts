import { describe, it, expect } from "vitest";
import { fromAgentIngressEvent } from "../src/adapters/generic_agent.js";
import { normalize } from "../src/normalizer/normalize.js";

describe("L0 adapter: AgentIngressEvent -> AuditRequest", () => {
  it("builds AuditRequest with provenance (promptChunks) and works with normalize()", () => {
    const req = fromAgentIngressEvent({
      requestId: "r1",
      timestamp: 1,
      userPrompt: "  hello  ",
      systemPrompt: "  system rules  ",
      developerPrompt: " dev note ",
      retrievalDocs: [
        { text: "  doc1  ", docId: "d1", score: 0.9 },
        { text: "doc2", url: "https://example.com", score: 0.7 },
      ],
      toolCalls: [{ toolName: "web.search", args: { q: "x" } }],
      toolResults: [{ toolName: "web.search", ok: true, result: { items: [1] } }],
      metadata: { upstream: "generic-agent" },
    });

    // L0: prompt stays as provided (raw-ish)
    expect(req.prompt).toBe("  hello  ");

    // L0: provenance chunks exist and keep sources separated
    expect(req.promptChunks?.length).toBeGreaterThan(0);
    expect(req.promptChunks?.[0]?.source).toBe("system");

    // L1 normalize still works and trims canonical prompt
    const n = normalize(req);
    expect(n.canonical.prompt).toBe("hello");

    // Tool name extraction still works
    expect(n.features.toolNames).toContain("web.search");

    // Provenance is preserved through L1 (trim-only cleanup at this stage)
    expect(n.canonical.promptChunksCanonical?.some(c => c.source === "retrieval")).toBe(true);
  });
});
