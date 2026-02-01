import { describe, it, expect } from "vitest";
import { normalize } from "../src/normalizer/normalize.js";

describe("smoke", () => {
  it("normalize runs", () => {
    const n = normalize({
      requestId: "r1",
      timestamp: 1,
      prompt: " hello ",
    });

    expect(n.requestId).toBe("r1");
    expect(n.canonical.prompt).toBe("hello");
  });
});
