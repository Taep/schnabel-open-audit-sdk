import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { fromAgentIngressEvent } from "../src/adapters/generic_agent.js";
import { createInnoAuditSession, InnoAuditSession } from "../src/inno/run_audit_inno.js";
import { UnicodeSanitizerScanner } from "../src/signals/scanners/sanitize/unicode_sanitizer.js";
import { KeywordInjectionScanner } from "../src/signals/scanners/detect/keyword_injection.js";
import type { MultisigWalletResponse } from "../src/inno/types.js";

// ---------------------------------------------------------------------------
// Mock data
// ---------------------------------------------------------------------------

const MOCK_WALLET: MultisigWalletResponse = {
  multisigAddress: "0xabc123multisig",
  userKeyShare: "secret-key-share",
  participants: [
    { publicKey: "pk-user", weight: 1 },
    { publicKey: "pk-server", weight: 1 },
  ],
  threshold: 2,
};

const MOCK_SUBMIT = {
  txDigest: "DiGeSt456",
  walrusBlobId: "walrus-blob-002",
  timestamp: 1700000000000,
  network: "mainnet",
};

const SCANNERS = [UnicodeSanitizerScanner, KeywordInjectionScanner];

function makeRequest(prompt = "Hello world") {
  return fromAgentIngressEvent({
    requestId: `r-inno-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    timestamp: Date.now(),
    userPrompt: prompt,
  });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("InnoAuditSession", () => {
  let originalFetch: typeof globalThis.fetch;
  let fetchCallCount: number;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetchCallCount = 0;

    // Mock fetch: first call → wallet, subsequent calls → submit
    globalThis.fetch = vi.fn().mockImplementation(() => {
      fetchCallCount++;
      if (fetchCallCount === 1) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(MOCK_WALLET),
        } as Response);
      }
      return Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve(MOCK_SUBMIT),
      } as Response);
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // -- Factory --

  it("createInnoAuditSession returns an InnoAuditSession", () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });
    expect(session).toBeInstanceOf(InnoAuditSession);
    expect(session.sessionState).toBe("idle");
  });

  // -- Lifecycle: start → audit → finish --

  it("full lifecycle: start → multiple audits → finish", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start();
    expect(session.sessionState).toBe("started");
    expect(session.walletInfo?.multisigAddress).toBe("0xabc123multisig");

    // Run 3 audits
    const r1 = await session.audit(makeRequest("Test prompt 1"));
    const r2 = await session.audit(makeRequest("Test prompt 2"));
    const r3 = await session.audit(makeRequest("Test prompt 3"));
    expect(session.auditCount).toBe(3);
    expect(r1.decision).toBeDefined();
    expect(r2.decision).toBeDefined();
    expect(r3.decision).toBeDefined();

    // Finish → submit all
    const result = await session.finish();
    expect(session.sessionState).toBe("finished");
    expect(result.auditResults).toHaveLength(3);
    expect(result.inno?.submission?.txDigest).toBe("DiGeSt456");
    expect(result.inno?.walletExplorerUrl).toBe("https://suiscan.xyz/mainnet/account/0xabc123multisig");
    expect(result.inno?.txExplorerUrl).toBe("https://suiscan.xyz/mainnet/tx/DiGeSt456");
  });

  // -- wallet callback --

  it("calls onWalletCreated with full wallet info (including keyShare)", async () => {
    const walletCallback = vi.fn();
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
      onWalletCreated: walletCallback,
    });

    await session.start();

    expect(walletCallback).toHaveBeenCalledOnce();
    const received = walletCallback.mock.calls[0]![0] as MultisigWalletResponse;
    expect(received.userKeyShare).toBe("secret-key-share");
    expect(received.multisigAddress).toBe("0xabc123multisig");
  });

  // -- security: no keyShare in results --

  it("does NOT expose userKeyShare in walletInfo or session result", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start();
    expect("userKeyShare" in session.walletInfo!).toBe(false);

    await session.audit(makeRequest());
    const result = await session.finish();
    expect("userKeyShare" in result.inno!.wallet).toBe(false);
  });

  // -- network config --

  it("uses specified network for explorer URL", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
      network: "testnet",
    });

    await session.start();
    await session.audit(makeRequest());
    const result = await session.finish();

    expect(result.inno!.txExplorerUrl).toBe("https://suiscan.xyz/testnet/tx/DiGeSt456");
  });

  // -- error handling: wallet fail + continue --

  it("continues when wallet creation fails (continueOnInnoError default)", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network down"));
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start(); // should not throw
    expect(session.sessionState).toBe("started");
    expect(session.walletInfo).toBeUndefined();

    await session.audit(makeRequest());
    const result = await session.finish();

    expect(result.auditResults).toHaveLength(1);
    expect(result.inno).toBeUndefined(); // no wallet → no inno meta

    consoleSpy.mockRestore();
  });

  // -- error handling: wallet fail + throw --

  it("throws when wallet creation fails and continueOnInnoError is false", async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error("network down"));

    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
      continueOnInnoError: false,
    });

    await expect(session.start()).rejects.toThrow("network down");
  });

  // -- error handling: submit fail + continue --

  it("returns wallet info even when submission fails", async () => {
    let callCount = 0;
    globalThis.fetch = vi.fn().mockImplementation(() => {
      callCount++;
      if (callCount === 1) {
        return Promise.resolve({
          ok: true,
          status: 200,
          json: () => Promise.resolve(MOCK_WALLET),
        } as Response);
      }
      return Promise.reject(new Error("submit failed"));
    });
    const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});

    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start();
    await session.audit(makeRequest());
    const result = await session.finish();

    expect(result.inno?.wallet.multisigAddress).toBe("0xabc123multisig");
    expect(result.inno?.submission).toBeUndefined();

    consoleSpy.mockRestore();
  });

  // -- state guards --

  it("throws when calling start() twice", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start();
    await expect(session.start()).rejects.toThrow(/cannot start/);
  });

  it("throws when calling audit() before start()", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await expect(session.audit(makeRequest())).rejects.toThrow(/Call start\(\) first/);
  });

  it("throws when calling finish() before start()", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await expect(session.finish()).rejects.toThrow(/cannot finish/);
  });

  it("throws when calling audit() after finish()", async () => {
    const session = createInnoAuditSession({
      inno: { baseUrl: "https://api.inno.test" },
      auditDefaults: { scanners: SCANNERS },
    });

    await session.start();
    await session.finish();
    await expect(session.audit(makeRequest())).rejects.toThrow(/cannot audit/);
  });
});
