import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { InnoConnect, InnoConnectError } from "../src/inno/inno_connect.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const MOCK_WALLET = {
  multisigAddress: "0xabc123multisig",
  userKeyShare: "user-key-share-secret",
  participants: [
    { publicKey: "pk-user", weight: 1 },
    { publicKey: "pk-server", weight: 1 },
  ],
  threshold: 2,
};

const MOCK_SUBMIT = {
  txDigest: "DiGeSt123AbC",
  walrusBlobId: "walrus-blob-001",
  timestamp: 1700000000000,
  network: "mainnet",
};

function mockFetchOk(body: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
  } as Response);
}

function mockFetchError(status: number, body?: unknown): typeof globalThis.fetch {
  return vi.fn().mockResolvedValue({
    ok: false,
    status,
    json: () => Promise.resolve(body ?? {}),
  } as Response);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("InnoConnect", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  // -- createMultisigWallet ------------------------------------------------

  describe("createMultisigWallet()", () => {
    it("calls POST /v1/wallet/multisig/create and returns wallet info", async () => {
      const mockFn = mockFetchOk(MOCK_WALLET);
      globalThis.fetch = mockFn;

      const client = new InnoConnect({ baseUrl: "https://api.inno.test" });
      const wallet = await client.createMultisigWallet();

      expect(wallet.multisigAddress).toBe("0xabc123multisig");
      expect(wallet.userKeyShare).toBe("user-key-share-secret");
      expect(wallet.participants).toHaveLength(2);
      expect(wallet.threshold).toBe(2);

      expect(mockFn).toHaveBeenCalledOnce();
      const [url, opts] = (mockFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(url).toBe("https://api.inno.test/v1/wallet/multisig/create");
      expect(opts.method).toBe("POST");
    });

    it("sends Authorization header when apiKey is provided", async () => {
      const mockFn = mockFetchOk(MOCK_WALLET);
      globalThis.fetch = mockFn;

      const client = new InnoConnect({
        baseUrl: "https://api.inno.test",
        apiKey: "my-secret-key",
      });
      await client.createMultisigWallet();

      const [, opts] = (mockFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(opts.headers["Authorization"]).toBe("Bearer my-secret-key");
    });

    it("strips trailing slash from baseUrl", async () => {
      const mockFn = mockFetchOk(MOCK_WALLET);
      globalThis.fetch = mockFn;

      const client = new InnoConnect({ baseUrl: "https://api.inno.test///" });
      await client.createMultisigWallet();

      const [url] = (mockFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(url).toBe("https://api.inno.test/v1/wallet/multisig/create");
    });
  });

  // -- submitAuditResult ---------------------------------------------------

  describe("submitAuditResult()", () => {
    it("calls POST /v1/audit/submit with payload and returns tx info", async () => {
      const mockFn = mockFetchOk(MOCK_SUBMIT);
      globalThis.fetch = mockFn;

      const client = new InnoConnect({ baseUrl: "https://api.inno.test" });
      const result = await client.submitAuditResult({
        walletAddress: "0xabc",
        evidencePackage: { schema: "schnabel-evidence-v0" } as any,
        reportMarkdown: "# Report",
        requestId: "req-1",
      });

      expect(result.txDigest).toBe("DiGeSt123AbC");
      expect(result.walrusBlobId).toBe("walrus-blob-001");
      expect(result.network).toBe("mainnet");

      const [url, opts] = (mockFn as ReturnType<typeof vi.fn>).mock.calls[0]!;
      expect(url).toBe("https://api.inno.test/v1/audit/submit");
      const body = JSON.parse(opts.body);
      expect(body.walletAddress).toBe("0xabc");
      expect(body.requestId).toBe("req-1");
    });
  });

  // -- Error handling ------------------------------------------------------

  describe("error handling", () => {
    it("throws InnoConnectError on HTTP 4xx", async () => {
      globalThis.fetch = mockFetchError(400, {
        code: "INVALID_REQUEST",
        message: "Missing required field",
      });

      const client = new InnoConnect({ baseUrl: "https://api.inno.test" });
      await expect(client.createMultisigWallet()).rejects.toThrow(InnoConnectError);

      try {
        await client.createMultisigWallet();
      } catch (err) {
        expect(err).toBeInstanceOf(InnoConnectError);
        const e = err as InnoConnectError;
        expect(e.status).toBe(400);
        expect(e.code).toBe("INVALID_REQUEST");
        expect(e.message).toBe("Missing required field");
      }
    });

    it("throws InnoConnectError on HTTP 500 with no body", async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        json: () => Promise.reject(new Error("no body")),
      } as unknown as Response);

      const client = new InnoConnect({ baseUrl: "https://api.inno.test" });
      await expect(client.createMultisigWallet()).rejects.toThrow(
        /Inno Platform returned HTTP 500/,
      );
    });

    it("throws InnoConnectError on network failure", async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new TypeError("fetch failed"));

      const client = new InnoConnect({ baseUrl: "https://api.inno.test" });
      await expect(client.createMultisigWallet()).rejects.toThrow(
        /network error.*fetch failed/i,
      );
    });

    it("throws InnoConnectError on timeout (AbortError)", async () => {
      globalThis.fetch = vi.fn().mockImplementation(() => {
        const err = new DOMException("signal is aborted", "AbortError");
        return Promise.reject(err);
      });

      const client = new InnoConnect({
        baseUrl: "https://api.inno.test",
        timeoutMs: 100,
      });
      await expect(client.createMultisigWallet()).rejects.toThrow(/timed out/);
    });
  });
});
