/**
 * InnoConnect — REST API client for Inno Platform.
 *
 * Handles:
 *  - Multisig wallet creation on SUI
 *  - Audit evidence submission → Walrus + SUI mainnet recording
 *
 * Uses Node.js built-in `fetch` (Node 18+). No external dependencies.
 */

import type { EvidencePackageV0 } from "../core/evidence_package.js";
import type {
  InnoConnectConfig,
  MultisigWalletResponse,
  InnoSubmitResponse,
} from "./types.js";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/** Error thrown when an Inno Platform API call fails. */
export class InnoConnectError extends Error {
  /** HTTP status code (if the request reached the server). */
  status?: number | undefined;
  /** Machine-readable error code from the server response body. */
  code?: string | undefined;

  constructor(message: string, opts?: { status?: number; code?: string | undefined }) {
    super(message);
    this.name = "InnoConnectError";
    this.status = opts?.status;
    this.code = opts?.code;
  }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

const DEFAULT_TIMEOUT_MS = 30_000;

export class InnoConnect {
  private readonly baseUrl: string;
  private readonly timeoutMs: number;
  private readonly defaultHeaders: Record<string, string>;

  constructor(config: InnoConnectConfig) {
    // Strip trailing slash for consistent URL joining.
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;

    this.defaultHeaders = {
      "Content-Type": "application/json",
      Accept: "application/json",
      ...(config.apiKey ? { Authorization: `Bearer ${config.apiKey}` } : {}),
      ...(config.headers ?? {}),
    };
  }

  // -----------------------------------------------------------------------
  // Public API
  // -----------------------------------------------------------------------

  /**
   * Create a new SUI multisig wallet via Inno Platform.
   *
   * POST {baseUrl}/v1/wallet/multisig/create
   */
  async createMultisigWallet(): Promise<MultisigWalletResponse> {
    return this.post<MultisigWalletResponse>("/v1/wallet/multisig/create", {});
  }

  /**
   * Submit audit evidence + report to Inno Platform.
   * The server stores data on Walrus and records it on SUI mainnet.
   *
   * POST {baseUrl}/v1/audit/submit
   */
  async submitAuditResult(payload: {
    walletAddress: string;
    evidencePackage: EvidencePackageV0;
    reportMarkdown: string;
    requestId: string;
  }): Promise<InnoSubmitResponse> {
    return this.post<InnoSubmitResponse>("/v1/audit/submit", payload);
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    let res: Response;
    try {
      res = await fetch(url, {
        method: "POST",
        headers: this.defaultHeaders,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new InnoConnectError(
          `Inno Platform request timed out after ${this.timeoutMs}ms: POST ${path}`,
        );
      }
      const msg = err instanceof Error ? err.message : String(err);
      throw new InnoConnectError(`Inno Platform network error: ${msg}`);
    } finally {
      clearTimeout(timer);
    }

    if (!res.ok) {
      let serverCode: string | undefined;
      let serverMessage: string | undefined;
      try {
        const errBody: unknown = await res.json();
        if (typeof errBody === "object" && errBody !== null) {
          const obj = errBody as Record<string, unknown>;
          if (typeof obj["code"] === "string") serverCode = obj["code"];
          if (typeof obj["message"] === "string") serverMessage = obj["message"];
        }
      } catch {
        // ignore JSON parse failure on error body
      }

      throw new InnoConnectError(
        serverMessage ?? `Inno Platform returned HTTP ${res.status}: POST ${path}`,
        { status: res.status, code: serverCode },
      );
    }

    return (await res.json()) as T;
  }
}
