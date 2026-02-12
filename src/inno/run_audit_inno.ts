/**
 * InnoAuditSession — Session-based orchestrator for Inno Platform integration.
 *
 * Lifecycle:
 *  1. start()  → Create multisig wallet (once per session)
 *  2. audit()  → Run individual audits, results accumulate
 *  3. finish() → Submit all accumulated evidence to Inno Platform,
 *                optionally open SUI explorer
 *
 * This models real-world usage where multiple audits are run in a session
 * (e.g. red-team scenario batches) and submitted together at the end.
 */

import type { AuditRequest } from "../normalizer/types.js";
import { runAudit, type AuditRunOptions, type AuditResult } from "../core/run_audit.js";
import { renderEvidenceReportEN } from "../core/evidence_report_en.js";
import type { EvidencePackageV0 } from "../core/evidence_package.js";

import type {
  InnoConnectConfig,
  MultisigWalletResponse,
  InnoSubmitResponse,
  InnoAuditMeta,
} from "./types.js";
import { InnoConnect, InnoConnectError } from "./inno_connect.js";
import {
  getSuiExplorerTxUrl,
  getSuiExplorerAccountUrl,
  openSuiExplorer,
  openSuiExplorerAccount,
  type SuiNetwork,
} from "./explorer.js";

// ---------------------------------------------------------------------------
// Session config
// ---------------------------------------------------------------------------

export interface InnoAuditSessionConfig {
  /** Inno Platform connection config. */
  inno: InnoConnectConfig;

  /** Default scanner chain & audit options used for each audit() call. */
  auditDefaults: AuditRunOptions;

  /** Called once when the multisig wallet is created during start(). */
  onWalletCreated?: ((wallet: MultisigWalletResponse) => void) | undefined;

  /** Open suiscan.xyz account page when wallet is created. Default: false. */
  openExplorerOnWalletCreated?: boolean | undefined;

  /** SUI network for explorer URLs. Default: "mainnet". */
  network?: SuiNetwork | undefined;

  /**
   * If true (default), Inno API errors are caught and logged as warnings.
   * If false, errors propagate and the caller must handle them.
   */
  continueOnInnoError?: boolean | undefined;
}

// ---------------------------------------------------------------------------
// Session result (returned by finish())
// ---------------------------------------------------------------------------

export interface InnoSessionResult {
  /** All audit results collected during the session. */
  auditResults: AuditResult[];

  /** Inno/SUI metadata (wallet, submission, explorer URL). */
  inno?: InnoAuditMeta | undefined;
}

// ---------------------------------------------------------------------------
// Session class
// ---------------------------------------------------------------------------

type SessionState = "idle" | "started" | "finished";

export class InnoAuditSession {
  private readonly connect: InnoConnect;
  private readonly config: InnoAuditSessionConfig;
  private readonly network: SuiNetwork;
  private readonly continueOnError: boolean;

  private state: SessionState = "idle";
  private wallet: MultisigWalletResponse | undefined;
  private results: AuditResult[] = [];

  constructor(config: InnoAuditSessionConfig) {
    this.config = config;
    this.connect = new InnoConnect(config.inno);
    this.network = config.network ?? "mainnet";
    this.continueOnError = config.continueOnInnoError ?? true;
  }

  // -----------------------------------------------------------------------
  // Lifecycle
  // -----------------------------------------------------------------------

  /**
   * Start the audit session.
   * Creates a multisig wallet via Inno Platform.
   */
  async start(): Promise<void> {
    if (this.state !== "idle") {
      throw new Error(`InnoAuditSession: cannot start() in state "${this.state}"`);
    }

    try {
      this.wallet = await this.connect.createMultisigWallet();
      if (this.config.onWalletCreated) {
        this.config.onWalletCreated(this.wallet);
      }
      if (this.config.openExplorerOnWalletCreated && this.wallet) {
        try {
          await openSuiExplorerAccount(this.wallet.multisigAddress, this.network);
        } catch {
          // Best-effort
        }
      }
    } catch (err) {
      if (!this.continueOnError) throw err;
      console.warn(
        "[InnoConnect] Multisig wallet creation failed:",
        err instanceof InnoConnectError ? err.message : err,
      );
    }

    this.state = "started";
  }

  /**
   * Run a single audit within the session.
   * Results are accumulated for the final submission.
   *
   * @param req       The audit request.
   * @param overrides Optional per-audit option overrides (merged with session defaults).
   */
  async audit(
    req: AuditRequest,
    overrides?: Partial<AuditRunOptions>,
  ): Promise<AuditResult> {
    if (this.state !== "started") {
      throw new Error(`InnoAuditSession: cannot audit() in state "${this.state}". Call start() first.`);
    }

    const opts: AuditRunOptions = { ...this.config.auditDefaults, ...overrides };
    const result = await runAudit(req, opts);
    this.results.push(result);
    return result;
  }

  /**
   * Finish the session: submit all accumulated evidence to Inno Platform
   * and optionally open the SUI explorer.
   */
  async finish(opts?: {
    openExplorer?: boolean;
  }): Promise<InnoSessionResult> {
    if (this.state !== "started") {
      throw new Error(`InnoAuditSession: cannot finish() in state "${this.state}".`);
    }

    this.state = "finished";

    let innoMeta: InnoAuditMeta | undefined;

    if (this.wallet && this.results.length > 0) {
      const walletMeta = this.buildWalletMeta();

      // Build combined evidence + report for submission
      const evidencePackages = this.results.map(r => r.evidence);
      const reportSections = this.results.map(r =>
        renderEvidenceReportEN(r.evidence, {
          maxPreviewChars: 120,
          includeNotes: true,
          includeDetails: false,
        }),
      );
      const combinedReport = reportSections.join("\n\n---\n\n");

      // Use the first result's requestId as the session-level identifier,
      // or build a composite one.
      const sessionRequestId = this.results.length === 1
        ? this.results[0]!.requestId
        : `session-${this.results[0]!.requestId}-${this.results.length}runs`;

      // Wrap all evidence packages in a session envelope
      const sessionEvidence: EvidencePackageV0 & { sessionEntries?: EvidencePackageV0[] } = {
        ...this.results[this.results.length - 1]!.evidence,
        sessionEntries: evidencePackages,
      };

      try {
        const submission = await this.connect.submitAuditResult({
          walletAddress: this.wallet.multisigAddress,
          evidencePackage: sessionEvidence,
          reportMarkdown: combinedReport,
          requestId: sessionRequestId,
        });

        innoMeta = {
          ...walletMeta,
          submission,
          txExplorerUrl: getSuiExplorerTxUrl(submission.txDigest, this.network),
        };

        if (opts?.openExplorer) {
          try {
            await openSuiExplorer(submission.txDigest, this.network);
          } catch {
            // Best-effort
          }
        }
      } catch (err) {
        if (!this.continueOnError) throw err;
        console.warn(
          "[InnoConnect] Session submission failed:",
          err instanceof InnoConnectError ? err.message : err,
        );

        innoMeta = walletMeta;
      }
    } else if (this.wallet) {
      innoMeta = this.buildWalletMeta();
    }

    return {
      auditResults: this.results,
      inno: innoMeta,
    };
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private buildWalletMeta(): InnoAuditMeta {
    return {
      wallet: {
        multisigAddress: this.wallet!.multisigAddress,
        participants: this.wallet!.participants,
        threshold: this.wallet!.threshold,
      },
      walletExplorerUrl: getSuiExplorerAccountUrl(this.wallet!.multisigAddress, this.network),
    };
  }

  // -----------------------------------------------------------------------
  // Accessors
  // -----------------------------------------------------------------------

  /** Current session state. */
  get sessionState(): SessionState { return this.state; }

  /** Wallet info (without userKeyShare). Undefined until start() succeeds. */
  get walletInfo(): Omit<MultisigWalletResponse, "userKeyShare"> | undefined {
    if (!this.wallet) return undefined;
    return {
      multisigAddress: this.wallet.multisigAddress,
      participants: this.wallet.participants,
      threshold: this.wallet.threshold,
    };
  }

  /** Number of audits completed so far. */
  get auditCount(): number { return this.results.length; }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Create a new Inno audit session. */
export function createInnoAuditSession(
  config: InnoAuditSessionConfig,
): InnoAuditSession {
  return new InnoAuditSession(config);
}
