/**
 * Inno Platform + SUI Multisig Wallet type definitions.
 *
 * Inno Platform handles SUI blockchain operations (multisig wallet creation,
 * Walrus storage, mainnet recording). The SDK calls Inno Platform REST APIs
 * via the InnoConnect client.
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/** Inno Platform REST API connection configuration. */
export interface InnoConnectConfig {
  /** Inno Platform REST API base URL (e.g. "https://api.innoplatform.io") */
  baseUrl: string;
  /** API key or auth token sent as `Authorization: Bearer <apiKey>`. */
  apiKey?: string | undefined;
  /** Request timeout in milliseconds. Default: 30 000. */
  timeoutMs?: number | undefined;
  /** Extra headers merged into every request. */
  headers?: Record<string, string> | undefined;
}

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

/** Multisig wallet participant info. */
export interface MultisigParticipant {
  publicKey: string;
  weight: number;
}

/** Response from the multisig wallet creation API. */
export interface MultisigWalletResponse {
  /** Multisig wallet address on SUI. */
  multisigAddress: string;
  /** User's key share (must be stored securely by the caller). */
  userKeyShare: string;
  /** All participants (public keys + weights). */
  participants: MultisigParticipant[];
  /** Minimum total weight required to sign a transaction. */
  threshold: number;
}

// ---------------------------------------------------------------------------
// Audit submission
// ---------------------------------------------------------------------------

/** Response from the audit result submission API (SUI/Walrus recording). */
export interface InnoSubmitResponse {
  /** SUI mainnet transaction digest. */
  txDigest: string;
  /** Walrus blob ID referencing the stored audit data. */
  walrusBlobId?: string | undefined;
  /** Server-side recording timestamp (epoch ms). */
  timestamp: number;
  /** SUI network used (mainnet / testnet / devnet). */
  network: string;
}

// ---------------------------------------------------------------------------
// Audit meta (safe — excludes sensitive key material)
// ---------------------------------------------------------------------------

/** SUI/Inno metadata attached to the audit result.
 *  `userKeyShare` is intentionally excluded for security. */
export interface InnoAuditMeta {
  wallet: Omit<MultisigWalletResponse, "userKeyShare">;
  /** suiscan.xyz account URL for the multisig wallet. */
  walletExplorerUrl?: string | undefined;
  submission?: InnoSubmitResponse | undefined;
  /** suiscan.xyz TX URL for the submission transaction. */
  txExplorerUrl?: string | undefined;
}
