/**
 * SUI Explorer utilities.
 *
 * Generates suiscan.xyz URLs and opens them in the default browser.
 * No external dependencies — uses platform-native open commands.
 */

import { exec } from "node:child_process";

const SUISCAN_BASE = "https://suiscan.xyz";

export type SuiNetwork = "mainnet" | "testnet" | "devnet";

// ---------------------------------------------------------------------------
// URL builders
// ---------------------------------------------------------------------------

/**
 * Build the suiscan.xyz URL for a transaction.
 *
 * @example
 * getSuiExplorerTxUrl("AbC123", "mainnet")
 * // → "https://suiscan.xyz/mainnet/tx/AbC123"
 */
export function getSuiExplorerTxUrl(
  txDigest: string,
  network: SuiNetwork = "mainnet",
): string {
  return `${SUISCAN_BASE}/${network}/tx/${txDigest}`;
}

/**
 * Build the suiscan.xyz URL for a wallet/account.
 *
 * @example
 * getSuiExplorerAccountUrl("0xabc123", "mainnet")
 * // → "https://suiscan.xyz/mainnet/account/0xabc123"
 */
export function getSuiExplorerAccountUrl(
  address: string,
  network: SuiNetwork = "mainnet",
): string {
  return `${SUISCAN_BASE}/${network}/account/${address}`;
}

/** @deprecated Use `getSuiExplorerTxUrl` instead. */
export const getSuiExplorerUrl = getSuiExplorerTxUrl;

// ---------------------------------------------------------------------------
// Browser open
// ---------------------------------------------------------------------------

/**
 * Open any URL in the default browser.
 *
 * Uses platform-native commands:
 *  - Windows : `start ""`
 *  - macOS   : `open`
 *  - Linux   : `xdg-open`
 */
export async function openInBrowser(url: string): Promise<void> {
  const platform = process.platform;
  let cmd: string;

  if (platform === "win32") {
    cmd = `start "" "${url}"`;
  } else if (platform === "darwin") {
    cmd = `open "${url}"`;
  } else {
    cmd = `xdg-open "${url}"`;
  }

  return new Promise<void>((resolve, reject) => {
    exec(cmd, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

/** Open the SUI explorer TX page in the browser. */
export async function openSuiExplorer(
  txDigest: string,
  network: SuiNetwork = "mainnet",
): Promise<void> {
  return openInBrowser(getSuiExplorerTxUrl(txDigest, network));
}

/** Open the SUI explorer account page in the browser. */
export async function openSuiExplorerAccount(
  address: string,
  network: SuiNetwork = "mainnet",
): Promise<void> {
  return openInBrowser(getSuiExplorerAccountUrl(address, network));
}
