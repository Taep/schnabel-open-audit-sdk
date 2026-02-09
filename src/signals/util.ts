import { createHash } from "node:crypto";

/**
 * Stable sha256 for deterministic IDs.
 */
export function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * Generate a deterministic finding id based on scanner + request + key.
 */
export function makeFindingId(scanner: string, requestId: string, key: string): string {
  const h = sha256Hex(`${scanner}:${requestId}:${key}`);
  return `f_${h.slice(0, 20)}`;
}
