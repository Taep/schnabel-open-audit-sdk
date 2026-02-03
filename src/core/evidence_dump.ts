import fs from "node:fs/promises";
import path from "node:path";
import type { EvidencePackageV0 } from "./evidence_package.js";

export interface SaveEvidenceOptions {
  outDir?: string;      // default: artifacts/evidence
  fileName?: string;    // default: <requestId>.<generatedAtMs>.evidence.json
  pretty?: boolean;     // default: true (2-space JSON)
}

/**
 * Make a filesystem-safe filename fragment.
 */
function safeName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Save EvidencePackageV0 to a JSON file.
 * Returns the absolute path of the saved file.
 */
export async function saveEvidencePackage(
  evidence: EvidencePackageV0,
  opts: SaveEvidenceOptions = {}
): Promise<string> {
  const outDir = opts.outDir ?? "artifacts/evidence";
  const pretty = opts.pretty ?? true;

  const safeRequestId = safeName(evidence.requestId || "unknown");
  const fileName =
    opts.fileName ?? `${safeRequestId}.${evidence.generatedAtMs}.evidence.json`;

  const absPath = path.resolve(outDir, fileName);

  await fs.mkdir(path.dirname(absPath), { recursive: true });

  const json = JSON.stringify(evidence, null, pretty ? 2 : 0);
  await fs.writeFile(absPath, json, "utf8");

  return absPath;
}
