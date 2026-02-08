import fs from "node:fs/promises";
import path from "node:path";
import type { EvidencePackageV0 } from "./evidence_package.js";

export interface SaveEvidenceOptions {
  outDir?: string;      // default: artifacts/evidence
  fileName?: string;    // default: <requestId>.<generatedAtMs>.evidence.json
  pretty?: boolean;     // default: true (2-space JSON)
}

function safeName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/** Human-readable timestamp for filenames: YYYYMMDD-HHmmss */
function filenameTimestamp(ms: number): string {
  const d = new Date(ms);
  const y = d.getFullYear();
  const M = String(d.getMonth() + 1).padStart(2, "0");
  const D = String(d.getDate()).padStart(2, "0");
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  const s = String(d.getSeconds()).padStart(2, "0");
  return `${y}${M}${D}-${h}${m}${s}`;
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
  const ts = evidence.generatedAtMs ?? Date.now();
  const fileName =
    opts.fileName ?? `${filenameTimestamp(ts)}_${safeRequestId}.evidence.json`;

  const absPath = path.resolve(outDir, fileName);

  await fs.mkdir(path.dirname(absPath), { recursive: true });

  const json = JSON.stringify(evidence, null, pretty ? 2 : 0);
  await fs.writeFile(absPath, json, "utf8");

  return absPath;
}
