import fs from "node:fs/promises";
import path from "node:path";

import type { EvidencePackageV0 } from "./evidence_package.js";
import { renderEvidenceReportKR } from "./evidence_report_kr.js";

export interface SaveEvidenceReportOptions {
  outDir?: string;      // default: artifacts/reports
  fileName?: string;    // default: <requestId>.<generatedAtMs>.report.ko.md
}

function safeName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

/**
 * Save a markdown report to disk and return absolute path.
 */
export async function saveEvidenceReportMarkdown(
  markdown: string,
  opts: SaveEvidenceReportOptions = {}
): Promise<string> {
  const outDir = opts.outDir ?? "artifacts/reports";
  const fileName = opts.fileName ?? `report.${Date.now()}.md`;
  const absPath = path.resolve(outDir, fileName);

  await fs.mkdir(path.dirname(absPath), { recursive: true });
  await fs.writeFile(absPath, markdown, "utf8");

  return absPath;
}

/**
 * Generate a Korean markdown report from EvidencePackageV0 and save to disk.
 */
export async function saveEvidenceReportKR(
  evidence: EvidencePackageV0,
  opts: SaveEvidenceReportOptions = {}
): Promise<string> {
  const outDir = opts.outDir ?? "artifacts/reports";
  const safeRequestId = safeName(evidence.requestId || "unknown");

  const fileName =
    opts.fileName ?? `${safeRequestId}.${evidence.generatedAtMs}.report.ko.md`;

  const md = renderEvidenceReportKR(evidence);
  return saveEvidenceReportMarkdown(md, { outDir, fileName });
}
