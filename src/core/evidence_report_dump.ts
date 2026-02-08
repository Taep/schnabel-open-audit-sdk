import fs from "node:fs/promises";
import path from "node:path";

import type { EvidencePackageV0 } from "./evidence_package.js";
import { renderEvidenceReportEN } from "./evidence_report_en.js";

export interface SaveEvidenceReportOptions {
  outDir?: string;      // default: artifacts/reports
  fileName?: string;    // default: <requestId>.<generatedAtMs>.report.en.md
}

function safeName(s: string): string {
  return s.replace(/[^a-zA-Z0-9._-]/g, "_");
}

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

export async function saveEvidenceReportEN(
  evidence: EvidencePackageV0,
  opts: SaveEvidenceReportOptions = {}
): Promise<string> {
  const outDir = opts.outDir ?? "artifacts/reports";
  const safeRequestId = safeName(evidence.requestId || "unknown");
  const ts = evidence.generatedAtMs ?? Date.now();
  const fileName = opts.fileName ?? `${filenameTimestamp(ts)}_${safeRequestId}.report.en.md`;

  const md = renderEvidenceReportEN(evidence, {
  maxPreviewChars: 120,
  includeNotes: true,
  includeDetails: false,
});

  return saveEvidenceReportMarkdown(md, { outDir, fileName });
}

// Compatibility alias (in case old code calls KR)
export const saveEvidenceReportKR = saveEvidenceReportEN;
