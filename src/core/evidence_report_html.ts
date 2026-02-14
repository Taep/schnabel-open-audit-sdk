/**
 * Self-contained HTML report renderer for audit results.
 *
 * Produces a single HTML string with inline CSS — no external dependencies.
 * Suitable for Walrus blob upload (content-type: text/html) or local file save.
 */

import type { AuditResult } from "./run_audit.js";
import type { EvidencePackageV0 } from "./evidence_package.js";
import { RISK_ORDER } from "../signals/types.js";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export interface HtmlReportOptions {
  title?: string;
  runId?: string;
  /** SUI wallet address (public, not private key). */
  walletAddress?: string;
  walletExplorerUrl?: string;
  blobId?: string;
  blobUrl?: string;
  blobObjectId?: string;
  network?: string;
  /** Per-scenario pass/fail info (red team runner). Omit for plain audit report. */
  scenarioResults?: ScenarioResultMeta[];
}

export interface ScenarioResultMeta {
  name: string;
  id?: string;
  ok: boolean;
  error?: string;
  encoding?: string;
  source?: string;
}

/**
 * Render audit results as a self-contained HTML page.
 */
export function renderAuditReportHTML(
  results: AuditResult[],
  opts: HtmlReportOptions = {},
): string {
  const title = opts.title ?? "Schnabel Audit Report";
  const runId = opts.runId ?? new Date().toISOString();
  const now = formatTs(Date.now());

  const scenarios = opts.scenarioResults;
  const hasScenarios = scenarios !== undefined && scenarios.length > 0;

  // Compute summary stats
  const totalResults = results.length;
  const byAction: Record<string, number> = {};
  const byRisk: Record<string, number> = {};
  for (const r of results) {
    const a = r.decision.action;
    byAction[a] = (byAction[a] ?? 0) + 1;
    const risk = r.decision.risk ?? "none";
    byRisk[risk] = (byRisk[risk] ?? 0) + 1;
  }

  let passed = 0;
  let failed = 0;
  let crashed = 0;
  if (hasScenarios) {
    for (const s of scenarios) {
      if (s.error) crashed++;
      else if (s.ok) passed++;
      else failed++;
    }
  }

  const parts: string[] = [];

  // --- HTML head ---
  parts.push(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)}</title>
${CSS}
</head>
<body>
<div class="container">`);

  // --- Header ---
  parts.push(`
<header>
  <h1>${esc(title)}</h1>
  <p class="meta">Run: <code>${esc(runId)}</code> &middot; Generated: <code>${esc(now)}</code></p>
</header>`);

  // --- SUI / Walrus info ---
  if (opts.walletAddress || opts.blobId) {
    parts.push(`<section class="card sui-card">
  <h2>SUI / Walrus</h2>
  <table class="kv-table">`);
    if (opts.walletAddress) {
      const walletLink = opts.walletExplorerUrl
        ? `<a href="${esc(opts.walletExplorerUrl)}" target="_blank" rel="noopener">${esc(opts.walletAddress)}</a>`
        : `<code>${esc(opts.walletAddress)}</code>`;
      parts.push(`<tr><td>Wallet</td><td>${walletLink}</td></tr>`);
    }
    if (opts.blobId) {
      const blobLink = opts.blobUrl
        ? `<a href="${esc(opts.blobUrl)}" target="_blank" rel="noopener">${esc(opts.blobId)}</a>`
        : `<code>${esc(opts.blobId)}</code>`;
      parts.push(`<tr><td>Blob ID</td><td>${blobLink}</td></tr>`);
    }
    if (opts.blobObjectId) {
      parts.push(`<tr><td>Object ID</td><td><code>${esc(opts.blobObjectId)}</code></td></tr>`);
    }
    if (opts.network) {
      parts.push(`<tr><td>Network</td><td>${esc(opts.network)}</td></tr>`);
    }
    parts.push(`</table></section>`);
  }

  // --- Summary Dashboard ---
  parts.push(`<section class="card">
  <h2>Summary</h2>
  <div class="dashboard">`);

  if (hasScenarios) {
    parts.push(`
    <div class="stat"><span class="stat-value">${totalResults}</span><span class="stat-label">Scenarios</span></div>
    <div class="stat stat-pass"><span class="stat-value">${passed}</span><span class="stat-label">Passed</span></div>
    <div class="stat stat-fail"><span class="stat-value">${failed}</span><span class="stat-label">Failed</span></div>
    <div class="stat stat-crash"><span class="stat-value">${crashed}</span><span class="stat-label">Crashed</span></div>`);
  } else {
    parts.push(`<div class="stat"><span class="stat-value">${totalResults}</span><span class="stat-label">Audits</span></div>`);
  }
  parts.push(`</div>`);

  // Action distribution
  parts.push(`<div class="dist-row">`);
  parts.push(`<div class="dist-block"><h3>By Decision</h3><table class="dist-table">`);
  for (const action of ["allow", "allow_with_warning", "challenge", "block"] as const) {
    const count = byAction[action] ?? 0;
    if (count === 0 && !byAction[action]) continue;
    parts.push(`<tr><td><span class="badge badge-${action}">${esc(action)}</span></td><td class="num">${count}</td></tr>`);
  }
  parts.push(`</table></div>`);

  parts.push(`<div class="dist-block"><h3>By Risk</h3><table class="dist-table">`);
  for (const risk of ["none", "low", "medium", "high", "critical"] as const) {
    const count = byRisk[risk] ?? 0;
    parts.push(`<tr><td><span class="badge badge-risk-${risk}">${esc(risk)}</span></td><td class="num">${count}</td></tr>`);
  }
  parts.push(`</table></div>`);
  parts.push(`</div></section>`);

  // --- Scenario / Result details ---
  parts.push(`<section class="card">
  <h2>Details</h2>`);

  for (let i = 0; i < results.length; i++) {
    const r = results[i]!;
    const e = r.evidence;
    const sc = hasScenarios ? scenarios[i] : undefined;

    const primary = pickPrimaryDetect(e);
    const detectCount = (e.findings ?? []).filter(f => f.kind === "detect").length;
    const action = e.decision.action;

    // Verdict
    let verdictClass = "verdict-pass";
    let verdictText = "PASS";
    if (sc) {
      if (sc.error) { verdictClass = "verdict-crash"; verdictText = "CRASH"; }
      else if (!sc.ok) { verdictClass = "verdict-fail"; verdictText = "FAIL"; }
    }

    const scenarioLabel = sc
      ? `${esc(sc.name)} <code class="dim">${esc(sc.id ?? "")}</code>`
      : `<code>${esc(e.requestId)}</code>`;

    parts.push(`
  <details class="result-card">
    <summary>
      <span class="verdict ${verdictClass}">${verdictText}</span>
      <span class="scenario-name">${scenarioLabel}</span>
      <span class="badge badge-${action}">${esc(action)}</span>
    </summary>
    <div class="result-body">`);

    // Meta row
    if (sc) {
      parts.push(`<p class="dim">Source: ${esc(sc.source ?? "user")} &middot; Encoding: ${esc(sc.encoding ?? "plain")}</p>`);
    }
    if (sc?.error) {
      parts.push(`<pre class="error-block">${esc(sc.error)}</pre>`);
    } else {
      // Decision info
      parts.push(`<table class="kv-table">
        <tr><td>Decision</td><td><span class="badge badge-${action}">${esc(action)}</span> &middot; risk=${esc(e.decision.risk ?? "none")} &middot; confidence=${e.decision.confidence.toFixed(2)}</td></tr>
        <tr><td>Detect Findings</td><td>${detectCount} / ${(e.findings ?? []).length} total</td></tr>`);
      if (primary) {
        const mvRaw = primary.evidence?.["matchedViews"];
        const mv = Array.isArray(mvRaw) ? mvRaw.join(", ") : "";
        parts.push(`<tr><td>Primary</td><td>${esc(primary.scanner)} &middot; risk=${esc(primary.risk)} &middot; view=${esc(primary.target.view)}${mv ? ` &middot; matchedViews=[${esc(mv)}]` : ""}</td></tr>`);
      }
      if (e.decision.reasons?.length) {
        parts.push(`<tr><td>Reason</td><td>${esc(e.decision.reasons[0] ?? "")}</td></tr>`);
      }
      parts.push(`<tr><td>Root Hash</td><td><code class="hash">${esc(e.integrity?.rootHash ?? "N/A")}</code></td></tr>`);
      parts.push(`</table>`);

      // Findings table
      if ((e.findings ?? []).length > 0) {
        parts.push(`<details class="findings-toggle"><summary>Findings (${(e.findings ?? []).length})</summary>`);
        parts.push(`<table class="findings-table">
          <thead><tr><th>Kind</th><th>Scanner</th><th>Risk</th><th>Score</th><th>View</th><th>Summary</th></tr></thead><tbody>`);
        for (const f of e.findings ?? []) {
          parts.push(`<tr>
            <td><span class="badge badge-kind-${f.kind}">${esc(f.kind)}</span></td>
            <td>${esc(f.scanner)}</td>
            <td><span class="badge badge-risk-${f.risk}">${esc(f.risk)}</span></td>
            <td class="num">${f.score.toFixed(2)}</td>
            <td>${esc(f.target.view)}</td>
            <td>${esc(clip(f.summary, 120))}</td>
          </tr>`);
        }
        parts.push(`</tbody></table></details>`);
      }
    }

    parts.push(`</div></details>`);
  }

  parts.push(`</section>`);

  // --- Footer ---
  parts.push(`
<footer>
  <p>Generated by <strong>Schnabel Open Audit SDK</strong> &middot; ${esc(now)}</p>
</footer>
</div>
</body>
</html>`);

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function clip(s: string, n: number): string {
  const t = (s ?? "").replace(/\s+/g, " ").trim();
  return t.length <= n ? t : t.slice(0, n) + "\u2026";
}

function formatTs(ms: number): string {
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
}

function pickPrimaryDetect(e: EvidencePackageV0) {
  const detect = (e.findings ?? []).filter(f => f.kind === "detect");
  if (!detect.length) return null;
  detect.sort((a, b) => {
    const ra = RISK_ORDER.indexOf(a.risk);
    const rb = RISK_ORDER.indexOf(b.risk);
    if (rb !== ra) return rb - ra;
    return (b.score ?? 0) - (a.score ?? 0);
  });
  return detect[0]!;
}

// ---------------------------------------------------------------------------
// Inline CSS
// ---------------------------------------------------------------------------

const CSS = `<style>
:root {
  --bg: #0a0e27;
  --bg-card: #111638;
  --bg-card-hover: #161d4a;
  --text: #e0e6f0;
  --text-dim: #7a83a6;
  --accent: #4FC1FF;
  --accent2: #6C63FF;
  --green: #22c55e;
  --red: #ef4444;
  --yellow: #f59e0b;
  --orange: #f97316;
  --border: #1e2650;
  --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --mono: "Fira Code", "Cascadia Code", Consolas, monospace;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--font);
  font-size: 14px;
  line-height: 1.6;
}
.container { max-width: 1100px; margin: 0 auto; padding: 24px 16px; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, .hash { font-family: var(--mono); font-size: 0.85em; background: rgba(79,193,255,0.08); padding: 2px 6px; border-radius: 4px; }
pre { font-family: var(--mono); font-size: 0.85em; }
header { margin-bottom: 24px; }
header h1 { font-size: 1.8em; background: linear-gradient(135deg, var(--accent), var(--accent2)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
header .meta { color: var(--text-dim); margin-top: 4px; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 20px; margin-bottom: 16px; }
.sui-card { border-color: var(--accent2); border-left: 4px solid var(--accent2); }
h2 { font-size: 1.2em; margin-bottom: 12px; color: var(--accent); }
h3 { font-size: 0.95em; margin-bottom: 8px; color: var(--text-dim); }

/* Dashboard */
.dashboard { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
.stat { background: rgba(79,193,255,0.06); border: 1px solid var(--border); border-radius: 8px; padding: 12px 20px; text-align: center; min-width: 100px; }
.stat-value { display: block; font-size: 1.8em; font-weight: 700; color: var(--accent); }
.stat-pass .stat-value { color: var(--green); }
.stat-fail .stat-value { color: var(--red); }
.stat-crash .stat-value { color: var(--yellow); }
.stat-label { font-size: 0.8em; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }

/* Distribution */
.dist-row { display: flex; gap: 24px; flex-wrap: wrap; }
.dist-block { flex: 1; min-width: 200px; }
.dist-table { width: 100%; }
.dist-table td { padding: 4px 8px; }
.num { text-align: right; font-family: var(--mono); }

/* Key-value table */
.kv-table { width: 100%; border-collapse: collapse; }
.kv-table td { padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.kv-table td:first-child { color: var(--text-dim); white-space: nowrap; width: 140px; }

/* Badges */
.badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: 600; }
.badge-allow { background: rgba(34,197,94,0.15); color: var(--green); }
.badge-allow_with_warning { background: rgba(245,158,11,0.15); color: var(--yellow); }
.badge-challenge { background: rgba(249,115,22,0.15); color: var(--orange); }
.badge-block { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-risk-none { background: rgba(122,131,166,0.15); color: var(--text-dim); }
.badge-risk-low { background: rgba(79,193,255,0.15); color: var(--accent); }
.badge-risk-medium { background: rgba(245,158,11,0.15); color: var(--yellow); }
.badge-risk-high { background: rgba(249,115,22,0.15); color: var(--orange); }
.badge-risk-critical { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-kind-sanitize { background: rgba(108,99,255,0.15); color: var(--accent2); }
.badge-kind-detect { background: rgba(249,115,22,0.15); color: var(--orange); }
.badge-kind-enrich { background: rgba(79,193,255,0.15); color: var(--accent); }

/* Result cards */
.result-card { border: 1px solid var(--border); border-radius: 8px; margin-bottom: 8px; overflow: hidden; }
.result-card > summary { display: flex; align-items: center; gap: 10px; padding: 10px 14px; cursor: pointer; background: var(--bg-card); transition: background 0.15s; }
.result-card > summary:hover { background: var(--bg-card-hover); }
.result-card[open] > summary { border-bottom: 1px solid var(--border); }
.result-body { padding: 14px; }
.scenario-name { flex: 1; }
.dim { color: var(--text-dim); }
.verdict { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
.verdict-pass { background: rgba(34,197,94,0.15); color: var(--green); }
.verdict-fail { background: rgba(239,68,68,0.15); color: var(--red); }
.verdict-crash { background: rgba(245,158,11,0.15); color: var(--yellow); }

/* Findings */
.findings-toggle { margin-top: 10px; }
.findings-toggle > summary { cursor: pointer; color: var(--text-dim); font-size: 0.9em; }
.findings-table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 0.85em; }
.findings-table th { text-align: left; padding: 6px 8px; border-bottom: 2px solid var(--border); color: var(--text-dim); font-weight: 600; }
.findings-table td { padding: 6px 8px; border-bottom: 1px solid var(--border); }

.error-block { background: rgba(239,68,68,0.1); color: var(--red); padding: 10px; border-radius: 6px; margin-top: 6px; white-space: pre-wrap; word-break: break-all; }

footer { text-align: center; color: var(--text-dim); font-size: 0.85em; margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); }

@media (max-width: 640px) {
  .dashboard { flex-direction: column; }
  .dist-row { flex-direction: column; }
  .kv-table td:first-child { width: auto; }
}
</style>`;
