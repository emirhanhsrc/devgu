import { createHash } from "node:crypto";
import type { ScanResult } from "@devgu/shared";
import { CLIENT_SCRIPT } from "./client.js";

const STYLE = `
:root{color-scheme:dark light;--bg:#0b0d12;--bg2:#121620;--surface:#191f2b;--border:#2a3242;--text:#e8ecf3;--muted:#8f9aae;--accent:#2baae2;--critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;--info:#8f9aae;--ok:#22c55e}
@media (prefers-color-scheme:light){:root{--bg:#f6f7fa;--bg2:#eceff5;--surface:#ffffff;--border:#d5dae4;--text:#161b26;--muted:#5b6578;--accent:#0b78a8;--medium:#a37a00;--info:#5b6578}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;justify-content:space-between;border-bottom:1px solid var(--border);padding-bottom:16px;margin-bottom:20px}
h1{margin:0;font-size:22px;letter-spacing:.08em}h1 span{color:var(--accent)}
.tag{color:var(--muted);margin:0}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin:0 0 20px}
.meta div{background:var(--surface);border:1px solid var(--border);padding:8px 12px;border-radius:6px}
.meta dt{color:var(--muted);font-size:12px}.meta dd{margin:0;overflow-wrap:anywhere}
#severity-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px;margin-bottom:20px}
.card{cursor:pointer;background:var(--surface);color:var(--text);border:1px solid var(--border);border-left:4px solid var(--info);border-radius:6px;padding:10px 12px;text-align:left;font:inherit}
.card[aria-pressed=true]{outline:2px solid var(--accent)}
.card-count{display:block;font-size:24px;font-weight:600}.card-label{color:var(--muted);font-size:12px;letter-spacing:.06em}
.sev-CRITICAL{--c:var(--critical)}.sev-HIGH{--c:var(--high)}.sev-MEDIUM{--c:var(--medium)}.sev-LOW{--c:var(--low)}.sev-INFO{--c:var(--info)}
.card.sev-CRITICAL,.card.sev-HIGH,.card.sev-MEDIUM,.card.sev-LOW,.card.sev-INFO{border-left-color:var(--c)}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:12px}
.filters label{display:flex;flex-direction:column;font-size:12px;color:var(--muted);gap:2px}
select,input[type=search]{background:var(--surface);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:6px 8px;font:inherit}
input[type=search]{min-width:220px}
.check{flex-direction:row!important;align-items:center;gap:6px!important;margin-top:16px}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
#count{color:var(--muted);margin:8px 0}
.finding{background:var(--surface);border:1px solid var(--border);border-left:4px solid var(--c,var(--info));border-radius:6px;margin-bottom:8px}
.finding.is-suppressed{opacity:.6}
.finding summary{cursor:pointer;padding:10px 12px;display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center}
.badge{font-size:11px;font-weight:600;letter-spacing:.05em;border-radius:4px;padding:2px 6px;border:1px solid var(--border)}
.badge.sev-CRITICAL,.badge.sev-HIGH,.badge.sev-MEDIUM,.badge.sev-LOW,.badge.sev-INFO{color:var(--c);border-color:var(--c)}
.badge.conf{color:var(--muted)}
.title{font-weight:600;flex:1 1 280px;overflow-wrap:anywhere}.where{color:var(--muted);font-family:ui-monospace,Consolas,monospace;font-size:12px;overflow-wrap:anywhere}
.body{padding:0 14px 14px;border-top:1px solid var(--border)}
.body h4{margin:14px 0 4px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.body p{margin:0;overflow-wrap:anywhere}.rule{color:var(--muted);margin-top:10px!important;font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{margin:0;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:10px;overflow-x:auto;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;overflow-wrap:anywhere}
.flow{margin:0;padding-left:20px;font-family:ui-monospace,Consolas,monospace;font-size:12px}.flow li{overflow-wrap:anywhere}
.refs{margin:0;padding-left:20px;overflow-wrap:anywhere}a{color:var(--accent)}
.fp{color:var(--muted);font:11px ui-monospace,Consolas,monospace;margin-top:12px!important}
#empty{padding:24px;text-align:center;color:var(--muted);background:var(--surface);border:1px dashed var(--border);border-radius:6px}
h2{font-size:15px;margin:32px 0 8px}
#stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin:0}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:8px 12px}.stat dt{color:var(--muted);font-size:12px}.stat dd{margin:0}
#diag-list{padding-left:20px;overflow-wrap:anywhere}
footer{margin-top:40px;color:var(--muted);font-size:12px}
@media print{body{background:#fff;color:#000}.filters{display:none}.finding{break-inside:avoid}details>*{display:block!important}}
`;

/** HTML-escapes text that goes into markup (only the document title is built this way). */
function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

/**
 * Serializes data for a <script type="application/json"> block. `<`, `>` and `&` become unicode
 * escapes so no string can close the script element or open a comment, and the JS-only line
 * separators are escaped as well.
 */
export function embedJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

const BODY = `
<main>
  <header>
    <h1>DEV<span>GU</span></h1>
    <p class="tag">Understand Your Code. Secure Your Software.</p>
  </header>
  <dl class="meta" aria-label="Scan information">
    <div><dt>Repository</dt><dd id="m-root"></dd></div>
    <div><dt>Scanned at</dt><dd id="m-time"></dd></div>
    <div><dt>Scanner version</dt><dd id="m-version"></dd></div>
    <div><dt>Rule set</dt><dd id="m-ruleset"></dd></div>
    <div><dt>Engines</dt><dd id="m-engines"></dd></div>
    <div><dt>Enabled rules</dt><dd id="m-rules"></dd></div>
  </dl>
  <section aria-label="Findings by severity"><div id="severity-cards"></div></section>
  <section aria-label="Findings">
    <h2>Findings</h2>
    <div class="filters" role="search">
      <label>Search<input type="search" id="f-query" placeholder="rule, file, text"></label>
      <label>Severity<select id="f-severity"><option value="">All</option></select></label>
      <label>Confidence<select id="f-confidence"><option value="">All</option></select></label>
      <label>Category<select id="f-category"><option value="">All</option></select></label>
      <label>Engine<select id="f-engine"><option value="">All</option></select></label>
      <label class="check"><input type="checkbox" id="f-suppressed"> Show suppressed</label>
    </div>
    <p id="count" aria-live="polite"></p>
    <div id="findings"></div>
    <p id="empty" hidden></p>
  </section>
  <section id="diagnostics" aria-label="Diagnostics"><h2>Diagnostics and skipped files</h2><ul id="diag-list"></ul></section>
  <section aria-label="Scan statistics"><h2>Scan statistics</h2><dl id="stats"></dl></section>
  <footer>Generated by DEVGU. Findings come from deterministic rules; each lists its limitations. No data left this machine to produce this report.</footer>
</main>`;

export interface HtmlReportData {
  meta: ScanResult["meta"];
  stats: ScanResult["stats"];
  findings: ScanResult["findings"];
  diagnostics: ScanResult["diagnostics"];
  skipped: ScanResult["skipped"];
}

/**
 * Self-contained HTML report. Its content originates from untrusted repositories, so:
 *  - data is embedded as inert JSON and rendered with textContent only (see client.ts);
 *  - a CSP allows nothing except this document's own style and its single hashed script;
 *  - there are no external resources, fonts, images or network calls.
 */
export function renderHtml(result: ScanResult): string {
  const data: HtmlReportData = {
    meta: result.meta,
    stats: result.stats,
    findings: [...result.findings, ...result.suppressed],
    diagnostics: result.diagnostics,
    skipped: result.skipped.slice(0, 500),
  };
  const scriptHash = createHash("sha256").update(CLIENT_SCRIPT).digest("base64");
  const csp = [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    `script-src 'sha256-${scriptHash}'`,
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="${csp}">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    '<meta name="color-scheme" content="dark light">',
    `<title>DEVGU report - ${escapeHtml(result.meta.rootName)}</title>`,
    `<style>${STYLE}</style>`,
    "</head>",
    "<body>",
    BODY,
    `<script type="application/json" id="devgu-data">${embedJson(data)}</script>`,
    `<script>${CLIENT_SCRIPT}</script>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
