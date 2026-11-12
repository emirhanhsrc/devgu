import { createHash } from "node:crypto";
import { htmlStrings, type HtmlStrings, type ScanResult } from "@devgu/shared";
import { CLIENT_SCRIPT } from "./client.js";

const STYLE = `
:root{color-scheme:dark;--bg:#000;--bg2:#050a06;--surface:#0a110b;--text:#c8ffd0;--border:#2fd14a;--muted:#6fa879;--accent:#39ff14;--accent-ink:#000;--link:#7dffb0;--critical:#ff3b3b;--high:#ff9f1c;--medium:#ffe600;--low:#3da5ff;--info:#8a9a8a;--ok:#39ff14;--off:rgba(57,255,20,.13);--shadow:#0c4a18;--mono:"SF Mono",ui-monospace,Menlo,Consolas,"Courier New",monospace}
*{box-sizing:border-box;border-radius:0}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 var(--mono)}
body::before{content:"";position:fixed;inset:0;pointer-events:none;z-index:9;background:repeating-linear-gradient(0deg,transparent 0 2px,rgba(57,255,20,.05) 2px 3px)}
main{max-width:1120px;margin:0 auto;padding:28px 16px 72px}
header{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:center;justify-content:space-between;background:var(--surface);border:3px solid var(--border);box-shadow:5px 5px 0 var(--shadow);padding:14px 18px;margin-bottom:6px}
h1{margin:0;font-size:26px;letter-spacing:.18em;font-weight:800}h1 span{color:var(--accent)}
.tag{color:var(--muted);margin:0}
.prompt{margin:14px 2px 22px;font-weight:700}.prompt::after{content:"\\2588";margin-left:4px;color:var(--accent);animation:blink 1s steps(1) infinite}
@keyframes blink{50%{opacity:0}}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin:0 0 22px}
.meta div{background:var(--surface);border:3px solid var(--border);padding:6px 10px;min-width:0}
.meta dt{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.meta dd{margin:0;overflow-wrap:anywhere;font-weight:700}
#severity-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:22px}
.card{cursor:pointer;background:var(--surface);color:var(--text);border:3px solid var(--border);border-left:10px solid var(--c,var(--info));box-shadow:4px 4px 0 var(--shadow);padding:8px 12px;text-align:left;font:inherit;transition:transform .08s,box-shadow .08s}
.card:hover{transform:translate(-1px,-1px);box-shadow:6px 6px 0 var(--shadow)}
.card:active{transform:translate(3px,3px);box-shadow:1px 1px 0 var(--shadow)}
.card[aria-pressed=true]{background:var(--c,var(--accent));color:var(--accent-ink)}.card[aria-pressed=true] .card-label{color:inherit}
.card-count{display:block;font-size:28px;font-weight:800;line-height:1.2}.card-label{color:var(--muted);font-size:11px;letter-spacing:.12em}
.sev-CRITICAL{--c:var(--critical)}.sev-HIGH{--c:var(--high)}.sev-MEDIUM{--c:var(--medium)}.sev-LOW{--c:var(--low)}.sev-INFO{--c:var(--info)}
.filters{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin-bottom:12px;background:var(--surface);border:3px solid var(--border);padding:10px 12px}
.filters label{display:flex;flex-direction:column;font-size:11px;color:var(--muted);gap:2px;text-transform:uppercase;letter-spacing:.08em}
select,input[type=search]{background:var(--bg);color:var(--text);border:3px solid var(--border);padding:4px 8px;font:inherit;text-transform:none;letter-spacing:0}
input[type=search]{min-width:220px}
.check{flex-direction:row!important;align-items:center;gap:6px!important}
input[type=checkbox]{accent-color:var(--accent);width:16px;height:16px}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
#count{color:var(--muted);margin:10px 0}
.finding{background:var(--surface);border:3px solid var(--border);border-left:10px solid var(--c,var(--info));box-shadow:4px 4px 0 var(--shadow);margin-bottom:12px}
.finding.is-suppressed{opacity:.6}
.finding summary{cursor:pointer;padding:8px 12px;display:flex;flex-wrap:wrap;gap:6px 10px;align-items:center}
.finding summary:hover{background:var(--bg2)}
.finding[open] summary{background:var(--accent);color:var(--accent-ink);border-bottom:3px solid var(--border)}
.finding[open] .where,.finding[open] .badge.conf{color:inherit}
.badge{font-size:11px;font-weight:800;letter-spacing:.06em;padding:1px 6px;border:2px solid var(--border);background:var(--bg);color:var(--text)}
.badge.sev-CRITICAL,.badge.sev-HIGH,.badge.sev-MEDIUM,.badge.sev-LOW,.badge.sev-INFO{background:var(--c);color:#fff;border-color:var(--border)}
.badge.sev-MEDIUM{color:#000}
.badge.conf{color:var(--muted);background:transparent}
.title{font-weight:800;flex:1 1 280px;overflow-wrap:anywhere}.where{color:var(--link);font-size:12px;overflow-wrap:anywhere;text-decoration:none;border-bottom:2px dotted currentColor}
a.where:hover{background:var(--link);color:var(--surface)}
.body{padding:0 14px 14px}
.body h4{margin:14px 0 4px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted)}
.body p{margin:0;overflow-wrap:anywhere}.rule{color:var(--muted);margin-top:10px!important;font-size:12px}
pre{margin:0;background:var(--bg);border:3px solid var(--border);padding:10px;overflow-x:auto;font:12px/1.5 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere}
.flow{margin:0;padding-left:20px;font-size:12px}.flow li{overflow-wrap:anywhere}
.refs{margin:0;padding-left:20px;overflow-wrap:anywhere}a{color:var(--link)}
.fp{color:var(--muted);font-size:11px;margin-top:12px!important}
#empty{padding:24px;text-align:center;color:var(--muted);background:var(--surface);border:3px dashed var(--border)}
h2,.chart h3{display:flex;justify-content:space-between;align-items:center;gap:8px;background:var(--accent);color:var(--accent-ink);border:3px solid var(--border);margin:0;padding:3px 8px;font-size:14px;font-weight:800;letter-spacing:.04em}
h2{margin:34px 0 10px;box-shadow:4px 4px 0 var(--shadow)}
.win{display:flex;gap:3px;flex:none}
.win button{width:20px;height:18px;padding:0;background:var(--surface);color:var(--text);border:2px solid var(--border);font:800 11px/1 var(--mono);cursor:pointer}
.win button:hover{background:var(--text);color:var(--surface)}
.win button:active{transform:translate(1px,1px)}
.win-hidden{display:none!important}
.win-max{position:fixed!important;inset:14px;z-index:50;overflow:auto;margin:0!important;background:var(--bg);padding:0 16px 16px;box-shadow:0 0 0 100vmax rgba(0,0,0,.8)!important;animation:none!important}
section.win-max{padding:16px}
.chart.win-max{padding:0 16px 16px}
.win-max .ring{max-width:min(480px,70vw)}.win-max .heat{max-width:none!important}
#taskbar{position:fixed;left:0;right:0;bottom:0;z-index:60;display:flex;gap:8px;flex-wrap:wrap;padding:6px 12px;background:var(--bg2);border-top:3px solid var(--border)}
#taskbar[hidden]{display:none}
#taskbar button{background:var(--accent);color:var(--accent-ink);border:3px solid var(--border);box-shadow:3px 3px 0 var(--shadow);font:700 12px var(--mono);padding:2px 10px;cursor:pointer;max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
#taskbar button:active{transform:translate(2px,2px);box-shadow:1px 1px 0 var(--shadow)}
#stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0}
.stat{background:var(--surface);border:3px solid var(--border);padding:6px 10px}.stat dt{color:var(--muted);font-size:11px;text-transform:uppercase}.stat dd{margin:0;font-weight:700}
#diag-list{padding-left:20px;overflow-wrap:anywhere}
footer{margin-top:44px;color:var(--muted);font-size:12px;border-top:3px solid var(--border);padding-top:10px}
.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:22px}
.chart{position:relative;background:var(--surface);border:3px solid var(--border);box-shadow:5px 5px 0 var(--shadow);padding:0 16px 16px;min-width:0;overflow:hidden;animation:rise .45s steps(6) both}
.chart:nth-child(2){animation-delay:.08s}.chart:nth-child(3){animation-delay:.16s}.chart:nth-child(4){animation-delay:.24s}
.chart h3{margin:0 -16px;border-width:0 0 3px;padding:4px 10px}
.chart .sub{margin:10px 0 14px;color:var(--muted);font-size:12px}
.ring-wrap{display:flex;flex-direction:column;align-items:center;gap:10px}
.ring{width:100%;max-width:240px;height:auto}
.px{fill:var(--c,var(--off));animation:pop .45s steps(3) both;animation-delay:var(--d,0s)}
.px.off{fill:var(--off)}.px.dim{fill:var(--muted);opacity:.5}.px.hi{fill:var(--text)}
.px.hit{cursor:pointer}.px.hit:hover{filter:brightness(1.35)}
.ring text{text-anchor:middle;fill:var(--text);font-family:var(--mono)}.ring .n{font-size:40px;font-weight:800}.ring .l{font-size:10px;fill:var(--muted);letter-spacing:.12em;text-transform:uppercase}
.legend{list-style:none;margin:0;padding:0;display:flex;flex-wrap:wrap;gap:4px 14px;justify-content:center;font-size:12px}
.legend li{display:flex;align-items:center;gap:6px}.legend i{width:10px;height:10px;background:var(--c);border:2px solid var(--border);display:inline-block}
.seg-rows{list-style:none;margin:0;padding:0}
.seg-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 10px;margin-bottom:12px;cursor:pointer}
.seg-row .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;direction:rtl;text-align:left}
.seg-row .val{font-weight:800}
.cells{grid-column:1/-1;display:grid;grid-template-columns:repeat(24,1fr);gap:3px}
.cell{aspect-ratio:1;max-height:10px;background:var(--off);animation:pop .35s steps(3) both;animation-delay:var(--d,0s)}
.cell.on{background:var(--accent)}
.seg-row:hover .name{background:var(--text);color:var(--surface)}
.heat{width:100%;height:auto}.heat text{fill:var(--muted);font-size:9px;font-family:var(--mono)}
.dancer{border:3px solid #39ff14;background:#07120a;box-shadow:4px 4px 0 var(--shadow);flex:none}
.dance-bar{background:#39ff14;color:#000;font:800 10px var(--mono);padding:1px 6px;border-bottom:3px solid #39ff14}
.dance-field{position:relative;padding:6px 26px 4px;line-height:0}
.dance{width:48px;height:72px;overflow:visible;animation:bounce .6s steps(1) infinite}
.fr{opacity:0;animation:fr4 1.2s steps(1) infinite;animation-delay:calc(var(--k)*.3s)}
.note{position:absolute;font:800 14px var(--mono);color:#3da5ff;opacity:0;animation:float 1.8s steps(6) infinite}
.n1{left:6px;bottom:30px}.n2{right:6px;bottom:44px;animation-delay:.9s;color:#39ff14}
@keyframes fr4{0%{opacity:1}25%{opacity:0}}
@keyframes bounce{50%{transform:translateY(-3px)}}
@keyframes float{0%{opacity:1;transform:translateY(8px)}100%{opacity:0;transform:translateY(-22px)}}
@keyframes rise{from{opacity:0;transform:translateY(8px)}}
@keyframes pop{from{opacity:0}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}.fr:first-child{opacity:1!important}}
@media print{body{background:#fff;color:#000}body::before,.filters{display:none}.finding{break-inside:avoid}details>*{display:block!important}}
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

/** Escapes text placed inside an attribute value in the static document template. */
function attr(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

function body(h: HtmlStrings): string {
  return `
<main>
  <header>
    <h1>DEV<span>GU</span></h1>
    <p class="tag">${attr(h.tagline)}</p>
  </header>
  <p class="prompt" id="prompt" aria-hidden="true"></p>
  <dl class="meta" aria-label="${attr(h.scanInfoAria)}">
    <div><dt>${attr(h.repository)}</dt><dd id="m-root"></dd></div>
    <div><dt>${attr(h.scannedAt)}</dt><dd id="m-time"></dd></div>
    <div><dt>${attr(h.scannerVersion)}</dt><dd id="m-version"></dd></div>
    <div><dt>${attr(h.ruleSet)}</dt><dd id="m-ruleset"></dd></div>
    <div><dt>${attr(h.engines)}</dt><dd id="m-engines"></dd></div>
    <div><dt>${attr(h.enabledRules)}</dt><dd id="m-rules"></dd></div>
  </dl>
  <section aria-label="${attr(h.findingsAria)}"><div id="severity-cards"></div></section>
  <section id="charts" class="charts" aria-label="${attr(h.client.chartSeverity)}"></section>
  <section aria-label="${attr(h.findingsAria)}">
    <h2>${attr(h.findings)}</h2>
    <div class="filters" role="search">
      <label>${attr(h.search)}<input type="search" id="f-query" placeholder="${attr(h.searchPlaceholder)}"></label>
      <label>${attr(h.severity)}<select id="f-severity"><option value="">${attr(h.all)}</option></select></label>
      <label>${attr(h.confidence)}<select id="f-confidence"><option value="">${attr(h.all)}</option></select></label>
      <label>${attr(h.category)}<select id="f-category"><option value="">${attr(h.all)}</option></select></label>
      <label>${attr(h.engine)}<select id="f-engine"><option value="">${attr(h.all)}</option></select></label>
      <label class="check"><input type="checkbox" id="f-suppressed"> ${attr(h.showSuppressed)}</label>
    </div>
    <p id="count" aria-live="polite"></p>
    <div id="findings"></div>
    <p id="empty" hidden></p>
  </section>
  <section id="diagnostics" aria-label="${attr(h.diagnosticsHeading)}"><h2>${attr(h.diagnosticsHeading)}</h2><ul id="diag-list"></ul></section>
  <section aria-label="${attr(h.statsHeading)}"><h2>${attr(h.statsHeading)}</h2><dl id="stats"></dl></section>
  <footer>${attr(h.footer)}</footer>
</main>`;
}

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
export const EDITOR_SCHEMES = ["vscode", "vscode-insiders", "cursor", "windsurf"] as const;
export type EditorScheme = (typeof EDITOR_SCHEMES)[number];

/** Opt-in: finding locations become `scheme://file/<abs path>:<line>` links. Embeds the local root path. */
export interface EditorLinks {
  scheme: EditorScheme;
  root: string;
}

function editorBase(links: EditorLinks): { scheme: string; root: string } {
  let root = links.root.replace(/\\/g, "/").replace(/\/+$/, "");
  if (!root.startsWith("/")) root = `/${root}`; // Windows drive paths: C:/x -> /C:/x
  return { scheme: links.scheme, root };
}

export function renderHtml(result: ScanResult, editor?: EditorLinks): string {
  const h = htmlStrings(result.meta.lang);
  const data: HtmlReportData & {
    strings: HtmlStrings["client"];
    editor?: { scheme: string; root: string };
  } = {
    meta: result.meta,
    stats: result.stats,
    findings: [...result.findings, ...result.suppressed],
    diagnostics: result.diagnostics,
    skipped: result.skipped.slice(0, 500),
    strings: h.client,
    ...(editor ? { editor: editorBase(editor) } : {}),
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
    `<html lang="${attr(h.htmlLang)}">`,
    "<head>",
    '<meta charset="utf-8">',
    `<meta http-equiv="Content-Security-Policy" content="${csp}">`,
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta name="referrer" content="no-referrer">',
    '<meta name="color-scheme" content="dark light">',
    `<title>${escapeHtml(h.titlePrefix)} - ${escapeHtml(result.meta.rootName)}</title>`,
    `<style>${STYLE}</style>`,
    "</head>",
    "<body>",
    body(h),
    `<script type="application/json" id="devgu-data">${embedJson(data)}</script>`,
    `<script>${CLIENT_SCRIPT}</script>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}
