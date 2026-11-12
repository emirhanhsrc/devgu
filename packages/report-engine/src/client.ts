/**
 * Browser code embedded in the HTML report. Rules for this file:
 *  - it must never use innerHTML/outerHTML/insertAdjacentHTML/document.write, eval or Function:
 *    every dynamic string is rendered with textContent;
 *  - it must not contain backticks or "${" (it lives inside a template literal);
 *  - it runs under a CSP that only allows this exact script (by hash).
 */
export const CLIENT_SCRIPT = String.raw`(function () {
  "use strict";
  var data = JSON.parse(document.getElementById("devgu-data").textContent);
  var S = data.strings || {};
  var SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  var state = { severity: "", confidence: "", category: "", engine: "", query: "", suppressed: false };

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }
  function byId(id) { return document.getElementById(id); }
  function safeSeverity(value) { return SEVERITIES.indexOf(value) >= 0 ? value : "INFO"; }
  function isHttps(url) { return typeof url === "string" && /^https:\/\//i.test(url); }
  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  function setText(id, text) { byId(id).textContent = text; }

  function renderMeta() {
    setText("m-root", data.meta.rootName);
    setText("m-time", data.meta.scannedAt);
    setText("m-version", data.meta.toolVersion);
    setText("m-ruleset", data.meta.rulesetVersion);
    setText("m-engines", data.meta.engines.join(", ") || "-");
    setText("m-rules", String(data.meta.enabledRules.length));
  }

  function openFindings() { return data.findings.filter(function (f) { return f.status === "open"; }); }

  function renderStats() {
    var box = byId("severity-cards");
    clear(box);
    var counts = {};
    SEVERITIES.forEach(function (s) { counts[s] = 0; });
    openFindings().forEach(function (f) { counts[safeSeverity(f.severity)] += 1; });
    SEVERITIES.forEach(function (s) {
      var button = el("button", "card sev-" + s);
      button.type = "button";
      button.setAttribute("aria-pressed", String(state.severity === s));
      button.appendChild(el("span", "card-count", counts[s]));
      button.appendChild(el("span", "card-label", s));
      button.addEventListener("click", function () {
        state.severity = state.severity === s ? "" : s;
        byId("f-severity").value = state.severity;
        render();
      });
      box.appendChild(button);
    });
    var s = data.stats;
    var rows = [
      [S.filesScanned, s.filesScanned], [S.filesSkipped, s.filesSkipped],
      [S.cacheHits, s.cacheHits + " / " + (s.cacheHits + s.cacheMisses)],
      [S.parseTime, s.parseMs + " ms"], [S.ruleTime, s.ruleMs + " ms"],
      [S.totalTime, s.totalMs + " ms"], [S.heapUsed, s.heapUsedMb + " MB"]
    ];
    var list = byId("stats");
    clear(list);
    rows.forEach(function (row) {
      var item = el("div", "stat");
      item.appendChild(el("dt", "", row[0]));
      item.appendChild(el("dd", "", row[1]));
      list.appendChild(item);
    });
  }

  function fillSelect(id, values) {
    var select = byId(id);
    values.forEach(function (value) {
      var option = el("option", "", value);
      option.value = value;
      select.appendChild(option);
    });
  }

  function distinct(key) {
    var seen = {};
    data.findings.forEach(function (f) { seen[f[key]] = true; });
    return Object.keys(seen).sort();
  }

  function matches(f) {
    if (f.status === "suppressed" && !state.suppressed) return false;
    if (state.severity && f.severity !== state.severity) return false;
    if (state.confidence && f.confidence !== state.confidence) return false;
    if (state.category && f.category !== state.category) return false;
    if (state.engine && f.engine !== state.engine) return false;
    if (state.query) {
      var hay = (f.ruleId + " " + f.title + " " + f.filePath + " " + f.evidence).toLowerCase();
      if (hay.indexOf(state.query) < 0) return false;
    }
    return true;
  }

  function section(title, text) {
    var wrap = el("div", "section");
    wrap.appendChild(el("h4", "", title));
    wrap.appendChild(el("p", "", text));
    return wrap;
  }

  function renderFinding(f) {
    var sev = safeSeverity(f.severity);
    var details = el("details", "finding sev-" + sev + (f.status === "suppressed" ? " is-suppressed" : ""));
    var summary = el("summary");
    summary.appendChild(el("span", "badge sev-" + sev, sev));
    summary.appendChild(el("span", "badge conf", S.confidenceTpl.replace("{c}", f.confidence)));
    summary.appendChild(el("span", "title", f.title));
    summary.appendChild(el("span", "where", f.filePath + ":" + f.startLine));
    details.appendChild(summary);

    var body = el("div", "body");
    body.appendChild(el("p", "rule", f.ruleId + " · " + f.category + " · " + f.engine));
    body.appendChild(section(S.whatDetected, f.description));
    body.appendChild(el("h4", "", S.evidence));
    body.appendChild(el("pre", "evidence", f.evidence));
    if (f.dataFlow && f.dataFlow.length) {
      body.appendChild(el("h4", "", S.dataFlow));
      var flow = el("ol", "flow");
      f.dataFlow.forEach(function (step) {
        flow.appendChild(el("li", "", step.filePath + ":" + step.line + " — " + step.description));
      });
      body.appendChild(flow);
    }
    body.appendChild(section(S.howToFix, f.remediation));
    body.appendChild(section(S.limitationsDetail, f.limitations));
    if (f.suppression) body.appendChild(section(S.suppressedTpl.replace("{kind}", f.suppression.kind), f.suppression.justification));
    if (f.references && f.references.length) {
      body.appendChild(el("h4", "", S.references));
      var refs = el("ul", "refs");
      f.references.forEach(function (url) {
        var item = el("li");
        if (isHttps(url)) {
          var link = el("a", "", url);
          link.setAttribute("href", url);
          link.setAttribute("rel", "noopener noreferrer");
          link.setAttribute("target", "_blank");
          item.appendChild(link);
        } else {
          item.textContent = url;
        }
        refs.appendChild(item);
      });
      body.appendChild(refs);
    }
    body.appendChild(el("p", "fp", S.fingerprintLabel + " " + f.fingerprint));
    details.appendChild(body);
    return details;
  }

  function render() {
    renderStats();
    var list = byId("findings");
    clear(list);
    var shown = data.findings.filter(matches);
    shown.forEach(function (f) { list.appendChild(renderFinding(f)); });
    var total = state.suppressed ? data.findings.length : openFindings().length;
    setText("count", S.showingTpl.replace("{shown}", shown.length).replace("{total}", total));
    byId("empty").hidden = shown.length !== 0;
    byId("empty").textContent = total === 0 ? S.noFindings : S.noMatch;
  }

  function renderDiagnostics() {
    var box = byId("diagnostics");
    if (!data.diagnostics.length && !data.skipped.length) { box.hidden = true; return; }
    var list = byId("diag-list");
    data.diagnostics.forEach(function (d) {
      list.appendChild(el("li", "", d.source + (d.filePath ? " " + d.filePath : "") + ": " + d.message));
    });
    data.skipped.forEach(function (s) {
      list.appendChild(el("li", "", S.skippedTpl.replace("{file}", s.filePath).replace("{reason}", s.reason)));
    });
  }

  function bind() {
    byId("f-severity").addEventListener("change", function (e) { state.severity = e.target.value; render(); });
    byId("f-confidence").addEventListener("change", function (e) { state.confidence = e.target.value; render(); });
    byId("f-category").addEventListener("change", function (e) { state.category = e.target.value; render(); });
    byId("f-engine").addEventListener("change", function (e) { state.engine = e.target.value; render(); });
    byId("f-query").addEventListener("input", function (e) { state.query = e.target.value.toLowerCase(); render(); });
    byId("f-suppressed").addEventListener("change", function (e) { state.suppressed = e.target.checked; render(); });
  }

  renderMeta();
  fillSelect("f-severity", SEVERITIES);
  fillSelect("f-confidence", ["HIGH", "MEDIUM", "LOW"]);
  fillSelect("f-category", distinct("category"));
  fillSelect("f-engine", distinct("engine"));
  bind();
  renderDiagnostics();
  render();
})();`;
