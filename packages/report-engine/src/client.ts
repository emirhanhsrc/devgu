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
    setText("prompt", "$ devgu scan " + data.meta.rootName);
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
      var cnt = el("span", "card-count", counts[s]);
      if (!state.animated) countUp(cnt, counts[s]);
      button.appendChild(cnt);
      button.appendChild(el("span", "card-label", s));
      button.addEventListener("click", function () {
        state.severity = state.severity === s ? "" : s;
        byId("f-severity").value = state.severity;
        render();
      });
      box.appendChild(button);
    });
    state.animated = true;
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

  var NS = "http://www.w3.org/2000/svg";
  function svg(tag, attrs) {
    var node = document.createElementNS(NS, tag);
    Object.keys(attrs || {}).forEach(function (k) { node.setAttribute(k, String(attrs[k])); });
    return node;
  }

  function tally(keyFn) {
    var map = {};
    openFindings().forEach(function (f) { var k = keyFn(f); map[k] = (map[k] || 0) + 1; });
    return Object.keys(map).map(function (k) { return [k, map[k]]; })
      .sort(function (a, b) { return b[1] - a[1] || (a[0] < b[0] ? -1 : 1); }).slice(0, 8);
  }

  function countUp(node, to) {
    if (window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    var start = null;
    function tick(t) {
      if (start === null) start = t;
      var p = Math.min(1, (t - start) / 700);
      node.textContent = String(Math.round(to * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    }
    node.textContent = "0";
    requestAnimationFrame(tick);
  }

  function panel(title, sub) {
    var box = el("div", "chart");
    box.appendChild(el("h3", "", title));
    box.appendChild(el("p", "sub", sub));
    return box;
  }

  /* Squares arranged on a ring; slots is a list of [className, count] allocated by share. */
  function ringOf(g, radius, n, slots, total, delay, onPick) {
    var cum = 0, idx = 0;
    slots.forEach(function (slot) {
      cum += slot[1];
      var upto = total ? Math.round(n * cum / total) : 0;
      for (; idx < upto; idx++) place(slot[0], slot[2]);
    });
    for (; idx < n; idx++) place("off");
    function place(cls, pick) {
      var ang = 360 * idx / n;
      var r = svg("rect", {
        "class": "px " + cls + (pick ? " hit" : ""), x: -2, y: -radius - 3.5, width: 4, height: 7,
        transform: "translate(120 120) rotate(" + ang.toFixed(2) + ")"
      });
      r.style.setProperty("--d", (delay + idx * 0.008).toFixed(3) + "s");
      if (pick && onPick) r.addEventListener("click", function () { onPick(pick); });
      g.appendChild(r);
    }
  }

  function ringChart() {
    var box = panel(S.chartSeverity, S.chartSeveritySub);
    var wrap = el("div", "ring-wrap");
    var sev = {}, conf = { HIGH: 0, MEDIUM: 0, LOW: 0 }, total = 0;
    SEVERITIES.forEach(function (s) { sev[s] = 0; });
    openFindings().forEach(function (f) {
      sev[safeSeverity(f.severity)] += 1; total += 1;
      if (conf[f.confidence] !== undefined) conf[f.confidence] += 1;
    });
    var chart = svg("svg", { "class": "ring", viewBox: "0 0 240 240", role: "img", "aria-label": S.chartSeverity });
    var pick = function (s) {
      state.severity = state.severity === s ? "" : s;
      byId("f-severity").value = state.severity;
      render();
    };
    ringOf(chart, 112, 96, SEVERITIES.map(function (s) { return ["sev-" + s, sev[s], s]; }), total, 0.1, pick);
    ringOf(chart, 98, 84, [["hi", conf.HIGH], ["dim", conf.MEDIUM], ["off", conf.LOW]], total, 0.35);
    ringOf(chart, 84, 72, [], 0, 0.6);
    var n = svg("text", { "class": "n", x: 120, y: 128 });
    n.textContent = String(total);
    var l = svg("text", { "class": "l", x: 120, y: 148 });
    l.textContent = S.chartTotal;
    chart.appendChild(n);
    chart.appendChild(l);
    wrap.appendChild(chart);
    var legend = el("ul", "legend");
    SEVERITIES.forEach(function (s) {
      if (!sev[s]) return;
      var li = el("li", "sev-" + s);
      li.appendChild(el("i"));
      li.appendChild(el("span", "", s + " " + sev[s]));
      legend.appendChild(li);
    });
    wrap.appendChild(legend);
    box.appendChild(wrap);
    countUp(n, total);
    return box;
  }

  function segChart(title, sub, rows, total, onPick) {
    var box = panel(title, sub);
    var list = el("ul", "seg-rows");
    var max = rows.length ? rows[0][1] : 1;
    rows.forEach(function (row, r) {
      var li = el("li", "seg-row");
      li.setAttribute("title", row[0]);
      li.appendChild(el("span", "name", "\u200E" + row[0]));
      li.appendChild(el("span", "val", row[1] + " · " + Math.round(100 * row[1] / total) + "%"));
      var cells = el("span", "cells");
      var on = Math.max(1, Math.round(24 * row[1] / max));
      for (var k = 0; k < 24; k++) {
        var cell = el("i", "cell" + (k < on ? " on" : ""));
        cell.style.setProperty("--d", (r * 0.05 + k * 0.015).toFixed(3) + "s");
        cells.appendChild(cell);
      }
      li.appendChild(cells);
      li.addEventListener("click", function () { onPick(row[0]); });
      list.appendChild(li);
    });
    box.appendChild(list);
    return box;
  }

  function heatChart() {
    var box = panel(S.chartHeat, S.chartHeatSub);
    var cats = tally(function (f) { return f.category; }).map(function (x) { return x[0]; });
    var grid = {}, max = 1;
    openFindings().forEach(function (f) {
      var k = safeSeverity(f.severity) + "|" + f.category;
      grid[k] = (grid[k] || 0) + 1;
      if (grid[k] > max) max = grid[k];
    });
    var rows = SEVERITIES.filter(function (s) { return cats.some(function (c) { return grid[s + "|" + c]; }); });
    var step = 22, left = 54, top = 4;
    var w = left + cats.length * step, h = top + rows.length * step + 58;
    var chart = svg("svg", { "class": "heat", viewBox: "0 0 " + w + " " + h, role: "img", "aria-label": S.chartHeat });
    rows.forEach(function (s, y) {
      var t = svg("text", { x: 0, y: top + y * step + 13 });
      t.textContent = s;
      chart.appendChild(t);
      cats.forEach(function (c, x) {
        var count = grid[s + "|" + c] || 0;
        var rect = svg("rect", { "class": "px " + (count ? "sev-" + s + " hit" : "off"), x: left + x * step, y: top + y * step, width: 16, height: 16 });
        if (count) {
          rect.setAttribute("opacity", (0.3 + 0.7 * count / max).toFixed(2));
          var tip = svg("title");
          tip.textContent = s + " / " + c + ": " + count;
          rect.appendChild(tip);
          rect.addEventListener("click", function () {
            state.severity = s; state.category = c;
            byId("f-severity").value = s; byId("f-category").value = c;
            render();
          });
        }
        rect.style.setProperty("--d", ((x + y) * 0.04).toFixed(3) + "s");
        chart.appendChild(rect);
      });
    });
    cats.forEach(function (c, x) {
      var tx = left + x * step + 8, ty = top + rows.length * step + 8;
      var t = svg("text", { x: tx, y: ty, transform: "rotate(45 " + tx + " " + ty + ")" });
      t.textContent = c.length > 14 ? c.slice(0, 13) + "\u2026" : c;
      chart.appendChild(t);
    });
    chart.style.maxWidth = Math.round(w * 1.5) + "px";
    box.appendChild(chart);
    return box;
  }

  function renderCharts() {
    var box = byId("charts");
    clear(box);
    var total = openFindings().length;
    if (!total) { box.hidden = true; return; }
    box.hidden = false;
    function search(v) { byId("f-query").value = v; state.query = v.toLowerCase(); render(); }
    box.appendChild(ringChart());
    box.appendChild(segChart(S.chartFiles, S.chartFilesSub, tally(function (f) { return f.filePath; }), total, search));
    box.appendChild(segChart(S.chartRules, S.chartRulesSub, tally(function (f) { return f.ruleId; }), total, search));
    box.appendChild(heatChart());
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

  var EDITORS = ["vscode", "vscode-insiders", "cursor", "windsurf"];
  function location(filePath, line) {
    var label = filePath + ":" + line;
    var ed = data.editor;
    if (!ed || EDITORS.indexOf(ed.scheme) < 0) return el("span", "where", label);
    var a = el("a", "where", label);
    a.href = ed.scheme + "://file" + encodeURI(ed.root + "/" + filePath) + ":" + line;
    a.title = ed.scheme;
    a.addEventListener("click", function (e) { e.stopPropagation(); });
    return a;
  }

  function renderFinding(f) {
    var sev = safeSeverity(f.severity);
    var details = el("details", "finding sev-" + sev + (f.status === "suppressed" ? " is-suppressed" : ""));
    var summary = el("summary");
    summary.appendChild(el("span", "badge sev-" + sev, sev));
    summary.appendChild(el("span", "badge conf", S.confidenceTpl.replace("{c}", f.confidence)));
    summary.appendChild(el("span", "title", f.title));
    summary.appendChild(location(f.filePath, f.startLine));
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

  /* Pixel dancer: four hand-drawn frames flipped by CSS (no timers, no assets). */
  var DANCE_PAL = { H: "#3b4cc0", S: "#e0a068", O: "#39ff14", B: "#2f7bff", N: "#3b4cc0", W: "#c8ffd0", G: "#0b3d12" };
  var DANCE_BASE = [
    "...HHHHHH...", "..OHHHHHHO..", "..OSSSSSSO..", "..OSGSSGSO..", "...SSSSSS...", "....SSSS....",
    "...OOOOOO...", "..OOBBBBOO..", "..OOBBBBOO..", "...OOOOOO...", "....NNNN...."
  ];
  var LEGS = {
    apart: ["...SS...SS..", "...SS...SS..", "...SS...SS..", "...SS...SS..", "...SS...SS..", "..WWW...WWW.", "..WWW...WWW."],
    liftL: ["....SS.SS...", "....SS.SS...", "...SS..SS...", "..WWW..SS...", ".......SS...", "......WWW...", "......WWW..."],
    together: ["....SSSS....", "....SSSS....", "....SSSS....", "....SSSS....", "....SSSS....", "...WWWWWW...", "...WWWWWW..."],
    liftR: ["....SS.SS...", "....SS.SS...", "....SS..SS..", "....SS..WWW.", "....SS......", "...WWW......", "...WWW......"]
  };
  function armUp(col) { return [[1, col, "S"], [2, col, "O"], [3, col, "O"], [4, col, "O"], [5, col, "O"]]; }
  function armDown(col) { return [[7, col, "O"], [8, col, "O"], [9, col, "O"], [10, col, "S"]]; }
  var DANCE_FRAMES = [
    [armUp(1).concat(armUp(10)), LEGS.apart],
    [armDown(1).concat(armUp(10)), LEGS.liftL],
    [armDown(1).concat(armDown(10)), LEGS.together],
    [armUp(1).concat(armDown(10)), LEGS.liftR]
  ];

  function dancer() {
    var stage = el("div", "dancer");
    stage.setAttribute("aria-hidden", "true");
    stage.appendChild(el("div", "dance-bar", "\u266A dance.exe"));
    var field = el("div", "dance-field");
    var chart = svg("svg", { viewBox: "0 0 12 18", "class": "dance", "shape-rendering": "crispEdges" });
    DANCE_FRAMES.forEach(function (frame, k) {
      var rows = DANCE_BASE.concat(frame[1]).map(function (r) { return r.split(""); });
      frame[0].forEach(function (a) { rows[a[0]][a[1]] = a[2]; });
      var g = svg("g", { "class": "fr" });
      g.style.setProperty("--k", String(k));
      rows.forEach(function (row, y) {
        row.forEach(function (ch, x) {
          if (ch === ".") return;
          g.appendChild(svg("rect", { x: x, y: y, width: 1, height: 1, fill: DANCE_PAL[ch] }));
        });
      });
      chart.appendChild(g);
    });
    field.appendChild(chart);
    field.appendChild(el("span", "note n1", "\u266A"));
    field.appendChild(el("span", "note n2", "\u266B"));
    stage.appendChild(field);
    return stage;
  }

  /* Retro window chrome: minimize/close send a window to the taskbar, maximize toggles fullscreen. */
  var taskbar = el("nav");
  taskbar.id = "taskbar";
  taskbar.hidden = true;
  document.body.appendChild(taskbar);
  var maximized = null;

  function setMaximized(win, on) {
    if (maximized && maximized !== win) maximized.classList.remove("win-max");
    win.classList.toggle("win-max", on);
    maximized = on ? win : null;
  }

  function hideWindow(win, title) {
    if (maximized === win) setMaximized(win, false);
    win.classList.add("win-hidden");
    var chip = el("button", "", "\u25A3 " + title);
    chip.type = "button";
    chip.title = S.winRestore;
    chip.addEventListener("click", function () {
      win.classList.remove("win-hidden");
      taskbar.removeChild(chip);
      taskbar.hidden = !taskbar.childNodes.length;
    });
    taskbar.appendChild(chip);
    taskbar.hidden = false;
  }

  function addWindowButtons(bar, win) {
    var title = bar.textContent;
    var box = el("span", "win");
    [["\u2212", S.winMinimize, function () { hideWindow(win, title); }],
     ["\u25A1", S.winMaximize, function () { setMaximized(win, !win.classList.contains("win-max")); }],
     ["\u00D7", S.winClose, function () { hideWindow(win, title); }]].forEach(function (b) {
      var btn = el("button", "", b[0]);
      btn.type = "button";
      btn.title = b[1];
      btn.setAttribute("aria-label", b[1] + ": " + title);
      btn.addEventListener("click", b[2]);
      box.appendChild(btn);
    });
    bar.appendChild(box);
    bar.addEventListener("dblclick", function (e) {
      if (e.target.closest && e.target.closest(".win")) return;
      setMaximized(win, !win.classList.contains("win-max"));
    });
  }

  function setupWindows() {
    Array.prototype.forEach.call(document.querySelectorAll("main > section > h2, .chart > h3"), function (bar) {
      addWindowButtons(bar, bar.parentNode);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && maximized) setMaximized(maximized, false);
    });
  }

  renderMeta();
  fillSelect("f-severity", SEVERITIES);
  fillSelect("f-confidence", ["HIGH", "MEDIUM", "LOW"]);
  fillSelect("f-category", distinct("category"));
  fillSelect("f-engine", distinct("engine"));
  bind();
  renderDiagnostics();
  renderCharts();
  render();
  setupWindows();
  var headerEl = document.querySelector("header");
  if (headerEl) headerEl.appendChild(dancer());
})();`;
