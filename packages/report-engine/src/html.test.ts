import { createHash } from "node:crypto";
import { JSDOM } from "jsdom";
import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "@devgu/shared";
import { CLIENT_SCRIPT } from "./client.js";
import { embedJson, renderHtml } from "./html.js";
import { mdEscape, renderMarkdown } from "./markdown.js";

const PAYLOAD = '</script><img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "JS-XSS-001-abcd1234-L3",
    ruleId: "JS-XSS-001",
    engine: "security",
    title: "Dynamic value assigned to innerHTML",
    description: "desc",
    severity: "HIGH",
    confidence: "MEDIUM",
    category: "xss",
    filePath: "src/a.jsx",
    startLine: 3,
    endLine: 3,
    evidence: "el.innerHTML = x;",
    remediation: "fix it",
    references: ["https://example.org/ref", "javascript:alert(1)"],
    limitations: "may be wrong",
    fingerprint: "f".repeat(32),
    status: "open",
    ...overrides,
  };
}

function result(findings: Finding[], suppressed: Finding[] = [], rootName = "demo"): ScanResult {
  return {
    meta: {
      tool: "devgu",
      toolVersion: "0.1.0",
      rulesetVersion: "abc",
      scannedAt: "2026-01-01T00:00:00.000Z",
      rootName,
      engines: ["security", "taint"],
      enabledRules: ["JS-XSS-001"],
    },
    findings,
    suppressed,
    skipped: [{ filePath: PAYLOAD, reason: "binary" }],
    diagnostics: [{ source: PAYLOAD, filePath: PAYLOAD, message: PAYLOAD }],
    stats: {
      filesDiscovered: 2,
      filesScanned: 1,
      filesSkipped: 1,
      cacheHits: 0,
      cacheMisses: 1,
      parseMs: 1,
      ruleMs: 1,
      totalMs: 5,
      heapUsedMb: 10,
      findingsBySeverity: { CRITICAL: 0, HIGH: findings.length, MEDIUM: 0, LOW: 0, INFO: 0 },
    },
  };
}

const hostile = finding({
  title: PAYLOAD,
  description: PAYLOAD,
  evidence: PAYLOAD,
  remediation: PAYLOAD,
  limitations: PAYLOAD,
  filePath: PAYLOAD,
  category: PAYLOAD,
  dataFlow: [{ filePath: PAYLOAD, line: 1, description: PAYLOAD }],
});

function load(html: string) {
  return new JSDOM(html, { runScripts: "dangerously", pretendToBeVisual: true });
}

describe("HTML report security", () => {
  const html = renderHtml(
    result(
      [hostile],
      [finding({ status: "suppressed", suppression: { kind: "inline", justification: PAYLOAD } })],
      PAYLOAD,
    ),
  );

  it("never emits hostile markup into the document source", () => {
    expect(html).not.toContain("</script><img");
    expect(html).not.toContain('onerror="window');
    expect(html.match(/<script/g)).toHaveLength(2); // data block + app script
    expect(html.match(/<\/script>/g)).toHaveLength(2);
  });

  it("uses a CSP that allows only the embedded script by hash", () => {
    const hash = createHash("sha256").update(CLIENT_SCRIPT).digest("base64");
    expect(html).toContain(`script-src 'sha256-${hash}'`);
    expect(html).toContain("default-src 'none'");
    expect(html).not.toContain("unsafe-eval");
    const scriptBody = /<script>([\s\S]*?)<\/script>/.exec(html)?.[1] ?? "";
    expect(createHash("sha256").update(scriptBody).digest("base64")).toBe(hash);
  });

  it("contains no external resources", () => {
    expect(html).not.toMatch(/<(link|img|iframe|object|embed)\b/i);
    expect(html).not.toMatch(/\bsrc\s*=\s*["']https?:/i);
  });

  it("client code avoids dangerous DOM APIs", () => {
    for (const forbidden of [
      "innerHTML",
      "outerHTML",
      "insertAdjacentHTML",
      "document.write",
      "eval(",
      "new Function",
    ]) {
      expect(CLIENT_SCRIPT).not.toContain(forbidden);
    }
    expect(CLIENT_SCRIPT).not.toContain("`");
  });

  it("renders hostile data as inert text when actually executed", () => {
    const dom = load(html);
    const doc = dom.window.document;
    expect(doc.querySelectorAll("img")).toHaveLength(0);
    expect(doc.querySelectorAll("script")).toHaveLength(2);
    expect((dom.window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    expect(doc.getElementById("m-root")?.textContent).toBe(PAYLOAD);
    expect(doc.querySelector(".finding .title")?.textContent).toBe(PAYLOAD);
    expect(doc.querySelector(".evidence")?.textContent).toBe(PAYLOAD);
    expect(doc.title).toBe(`DEVGU report - ${PAYLOAD}`);
    dom.window.close();
  });

  it("only links https references", () => {
    const dom = load(renderHtml(result([finding()])));
    const hrefs = [...dom.window.document.querySelectorAll(".refs a")].map((a) =>
      a.getAttribute("href"),
    );
    expect(hrefs).toEqual(["https://example.org/ref"]);
    expect(dom.window.document.querySelector(".refs")?.textContent).toContain(
      "javascript:alert(1)",
    );
    dom.window.close();
  });
});

describe("HTML report behaviour", () => {
  const findings = [
    finding({
      severity: "CRITICAL",
      title: "first",
      category: "code-execution",
      ruleId: "JS-EXEC-001",
    }),
    finding({
      severity: "LOW",
      title: "second",
      category: "xss",
      ruleId: "JS-TAINT-001",
      engine: "taint",
      confidence: "LOW",
    }),
  ];
  const suppressed = [
    finding({
      title: "hidden",
      status: "suppressed",
      suppression: { kind: "config", justification: "accepted" },
    }),
  ];

  it("renders counts, filters and suppressed toggle", () => {
    const dom = load(renderHtml(result(findings, suppressed)));
    const doc = dom.window.document;
    const titles = (): string[] =>
      [...doc.querySelectorAll(".finding .title")].map((n) => n.textContent ?? "");
    expect(titles()).toEqual(["first", "second"]);
    expect(doc.getElementById("count")?.textContent).toBe("Showing 2 of 2 finding(s)");

    const select = doc.getElementById("f-severity") as HTMLSelectElement;
    select.value = "CRITICAL";
    select.dispatchEvent(new dom.window.Event("change"));
    expect(titles()).toEqual(["first"]);
    select.value = "";
    select.dispatchEvent(new dom.window.Event("change"));

    const query = doc.getElementById("f-query") as HTMLInputElement;
    query.value = "SECOND";
    query.dispatchEvent(new dom.window.Event("input"));
    expect(titles()).toEqual(["second"]);
    query.value = "";
    query.dispatchEvent(new dom.window.Event("input"));

    const toggle = doc.getElementById("f-suppressed") as HTMLInputElement;
    toggle.checked = true;
    toggle.dispatchEvent(new dom.window.Event("change"));
    expect(titles()).toEqual(["first", "second", "hidden"]);
    dom.window.close();
  });

  it("explains an empty result without claiming safety", () => {
    const dom = load(renderHtml(result([])));
    const empty = dom.window.document.getElementById("empty");
    expect(empty?.hidden).toBe(false);
    expect(empty?.textContent).toContain("does not prove");
    dom.window.close();
  });

  it("shows the data flow path", () => {
    const flow = finding({
      dataFlow: [
        { filePath: "a.js", line: 1, description: "Source: location.search" },
        { filePath: "a.js", line: 3, description: "Sink: innerHTML assignment" },
      ],
    });
    const dom = load(renderHtml(result([flow])));
    const steps = [...dom.window.document.querySelectorAll(".flow li")].map((n) => n.textContent);
    expect(steps).toEqual([
      "a.js:1 — Source: location.search",
      "a.js:3 — Sink: innerHTML assignment",
    ]);
    dom.window.close();
  });
});

describe("embedJson", () => {
  it("escapes characters that could end the script block", () => {
    const original = { a: "</script><!-- & " + String.fromCharCode(0x2028, 0x2029) };
    const text = embedJson(original);
    expect(text).not.toMatch(/[<>&\u2028\u2029]/);
    expect(JSON.parse(text)).toEqual(original);
  });
});

describe("Markdown report", () => {
  it("escapes hostile content and fences evidence safely", () => {
    const md = renderMarkdown(
      result([
        finding({
          title: "[click](javascript:alert(1)) <b>x</b>",
          evidence: "```\n# injected\n```",
          filePath: "a|b.js",
        }),
      ]),
    );
    expect(md).not.toContain("<b>");
    expect(md).not.toContain("[click](javascript");
    expect(md).toContain("\\[click\\]");
    expect(md).toContain("````"); // fence is longer than the backtick run in the evidence
    expect(md).toContain("a\\|b\\.js");
  });
  it("lists summary, suppressed findings and a no-findings notice", () => {
    expect(renderMarkdown(result([]))).toContain("No findings. This does not prove");
    const md = renderMarkdown(
      result(
        [finding()],
        [
          finding({
            status: "suppressed",
            suppression: { kind: "inline", justification: "reviewed" },
          }),
        ],
      ),
    );
    expect(md).toContain("## Suppressed findings");
    expect(md).toContain("| HIGH | 1 |");
  });
  it("mdEscape strips control characters and newlines", () => {
    expect(mdEscape("a\u001b[31m\nb")).not.toMatch(/[\u001b\n]/);
  });
});
