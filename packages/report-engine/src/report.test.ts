import { describe, expect, it } from "vitest";
import type { Finding, ScanResult } from "@devgu/shared";
import { renderJson, renderReport, renderSarif, renderText } from "./index.js";

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
    filePath: "src/my app/a.jsx",
    startLine: 3,
    endLine: 3,
    evidence: "el.innerHTML = x;",
    remediation: "fix it",
    references: ["https://example.org/ref"],
    limitations: "may be wrong",
    fingerprint: "f".repeat(32),
    status: "open",
    ...overrides,
  };
}

function result(findings: Finding[] = [finding()], suppressed: Finding[] = []): ScanResult {
  return {
    meta: {
      tool: "devgu",
      toolVersion: "0.1.0",
      rulesetVersion: "abc",
      scannedAt: "2026-01-01T00:00:00.000Z",
      rootName: "demo",
      engines: ["security"],
      enabledRules: ["JS-XSS-001"],
    },
    findings,
    suppressed,
    skipped: [],
    diagnostics: [],
    stats: {
      filesDiscovered: 1,
      filesScanned: 1,
      filesSkipped: 0,
      cacheHits: 0,
      cacheMisses: 1,
      parseMs: 1,
      ruleMs: 1,
      totalMs: 3,
      heapUsedMb: 10,
      findingsBySeverity: { CRITICAL: 0, HIGH: findings.length, MEDIUM: 0, LOW: 0, INFO: 0 },
    },
  };
}

describe("SARIF", () => {
  const sarif = JSON.parse(renderSarif(result())) as {
    version: string;
    runs: Array<{
      tool: { driver: { name: string; rules: Array<Record<string, unknown>> } };
      results: Array<Record<string, any>>;
    }>;
  };
  it("is a SARIF 2.1.0 log with tool, rules and results", () => {
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0]!;
    expect(run.tool.driver.name).toBe("DEVGU");
    expect(run.tool.driver.rules).toHaveLength(1);
    expect(run.results).toHaveLength(1);
  });
  it("links results to rules and maps severity", () => {
    const run = sarif.runs[0]!;
    const r = run.results[0]!;
    expect(r.ruleId).toBe(run.tool.driver.rules[0]!["id"]);
    expect(r.ruleIndex).toBe(0);
    expect(r.level).toBe("error");
    expect((run.tool.driver.rules[0] as any).properties["security-severity"]).toBe("8.0");
  });
  it("uses relative, percent-encoded URIs and fingerprints", () => {
    const r = sarif.runs[0]!.results[0]!;
    const loc = r.locations[0].physicalLocation;
    expect(loc.artifactLocation.uri).toBe("src/my%20app/a.jsx");
    expect(loc.artifactLocation.uriBaseId).toBe("%SRCROOT%");
    expect(loc.region.startLine).toBe(3);
    expect(r.partialFingerprints["devgu/v1"]).toHaveLength(32);
  });
  it("emits code flows for data-flow findings and suppressions for suppressed ones", () => {
    const flow = finding({
      dataFlow: [
        { filePath: "a.js", line: 1, description: "source" },
        { filePath: "a.js", line: 3, description: "sink" },
      ],
    });
    const suppressed = finding({
      status: "suppressed",
      suppression: { kind: "inline", justification: "reviewed" },
    });
    const log = JSON.parse(renderSarif(result([flow], [suppressed])));
    const [first, second] = log.runs[0].results;
    expect(first.codeFlows[0].threadFlows[0].locations).toHaveLength(2);
    expect(second.suppressions[0]).toEqual({ kind: "inSource", justification: "reviewed" });
  });
  it("is valid for a clean scan", () => {
    const log = JSON.parse(renderSarif(result([])));
    expect(log.runs[0].results).toEqual([]);
  });
});

describe("text and json", () => {
  it("never lets repository content inject terminal escapes", () => {
    const hostile = finding({
      evidence: "\u001b[2J\u001b]0;pwned\u0007x",
      filePath: "a\u001b[31m.js",
    });
    const text = renderText(result([hostile]), { color: false });
    expect(text).not.toContain("\u001b");
    expect(text).not.toContain("\u0007");
  });
  it("round-trips JSON and dispatches by format", () => {
    const r = result();
    expect(JSON.parse(renderJson(r))).toEqual(r);
    expect(renderReport("json", r)).toBe(renderJson(r));
    expect(renderReport("text", r)).toContain("JS-XSS-001");
  });
});
