import { describe, expect, it } from "vitest";
import { createSourceFile } from "@devgu/parser";
import { RuleRegistry, rulesetFingerprint, runRules } from "./runner.js";
import type { Rule } from "./types.js";

function testRule(overrides: Partial<Rule["meta"]> = {}, check?: Rule["check"]): Rule {
  return {
    meta: {
      id: "T-001",
      name: "Test rule",
      description: "d",
      category: "test",
      severity: "LOW",
      confidence: "HIGH",
      targets: "text",
      remediation: "r",
      references: [],
      limitations: "l",
      version: 1,
      engine: "test",
      ...overrides,
    },
    check:
      check ??
      ((ctx) => {
        ctx.file.lines.forEach((line, i) => {
          if (line.includes("BAD")) ctx.report({ line: i + 1 });
        });
      }),
  };
}

const file = createSourceFile("a.js", "ok\n  BAD thing\nok");

describe("runRules", () => {
  it("builds findings from reports", () => {
    const { findings } = runRules(file, [testRule()], {});
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: "T-001",
      startLine: 2,
      evidence: "BAD thing",
      status: "open",
    });
  });
  it("honours enable/disable and severity override", () => {
    expect(runRules(file, [testRule()], { "T-001": { enabled: false } }).findings).toHaveLength(0);
    const overridden = runRules(file, [testRule()], { "T-001": { severity: "CRITICAL" } });
    expect(overridden.findings[0]?.severity).toBe("CRITICAL");
  });
  it("skips ast rules for files without an AST", () => {
    const text = createSourceFile("a.json", "BAD");
    expect(runRules(text, [testRule({ targets: "ast" })], {}).findings).toHaveLength(0);
  });
  it("isolates a throwing rule", () => {
    const boom = testRule({ id: "T-002" }, () => {
      throw new Error("boom");
    });
    const result = runRules(file, [boom, testRule()], {});
    expect(result.findings).toHaveLength(1);
    expect(result.diagnostics[0]).toMatchObject({ source: "T-002" });
  });
  it("caps findings per rule and file", () => {
    const many = createSourceFile("b.js", Array(500).fill("BAD").join("\n"));
    expect(runRules(many, [testRule()], {}).findings).toHaveLength(200);
  });
});

describe("RuleRegistry", () => {
  it("rejects duplicate ids", () => {
    expect(() => new RuleRegistry([testRule(), testRule()])).toThrow(/Duplicate/);
  });
  it("lists rules sorted", () => {
    const registry = new RuleRegistry([testRule({ id: "B-1" }), testRule({ id: "A-1" })]);
    expect(registry.list().map((r) => r.meta.id)).toEqual(["A-1", "B-1"]);
  });
});

describe("rulesetFingerprint", () => {
  it("changes with settings and rule version", () => {
    const base = rulesetFingerprint([testRule()], {});
    expect(rulesetFingerprint([testRule()], { "T-001": { enabled: false } })).not.toBe(base);
    expect(rulesetFingerprint([testRule({ version: 2 })], {})).not.toBe(base);
  });
});
