import {
  fingerprint,
  sha256Hex,
  truncate,
  type Diagnostic,
  type Finding,
  type Severity,
} from "@devgu/shared";
import { mergeVisitors, traverse, type SourceFile, type Visitor } from "@devgu/parser";
import type { Report, Rule, RuleMeta } from "./types.js";

export interface RuleSettings {
  enabled?: boolean;
  severity?: Severity;
}

export type RuleSettingsMap = Readonly<Record<string, RuleSettings | undefined>>;

const MAX_FINDINGS_PER_RULE_PER_FILE = 200;
const MAX_EVIDENCE_LENGTH = 240;

export class RuleRegistry {
  private readonly rules = new Map<string, Rule>();

  constructor(rules: readonly Rule[] = []) {
    for (const rule of rules) this.register(rule);
  }

  register(rule: Rule): void {
    if (this.rules.has(rule.meta.id)) {
      throw new Error(`Duplicate rule id: ${rule.meta.id}`);
    }
    this.rules.set(rule.meta.id, rule);
  }

  get(id: string): Rule | undefined {
    return this.rules.get(id);
  }

  list(): Rule[] {
    return [...this.rules.values()].sort((a, b) => a.meta.id.localeCompare(b.meta.id));
  }
}

export function isRuleEnabled(meta: RuleMeta, settings: RuleSettingsMap): boolean {
  return settings[meta.id]?.enabled !== false;
}

/** Fingerprint of everything that influences rule output; used as part of the cache key. */
export function rulesetFingerprint(rules: readonly Rule[], settings: RuleSettingsMap): string {
  const parts = rules
    .map(
      (r) =>
        `${r.meta.id}@${r.meta.version}:${isRuleEnabled(r.meta, settings)}:${settings[r.meta.id]?.severity ?? ""}`,
    )
    .sort();
  return sha256Hex(parts.join("|")).slice(0, 16);
}

export function buildFinding(
  meta: RuleMeta,
  file: SourceFile,
  report: Report,
  settings: RuleSettingsMap,
): Finding {
  const startLine = Math.max(1, report.line);
  const endLine = Math.max(startLine, report.endLine ?? startLine);
  const evidence = truncate(
    (report.evidence ?? file.lines[startLine - 1] ?? "").trim(),
    MAX_EVIDENCE_LENGTH,
  );
  const print = fingerprint(meta.id, file.relPath, report.fingerprintMaterial ?? evidence);
  return {
    id: `${meta.id}-${print.slice(0, 8)}-L${startLine}`,
    ruleId: meta.id,
    engine: meta.engine,
    title: report.title ?? meta.name,
    description: report.description ?? meta.description,
    severity: settings[meta.id]?.severity ?? report.severity ?? meta.severity,
    confidence: report.confidence ?? meta.confidence,
    category: meta.category,
    filePath: file.relPath,
    startLine,
    endLine,
    evidence,
    remediation: meta.remediation,
    references: meta.references,
    limitations: meta.limitations,
    fingerprint: print,
    status: "open",
    ...(report.dataFlow ? { dataFlow: report.dataFlow } : {}),
  };
}

export interface RunResult {
  findings: Finding[];
  diagnostics: Diagnostic[];
}

type Handler = (...args: unknown[]) => unknown;

/**
 * Wraps every handler of a visitor so that an exception disables only that rule instead of
 * aborting the shared traversal (and with it all other rules).
 */
function guardVisitor(visitor: Visitor, onError: (error: unknown) => void): Visitor {
  let failed = false;
  const guard = (fn: Handler): Handler =>
    function (this: unknown, ...args: unknown[]) {
      if (failed) return undefined;
      try {
        return fn.apply(this, args);
      } catch (error) {
        failed = true;
        onError(error);
        return undefined;
      }
    };
  const guarded: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(visitor as Record<string, unknown>)) {
    if (typeof value === "function") {
      guarded[key] = guard(value as Handler);
    } else if (value && typeof value === "object") {
      const hooks = value as { enter?: Handler; exit?: Handler };
      guarded[key] = {
        ...(hooks.enter ? { enter: guard(hooks.enter) } : {}),
        ...(hooks.exit ? { exit: guard(hooks.exit) } : {}),
      };
    }
  }
  return guarded as Visitor;
}

/**
 * Runs all enabled rules on a file. A failing rule never aborts the scan. Rules that expose an
 * AST visitor share one traversal; the others run their own `check`.
 */
export function runRules(
  file: SourceFile,
  rules: readonly Rule[],
  settings: RuleSettingsMap,
): RunResult {
  const findings: Finding[] = [];
  const diagnostics: Diagnostic[] = [];
  const visitors: Visitor[] = [];
  const failure = (rule: Rule) => (error: unknown) => {
    diagnostics.push({
      source: rule.meta.id,
      filePath: file.relPath,
      message: `Rule failed: ${error instanceof Error ? error.message : String(error)}`,
    });
  };

  for (const rule of rules) {
    if (!isRuleEnabled(rule.meta, settings)) continue;
    if (rule.meta.targets === "ast" && !file.ast) continue;
    let count = 0;
    const context = {
      file,
      report: (report: Report) => {
        if (count >= MAX_FINDINGS_PER_RULE_PER_FILE) return;
        count += 1;
        findings.push(buildFinding(rule.meta, file, report, settings));
      },
    };
    try {
      if (rule.visitor && file.ast)
        visitors.push(guardVisitor(rule.visitor(context), failure(rule)));
      else rule.check(context);
    } catch (error) {
      failure(rule)(error);
    }
  }

  if (visitors.length > 0 && file.ast) {
    try {
      traverse(file.ast, mergeVisitors(visitors));
    } catch (error) {
      diagnostics.push({
        source: "rule-engine",
        filePath: file.relPath,
        message: `AST traversal failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return { findings, diagnostics };
}
