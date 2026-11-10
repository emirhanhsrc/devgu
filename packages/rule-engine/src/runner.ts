import {
  fingerprint,
  sha256Hex,
  truncate,
  type Diagnostic,
  type Finding,
  type Severity,
} from "@devgu/shared";
import type { SourceFile } from "@devgu/parser";
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

/** Runs all enabled rules on a file. A failing rule never aborts the scan. */
export function runRules(
  file: SourceFile,
  rules: readonly Rule[],
  settings: RuleSettingsMap,
): RunResult {
  const findings: Finding[] = [];
  const diagnostics: Diagnostic[] = [];
  for (const rule of rules) {
    if (!isRuleEnabled(rule.meta, settings)) continue;
    if (rule.meta.targets === "ast" && !file.ast) continue;
    let count = 0;
    try {
      rule.check({
        file,
        report: (report) => {
          if (count >= MAX_FINDINGS_PER_RULE_PER_FILE) return;
          count += 1;
          findings.push(buildFinding(rule.meta, file, report, settings));
        },
      });
    } catch (error) {
      diagnostics.push({
        source: rule.meta.id,
        filePath: file.relPath,
        message: `Rule failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }
  return { findings, diagnostics };
}
