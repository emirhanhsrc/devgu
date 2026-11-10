import type { Confidence, FlowStep, Severity } from "@devgu/shared";
import type { SourceFile } from "@devgu/parser";

export interface RuleMeta {
  /** Unique, stable identifier, e.g. JS-XSS-001. */
  id: string;
  name: string;
  description: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  /** "ast" rules need a parsed script, "text" rules run on any scannable file. */
  targets: "ast" | "text";
  remediation: string;
  references: string[];
  /** What this rule cannot detect or may misreport. Mandatory. */
  limitations: string;
  /** Bump when detection logic changes; part of the cache key. */
  version: number;
  engine: string;
}

export interface Report {
  line: number;
  endLine?: number;
  /** Defaults to the trimmed source line. Must already be safe to display (e.g. secrets masked). */
  evidence?: string;
  title?: string;
  description?: string;
  severity?: Severity;
  confidence?: Confidence;
  dataFlow?: FlowStep[];
  /** Replaces the evidence as fingerprint material (used for secrets). */
  fingerprintMaterial?: string;
}

export interface RuleContext {
  readonly file: SourceFile;
  report(report: Report): void;
}

export interface Rule {
  meta: RuleMeta;
  check(context: RuleContext): void;
}
