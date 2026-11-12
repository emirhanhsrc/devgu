import type { Confidence, FlowStep, Lang, LocalizedString, Severity } from "@devgu/shared";
import type { SourceFile, Visitor } from "@devgu/parser";

export interface RuleMeta {
  /** Unique, stable identifier, e.g. JS-XSS-001. */
  id: string;
  name: LocalizedString;
  description: LocalizedString;
  category: string;
  severity: Severity;
  confidence: Confidence;
  /** "ast" rules need a parsed script, "text" rules run on any scannable file. */
  targets: "ast" | "text";
  remediation: LocalizedString;
  references: string[];
  /** What this rule cannot detect or may misreport. Mandatory. */
  limitations: LocalizedString;
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
  /** Language the scan runs in; rules localise any dynamic text they build. */
  readonly lang: Lang;
  report(report: Report): void;
}

export interface Rule {
  meta: RuleMeta;
  /**
   * Optional AST visitor. The runner merges the visitors of all enabled rules into a single
   * traversal, which is much faster than one traversal per rule. Rules that provide it also
   * implement `check` (a stand-alone traversal) for direct use.
   */
  visitor?(context: RuleContext): Visitor;
  check(context: RuleContext): void;
}
