import type { Finding, Severity } from "./finding.js";
import type { Lang } from "./i18n.js";

export type SkipReason =
  "symlink" | "too-large" | "file-limit" | "binary" | "minified-or-generated" | "unreadable";

export interface SkippedFile {
  filePath: string;
  reason: SkipReason;
}

export interface Diagnostic {
  /** Where the problem happened: a rule id, "parser", "discovery", "dependencies", ... */
  source: string;
  filePath?: string;
  message: string;
}

export interface ScanStats {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  cacheHits: number;
  cacheMisses: number;
  parseMs: number;
  ruleMs: number;
  totalMs: number;
  heapUsedMb: number;
  findingsBySeverity: Record<Severity, number>;
}

export interface ScanMeta {
  tool: "devgu";
  toolVersion: string;
  rulesetVersion: string;
  /** Language the human-readable finding and report text is rendered in. */
  lang: Lang;
  scannedAt: string;
  /** Base name of the scanned directory. The absolute path is intentionally not recorded. */
  rootName: string;
  engines: string[];
  enabledRules: string[];
}

export interface ScanResult {
  meta: ScanMeta;
  findings: Finding[];
  suppressed: Finding[];
  skipped: SkippedFile[];
  diagnostics: Diagnostic[];
  stats: ScanStats;
}
