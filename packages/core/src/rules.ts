import type { Rule } from "@devgu/rule-engine";
import type { ProjectAnalyzer } from "./pipeline.js";

/** The complete built-in rule set. Engines register their rules here. */
export function defaultRules(): Rule[] {
  return [];
}

/** Project-level analyzers (dependency audit, ...). */
export function defaultAnalyzers(_options: { online: boolean }): ProjectAnalyzer[] {
  return [];
}

/** Masks secrets in free text. */
export function defaultRedactor(): (text: string) => string {
  return (text) => text;
}
