import { securityRules, type Rule } from "@devgu/rule-engine";
import { redactSecretsInText, secretRules } from "@devgu/secret-scanner";
import { taintRules } from "@devgu/taint-analysis";
import type { ProjectAnalyzer } from "./pipeline.js";

/** The complete built-in rule set. Engines register their rules here. */
export function defaultRules(): Rule[] {
  return [...securityRules, ...taintRules, ...secretRules];
}

/** Project-level analyzers (dependency audit, ...). */
export function defaultAnalyzers(_options: { online: boolean }): ProjectAnalyzer[] {
  return [];
}

/** Masks secrets in free text. Applied to all evidence before it leaves the scanner. */
export function defaultRedactor(): (text: string) => string {
  return redactSecretsInText;
}
