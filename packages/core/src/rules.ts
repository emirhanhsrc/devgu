import { auditDependencies, DEPENDENCY_RULE } from "@devgu/dependency-engine";
import { securityRules, type Rule, type RuleMeta } from "@devgu/rule-engine";
import { redactSecretsInText, secretRules } from "@devgu/secret-scanner";
import { taintRules } from "@devgu/taint-analysis";
import { defaultCacheDir } from "./cache.js";
import type { ProjectAnalyzer } from "./pipeline.js";

/** The complete built-in rule set. Engines register their rules here. */
export function defaultRules(): Rule[] {
  return [...securityRules, ...taintRules, ...secretRules];
}

/** Project-level analyzers (dependency audit, ...). */
export function defaultAnalyzers(options: { online: boolean }): ProjectAnalyzer[] {
  return [
    {
      name: "dependencies",
      run: ({ root, signal, lang }) =>
        auditDependencies({
          root,
          online: options.online,
          cacheDir: defaultCacheDir(),
          lang,
          ...(signal ? { signal } : {}),
        }),
    },
  ];
}

/** Metadata of every finding type, including those produced by project-level analyzers. */
export function ruleCatalog(): RuleMeta[] {
  return [...defaultRules().map((rule) => rule.meta), DEPENDENCY_RULE].sort((a, b) =>
    a.id.localeCompare(b.id),
  );
}

/** Masks secrets in free text. Applied to all evidence before it leaves the scanner. */
export function defaultRedactor(): (text: string) => string {
  return redactSecretsInText;
}
