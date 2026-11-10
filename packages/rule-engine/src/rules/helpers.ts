import {
  dottedName,
  staticString,
  t,
  traverse,
  unwrap,
  type NodePath,
  type Visitor,
} from "@devgu/parser";
import type { Rule, RuleContext, RuleMeta } from "../types.js";

/** Calls that neutralize HTML. Shared with the taint engine. */
export const HTML_SANITIZERS = new Set([
  "DOMPurify.sanitize",
  "purify.sanitize",
  "sanitizeHtml",
  "escapeHtml",
  "_.escape",
  "he.encode",
  "he.escape",
  "xss",
  "filterXSS",
  "validator.escape",
]);

export function isHtmlSanitizerCall(node: t.Node): boolean {
  const inner = unwrap(node);
  return t.isCallExpression(inner) && HTML_SANITIZERS.has(dottedName(inner.callee) ?? "");
}

/** True when a dynamic (non-constant) value reaches the expression and nothing sanitizes it. */
export function isUnsafeDynamicHtml(node: t.Node | null | undefined): boolean {
  if (!node) return false;
  return staticString(node) === null && !isHtmlSanitizerCall(node);
}

type MetaInput = Omit<RuleMeta, "engine" | "targets" | "version" | "category"> & {
  category: string;
  version?: number;
};

/** Defines an AST based security rule. `visitors` receives the context and returns a Babel visitor. */
export function astRule(meta: MetaInput, visitors: (context: RuleContext) => Visitor): Rule {
  return {
    meta: { engine: "security", targets: "ast", version: 1, ...meta },
    visitor: visitors,
    check(context) {
      if (!context.file.ast) return;
      traverse(context.file.ast, visitors(context));
    },
  };
}

export function lineOf(node: t.Node): number {
  return node.loc?.start.line ?? 1;
}

export function endLineOf(node: t.Node): number {
  return node.loc?.end.line ?? lineOf(node);
}

/** Whether `name` is declared in the local scope chain (shadowing a global like eval). */
export function isLocallyBound(path: NodePath, name: string): boolean {
  return path.scope.hasBinding(name, { noGlobals: true });
}
