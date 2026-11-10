import traverseModule, { type TraverseOptions } from "@babel/traverse";
import * as t from "@babel/types";

export type { NodePath, Scope, Binding, Visitor } from "@babel/traverse";
export { t };

type TraverseFn = (parent: t.Node, opts?: TraverseOptions) => void;
/** @babel/traverse is CommonJS; under Node ESM the callable may sit on `.default`. */
const traverseExport = traverseModule as unknown as TraverseFn | { default: TraverseFn };
export const traverse: TraverseFn =
  typeof traverseExport === "function" ? traverseExport : traverseExport.default;

/** Name of a non-computed (or string-literal computed) member property, otherwise null. */
export function propertyName(node: t.Node): string | null {
  if (!t.isMemberExpression(node) && !t.isOptionalMemberExpression(node)) return null;
  const { property, computed } = node;
  if (!computed && t.isIdentifier(property)) return property.name;
  if (t.isStringLiteral(property)) return property.value;
  return null;
}

const GLOBAL_ALIASES = new Set(["window", "globalThis", "self"]);

/**
 * Dotted name of an expression such as `document.write` or `DOMPurify.sanitize`.
 * A leading `window.` / `globalThis.` / `self.` is dropped. Returns null for anything dynamic.
 */
export function dottedName(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  if (t.isIdentifier(node)) return node.name;
  if (t.isThisExpression(node)) return "this";
  if (t.isMetaProperty(node)) return `${node.meta.name}.${node.property.name}`;
  if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
    const name = propertyName(node);
    const object = dottedName(node.object);
    if (name === null || object === null) return null;
    return GLOBAL_ALIASES.has(object) ? name : `${object}.${name}`;
  }
  return null;
}

/** Value of an expression made only of string literals / interpolation-free templates / `+`. */
export function staticString(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node) && node.expressions.length === 0) {
    return node.quasis.map((q) => q.value.cooked ?? q.value.raw).join("");
  }
  if (t.isBinaryExpression(node) && node.operator === "+") {
    const left = staticString(node.left);
    const right = staticString(node.right);
    return left !== null && right !== null ? left + right : null;
  }
  if (t.isParenthesizedExpression(node)) return staticString(node.expression);
  return null;
}

/** The constant text a string expression starts with (`"a=" + x` -> `a=`), or null. */
export function leadingStaticText(node: t.Node | null | undefined): string | null {
  if (!node) return null;
  const whole = staticString(node);
  if (whole !== null) return whole;
  if (t.isTemplateLiteral(node))
    return node.quasis[0]?.value.cooked ?? node.quasis[0]?.value.raw ?? null;
  if (t.isBinaryExpression(node) && node.operator === "+") return leadingStaticText(node.left);
  return null;
}

/** Removes TypeScript/parenthesis wrappers that do not change runtime values. */
export function unwrap(node: t.Node): t.Node {
  let current = node;
  for (;;) {
    if (
      t.isParenthesizedExpression(current) ||
      t.isTSAsExpression(current) ||
      t.isTSNonNullExpression(current) ||
      t.isTSSatisfiesExpression(current) ||
      t.isTSTypeAssertion(current) ||
      t.isTypeCastExpression(current)
    ) {
      current = current.expression;
    } else {
      return current;
    }
  }
}
