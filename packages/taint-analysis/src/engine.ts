import {
  dottedName,
  propertyName,
  staticString,
  t,
  traverse,
  unwrap,
  type Binding,
  type NodePath,
  type Scope,
} from "@devgu/parser";
import type { SourceFile } from "@devgu/parser";
import { HTML_SANITIZERS, checksOrigin, isLocallyBound, resolveHandler } from "@devgu/rule-engine";

export type SinkKind = "html" | "url" | "code";
export type SourceReliability = "HIGH" | "MEDIUM" | "LOW";

/**
 * A data-flow step as a language-neutral descriptor. The engine stays locale-agnostic; the human
 * text is produced once, in the chosen language, when a finding is built (see the taint rules).
 */
export type StepDescriptor =
  | { kind: "source"; label: string }
  | { kind: "sink"; label: string }
  | { kind: "interpolated" }
  | { kind: "concatenated" }
  | { kind: "passedThrough"; name: string }
  | { kind: "sanitized"; name: string; neutralizes: string }
  | { kind: "resultOf"; method: string }
  | { kind: "assignedTo"; name: string }
  | { kind: "storedIn"; name: string };

export type FlowStep = { line: number } & StepDescriptor;

/** What is known about one tainted value. Instances are immutable. */
export interface TaintInfo {
  source: string;
  reliability: SourceReliability;
  steps: readonly FlowStep[];
  /** Sink kinds for which a sanitizer has already neutralized the value. */
  sanitizedFor: ReadonlySet<SinkKind>;
}

export interface TaintFlow {
  kind: SinkKind;
  line: number;
  endLine: number;
  sink: string;
  info: TaintInfo;
}

const MAX_STEPS = 30;
/**
 * Cheap pre-filter: a file that never mentions any known source cannot contain a flow, so the
 * two AST passes are skipped. It must list every source the engine understands.
 */
const SOURCE_HINT =
  /\b(location|referrer|documentURI|useSearchParams|useParams|useLocation|addEventListener|onmessage)\b|document\.URL|\b(window|self|globalThis)\.name\b|\.value\b/;
const MAX_EXPRESSION_DEPTH = 150;
const ALL_KINDS: readonly SinkKind[] = ["html", "url", "code"];

/** Property reads of these (on `location`/`document.location`) are attacker controlled. */
const LOCATION_SOURCES = new Set([
  "location.search",
  "location.hash",
  "location.href",
  "location.pathname",
  "document.location.search",
  "document.location.hash",
  "document.location.href",
  "document.location.pathname",
  "document.URL",
  "document.documentURI",
  "document.referrer",
]);
/** Hooks whose return value carries URL data. */
const SOURCE_CALLS = new Set(["useSearchParams", "useParams", "useLocation"]);
const INPUT_ACCESSORS = new Set([
  "document.getElementById",
  "document.querySelector",
  "document.getElementsByName",
]);
/** Methods whose result does not carry the receiver's content. */
const NON_PROPAGATING_METHODS = new Set([
  "includes",
  "startsWith",
  "endsWith",
  "test",
  "has",
  "indexOf",
  "lastIndexOf",
  "localeCompare",
  "some",
  "every",
  "hasOwnProperty",
]);
/** Plain functions that return (a decoded form of) their input. */
const PROPAGATING_FUNCTIONS = new Set([
  "String",
  "decodeURIComponent",
  "decodeURI",
  "unescape",
  "atob",
  "JSON.parse",
  "JSON.stringify",
]);

const SANITIZERS = new Map<string, readonly SinkKind[]>([
  ...[...HTML_SANITIZERS].map((name): [string, readonly SinkKind[]] => [name, ["html"]]),
  ["encodeURIComponent", ["html", "url"]],
  ["sanitizeUrl", ["url"]],
  ["Number", ALL_KINDS],
  ["parseInt", ALL_KINDS],
  ["parseFloat", ALL_KINDS],
  ["Boolean", ALL_KINDS],
]);

function withStep(info: TaintInfo, line: number, step: StepDescriptor): TaintInfo {
  if (info.steps.length >= MAX_STEPS) return info;
  return { ...info, steps: [...info.steps, { line, ...step }] };
}

function lineOf(node: t.Node): number {
  return node.loc?.start.line ?? 1;
}

/** Keeps the more dangerous of two taints (fewer neutralized sink kinds). */
function merge(a: TaintInfo | null, b: TaintInfo | null): TaintInfo | null {
  if (!a) return b;
  if (!b) return a;
  const common = new Set([...a.sanitizedFor].filter((k) => b.sanitizedFor.has(k)));
  const base = a.sanitizedFor.size <= b.sanitizedFor.size ? a : b;
  return { ...base, sanitizedFor: common };
}

function source(label: string, reliability: SourceReliability, node: t.Node): TaintInfo {
  return {
    source: label,
    reliability,
    steps: [{ line: lineOf(node), kind: "source", label }],
    sanitizedFor: new Set(),
  };
}

function rootBinding(node: t.Node, scope: Scope): Binding | undefined {
  let current = unwrap(node);
  while (t.isMemberExpression(current) || t.isOptionalMemberExpression(current)) {
    current = unwrap(current.object);
  }
  return t.isIdentifier(current) ? scope.getBinding(current.name) : undefined;
}

/**
 * Intra-procedural taint analysis over one file. Findings mean "a flow was proven in this file";
 * flows through function calls, other files, promises or aliased containers are not followed.
 */
export function analyzeTaint(file: SourceFile): TaintFlow[] {
  if (!file.ast || !SOURCE_HINT.test(file.source)) return [];
  const ast = file.ast;
  const tainted = new Map<Binding, TaintInfo>();
  const messageEvents = new Set<Binding>();
  const flows: TaintFlow[] = [];

  // Pass 1: message handlers that do not verify event.origin make `event.data` a source.
  // Done before the main walk so declaration order of the handler does not matter.
  const registerHandler = (argPath: NodePath, node: t.Node): void => {
    const fn = resolveHandler(argPath, node);
    if (!fn || checksOrigin(fn)) return;
    const first = (fn.node as t.Function).params[0];
    if (t.isIdentifier(first)) {
      const binding = fn.scope.getBinding(first.name);
      if (binding) messageEvents.add(binding);
    } else if (t.isObjectPattern(first)) {
      for (const property of first.properties) {
        if (
          t.isObjectProperty(property) &&
          t.isIdentifier(property.key, { name: "data" }) &&
          t.isIdentifier(property.value)
        ) {
          const binding = fn.scope.getBinding(property.value.name);
          if (binding) tainted.set(binding, source("postMessage event.data", "MEDIUM", property));
        }
      }
    }
  };
  traverse(ast, {
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if ((propertyName(callee) ?? dottedName(callee)) !== "addEventListener") return;
      if (staticString(args[0]) !== "message" || !args[1]) return;
      const handler = path.get("arguments")[1];
      if (handler && !Array.isArray(handler)) registerHandler(handler, args[1]);
    },
    AssignmentExpression(path) {
      const { left, right } = path.node;
      if (
        t.isMemberExpression(left) &&
        t.isIdentifier(left.object, { name: "window" }) &&
        propertyName(left) === "onmessage"
      ) {
        registerHandler(path.get("right"), right);
      }
    },
  });

  let depth = 0;
  // Expressions nested deeper than this are treated as untainted instead of risking a stack overflow.
  const taintOf = (input: t.Node | null | undefined, scope: Scope): TaintInfo | null => {
    if (depth >= MAX_EXPRESSION_DEPTH) return null;
    depth += 1;
    try {
      return evaluate(input, scope);
    } finally {
      depth -= 1;
    }
  };

  const evaluate = (input: t.Node | null | undefined, scope: Scope): TaintInfo | null => {
    if (!input) return null;
    const node = unwrap(input);

    if (t.isIdentifier(node)) {
      const binding = scope.getBinding(node.name);
      return binding ? (tainted.get(binding) ?? null) : null;
    }
    if (
      t.isStringLiteral(node) ||
      t.isNumericLiteral(node) ||
      t.isBooleanLiteral(node) ||
      t.isNullLiteral(node)
    ) {
      return null;
    }
    if (t.isTemplateLiteral(node)) {
      let result: TaintInfo | null = null;
      for (const expression of node.expressions) result = merge(result, taintOf(expression, scope));
      return result ? withStep(result, lineOf(node), { kind: "interpolated" }) : null;
    }
    if (t.isBinaryExpression(node)) {
      if (node.operator !== "+") return null;
      const result = merge(taintOf(node.left, scope), taintOf(node.right, scope));
      return result ? withStep(result, lineOf(node), { kind: "concatenated" }) : null;
    }
    if (t.isConditionalExpression(node)) {
      return merge(taintOf(node.consequent, scope), taintOf(node.alternate, scope));
    }
    if (t.isLogicalExpression(node))
      return merge(taintOf(node.left, scope), taintOf(node.right, scope));
    if (t.isAssignmentExpression(node)) return taintOf(node.right, scope);
    if (t.isSequenceExpression(node))
      return taintOf(node.expressions[node.expressions.length - 1], scope);
    if (t.isAwaitExpression(node)) return taintOf(node.argument, scope);
    if (t.isSpreadElement(node)) return taintOf(node.argument, scope);
    if (t.isArrayExpression(node)) {
      let result: TaintInfo | null = null;
      for (const element of node.elements) result = merge(result, taintOf(element, scope));
      return result;
    }
    if (t.isObjectExpression(node)) {
      let result: TaintInfo | null = null;
      for (const property of node.properties) {
        result = merge(
          result,
          t.isObjectProperty(property) ? taintOf(property.value, scope) : taintOf(property, scope),
        );
      }
      return result;
    }

    if (t.isNewExpression(node)) {
      const name = dottedName(node.callee);
      if (name === "URLSearchParams" || name === "URL") return taintOf(node.arguments[0], scope);
      return null;
    }

    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const name = dottedName(node);
      if (name !== null && LOCATION_SOURCES.has(name)) return source(name, "HIGH", node);
      const prop = propertyName(node);
      if (
        prop === "name" &&
        t.isIdentifier(node.object) &&
        ["window", "self", "globalThis"].includes(node.object.name)
      ) {
        return source("window.name", "HIGH", node);
      }
      if (prop === "data" && t.isIdentifier(node.object)) {
        const binding = scope.getBinding(node.object.name);
        if (binding && messageEvents.has(binding))
          return source("postMessage event.data", "MEDIUM", node);
      }
      if (prop === "value") {
        const object = unwrap(node.object);
        const viaTarget =
          (t.isMemberExpression(object) || t.isOptionalMemberExpression(object)) &&
          propertyName(object) === "target";
        const viaLookup =
          t.isCallExpression(object) && INPUT_ACCESSORS.has(dottedName(object.callee) ?? "");
        if (viaTarget || viaLookup) return source("user input field value", "LOW", node);
      }
      return taintOf(node.object, scope);
    }

    if (t.isCallExpression(node) || t.isOptionalCallExpression(node)) {
      const callee = unwrap(node.callee);
      const name = dottedName(callee);
      if (name !== null) {
        const neutralizes = SANITIZERS.get(name);
        if (neutralizes) {
          const input = taintOf(node.arguments[0], scope);
          if (!input) return null;
          return withStep(
            { ...input, sanitizedFor: new Set([...input.sanitizedFor, ...neutralizes]) },
            lineOf(node),
            { kind: "sanitized", name, neutralizes: neutralizes.join("/") },
          );
        }
        if (SOURCE_CALLS.has(name)) return source(`${name}()`, "HIGH", node);
        if (PROPAGATING_FUNCTIONS.has(name)) {
          const input = taintOf(node.arguments[0], scope);
          return input ? withStep(input, lineOf(node), { kind: "passedThrough", name }) : null;
        }
      }
      if (t.isMemberExpression(callee) || t.isOptionalMemberExpression(callee)) {
        const method = propertyName(callee);
        if (method && !NON_PROPAGATING_METHODS.has(method)) {
          const receiver = taintOf(callee.object, scope);
          return receiver ? withStep(receiver, lineOf(node), { kind: "resultOf", method }) : null;
        }
      }
      return null;
    }
    return null;
  };

  const record = (kind: SinkKind, node: t.Node, sink: string, info: TaintInfo | null): void => {
    if (!info || info.sanitizedFor.has(kind)) return;
    flows.push({
      kind,
      line: lineOf(node),
      endLine: node.loc?.end.line ?? lineOf(node),
      sink,
      info,
    });
  };

  const bindIdentifiers = (pattern: t.Node, info: TaintInfo, scope: Scope, line: number): void => {
    for (const [name] of Object.entries(t.getBindingIdentifiers(pattern))) {
      const binding = scope.getBinding(name);
      if (binding) tainted.set(binding, withStep(info, line, { kind: "assignedTo", name }));
    }
  };

  /** Straight-line code directly in a function/program body can be strongly updated. */
  const isUnconditional = (statement: NodePath): boolean =>
    statement.parentPath?.isBlockStatement() === true
      ? statement.parentPath.parentPath?.isFunction() === true
      : statement.parentPath?.isProgram() === true;

  traverse(ast, {
    VariableDeclarator(path) {
      const { id, init } = path.node;
      if (!init) return;
      const unwrapped = unwrap(init);
      // const { data } = event  (message event with no origin check)
      if (t.isObjectPattern(id) && t.isIdentifier(unwrapped)) {
        const binding = path.scope.getBinding(unwrapped.name);
        if (binding && messageEvents.has(binding)) {
          for (const property of id.properties) {
            if (t.isObjectProperty(property) && t.isIdentifier(property.key, { name: "data" })) {
              bindIdentifiers(
                property.value,
                source("postMessage event.data", "MEDIUM", property),
                path.scope,
                lineOf(property),
              );
            }
          }
          return;
        }
      }
      const info = taintOf(init, path.scope);
      if (info) bindIdentifiers(id, info, path.scope, lineOf(path.node));
    },

    AssignmentExpression(path) {
      const { left, right, operator } = path.node;
      const info = taintOf(right, path.scope);
      const prop = propertyName(left);
      const leftName = dottedName(left);

      // Propagation
      if (t.isIdentifier(left)) {
        const binding = path.scope.getBinding(left.name);
        if (binding) {
          if (info) {
            const next = withStep(info, lineOf(path.node), {
              kind: "assignedTo",
              name: left.name,
            });
            tainted.set(
              binding,
              operator === "=" && isUnconditional(path.parentPath)
                ? next
                : (merge(tainted.get(binding) ?? null, next) as TaintInfo),
            );
          } else if (operator === "=" && isUnconditional(path.parentPath)) {
            tainted.delete(binding);
          }
        }
      } else if (info && (t.isMemberExpression(left) || t.isOptionalMemberExpression(left))) {
        // Only plain data containers ({} / []) are tainted by property writes; DOM nodes are not.
        const binding = rootBinding(left, path.scope);
        const declaration = binding?.path.isVariableDeclarator() ? binding.path.node.init : null;
        if (
          binding &&
          declaration &&
          (t.isObjectExpression(declaration) || t.isArrayExpression(declaration))
        ) {
          tainted.set(
            binding,
            merge(
              tainted.get(binding) ?? null,
              withStep(info, lineOf(path.node), {
                kind: "storedIn",
                name: dottedName(left) ?? "object",
              }),
            ) as TaintInfo,
          );
        }
      }

      // Sinks
      if (operator !== "=" && operator !== "+=") return;
      if (prop === "innerHTML" || prop === "outerHTML")
        record("html", path.node, `${prop} assignment`, info);
      else if (prop === "href" || prop === "action" || prop === "formAction")
        record("url", path.node, `${prop} assignment (open redirect / javascript: URL)`, info);
      else if (leftName === "location" || leftName === "document.location")
        record("url", path.node, "location assignment (open redirect / javascript: URL)", info);
    },

    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      const name = dottedName(callee);
      const method = propertyName(callee);
      const argInfo = (index: number): TaintInfo | null => taintOf(args[index], path.scope);

      if (method === "insertAdjacentHTML")
        record("html", path.node, "insertAdjacentHTML()", argInfo(1));
      else if (name === "document.write" || name === "document.writeln")
        record("html", path.node, `${name}()`, argInfo(0));
      else if (
        method === "html" &&
        args.length === 1 &&
        t.isCallExpression(unwrap((callee as t.MemberExpression).object))
      ) {
        const receiver = (unwrap((callee as t.MemberExpression).object) as t.CallExpression).callee;
        if (t.isIdentifier(receiver, { name: "$" }) || t.isIdentifier(receiver, { name: "jQuery" }))
          record("html", path.node, "jQuery .html()", argInfo(0));
      } else if (name === "eval" && !isLocallyBound(path, "eval"))
        record("code", path.node, "eval()", argInfo(0));
      else if ((name === "setTimeout" || name === "setInterval") && !isLocallyBound(path, name))
        record("code", path.node, `${name}() with a string`, argInfo(0));
      else if (name === "Function" && !isLocallyBound(path, "Function")) {
        for (let i = 0; i < args.length; i += 1)
          record("code", path.node, "Function() constructor", argInfo(i));
      } else if (
        name === "location.assign" ||
        name === "location.replace" ||
        name === "document.location.assign" ||
        name === "document.location.replace"
      ) {
        record("url", path.node, `${name}() (open redirect / javascript: URL)`, argInfo(0));
      } else if (name === "open" && !isLocallyBound(path, "open"))
        record("url", path.node, "window.open() (open redirect / javascript: URL)", argInfo(0));
    },

    NewExpression(path) {
      if (dottedName(path.node.callee) !== "Function" || isLocallyBound(path, "Function")) return;
      for (const arg of path.node.arguments)
        record("code", path.node, "Function() constructor", taintOf(arg, path.scope));
    },

    JSXAttribute(path) {
      const { name, value } = path.node;
      if (!t.isJSXIdentifier(name) || !t.isJSXExpressionContainer(value)) return;
      const expression = unwrap(value.expression as t.Node);
      if (name.name === "dangerouslySetInnerHTML" && t.isObjectExpression(expression)) {
        for (const property of expression.properties) {
          if (
            t.isObjectProperty(property) &&
            (t.isIdentifier(property.key, { name: "__html" }) ||
              t.isStringLiteral(property.key, { value: "__html" }))
          ) {
            record(
              "html",
              path.node,
              "dangerouslySetInnerHTML",
              taintOf(property.value, path.scope),
            );
          }
        }
      } else if (name.name === "href") {
        record(
          "url",
          path.node,
          "href attribute (open redirect / javascript: URL)",
          taintOf(expression, path.scope),
        );
      }
    },
  });

  const seen = new Set<string>();
  return flows.filter((flow) => {
    const key = `${flow.kind}:${flow.line}:${flow.sink}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
