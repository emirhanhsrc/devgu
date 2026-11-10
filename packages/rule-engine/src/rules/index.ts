import {
  dottedName,
  leadingStaticText,
  propertyName,
  staticString,
  t,
  unwrap,
  type NodePath,
} from "@devgu/parser";
import type { Rule } from "../types.js";
import { astRule, endLineOf, isLocallyBound, isUnsafeDynamicHtml, lineOf } from "./helpers.js";

export { HTML_SANITIZERS, isHtmlSanitizerCall, isUnsafeDynamicHtml } from "./helpers.js";

const OWASP_DOM_XSS =
  "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html";
const CWE = (n: number): string => `https://cwe.mitre.org/data/definitions/${n}.html`;

const SENSITIVE_KEY = /(token|secret|passw(?:or)?d|jwt|api[_-]?key|auth|credential|session)/i;

const xssInnerHtml = astRule(
  {
    id: "JS-XSS-001",
    name: "Dynamic value assigned to innerHTML/outerHTML",
    description:
      "A non-constant value is assigned to innerHTML or outerHTML. If any part of it is attacker-controlled the page is vulnerable to cross-site scripting. This rule only notes the risky API; JS-TAINT-001 reports flows from a proven untrusted source.",
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation:
      "Use textContent for text, build nodes with createElement, or sanitize the markup with a maintained sanitizer such as DOMPurify before assigning it.",
    references: [OWASP_DOM_XSS, CWE(79)],
    limitations:
      "Does not know where the value comes from, so the confidence is LOW. Constant strings and values passed through well-known sanitizers are ignored; custom sanitizers are not recognised.",
  },
  (ctx) => ({
    AssignmentExpression(path) {
      const { left, right, operator } = path.node;
      const name = propertyName(left);
      if ((name !== "innerHTML" && name !== "outerHTML") || (operator !== "=" && operator !== "+="))
        return;
      if (!isUnsafeDynamicHtml(right)) return;
      ctx.report({ line: lineOf(path.node), endLine: endLineOf(path.node) });
    },
  }),
);

const xssDangerouslySet = astRule(
  {
    id: "JS-XSS-002",
    name: "React dangerouslySetInnerHTML with dynamic markup",
    description:
      "dangerouslySetInnerHTML bypasses React's escaping. Dynamic markup that contains attacker-controlled content leads to cross-site scripting.",
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation:
      "Render the content as React elements, or sanitize it with DOMPurify before passing it in.",
    references: [
      "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
      CWE(79),
    ],
    limitations:
      "Cannot tell whether the markup is trusted. Constant strings and DOMPurify/sanitize-html calls are ignored; a variable that was sanitized elsewhere is still reported.",
  },
  (ctx) => ({
    JSXAttribute(path) {
      const { name, value } = path.node;
      if (!t.isJSXIdentifier(name, { name: "dangerouslySetInnerHTML" })) return;
      if (!t.isJSXExpressionContainer(value)) return;
      const expression = unwrap(value.expression);
      if (t.isObjectExpression(expression)) {
        const html = expression.properties.find(
          (p): p is t.ObjectProperty =>
            t.isObjectProperty(p) &&
            (t.isIdentifier(p.key, { name: "__html" }) ||
              t.isStringLiteral(p.key, { value: "__html" })),
        );
        if (html && !isUnsafeDynamicHtml(html.value)) return;
      }
      ctx.report({ line: lineOf(path.node) });
    },
  }),
);

const xssWriters = astRule(
  {
    id: "JS-XSS-003",
    name: "Dynamic HTML passed to insertAdjacentHTML or document.write",
    description:
      "insertAdjacentHTML, document.write and document.writeln parse their argument as HTML. A dynamic argument can introduce attacker-controlled markup.",
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation: "Insert text with textContent/insertAdjacentText, or sanitize the markup first.",
    references: [OWASP_DOM_XSS, CWE(79)],
    limitations:
      "Does not know the origin of the argument. Constant strings and recognised sanitizer calls are ignored.",
  },
  (ctx) => ({
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      const name = dottedName(callee);
      const method = propertyName(callee);
      let target: t.Node | undefined;
      if (method === "insertAdjacentHTML") target = args[1];
      else if (name === "document.write" || name === "document.writeln") target = args[0];
      if (target && isUnsafeDynamicHtml(target)) ctx.report({ line: lineOf(path.node) });
    },
  }),
);

const execEval = astRule(
  {
    id: "JS-EXEC-001",
    name: "Dynamic code execution (eval / Function constructor)",
    description:
      "eval() and the Function constructor compile strings into code. With non-constant input this allows arbitrary code execution and defeats Content-Security-Policy hardening.",
    category: "code-execution",
    severity: "HIGH",
    confidence: "MEDIUM",
    remediation:
      "Remove dynamic evaluation. Use JSON.parse for data, lookup tables for dispatch, or a real parser.",
    references: [
      "https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!",
      CWE(95),
    ],
    limitations:
      "Reports the API usage, not a proven exploit. A call with only constant strings is reported as LOW. Aliased calls such as `const e = eval` are not followed.",
  },
  (ctx) => {
    const check = (path: NodePath<t.CallExpression | t.NewExpression>): void => {
      const { callee, arguments: args } = path.node;
      if (!t.isIdentifier(callee)) {
        if (dottedName(callee) !== "eval" && dottedName(callee) !== "Function") return;
      }
      const name = dottedName(callee);
      if ((name !== "eval" && name !== "Function") || isLocallyBound(path, name)) return;
      if (args.length === 0) return;
      const allStatic = args.every((a) => staticString(a) !== null);
      ctx.report(
        allStatic
          ? {
              line: lineOf(path.node),
              severity: "LOW",
              confidence: "HIGH",
              title: `${name} with a constant string`,
            }
          : { line: lineOf(path.node) },
      );
    };
    return { CallExpression: check, NewExpression: check };
  },
);

const execTimers = astRule(
  {
    id: "JS-EXEC-002",
    name: "String passed to setTimeout/setInterval",
    description:
      "Passing a string instead of a function to a timer makes the browser evaluate it like eval(). It breaks strict Content-Security-Policy and is a code-injection sink.",
    category: "code-execution",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: "Pass a function: setTimeout(() => doWork(value), delay).",
    references: ["https://developer.mozilla.org/docs/Web/API/setTimeout#the_this_problem", CWE(95)],
    limitations:
      "Only detects string literals, templates and string concatenations; strings held in variables are not seen.",
  },
  (ctx) => ({
    CallExpression(path) {
      const name = dottedName(path.node.callee);
      if (name !== "setTimeout" && name !== "setInterval") return;
      if (isLocallyBound(path, name)) return;
      const first = path.node.arguments[0];
      if (!first) return;
      const isStringy =
        t.isStringLiteral(first) ||
        t.isTemplateLiteral(first) ||
        (t.isBinaryExpression(first, { operator: "+" }) &&
          (t.isStringLiteral(first.left) || t.isStringLiteral(first.right)));
      if (isStringy) ctx.report({ line: lineOf(path.node) });
    },
  }),
);

const URL_ATTRIBUTES = new Set(["href", "src", "action", "formAction", "xlinkHref"]);
const JS_URL = /^\s*javascript:/i;

const urlJavascript = astRule(
  {
    id: "JS-URL-001",
    name: "javascript: URL",
    description:
      "A javascript: URL executes code when followed. It is used in links and navigation targets and is blocked by a strict Content-Security-Policy.",
    category: "url",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: "Use an event handler or a button element instead of a javascript: URL.",
    references: [
      CWE(79),
      "https://developer.mozilla.org/docs/Web/URI/Reference/Schemes/javascript",
    ],
    limitations:
      "Only constant javascript: URLs in link attributes, href/src assignments and navigation calls are reported. Dynamic URLs are covered by JS-TAINT-003.",
  },
  (ctx) => {
    const reportIfJs = (node: t.Node | null | undefined, anchor: t.Node): void => {
      const value = staticString(node);
      if (value !== null && JS_URL.test(value)) ctx.report({ line: lineOf(anchor) });
    };
    return {
      JSXAttribute(path) {
        const { name, value } = path.node;
        if (!t.isJSXIdentifier(name) || !URL_ATTRIBUTES.has(name.name)) return;
        reportIfJs(
          t.isJSXExpressionContainer(value) ? (value.expression as t.Node) : value,
          path.node,
        );
      },
      AssignmentExpression(path) {
        const target = dottedName(path.node.left);
        const prop = propertyName(path.node.left);
        if (prop === "href" || prop === "src" || target === "location")
          reportIfJs(path.node.right, path.node);
      },
      CallExpression(path) {
        const name = dottedName(path.node.callee);
        if (name === "open" || name === "location.assign" || name === "location.replace") {
          reportIfJs(path.node.arguments[0], path.node);
        }
      },
    };
  },
);

const msgWildcard = astRule(
  {
    id: "JS-MSG-001",
    name: "postMessage with wildcard target origin",
    description:
      'window.postMessage(data, "*") delivers the message to whatever origin currently occupies the target window. Sensitive data can be received by an attacker page.',
    category: "postmessage",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: "Pass the exact expected origin as the second argument.",
    references: [
      "https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns",
      CWE(345),
    ],
    limitations:
      "Severity depends on how sensitive the posted data is, which a static scan cannot judge.",
  },
  (ctx) => ({
    CallExpression(path) {
      if (propertyName(path.node.callee) !== "postMessage") return;
      if (staticString(path.node.arguments[1]) === "*") ctx.report({ line: lineOf(path.node) });
    },
  }),
);

function resolveHandler(path: NodePath, node: t.Node): NodePath | null {
  if (t.isFunctionExpression(node) || t.isArrowFunctionExpression(node)) return path;
  if (!t.isIdentifier(node)) return null;
  const binding = path.scope.getBinding(node.name);
  const declaration = binding?.path;
  if (!declaration) return null;
  if (declaration.isFunctionDeclaration()) return declaration;
  if (declaration.isVariableDeclarator()) {
    const init = declaration.get("init");
    if (!Array.isArray(init) && (init.isFunctionExpression() || init.isArrowFunctionExpression()))
      return init;
  }
  return null;
}

function checksOrigin(fn: NodePath): boolean {
  let found = false;
  const markIfOrigin = (p: NodePath<t.MemberExpression | t.OptionalMemberExpression>): void => {
    if (propertyName(p.node) === "origin") {
      found = true;
      p.stop();
    }
  };
  fn.traverse({
    MemberExpression: markIfOrigin,
    OptionalMemberExpression: markIfOrigin,
    ObjectProperty(p) {
      if (p.parentPath.isObjectPattern() && t.isIdentifier(p.node.key, { name: "origin" })) {
        found = true;
        p.stop();
      }
    },
  });
  return found;
}

const msgOrigin = astRule(
  {
    id: "JS-MSG-002",
    name: "message event handler without origin check",
    description:
      "A window 'message' listener receives messages from any origin. Without verifying event.origin, any page that can obtain a reference to this window can send it data.",
    category: "postmessage",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: "Compare event.origin against an allow-list before using event.data.",
    references: [
      "https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns",
      CWE(346),
    ],
    limitations:
      "Handlers that cannot be resolved inside the same file (imported functions, inline references to other modules) are not analysed. Origin checks performed by a helper function are not recognised.",
  },
  (ctx) => ({
    CallExpression(path) {
      const { callee, arguments: args } = path.node;
      if ((propertyName(callee) ?? dottedName(callee)) !== "addEventListener") return;
      if (staticString(args[0]) !== "message" || !args[1]) return;
      const handlerArg = path.get("arguments")[1];
      if (!handlerArg || Array.isArray(handlerArg)) return;
      const handler = resolveHandler(handlerArg, args[1]);
      if (handler && !checksOrigin(handler)) ctx.report({ line: lineOf(path.node) });
    },
  }),
);

const storage = astRule(
  {
    id: "JS-STORE-001",
    name: "Sensitive-looking data in web storage or cookies",
    description:
      "Tokens, passwords and similar values stored in localStorage, sessionStorage or script-set cookies are readable by any script on the page, so an XSS flaw exposes them.",
    category: "storage",
    severity: "LOW",
    confidence: "LOW",
    remediation:
      "Prefer HttpOnly, Secure, SameSite cookies set by the server for session credentials. Never hardcode credentials.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
      CWE(922),
    ],
    limitations:
      "Decides from the key name only. Storing a token in localStorage is a trade-off, not always a vulnerability, so dynamic values are reported with LOW confidence.",
  },
  (ctx) => ({
    CallExpression(path) {
      const name = dottedName(path.node.callee);
      if (name !== "localStorage.setItem" && name !== "sessionStorage.setItem") return;
      const key = staticString(path.node.arguments[0]);
      if (key === null || !SENSITIVE_KEY.test(key)) return;
      const value = staticString(path.node.arguments[1]);
      if (value !== null) {
        if (value.length >= 8) {
          ctx.report({
            line: lineOf(path.node),
            severity: "MEDIUM",
            confidence: "MEDIUM",
            title: "Hardcoded sensitive value stored in web storage",
          });
        }
        return;
      }
      ctx.report({ line: lineOf(path.node) });
    },
    AssignmentExpression(path) {
      if (dottedName(path.node.left) !== "document.cookie") return;
      const prefix = leadingStaticText(path.node.right);
      const key = prefix?.split("=")[0] ?? "";
      if (prefix !== null && prefix.includes("=") && SENSITIVE_KEY.test(key)) {
        ctx.report({
          line: lineOf(path.node),
          title: "Sensitive-looking cookie set from script (cannot be HttpOnly)",
        });
      }
    },
  }),
);

const SAFE_HTTP_HOSTS =
  /^(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|.*\.local|.*\.test|.*\.invalid|.*\.example|example\.(com|org|net)|(www\.)?w3\.org|json-schema\.org|schema\.org|.*\.internal)$/i;

function insecureHttpHost(value: string): string | null {
  if (value.length > 500 || !/^http:\/\//i.test(value) || /\s/.test(value)) return null;
  try {
    const { hostname } = new URL(value);
    return hostname.includes(".") && !SAFE_HTTP_HOSTS.test(hostname) ? hostname : null;
  } catch {
    return null;
  }
}

const insecureHttp = astRule(
  {
    id: "JS-CFG-001",
    name: "Insecure http:// endpoint",
    description:
      "A hardcoded http:// URL sends traffic unencrypted and allows interception or tampering on the network path.",
    category: "configuration",
    severity: "LOW",
    confidence: "MEDIUM",
    remediation:
      "Use https:// (or a protocol-relative configuration value that is https in production).",
    references: [CWE(319)],
    limitations:
      "Loopback, .local/.test hosts and well-known namespace URLs are ignored. Cannot tell whether the URL is only used in development.",
  },
  (ctx) => {
    const check = (value: string | null | undefined, node: t.Node): void => {
      if (value && insecureHttpHost(value)) ctx.report({ line: lineOf(node) });
    };
    return {
      StringLiteral(path) {
        if (path.parentPath.isImportDeclaration() || path.parentPath.isExportDeclaration()) return;
        if (
          path.parentPath.isJSXAttribute() &&
          t.isJSXIdentifier(path.parentPath.node.name) &&
          /^xmlns/.test(path.parentPath.node.name.name)
        )
          return;
        check(path.node.value, path.node);
      },
      TemplateLiteral(path) {
        if (path.node.expressions.length === 0) check(staticString(path.node), path.node);
      },
    };
  },
);

const PUBLIC_PREFIX = /^(VITE|REACT_APP|NEXT_PUBLIC|PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|GATSBY)_/;

const publicEnvSecret = astRule(
  {
    id: "JS-CFG-002",
    name: "Secret-looking value in a public frontend environment variable",
    description:
      "Variables with prefixes such as VITE_, REACT_APP_ or NEXT_PUBLIC_ are embedded into the browser bundle at build time. Anything stored there is visible to every visitor.",
    category: "configuration",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation:
      "Keep secrets on the server and expose only a narrowly scoped endpoint to the frontend.",
    references: ["https://vite.dev/guide/env-and-mode#env-files", CWE(540)],
    limitations:
      "Judges by the variable name. Public identifiers such as map or analytics keys are legitimately exposed; names containing only KEY are reported as LOW.",
  },
  (ctx) => ({
    MemberExpression(path) {
      const base = dottedName(path.node.object);
      if (base !== "process.env" && base !== "import.meta.env") return;
      const name = propertyName(path.node);
      if (!name || !PUBLIC_PREFIX.test(name)) return;
      if (/(SECRET|PRIVATE|PASSWORD|PASSWD|TOKEN)/i.test(name))
        ctx.report({ line: lineOf(path.node) });
      else if (/KEY/i.test(name))
        ctx.report({ line: lineOf(path.node), severity: "LOW", confidence: "LOW" });
    },
  }),
);

export const securityRules: Rule[] = [
  xssInnerHtml,
  xssDangerouslySet,
  xssWriters,
  execEval,
  execTimers,
  urlJavascript,
  msgWildcard,
  msgOrigin,
  storage,
  insecureHttp,
  publicEnvSecret,
];
