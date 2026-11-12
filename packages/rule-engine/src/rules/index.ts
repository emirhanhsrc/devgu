import {
  dottedName,
  leadingStaticText,
  propertyName,
  staticString,
  t,
  unwrap,
  type NodePath,
} from "@devgu/parser";
import { loc } from "@devgu/shared";
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
    name: {
      en: "Dynamic value assigned to innerHTML/outerHTML",
      tr: "innerHTML/outerHTML'e dinamik değer atanıyor",
    },
    description: {
      en: "A non-constant value is assigned to innerHTML or outerHTML. If any part of it is attacker-controlled the page is vulnerable to cross-site scripting. This rule only notes the risky API; JS-TAINT-001 reports flows from a proven untrusted source.",
      tr: "innerHTML veya outerHTML'e sabit olmayan bir değer atanıyor. Değerin herhangi bir parçası saldırgan denetimindeyse sayfa XSS'e açıktır. Bu kural yalnızca riskli API kullanımını işaret eder; kanıtlanmış güvenilmez kaynaktan gelen akışları JS-TAINT-001 raporlar.",
    },
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation: {
      en: "Use textContent for text, build nodes with createElement, or sanitize the markup with a maintained sanitizer such as DOMPurify before assigning it.",
      tr: "Metin için textContent kullanın, düğümleri createElement ile oluşturun ya da işaretlemeyi atamadan önce DOMPurify gibi bakımlı bir temizleyiciyle temizleyin.",
    },
    references: [OWASP_DOM_XSS, CWE(79)],
    limitations: {
      en: "Does not know where the value comes from, so the confidence is LOW. Constant strings and values passed through well-known sanitizers are ignored; custom sanitizers are not recognised.",
      tr: "Değerin nereden geldiğini bilmez, bu yüzden güven düzeyi LOW'dur. Sabit dizgeler ve bilinen temizleyicilerden geçen değerler yok sayılır; özel temizleyiciler tanınmaz.",
    },
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
    name: {
      en: "React dangerouslySetInnerHTML with dynamic markup",
      tr: "Dinamik işaretleme ile React dangerouslySetInnerHTML",
    },
    description: {
      en: "dangerouslySetInnerHTML bypasses React's escaping. Dynamic markup that contains attacker-controlled content leads to cross-site scripting.",
      tr: "dangerouslySetInnerHTML, React'in kaçışlamasını devre dışı bırakır. Saldırgan denetimindeki içerik barındıran dinamik işaretleme XSS'e yol açar.",
    },
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation: {
      en: "Render the content as React elements, or sanitize it with DOMPurify before passing it in.",
      tr: "İçeriği React öğeleri olarak render edin ya da geçmeden önce DOMPurify ile temizleyin.",
    },
    references: [
      "https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html",
      CWE(79),
    ],
    limitations: {
      en: "Cannot tell whether the markup is trusted. Constant strings and DOMPurify/sanitize-html calls are ignored; a variable that was sanitized elsewhere is still reported.",
      tr: "İşaretlemenin güvenilir olup olmadığını anlayamaz. Sabit dizgeler ve DOMPurify/sanitize-html çağrıları yok sayılır; başka yerde temizlenmiş bir değişken yine de raporlanır.",
    },
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
    name: {
      en: "Dynamic HTML passed to insertAdjacentHTML or document.write",
      tr: "insertAdjacentHTML veya document.write'a dinamik HTML veriliyor",
    },
    description: {
      en: "insertAdjacentHTML, document.write and document.writeln parse their argument as HTML. A dynamic argument can introduce attacker-controlled markup.",
      tr: "insertAdjacentHTML, document.write ve document.writeln argümanını HTML olarak ayrıştırır. Dinamik bir argüman saldırgan denetimindeki işaretlemeyi sokabilir.",
    },
    category: "xss",
    severity: "MEDIUM",
    confidence: "LOW",
    remediation: {
      en: "Insert text with textContent/insertAdjacentText, or sanitize the markup first.",
      tr: "Metni textContent/insertAdjacentText ile ekleyin ya da işaretlemeyi önce temizleyin.",
    },
    references: [OWASP_DOM_XSS, CWE(79)],
    limitations: {
      en: "Does not know the origin of the argument. Constant strings and recognised sanitizer calls are ignored.",
      tr: "Argümanın kaynağını bilmez. Sabit dizgeler ve tanınan temizleyici çağrıları yok sayılır.",
    },
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
    name: {
      en: "Dynamic code execution (eval / Function constructor)",
      tr: "Dinamik kod yürütme (eval / Function yapıcısı)",
    },
    description: {
      en: "eval() and the Function constructor compile strings into code. With non-constant input this allows arbitrary code execution and defeats Content-Security-Policy hardening.",
      tr: "eval() ve Function yapıcısı dizgeleri koda derler. Sabit olmayan girdiyle bu, keyfi kod yürütülmesine izin verir ve Content-Security-Policy sıkılaştırmasını etkisiz kılar.",
    },
    category: "code-execution",
    severity: "HIGH",
    confidence: "MEDIUM",
    remediation: {
      en: "Remove dynamic evaluation. Use JSON.parse for data, lookup tables for dispatch, or a real parser.",
      tr: "Dinamik değerlendirmeyi kaldırın. Veri için JSON.parse, yönlendirme için arama tabloları veya gerçek bir ayrıştırıcı kullanın.",
    },
    references: [
      "https://developer.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_direct_eval!",
      CWE(95),
    ],
    limitations: {
      en: "Reports the API usage, not a proven exploit. A call with only constant strings is reported as LOW. Aliased calls such as `const e = eval` are not followed.",
      tr: "API kullanımını raporlar, kanıtlanmış bir istismarı değil. Yalnızca sabit dizgelerle yapılan çağrı LOW raporlanır. `const e = eval` gibi takma adlı çağrılar izlenmez.",
    },
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
              title: loc(
                {
                  en: `${name} with a constant string`,
                  tr: `${name} — sabit dizge ile`,
                },
                ctx.lang,
              ),
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
    name: {
      en: "String passed to setTimeout/setInterval",
      tr: "setTimeout/setInterval'e dizge veriliyor",
    },
    description: {
      en: "Passing a string instead of a function to a timer makes the browser evaluate it like eval(). It breaks strict Content-Security-Policy and is a code-injection sink.",
      tr: "Bir zamanlayıcıya fonksiyon yerine dizge vermek, tarayıcının onu eval() gibi değerlendirmesine yol açar. Katı Content-Security-Policy'yi bozar ve bir kod enjeksiyonu hedefidir.",
    },
    category: "code-execution",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: {
      en: "Pass a function: setTimeout(() => doWork(value), delay).",
      tr: "Fonksiyon geçirin: setTimeout(() => doWork(value), delay).",
    },
    references: ["https://developer.mozilla.org/docs/Web/API/setTimeout#the_this_problem", CWE(95)],
    limitations: {
      en: "Only detects string literals, templates and string concatenations; strings held in variables are not seen.",
      tr: "Yalnızca dizge sabitlerini, şablonları ve dizge birleştirmelerini algılar; değişkende tutulan dizgeler görülmez.",
    },
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
    name: { en: "javascript: URL", tr: "javascript: URL'si" },
    description: {
      en: "A javascript: URL executes code when followed. It is used in links and navigation targets and is blocked by a strict Content-Security-Policy.",
      tr: "javascript: URL'si takip edildiğinde kod çalıştırır. Bağlantılarda ve gezinme hedeflerinde kullanılır ve katı bir Content-Security-Policy tarafından engellenir.",
    },
    category: "url",
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: {
      en: "Use an event handler or a button element instead of a javascript: URL.",
      tr: "javascript: URL'si yerine bir olay işleyici veya buton öğesi kullanın.",
    },
    references: [
      CWE(79),
      "https://developer.mozilla.org/docs/Web/URI/Reference/Schemes/javascript",
    ],
    limitations: {
      en: "Only constant javascript: URLs in link attributes, href/src assignments and navigation calls are reported. Dynamic URLs are covered by JS-TAINT-003.",
      tr: "Yalnızca bağlantı özniteliklerindeki, href/src atamalarındaki ve gezinme çağrılarındaki sabit javascript: URL'leri raporlanır. Dinamik URL'ler JS-TAINT-003 kapsamındadır.",
    },
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
    name: {
      en: "postMessage with wildcard target origin",
      tr: "Joker (*) hedef origin ile postMessage",
    },
    description: {
      en: 'window.postMessage(data, "*") delivers the message to whatever origin currently occupies the target window. Sensitive data can be received by an attacker page.',
      tr: 'window.postMessage(data, "*") mesajı, hedef pencerede o an hangi origin varsa ona teslim eder. Hassas veriler bir saldırgan sayfası tarafından alınabilir.',
    },
    category: "postmessage",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: {
      en: "Pass the exact expected origin as the second argument.",
      tr: "İkinci argüman olarak beklenen tam origin'i geçirin.",
    },
    references: [
      "https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns",
      CWE(345),
    ],
    limitations: {
      en: "Severity depends on how sensitive the posted data is, which a static scan cannot judge.",
      tr: "Şiddet, gönderilen verinin ne kadar hassas olduğuna bağlıdır; bunu statik bir tarama değerlendiremez.",
    },
  },
  (ctx) => ({
    CallExpression(path) {
      if (propertyName(path.node.callee) !== "postMessage") return;
      if (staticString(path.node.arguments[1]) === "*") ctx.report({ line: lineOf(path.node) });
    },
  }),
);

export function resolveHandler(path: NodePath, node: t.Node): NodePath | null {
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

export function checksOrigin(fn: NodePath): boolean {
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
    name: {
      en: "message event handler without origin check",
      tr: "origin denetimi olmayan message olay işleyicisi",
    },
    description: {
      en: "A window 'message' listener receives messages from any origin. Without verifying event.origin, any page that can obtain a reference to this window can send it data.",
      tr: "Bir pencere 'message' dinleyicisi her origin'den mesaj alır. event.origin doğrulanmadan, bu pencereye erişebilen herhangi bir sayfa ona veri gönderebilir.",
    },
    category: "postmessage",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: {
      en: "Compare event.origin against an allow-list before using event.data.",
      tr: "event.data'yı kullanmadan önce event.origin'i bir izin listesiyle karşılaştırın.",
    },
    references: [
      "https://developer.mozilla.org/docs/Web/API/Window/postMessage#security_concerns",
      CWE(346),
    ],
    limitations: {
      en: "Handlers that cannot be resolved inside the same file (imported functions, inline references to other modules) are not analysed. Origin checks performed by a helper function are not recognised.",
      tr: "Aynı dosya içinde çözülemeyen işleyiciler (içe aktarılmış fonksiyonlar, başka modüllere satır içi atıflar) analiz edilmez. Bir yardımcı fonksiyonun yaptığı origin denetimleri tanınmaz.",
    },
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
    name: {
      en: "Sensitive-looking data in web storage or cookies",
      tr: "Web depolamasında veya çerezlerde hassas görünen veri",
    },
    description: {
      en: "Tokens, passwords and similar values stored in localStorage, sessionStorage or script-set cookies are readable by any script on the page, so an XSS flaw exposes them.",
      tr: "localStorage, sessionStorage veya betikle ayarlanan çerezlerde saklanan token, parola ve benzeri değerler sayfadaki her betik tarafından okunabilir; bu yüzden bir XSS açığı onları ifşa eder.",
    },
    category: "storage",
    severity: "LOW",
    confidence: "LOW",
    remediation: {
      en: "Prefer HttpOnly, Secure, SameSite cookies set by the server for session credentials. Never hardcode credentials.",
      tr: "Oturum kimlik bilgileri için sunucunun ayarladığı HttpOnly, Secure, SameSite çerezleri tercih edin. Kimlik bilgilerini asla koda gömmeyin.",
    },
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage",
      CWE(922),
    ],
    limitations: {
      en: "Decides from the key name only. Storing a token in localStorage is a trade-off, not always a vulnerability, so dynamic values are reported with LOW confidence.",
      tr: "Yalnızca anahtar adından karar verir. Bir token'ı localStorage'da saklamak her zaman bir zafiyet değil, bir ödünleşmedir; bu nedenle dinamik değerler LOW güvenle raporlanır.",
    },
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
            title: loc(
              {
                en: "Hardcoded sensitive value stored in web storage",
                tr: "Web depolamasına gömülü hassas değer",
              },
              ctx.lang,
            ),
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
          title: loc(
            {
              en: "Sensitive-looking cookie set from script (cannot be HttpOnly)",
              tr: "Betikten ayarlanan hassas görünen çerez (HttpOnly olamaz)",
            },
            ctx.lang,
          ),
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
    name: { en: "Insecure http:// endpoint", tr: "Güvensiz http:// uç noktası" },
    description: {
      en: "A hardcoded http:// URL sends traffic unencrypted and allows interception or tampering on the network path.",
      tr: "Koda gömülü bir http:// URL'si trafiği şifresiz gönderir ve ağ yolunda dinlenmeye veya değiştirilmeye olanak tanır.",
    },
    category: "configuration",
    severity: "LOW",
    confidence: "MEDIUM",
    remediation: {
      en: "Use https:// (or a protocol-relative configuration value that is https in production).",
      tr: "https:// kullanın (veya üretimde https olan protokol-göreli bir yapılandırma değeri).",
    },
    references: [CWE(319)],
    limitations: {
      en: "Loopback, .local/.test hosts and well-known namespace URLs are ignored. Cannot tell whether the URL is only used in development.",
      tr: "Loopback, .local/.test adresleri ve bilinen ad alanı URL'leri yok sayılır. URL'nin yalnızca geliştirmede kullanılıp kullanılmadığını anlayamaz.",
    },
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
    name: {
      en: "Secret-looking value in a public frontend environment variable",
      tr: "Herkese açık ön uç ortam değişkeninde sır görünümlü değer",
    },
    description: {
      en: "Variables with prefixes such as VITE_, REACT_APP_ or NEXT_PUBLIC_ are embedded into the browser bundle at build time. Anything stored there is visible to every visitor.",
      tr: "VITE_, REACT_APP_ veya NEXT_PUBLIC_ gibi önekli değişkenler, derleme sırasında tarayıcı paketine gömülür. Orada saklanan her şey her ziyaretçiye görünür.",
    },
    category: "configuration",
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: {
      en: "Keep secrets on the server and expose only a narrowly scoped endpoint to the frontend.",
      tr: "Sırları sunucuda tutun ve ön uca yalnızca dar kapsamlı bir uç nokta açın.",
    },
    references: ["https://vite.dev/guide/env-and-mode#env-files", CWE(540)],
    limitations: {
      en: "Judges by the variable name. Public identifiers such as map or analytics keys are legitimately exposed; names containing only KEY are reported as LOW.",
      tr: "Değişken adına göre karar verir. Harita veya analitik anahtarları gibi herkese açık kimlikler meşru biçimde ifşa edilir; yalnızca KEY içeren adlar LOW raporlanır.",
    },
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
