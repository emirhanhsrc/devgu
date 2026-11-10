import { describe, expect, it } from "vitest";
import { createSourceFile } from "@devgu/parser";
import { runRules } from "../runner.js";
import { securityRules } from "./index.js";

function lines(ruleId: string, code: string, file = "a.jsx"): number[] {
  const { findings, diagnostics } = runRules(createSourceFile(file, code), securityRules, {});
  expect(diagnostics).toEqual([]);
  return findings.filter((f) => f.ruleId === ruleId).map((f) => f.startLine);
}

describe("rule catalogue", () => {
  it("has unique ids, limitations and references", () => {
    const ids = securityRules.map((r) => r.meta.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const rule of securityRules) {
      expect(rule.meta.limitations.length).toBeGreaterThan(20);
      expect(rule.meta.remediation.length).toBeGreaterThan(10);
      expect(rule.meta.references.length).toBeGreaterThan(0);
    }
  });
});

describe("JS-XSS-001 innerHTML", () => {
  it("flags dynamic values", () => {
    expect(
      lines(
        "JS-XSS-001",
        "el.innerHTML = name;\nel.outerHTML = `<b>${x}</b>`;\nel.innerHTML += y;",
      ),
    ).toEqual([1, 2, 3]);
  });
  it("ignores constants and sanitized values", () => {
    expect(
      lines(
        "JS-XSS-001",
        'el.innerHTML = "";\nel.innerHTML = "<b>hi</b>";\nel.innerHTML = DOMPurify.sanitize(x);',
      ),
    ).toEqual([]);
  });
  it("ignores textContent", () => {
    expect(lines("JS-XSS-001", "el.textContent = name;")).toEqual([]);
  });
});

describe("JS-XSS-002 dangerouslySetInnerHTML", () => {
  it("flags dynamic markup", () => {
    expect(
      lines("JS-XSS-002", "const A = () => <div dangerouslySetInnerHTML={{ __html: html }} />;"),
    ).toEqual([1]);
    expect(
      lines("JS-XSS-002", "const A = () => <div dangerouslySetInnerHTML={markup} />;"),
    ).toEqual([1]);
  });
  it("ignores constants and DOMPurify", () => {
    expect(
      lines(
        "JS-XSS-002",
        'const A = () => <div dangerouslySetInnerHTML={{ __html: "<b>x</b>" }} />;',
      ),
    ).toEqual([]);
    expect(
      lines(
        "JS-XSS-002",
        "const A = () => <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;",
      ),
    ).toEqual([]);
  });
});

describe("JS-XSS-003 writers", () => {
  it("flags dynamic arguments", () => {
    expect(
      lines(
        "JS-XSS-003",
        "el.insertAdjacentHTML('beforeend', html);\ndocument.write(html);\nwindow.document.writeln(`<i>${a}</i>`);",
      ),
    ).toEqual([1, 2, 3]);
  });
  it("ignores constants", () => {
    expect(
      lines("JS-XSS-003", "el.insertAdjacentHTML('beforeend', '<hr>');\ndocument.write('<hr>');"),
    ).toEqual([]);
  });
});

describe("JS-EXEC-001 eval/Function", () => {
  it("flags dynamic eval and Function", () => {
    expect(lines("JS-EXEC-001", "eval(code);\nnew Function('a', body);\nwindow.eval(x);")).toEqual([
      1, 2, 3,
    ]);
  });
  it("downgrades constant strings", () => {
    const { findings } = runRules(createSourceFile("a.js", "eval('1+1');"), securityRules, {});
    expect(findings.find((f) => f.ruleId === "JS-EXEC-001")?.severity).toBe("LOW");
  });
  it("ignores shadowed eval and member calls", () => {
    expect(lines("JS-EXEC-001", "function f(eval) { eval(x); }\nobj.eval(x);")).toEqual([]);
  });
});

describe("JS-EXEC-002 string timers", () => {
  it("flags string callbacks", () => {
    expect(
      lines(
        "JS-EXEC-002",
        "setTimeout('go()', 10);\nsetInterval('a' + b, 5);\nsetTimeout(`x${y}`, 1);",
      ),
    ).toEqual([1, 2, 3]);
  });
  it("ignores function callbacks", () => {
    expect(lines("JS-EXEC-002", "setTimeout(() => go(), 10);\nsetTimeout(fn, 10);")).toEqual([]);
  });
});

describe("JS-URL-001 javascript: URLs", () => {
  it("flags constant javascript: URLs in links and navigation", () => {
    expect(
      lines(
        "JS-URL-001",
        "const A = () => <a href=\"javascript:void(0)\">x</a>;\nel.href = 'javascript:alert(1)';\nlocation.assign('JavaScript:a()');",
      ),
    ).toEqual([1, 2, 3]);
  });
  it("ignores validation code that mentions the scheme", () => {
    expect(
      lines(
        "JS-URL-001",
        "if (url.startsWith('javascript:')) throw new Error();\nconst re = /^javascript:/i;",
      ),
    ).toEqual([]);
  });
});

describe("JS-MSG-001 postMessage wildcard", () => {
  it("flags * target origin", () => {
    expect(lines("JS-MSG-001", "win.postMessage(data, '*');")).toEqual([1]);
  });
  it("ignores explicit origins and worker transfer lists", () => {
    expect(
      lines(
        "JS-MSG-001",
        "win.postMessage(data, 'https://a.com');\nworker.postMessage(buf, [buf]);",
      ),
    ).toEqual([]);
  });
});

describe("JS-MSG-002 message handler origin", () => {
  it("flags handlers that never look at origin", () => {
    const code =
      "window.addEventListener('message', (e) => { use(e.data); });\nfunction h(e) { run(e.data); }\nwindow.addEventListener('message', h);";
    expect(lines("JS-MSG-002", code)).toEqual([1, 3]);
  });
  it("accepts handlers that check origin", () => {
    expect(
      lines(
        "JS-MSG-002",
        "window.addEventListener('message', (e) => { if (e.origin !== 'https://a.com') return; use(e.data); });",
      ),
    ).toEqual([]);
    expect(
      lines(
        "JS-MSG-002",
        "window.addEventListener('message', ({ origin, data }) => { if (origin === A) use(data); });",
      ),
    ).toEqual([]);
  });
  it("does not guess about unresolvable handlers", () => {
    expect(
      lines(
        "JS-MSG-002",
        "import { handler } from './h';\nwindow.addEventListener('message', handler);",
      ),
    ).toEqual([]);
  });
});

describe("JS-STORE-001 storage", () => {
  it("flags sensitive keys", () => {
    expect(
      lines(
        "JS-STORE-001",
        "localStorage.setItem('authToken', tok);\nsessionStorage.setItem('jwt', t);\ndocument.cookie = 'session=' + id;",
      ),
    ).toEqual([1, 2, 3]);
  });
  it("reports hardcoded values with higher severity", () => {
    const { findings } = runRules(
      createSourceFile("a.js", "localStorage.setItem('apiKey', 'hunter2hunter2');"),
      securityRules,
      {},
    );
    expect(findings.find((f) => f.ruleId === "JS-STORE-001")?.severity).toBe("MEDIUM");
  });
  it("ignores harmless keys", () => {
    expect(
      lines(
        "JS-STORE-001",
        "localStorage.setItem('theme', 'dark');\nlocalStorage.setItem('authDismissed', '1');",
      ),
    ).toEqual([]);
  });
});

describe("JS-CFG-001 insecure http", () => {
  it("flags remote http endpoints", () => {
    expect(
      lines(
        "JS-CFG-001",
        "const api = 'http://api.shop.com/v1';\nconst t = `http://cdn.shop.com/a.js`;",
      ),
    ).toEqual([1, 2]);
  });
  it("ignores https, loopback, namespaces and prose", () => {
    expect(
      lines(
        "JS-CFG-001",
        "a('https://api.shop.com');\nb('http://localhost:3000');\nc('http://www.w3.org/2000/svg');\nd('see http://x.com for more');",
      ),
    ).toEqual([]);
  });
});

describe("JS-CFG-002 public env secrets", () => {
  it("flags secret-looking public variables", () => {
    expect(
      lines(
        "JS-CFG-002",
        "const a = import.meta.env.VITE_API_SECRET;\nconst b = process.env.REACT_APP_AUTH_TOKEN;",
      ),
    ).toEqual([1, 2]);
  });
  it("ignores server-side variables and benign names", () => {
    expect(
      lines(
        "JS-CFG-002",
        "const a = process.env.DATABASE_PASSWORD;\nconst b = import.meta.env.VITE_API_URL;",
      ),
    ).toEqual([]);
  });
  it("treats KEY-only names as LOW", () => {
    const { findings } = runRules(
      createSourceFile("a.js", "const k = process.env.NEXT_PUBLIC_MAPS_KEY;"),
      securityRules,
      {},
    );
    expect(findings.find((f) => f.ruleId === "JS-CFG-002")?.severity).toBe("LOW");
  });
});
