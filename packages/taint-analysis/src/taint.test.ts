import { describe, expect, it } from "vitest";
import { loc } from "@devgu/shared";
import { createSourceFile } from "@devgu/parser";
import { runRules } from "@devgu/rule-engine";
import { taintRules } from "./index.js";

function scan(code: string, file = "a.jsx") {
  const result = runRules(createSourceFile(file, code), taintRules, {});
  expect(result.diagnostics).toEqual([]);
  return result.findings;
}
const found = (code: string): string[] => scan(code).map((f) => `${f.ruleId}@${f.startLine}`);

describe("DOM XSS (JS-TAINT-001)", () => {
  it("tracks URLSearchParams through interpolation into innerHTML", () => {
    const code = [
      "const params = new URLSearchParams(location.search);",
      "const name = params.get('name');",
      "const html = `<h1>Hello ${name}</h1>`;",
      "document.getElementById('x').innerHTML = html;",
    ].join("\n");
    const [finding, ...rest] = scan(code);
    expect(rest).toEqual([]);
    expect(finding).toMatchObject({
      ruleId: "JS-TAINT-001",
      startLine: 4,
      severity: "HIGH",
      confidence: "HIGH",
      engine: "taint",
    });
    const steps = finding?.dataFlow?.map((s) => `${s.line}:${s.description}`) ?? [];
    expect(steps[0]).toBe("1:Source: location.search");
    expect(steps.at(-1)).toBe("4:Sink: innerHTML assignment");
    expect(steps.some((s) => s.includes("Interpolated"))).toBe(true);
  });
  it("follows location.hash, string methods and concatenation", () => {
    expect(
      found("const h = location.hash.slice(1).trim();\nel.innerHTML = '<b>' + h + '</b>';"),
    ).toEqual(["JS-TAINT-001@2"]);
  });
  it("follows destructuring and object containers", () => {
    expect(
      found(
        "const { q } = Object.fromEntries(new URLSearchParams(location.search));\nel.innerHTML = q;",
      ),
    ).toEqual([]);
    expect(found("const box = {};\nbox.v = location.search;\nel.innerHTML = box.v;")).toEqual([
      "JS-TAINT-001@3",
    ]);
    expect(found("const [a] = [location.hash];\nel.innerHTML = a;")).toEqual(["JS-TAINT-001@2"]);
  });
  it("covers insertAdjacentHTML, document.write and dangerouslySetInnerHTML", () => {
    const code = [
      "const q = location.search;",
      "el.insertAdjacentHTML('beforeend', q);",
      "document.write(q);",
      "const C = () => <div dangerouslySetInnerHTML={{ __html: q }} />;",
    ].join("\n");
    expect(found(code)).toEqual(["JS-TAINT-001@2", "JS-TAINT-001@3", "JS-TAINT-001@4"]);
  });
  it("recognises React Router hooks as sources", () => {
    const code =
      "function P() { const [sp] = useSearchParams(); const q = sp.get('q'); return <div dangerouslySetInnerHTML={{ __html: q }} />; }";
    expect(found(code)).toEqual(["JS-TAINT-001@1"]);
  });
  it("treats window.name and document.referrer as sources", () => {
    expect(found("el.innerHTML = window.name;\nel.innerHTML = document.referrer;")).toEqual([
      "JS-TAINT-001@1",
      "JS-TAINT-001@2",
    ]);
  });
  it("handles TypeScript assertions", () => {
    expect(
      scan("const q = (location.search as string)!;\nel.innerHTML = q;", "a.ts").map(
        (f) => f.startLine,
      ),
    ).toEqual([2]);
  });
});

describe("sanitizers", () => {
  it("respects HTML sanitizers for HTML sinks", () => {
    expect(found("el.innerHTML = DOMPurify.sanitize(location.hash);")).toEqual([]);
    expect(found("const c = DOMPurify.sanitize(location.hash);\nel.innerHTML = c;")).toEqual([]);
  });
  it("respects encodeURIComponent and numeric coercion", () => {
    expect(found("el.innerHTML = encodeURIComponent(location.search);")).toEqual([]);
    expect(found("el.innerHTML = Number(location.hash.slice(1));")).toEqual([]);
  });
  it("does not let an HTML sanitizer neutralize other sink kinds", () => {
    expect(found("eval(DOMPurify.sanitize(location.hash));")).toEqual(["JS-TAINT-002@1"]);
  });
  it("clears taint on straight-line reassignment but not on conditional reassignment", () => {
    expect(found("let v = location.search;\nv = 'safe';\nel.innerHTML = v;")).toEqual([]);
    expect(found("let v = location.search;\nif (ok) { v = 'safe'; }\nel.innerHTML = v;")).toEqual([
      "JS-TAINT-001@3",
    ]);
  });
  it("is not confused by constants or untainted values", () => {
    expect(
      found(
        "const t = 'x';\nel.innerHTML = t;\nel.innerHTML = props.html;\nel.textContent = location.hash;",
      ),
    ).toEqual([]);
    expect(found("if (location.hash.startsWith('#a')) { el.innerHTML = '<b>ok</b>'; }")).toEqual(
      [],
    );
  });
  it("respects shadowing", () => {
    expect(found("const q = location.search;\nfunction f(q) { el.innerHTML = q; }")).toEqual([]);
  });
});

describe("code injection (JS-TAINT-002)", () => {
  it("flags eval, Function and string timers fed by untrusted data", () => {
    const code = [
      "const c = location.hash.slice(1);",
      "eval(c);",
      "new Function(c)();",
      "setTimeout(c, 10);",
    ].join("\n");
    const result = found(code);
    expect(result).toEqual(["JS-TAINT-002@2", "JS-TAINT-002@3", "JS-TAINT-002@4"]);
    expect(scan(code)[0]?.severity).toBe("CRITICAL");
  });
  it("ignores constants and function callbacks", () => {
    expect(found("eval('1+1');\nsetTimeout(() => run(location.hash), 10);")).toEqual([]);
  });
});

describe("navigation sinks (JS-TAINT-003)", () => {
  it("flags open redirects and javascript: URL sinks", () => {
    const code = [
      "const next = new URLSearchParams(location.search).get('next');",
      "location.href = next;",
      "window.open(next);",
      "location.assign(next);",
      "const A = () => <a href={next}>go</a>;",
    ].join("\n");
    expect(found(code)).toEqual([
      "JS-TAINT-003@2",
      "JS-TAINT-003@3",
      "JS-TAINT-003@4",
      "JS-TAINT-003@5",
    ]);
  });
  it("accepts encoded or constant targets", () => {
    expect(found("location.href = '/home?x=' + encodeURIComponent(location.search);")).toEqual([]);
    expect(found("location.href = '/home';")).toEqual([]);
  });
});

describe("postMessage sources", () => {
  it("treats event.data as untrusted when the handler does not check origin", () => {
    const code = "window.addEventListener('message', (e) => { el.innerHTML = e.data; });";
    const [finding] = scan(code);
    expect(finding).toMatchObject({ ruleId: "JS-TAINT-001", confidence: "MEDIUM" });
  });
  it("works for handlers declared before registration and destructured data", () => {
    const code =
      "function h({ data }) { document.write(data); }\nwindow.addEventListener('message', h);";
    expect(found(code)).toEqual(["JS-TAINT-001@1"]);
  });
  it("trusts data from handlers that verify the origin", () => {
    const code =
      "window.addEventListener('message', (e) => { if (e.origin !== A) return; el.innerHTML = e.data; });";
    expect(found(code)).toEqual([]);
  });
});

describe("user input fields", () => {
  it("reports with LOW confidence (self-XSS)", () => {
    const [finding] = scan("const onChange = (e) => { preview.innerHTML = e.target.value; };");
    expect(finding).toMatchObject({ ruleId: "JS-TAINT-001", confidence: "LOW" });
  });
});

describe("robustness", () => {
  it("handles long expression chains and files without an AST", () => {
    const long =
      "const v = " + Array(100).fill("location.hash").join(" + ") + ";\nel.innerHTML = v;";
    expect(found(long)).toEqual(["JS-TAINT-001@2"]);
    expect(runRules(createSourceFile("a.json", "{}"), taintRules, {}).findings).toEqual([]);
  });
  it("never crashes the scan on absurdly nested input", () => {
    const hostile =
      "const v = " + Array(20_000).fill("location.hash").join(" + ") + ";\nel.innerHTML = v;";
    const result = runRules(createSourceFile("a.js", hostile), taintRules, {});
    // Handled or reported as an isolated rule failure, but never thrown.
    expect(Array.isArray(result.findings)).toBe(true);
  });
  it("caps the data flow path length", () => {
    const code = [
      "let v = location.hash;",
      ...Array(100).fill("v = v + 'x';"),
      "el.innerHTML = v;",
    ].join("\n");
    const [finding] = scan(code);
    expect(finding?.dataFlow?.length).toBeLessThanOrEqual(32);
  });
  it("exposes metadata with limitations on every rule", () => {
    expect(taintRules.map((r) => r.meta.id)).toEqual([
      "JS-TAINT-001",
      "JS-TAINT-002",
      "JS-TAINT-003",
    ]);
    expect(
      taintRules.every((r) => loc(r.meta.limitations, "en").includes("Intra-procedural")),
    ).toBe(true);
    expect(taintRules.every((r) => loc(r.meta.limitations, "tr").includes("Prosedür içi"))).toBe(
      true,
    );
  });
});
