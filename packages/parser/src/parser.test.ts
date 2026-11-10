import { describe, expect, it } from "vitest";
import { createSourceFile, languageOf } from "./index.js";

describe("languageOf", () => {
  it("maps extensions", () => {
    expect(languageOf("a/b.tsx")).toBe("tsx");
    expect(languageOf("a.MJS")).toBe("js");
    expect(languageOf("a.json")).toBeNull();
    expect(languageOf("Makefile")).toBeNull();
  });
});

describe("createSourceFile", () => {
  it("parses JSX inside .js files", () => {
    const file = createSourceFile("a.js", "const x = <div id='a'>hi</div>;");
    expect(file.ast).not.toBeNull();
  });
  it("parses TypeScript", () => {
    const file = createSourceFile("a.ts", "const x: number = 1; type T = { a: string };");
    expect(file.ast).not.toBeNull();
    expect(file.recoveredErrors).toBe(0);
  });
  it("parses TSX", () => {
    expect(
      createSourceFile("a.tsx", "const C = (p: {a: string}) => <b>{p.a}</b>;").ast,
    ).not.toBeNull();
  });
  it("never throws on broken input", () => {
    const file = createSourceFile("a.js", "function ( {{{ ;;;");
    expect(file.ast !== null || file.parseError !== undefined).toBe(true);
  });
  it("keeps non-script files without an AST", () => {
    const file = createSourceFile("a.json", '{"a":1}');
    expect(file.ast).toBeNull();
    expect(file.language).toBeNull();
    expect(file.lines).toEqual(['{"a":1}']);
  });
  it("splits CRLF lines", () => {
    expect(createSourceFile("a.js", "a\r\nb\nc").lines).toEqual(["a", "b", "c"]);
  });
});
