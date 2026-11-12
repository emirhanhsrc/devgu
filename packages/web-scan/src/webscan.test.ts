import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { prettifyMinified } from "./prettify.js";
import { scanUrl } from "./scanUrl.js";

const GOOGLE_KEY = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";
const APP_JS = `var a=1;function f(){return fetch("http://api.example.test/x")}\nconst cfg={key:"${GOOGLE_KEY}"};\n//# sourceMappingURL=app.js.map`;
const MAP = JSON.stringify({
  version: 3,
  sources: ["webpack:///./src/App.jsx", "webpack:///./node_modules/react/index.js"],
  sourcesContent: [
    "export const App = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
    "module.exports = {};",
  ],
});

let server: Server;
let base = "";

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = req.url ?? "/";
    if (url === "/") {
      res.setHeader("x-powered-by", "Express");
      res.setHeader("content-type", "text/html");
      res.end(
        `<!doctype html><html><body><script src="/app.js"></script><script src="https://cdn.example.test/x.js"></script></body></html>`,
      );
    } else if (url === "/app.js") {
      res.setHeader("content-type", "text/javascript");
      res.end(APP_JS);
    } else if (url === "/app.js.map") res.end(MAP);
    else if (url === "/.env") {
      res.setHeader("content-type", "text/plain");
      res.end("DB_HOST=localhost\nDB_PASSWORD=hunter2hunter2\n");
    } else if (url === "/robots.txt") res.end("User-agent: *\nDisallow: /private\n");
    else {
      res.statusCode = 404;
      res.end("not found");
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

describe("scanUrl", () => {
  it("scans served scripts, recovers source maps and reports site-level issues", async () => {
    const result = await scanUrl({ url: base });
    const ids = result.findings.map((f) => f.ruleId);
    expect(ids).toContain("WEB-HDR-001");
    expect(ids).toContain("WEB-HDR-003");
    expect(ids).toContain("WEB-HDR-005");
    expect(ids).toContain("WEB-MAP-001");
    expect(ids).toContain("WEB-EXP-001");
    expect(ids).toContain("SEC-GOOGLE-001");
    expect(ids).toContain("JS-XSS-002");
    // findings point at URLs, never at the temporary directory
    for (const f of result.findings) expect(f.filePath).toMatch(/^http:\/\/127\.0\.0\.1/);
    expect(result.findings.find((f) => f.ruleId === "JS-XSS-002")?.filePath).toContain(
      "app.js.map#src/App.jsx",
    );
    // secrets are masked, third-party scripts are not fetched
    expect(JSON.stringify(result)).not.toContain(GOOGLE_KEY);
    expect(JSON.stringify(result)).not.toContain("hunter2hunter2");
    expect(result.diagnostics.some((d) => /third-party/.test(d.message))).toBe(true);
  });

  it("rejects non-http URLs", async () => {
    await expect(scanUrl({ url: "file:///etc/passwd" })).rejects.toThrow(/http/);
  });
});

describe("prettifyMinified", () => {
  it("wraps long lines without touching strings", () => {
    const code = "var s='a;b,c}';" + "x=1;".repeat(1200);
    const out = prettifyMinified(code);
    expect(out.split("\n").length).toBeGreaterThan(5);
    expect(out).toContain("'a;b,c}'");
    expect(prettifyMinified("short\nlines")).toBe("short\nlines");
  });
});
