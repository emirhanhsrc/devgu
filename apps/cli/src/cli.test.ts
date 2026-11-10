import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { EXIT, main } from "./main.js";

let tmp: string;
let out: string;
let err: string;

beforeEach(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), "devgu-cli-"));
  process.env["DEVGU_CACHE_DIR"] = path.join(tmp, ".cache-home");
  out = "";
  err = "";
});
afterEach(async () => {
  delete process.env["DEVGU_CACHE_DIR"];
  await rm(tmp, { recursive: true, force: true });
});

const run = (args: string[]): Promise<number> =>
  main(args, { stdout: (t) => void (out += t), stderr: (t) => void (err += t), cwd: tmp });

describe("cli", () => {
  it("prints the version", async () => {
    expect(await run(["version"])).toBe(EXIT.OK);
    expect(out).toMatch(/^\d+\.\d+\.\d+\n$/);
  });
  it("shows help and fails without a command", async () => {
    expect(await run([])).toBe(EXIT.USAGE);
    expect(out).toContain("Usage:");
    out = "";
    expect(await run(["--help"])).toBe(EXIT.OK);
  });
  it("rejects unknown commands, options and formats", async () => {
    expect(await run(["nope"])).toBe(EXIT.USAGE);
    expect(await run(["scan", "--bogus"])).toBe(EXIT.USAGE);
    expect(await run(["scan", "--format", "xml"])).toBe(EXIT.USAGE);
    expect(await run(["scan", "--fail-on", "SEVERE"])).toBe(EXIT.USAGE);
  });
  it("returns a runtime error for a missing directory", async () => {
    expect(await run(["scan", "does-not-exist"])).toBe(EXIT.ERROR);
    expect(err).toContain("Not a directory");
  });
  it("scans a project and writes JSON to a file", async () => {
    await mkdir(path.join(tmp, "proj"));
    await writeFile(path.join(tmp, "proj", "a.js"), "const a = 1;\n");
    expect(await run(["scan", "proj", "-f", "json", "-o", "report.json", "-q"])).toBe(EXIT.OK);
    const report = JSON.parse(await readFile(path.join(tmp, "report.json"), "utf8"));
    expect(report.meta.tool).toBe("devgu");
    expect(report.stats.filesScanned).toBe(1);
    expect(JSON.stringify(report)).not.toContain(tmp);
  });
  it("lists and explains rules, including dependency findings", async () => {
    expect(await run(["rules", "list"])).toBe(EXIT.OK);
    expect(out).toContain("JS-XSS-001");
    expect(out).toContain("JS-TAINT-001");
    expect(out).toContain("DEP-VULN-001");
    out = "";
    expect(await run(["rules", "explain", "js-taint-001"])).toBe(EXIT.OK);
    expect(out).toContain("Limitations:");
    expect(await run(["rules", "explain", "NOPE-1"])).toBe(EXIT.USAGE);
  });
  it("fails the build only at or above --fail-on", async () => {
    await mkdir(path.join(tmp, "p"));
    await writeFile(path.join(tmp, "p", "a.js"), "eval(location.hash);\n");
    expect(await run(["scan", "p", "-q", "--no-cache"])).toBe(EXIT.FINDINGS);
    expect(await run(["scan", "p", "-q", "--no-cache", "--fail-on", "critical"])).toBe(
      EXIT.FINDINGS,
    );
    await writeFile(path.join(tmp, "p", "a.js"), "setTimeout('go()', 1);\n");
    expect(await run(["scan", "p", "-q", "--no-cache"])).toBe(EXIT.OK);
    expect(await run(["scan", "p", "-q", "--no-cache", "--fail-on", "medium"])).toBe(EXIT.FINDINGS);
  });
  it("selects engines", async () => {
    await mkdir(path.join(tmp, "q"));
    await writeFile(
      path.join(tmp, "q", "a.js"),
      'eval(x);\nconst db = { password: "Tr0ub4dor&3xx" };\n',
    );
    await run(["scan", "q", "--secrets", "-f", "json", "-q", "--no-cache"]);
    const secretsOnly = JSON.parse(out) as { findings: Array<{ engine: string }> };
    expect(secretsOnly.findings.every((f) => f.engine === "secrets")).toBe(true);
    expect(secretsOnly.findings.length).toBe(1);
  });
  it("writes html and markdown reports", async () => {
    await mkdir(path.join(tmp, "r"));
    await writeFile(path.join(tmp, "r", "a.js"), "el.innerHTML = location.hash;
");
    await run(["scan", "r", "-f", "html", "-o", "out.html", "-q", "--no-cache"]);
    await run(["scan", "r", "-f", "md", "-o", "out.md", "-q", "--no-cache"]);
    const html = await readFile(path.join(tmp, "out.html"), "utf8");
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).toContain("Content-Security-Policy");
    expect(await readFile(path.join(tmp, "out.md"), "utf8")).toContain("JS-TAINT-001");
  });
  it("creates a config once", async () => {
    expect(await run(["config", "init"])).toBe(EXIT.OK);
    expect(await run(["config", "init"])).toBe(EXIT.USAGE);
  });
  it("clears the cache", async () => {
    expect(await run(["cache", "clear"])).toBe(EXIT.OK);
  });
});
