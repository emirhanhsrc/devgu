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
  it("creates a config once", async () => {
    expect(await run(["config", "init"])).toBe(EXIT.OK);
    expect(await run(["config", "init"])).toBe(EXIT.USAGE);
  });
  it("clears the cache", async () => {
    expect(await run(["cache", "clear"])).toBe(EXIT.OK);
  });
});
