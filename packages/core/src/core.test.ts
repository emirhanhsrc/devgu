import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { Rule } from "@devgu/rule-engine";
import { ConfigSchema, defaultConfig, loadConfig } from "./config.js";
import { classifyFile, discoverFiles } from "./discovery.js";
import { scan } from "./pipeline.js";

let tmp: string;
let cacheDir: string;

beforeEach(async () => {
  tmp = await mkdtemp(path.join(os.tmpdir(), "devgu-core-"));
  cacheDir = await mkdtemp(path.join(os.tmpdir(), "devgu-cache-"));
});
afterEach(async () => {
  await rm(tmp, { recursive: true, force: true });
  await rm(cacheDir, { recursive: true, force: true });
});

async function write(rel: string, content: string): Promise<void> {
  const abs = path.join(tmp, rel);
  await mkdir(path.dirname(abs), { recursive: true });
  await writeFile(abs, content);
}

const badRule: Rule = {
  meta: {
    id: "T-BAD",
    name: "Bad word",
    description: "d",
    category: "test",
    severity: "HIGH",
    confidence: "HIGH",
    targets: "text",
    remediation: "r",
    references: [],
    limitations: "l",
    version: 1,
    engine: "test",
  },
  check(ctx) {
    ctx.file.lines.forEach((line, i) => {
      if (/(^|\s)BAD(\s|$)/.test(line)) ctx.report({ line: i + 1 });
    });
  },
};

describe("classifyFile", () => {
  it("classifies by name and extension", () => {
    expect(classifyFile("src/a.tsx")).toBe("script");
    expect(classifyFile("config/.env.local")).toBe("text");
    expect(classifyFile("a.json")).toBe("text");
    expect(classifyFile("package-lock.json")).toBeNull();
    expect(classifyFile("dist/app.min.js")).toBeNull();
    expect(classifyFile("logo.png")).toBeNull();
  });
});

describe("discoverFiles", () => {
  it("skips default exclusions and honours custom patterns", async () => {
    await write("src/a.js", "1");
    await write("node_modules/x/index.js", "1");
    await write("dist/out.js", "1");
    await write("generated/g.js", "1");
    await write("README.md", "x");
    const result = await discoverFiles({
      root: tmp,
      config: { ...defaultConfig(), exclude: ["generated/**"] },
    });
    expect(result.files.map((f) => f.relPath)).toEqual(["src/a.js"]);
    expect(result.ignoredCount).toBe(1);
  });
  it("skips files above the size limit", async () => {
    await write("big.js", "x".repeat(5000));
    const result = await discoverFiles({
      root: tmp,
      config: { ...defaultConfig(), maxFileSizeBytes: 1024 },
    });
    expect(result.files).toHaveLength(0);
    expect(result.skipped).toEqual([{ filePath: "big.js", reason: "too-large" }]);
  });
  it("enforces the file limit", async () => {
    await write("a.js", "1");
    await write("b.js", "1");
    const result = await discoverFiles({ root: tmp, config: { ...defaultConfig(), maxFiles: 1 } });
    expect(result.files).toHaveLength(1);
    expect(result.skipped.map((s) => s.reason)).toEqual(["file-limit"]);
  });
  it("never follows symlinks out of the root", async () => {
    const outside = await mkdtemp(path.join(os.tmpdir(), "devgu-outside-"));
    try {
      await writeFile(path.join(outside, "secret.js"), "BAD");
      await write("a.js", "1");
      try {
        await symlink(outside, path.join(tmp, "link"), "junction");
        await symlink(path.join(outside, "secret.js"), path.join(tmp, "file-link.js"), "file");
      } catch {
        return; // symlinks not permitted in this environment
      }
      const result = await discoverFiles({ root: tmp, config: defaultConfig() });
      expect(result.files.map((f) => f.relPath)).toEqual(["a.js"]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
  it("rejects a root that is not a directory", async () => {
    await write("a.js", "1");
    await expect(
      discoverFiles({ root: path.join(tmp, "a.js"), config: defaultConfig() }),
    ).rejects.toThrow(/Not a directory/);
  });
});

describe("loadConfig", () => {
  it("returns defaults when absent", async () => {
    expect(await loadConfig({ root: tmp })).toEqual(defaultConfig());
  });
  it("rejects unknown keys and bad values", async () => {
    await write("devgu.config.json", JSON.stringify({ unknown: 1 }));
    await expect(loadConfig({ root: tmp })).rejects.toThrow(/Invalid config/);
    await write("devgu.config.json", "{not json");
    await expect(loadConfig({ root: tmp })).rejects.toThrow(/not valid JSON/);
  });
  it("requires a justification for suppressions", () => {
    const bad = ConfigSchema.safeParse({
      suppressions: [{ fingerprint: "abcdef123456", justification: " " }],
    });
    expect(bad.success).toBe(false);
  });
});

describe("scan", () => {
  it("reports findings and caches per file content", async () => {
    await write("a.js", "ok\nBAD here\n");
    await write("b.js", "fine\n");
    const options = { root: tmp, rules: [badRule], cacheDir };
    const first = await scan(options);
    expect(first.findings).toHaveLength(1);
    expect(first.findings[0]).toMatchObject({ filePath: "a.js", startLine: 2 });
    expect(first.stats).toMatchObject({ cacheHits: 0, cacheMisses: 2, filesScanned: 2 });
    expect(JSON.stringify(first)).not.toContain(tmp);

    const second = await scan(options);
    expect(second.stats.cacheHits).toBe(2);
    expect(second.findings).toEqual(first.findings);

    await write("b.js", "BAD again\n");
    const third = await scan(options);
    expect(third.stats).toMatchObject({ cacheHits: 1, cacheMisses: 1 });
    expect(third.findings).toHaveLength(2);
  });
  it("invalidates the cache when rule settings change", async () => {
    await write("a.js", "BAD\n");
    await scan({ root: tmp, rules: [badRule], cacheDir });
    const config = ConfigSchema.parse({ rules: { "T-BAD": { severity: "LOW" } } });
    const result = await scan({ root: tmp, rules: [badRule], cacheDir, config });
    expect(result.stats.cacheHits).toBe(0);
    expect(result.findings[0]?.severity).toBe("LOW");
  });
  it("applies inline suppressions only with a justification", async () => {
    await write(
      "a.js",
      "// devgu-ignore T-BAD: legacy fixture, reviewed\nBAD one\nBAD two // devgu-ignore T-BAD:\n",
    );
    const result = await scan({ root: tmp, rules: [badRule], useCache: false });
    expect(result.suppressed).toHaveLength(1);
    expect(result.suppressed[0]?.suppression).toMatchObject({ kind: "inline" });
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.startLine).toBe(3);
  });
  it("applies config suppressions by fingerprint", async () => {
    await write("a.js", "BAD\n");
    const first = await scan({ root: tmp, rules: [badRule], useCache: false });
    const fingerprint = first.findings[0]?.fingerprint ?? "";
    const config = ConfigSchema.parse({
      suppressions: [{ fingerprint, justification: "accepted risk" }],
    });
    const second = await scan({ root: tmp, rules: [badRule], useCache: false, config });
    expect(second.findings).toHaveLength(0);
    expect(second.suppressed[0]?.suppression?.justification).toBe("accepted risk");
  });
  it("redacts evidence through the supplied function", async () => {
    await write("a.js", "BAD token-123\n");
    const result = await scan({
      root: tmp,
      rules: [badRule],
      useCache: false,
      redact: (t) => t.replace("token-123", "[redacted]"),
    });
    expect(result.findings[0]?.evidence).toBe("BAD [redacted]");
  });
  it("skips binary and minified files with a reason", async () => {
    await writeFile(path.join(tmp, "bin.js"), Buffer.from([0x61, 0x00, 0x62]));
    await write("min.js", "x".repeat(30_000));
    const result = await scan({ root: tmp, rules: [badRule], useCache: false });
    expect(result.skipped.map((s) => s.reason).sort()).toEqual(["binary", "minified-or-generated"]);
  });
  it("stops when cancelled", async () => {
    await write("a.js", "1");
    const controller = new AbortController();
    controller.abort();
    await expect(
      scan({ root: tmp, rules: [badRule], useCache: false, signal: controller.signal }),
    ).rejects.toThrow(/cancelled/);
  });
  it("records analyzer failures as diagnostics", async () => {
    await write("a.js", "1");
    const result = await scan({
      root: tmp,
      rules: [],
      useCache: false,
      analyzers: [{ name: "boom", run: () => Promise.reject(new Error("nope")) }],
    });
    expect(result.diagnostics[0]).toMatchObject({ source: "boom" });
  });
});
