import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ConfigSchema } from "./config.js";
import { scan } from "./pipeline.js";
import { defaultRedactor, defaultRules } from "./rules.js";

const fixturesRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../fixtures",
);

async function expectedFindings(root: string): Promise<string[]> {
  const expected: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const abs = path.join(dir, entry.name);
      if (entry.isDirectory()) await walk(abs);
      else if (entry.isFile()) {
        const rel = path.relative(root, abs).split(path.sep).join("/");
        (await readFile(abs, "utf8")).split(/\r?\n/).forEach((line, index) => {
          const match = /\bexpect:\s*([A-Z0-9, -]+?)\s*$/.exec(line);
          for (const id of match?.[1]?.split(",") ?? [])
            expected.push(`${id.trim()}@${rel}:${index + 1}`);
        });
      }
    }
  };
  await walk(root);
  return expected.sort();
}

async function scanFixture(name: string) {
  return scan({
    root: path.join(fixturesRoot, name),
    rules: defaultRules(),
    redact: defaultRedactor(),
    useCache: false,
    config: ConfigSchema.parse({}),
  });
}

describe("golden fixtures", () => {
  it("reports exactly the tagged findings in the vulnerable project", async () => {
    const result = await scanFixture("vulnerable");
    const actual = result.findings.map((f) => `${f.ruleId}@${f.filePath}:${f.startLine}`).sort();
    expect(actual).toEqual(await expectedFindings(path.join(fixturesRoot, "vulnerable")));
    expect(result.diagnostics).toEqual([]);
  });
  it("reports nothing in the safe project (no false positives)", async () => {
    const result = await scanFixture("safe");
    expect(result.findings.map((f) => `${f.ruleId}@${f.filePath}:${f.startLine}`)).toEqual([]);
    expect(result.diagnostics).toEqual([]);
  });
  it("never writes absolute paths or full secrets into the result", async () => {
    const dump = JSON.stringify(await scanFixture("vulnerable"));
    expect(dump).not.toContain(fixturesRoot);
    expect(dump).not.toContain("Tr0ub4dor&3xx");
    expect(dump).not.toContain("s3cr3tPw");
    expect(dump).not.toContain("q8Zr1xT7vB3nK9mW2pL5");
  });
});
