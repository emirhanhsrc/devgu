import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { auditDependencies } from "./audit.js";
import { cvss3BaseScore, severityFromScore } from "./cvss.js";
import { indexLocations, parsePackageLock } from "./lockfile.js";
import { OSV_BASE_URL, normalizeVulnerability, type FetchLike } from "./osv.js";

const lockV3 = JSON.stringify(
  {
    name: "demo",
    lockfileVersion: 3,
    packages: {
      "": {
        name: "demo",
        dependencies: { lodash: "^4.17.0" },
        devDependencies: { vitest: "^1.0.0" },
      },
      "node_modules/lodash": {
        version: "4.17.15",
        resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz",
      },
      "node_modules/vitest": {
        version: "1.0.0",
        dev: true,
        resolved: "https://registry.npmjs.org/vitest/-/vitest-1.0.0.tgz",
      },
      "node_modules/a/node_modules/@scope/b": {
        version: "2.0.0",
        resolved: "https://registry.npmjs.org/@scope/b/-/b-2.0.0.tgz",
      },
      "node_modules/gitdep": { version: "1.0.0", resolved: "git+ssh://git@github.com/x/y.git#abc" },
      "node_modules/local": { version: "1.0.0", resolved: "../local", link: true },
    },
  },
  null,
  2,
);

describe("parsePackageLock", () => {
  it("parses v3 with direct/transitive/dev and ignores non-registry packages", () => {
    const { packages, lockfileVersion } = parsePackageLock(lockV3);
    expect(lockfileVersion).toBe(3);
    const by = Object.fromEntries(packages.map((p) => [p.name, p]));
    expect(by["lodash"]).toMatchObject({ direct: true, dev: false, registry: true });
    expect(by["vitest"]).toMatchObject({ direct: true, dev: true });
    expect(by["@scope/b"]).toMatchObject({ direct: false, registry: true, version: "2.0.0" });
    expect(by["gitdep"]?.registry).toBe(false);
    expect(by["local"]?.registry).toBe(false);
  });
  it("parses v1 nested dependencies", () => {
    const v1 = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        a: { version: "1.0.0", dependencies: { b: { version: "2.0.0", dev: true } } },
      },
    });
    const { packages } = parsePackageLock(v1);
    expect(packages.map((p) => `${p.name}@${p.version}:${p.direct}`)).toEqual([
      "a@1.0.0:true",
      "b@2.0.0:false",
    ]);
  });
  it("rejects hostile input safely", () => {
    expect(() => parsePackageLock("not json")).toThrow(/not valid JSON/);
    expect(() => parsePackageLock("[]")).toThrow(/object/);
    expect(() => parsePackageLock("{}")).toThrow(/neither/);
    const weird = JSON.stringify({
      lockfileVersion: 3,
      packages: { "node_modules/x": { version: 5 }, "node_modules/y": "bad", "": null },
    });
    expect(parsePackageLock(weird).packages).toEqual([]);
  });
  it("indexes line numbers of lockfile entries", () => {
    expect(indexLocations(lockV3).get("node_modules/lodash")).toBeGreaterThan(1);
  });
});

describe("cvss", () => {
  it("computes CVSS v3 base scores", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3BaseScore("CVSS:4.0/AV:N")).toBeNull();
    expect(cvss3BaseScore("garbage")).toBeNull();
  });
  it("maps scores to severities", () => {
    expect([9.8, 7.5, 5, 2, 0].map(severityFromScore)).toEqual([
      "CRITICAL",
      "HIGH",
      "MEDIUM",
      "LOW",
      "INFO",
    ]);
  });
});

describe("normalizeVulnerability", () => {
  it("prefers the advisory label, falls back to CVSS, then to MEDIUM", () => {
    const base = { id: "GHSA-1", summary: "s" };
    expect(
      normalizeVulnerability({ ...base, database_specific: { severity: "MODERATE" } })?.severity,
    ).toBe("MEDIUM");
    expect(
      normalizeVulnerability({ ...base, database_specific: { severity: "CRITICAL" } })?.severity,
    ).toBe("CRITICAL");
    expect(
      normalizeVulnerability({
        ...base,
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
      })?.severity,
    ).toBe("CRITICAL");
    expect(normalizeVulnerability(base)).toMatchObject({
      severity: "MEDIUM",
      severityKnown: false,
    });
  });
  it("marks malicious packages critical, drops withdrawn advisories and unsafe links", () => {
    expect(normalizeVulnerability({ id: "MAL-2024-1", summary: "x" })?.severity).toBe("CRITICAL");
    expect(normalizeVulnerability({ id: "GHSA-2", withdrawn: "2024-01-01T00:00:00Z" })).toBeNull();
    expect(
      normalizeVulnerability({
        id: "GHSA-3",
        references: [
          { url: "javascript:alert(1)" },
          { url: "http://x.com" },
          { url: "https://ok.dev/a" },
        ],
      })?.references,
    ).toEqual(["https://ok.dev/a"]);
    expect(normalizeVulnerability("nonsense")).toBeNull();
  });
  it("collects fixed npm versions per package", () => {
    const vuln = normalizeVulnerability({
      id: "GHSA-4",
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }],
        },
      ],
    });
    expect(vuln?.fixed).toEqual({ lodash: ["4.17.21"] });
  });
});

describe("auditDependencies", () => {
  let root: string;
  let cacheDir: string;
  beforeEach(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "devgu-dep-"));
    cacheDir = await mkdtemp(path.join(os.tmpdir(), "devgu-depcache-"));
    await writeFile(path.join(root, "package-lock.json"), lockV3);
    await writeFile(path.join(root, "package.json"), "{}");
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(cacheDir, { recursive: true, force: true });
  });

  function fakeOsv(calls: string[]): FetchLike {
    return async (url, init) => {
      calls.push(`${init?.method ?? "GET"} ${url}`);
      expect(url.startsWith(OSV_BASE_URL)).toBe(true);
      if (url.endsWith("/v1/querybatch")) {
        const body = JSON.parse(init?.body ?? "{}") as {
          queries: Array<{ package: { name: string }; version: string }>;
        };
        // Only package names and versions may be sent.
        expect(Object.keys(body)).toEqual(["queries"]);
        const results = body.queries.map((q) =>
          q.package.name === "lodash" ? { vulns: [{ id: "GHSA-lodash-1" }] } : {},
        );
        return { ok: true, status: 200, text: async () => JSON.stringify({ results }) };
      }
      return {
        ok: true,
        status: 200,
        text: async () =>
          JSON.stringify({
            id: "GHSA-lodash-1",
            summary: "Prototype pollution in lodash",
            aliases: ["CVE-2020-8203"],
            database_specific: { severity: "HIGH" },
            affected: [
              {
                package: { name: "lodash", ecosystem: "npm" },
                ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.19" }] }],
              },
            ],
            references: [{ url: "https://github.com/advisories/GHSA-lodash-1" }],
          }),
      };
    };
  }

  it("makes no network call offline and explains how to get data", async () => {
    const calls: string[] = [];
    const result = await auditDependencies({
      root,
      online: false,
      cacheDir,
      fetchImpl: fakeOsv(calls),
    });
    expect(calls).toEqual([]);
    expect(result.findings).toEqual([]);
    expect(result.diagnostics[0]?.message).toContain("--online");
  });

  it("queries OSV online, reports findings and then works offline from the cache", async () => {
    const calls: string[] = [];
    const online = await auditDependencies({
      root,
      online: true,
      cacheDir,
      fetchImpl: fakeOsv(calls),
    });
    expect(calls).toEqual([
      "POST https://api.osv.dev/v1/querybatch",
      "GET https://api.osv.dev/v1/vulns/GHSA-lodash-1",
    ]);
    expect(online.diagnostics).toEqual([]);
    expect(online.findings).toHaveLength(1);
    expect(online.findings[0]).toMatchObject({
      ruleId: "DEP-VULN-001",
      severity: "HIGH",
      filePath: "package-lock.json",
      category: "dependency-vulnerability",
    });
    expect(online.findings[0]?.remediation).toContain("4.17.19");
    expect(online.findings[0]?.description).toContain("Direct dependency");
    expect(online.findings[0]?.startLine).toBeGreaterThan(1);

    const offline = await auditDependencies({
      root,
      online: false,
      cacheDir,
      fetchImpl: fakeOsv([]),
    });
    expect(offline.findings.map((f) => f.fingerprint)).toEqual(
      online.findings.map((f) => f.fingerprint),
    );
    expect(offline.diagnostics).toEqual([]);
  });

  it("degrades to cached data when OSV is unreachable", async () => {
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    const result = await auditDependencies({ root, online: true, cacheDir, fetchImpl: failing });
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.some((d) => d.message.includes("network down"))).toBe(true);
  });

  it("rejects malformed OSV responses", async () => {
    const bad: FetchLike = async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ results: "nope" }),
    });
    const result = await auditDependencies({ root, online: true, cacheDir, fetchImpl: bad });
    expect(result.findings).toEqual([]);
    expect(result.diagnostics.some((d) => d.message.includes("OSV request failed"))).toBe(true);
  });

  it("explains a missing lockfile and survives a corrupt one", async () => {
    await rm(path.join(root, "package-lock.json"));
    expect(
      (await auditDependencies({ root, online: false, cacheDir })).diagnostics[0]?.message,
    ).toContain("No package-lock.json");
    await writeFile(path.join(root, "package-lock.json"), "{broken");
    const corrupt = await auditDependencies({ root, online: false, cacheDir });
    expect(corrupt.findings).toEqual([]);
    expect(corrupt.diagnostics[0]?.filePath).toBe("package-lock.json");
  });

  it("ignores a lockfile that is a directory or absent project", async () => {
    const empty = await mkdtemp(path.join(os.tmpdir(), "devgu-empty-"));
    try {
      await mkdir(path.join(empty, "package-lock.json"));
      expect(await auditDependencies({ root: empty, online: false, cacheDir })).toEqual({
        findings: [],
        diagnostics: [],
      });
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });
});
