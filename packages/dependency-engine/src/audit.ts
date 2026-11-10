import { lstat, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { fingerprint, SeveritySchema, type Diagnostic, type Finding } from "@devgu/shared";
import { indexLocations, parsePackageLock, type LockedPackage } from "./lockfile.js";
import { OsvClient, type FetchLike, type Vulnerability } from "./osv.js";

export const DEPENDENCY_RULE = {
  id: "DEP-VULN-001",
  name: "Dependency with a known vulnerability",
  description:
    "A package version in the lockfile matches an advisory in the OSV database (GitHub Advisory Database, malicious package reports, ...).",
  category: "dependency-vulnerability",
  severity: "HIGH" as const,
  confidence: "HIGH" as const,
  engine: "dependencies",
  targets: "text" as const,
  remediation:
    "Upgrade to a fixed version (see the finding), or remove the dependency. Re-run `npm audit fix` or update the lockfile and review the changes.",
  references: ["https://osv.dev/", "https://cwe.mitre.org/data/definitions/1395.html"],
  limitations:
    "Matches the exact versions in the root package-lock.json against advisory data; it cannot tell whether your code calls the vulnerable function. Severity comes from the advisory (or CVSS v3 vector) and defaults to MEDIUM when absent. yarn.lock, pnpm-lock.yaml and nested lockfiles are not analysed yet.",
  version: 1,
};

const MAX_LOCKFILE_BYTES = 50 * 1024 * 1024;
const LOCKFILES = ["package-lock.json", "npm-shrinkwrap.json"] as const;
const REFRESH_AFTER_MS = 24 * 60 * 60 * 1000;
const CACHE_FILE = "osv-cache.json";

const VulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string(),
  aliases: z.array(z.string()),
  severity: SeveritySchema,
  severityKnown: z.boolean(),
  fixed: z.record(z.string(), z.array(z.string())),
  references: z.array(z.string()),
});

const VulnCacheSchema = z.object({
  version: z.literal(1),
  packages: z.record(z.string(), z.object({ ids: z.array(z.string()), fetchedAt: z.number() })),
  vulns: z.record(z.string(), VulnerabilitySchema),
});
type VulnCache = z.infer<typeof VulnCacheSchema>;

async function loadCache(dir: string): Promise<VulnCache> {
  try {
    const file = path.join(dir, CACHE_FILE);
    const info = await lstat(file);
    if (!info.isFile() || info.size > 100 * 1024 * 1024) throw new Error("unusable cache");
    return VulnCacheSchema.parse(JSON.parse(await readFile(file, "utf8")));
  } catch {
    return { version: 1, packages: {}, vulns: {} };
  }
}

async function saveCache(dir: string, cache: VulnCache): Promise<void> {
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const target = path.join(dir, CACHE_FILE);
  const tmp = `${target}.${randomBytes(6).toString("hex")}.tmp`;
  await writeFile(tmp, JSON.stringify(cache), { mode: 0o600, flag: "wx" });
  await rename(tmp, target);
}

export interface AuditOptions {
  root: string;
  /** When false (default for the CLI) no network request is made. */
  online: boolean;
  cacheDir: string;
  signal?: AbortSignal;
  fetchImpl?: FetchLike;
  now?: () => number;
}

export interface AuditResult {
  findings: Finding[];
  diagnostics: Diagnostic[];
}

async function readLockfile(root: string): Promise<{ name: string; text: string } | null> {
  for (const name of LOCKFILES) {
    const file = path.join(root, name);
    const info = await lstat(file).catch(() => null);
    if (!info || !info.isFile() || info.isSymbolicLink() || info.size > MAX_LOCKFILE_BYTES)
      continue;
    return { name, text: await readFile(file, "utf8") };
  }
  return null;
}

export async function auditDependencies(options: AuditOptions): Promise<AuditResult> {
  const diagnostics: Diagnostic[] = [];
  const now = options.now ?? Date.now;
  const lock = await readLockfile(options.root);
  if (!lock) {
    const hasManifest = await lstat(path.join(options.root, "package.json")).then(
      () => true,
      () => false,
    );
    if (hasManifest) {
      diagnostics.push({
        source: "dependencies",
        message:
          "No package-lock.json found; dependency analysis skipped (yarn.lock and pnpm-lock.yaml are not supported yet).",
      });
    }
    return { findings: [], diagnostics };
  }

  let parsed;
  try {
    parsed = parsePackageLock(lock.text);
  } catch (error) {
    diagnostics.push({
      source: "dependencies",
      filePath: lock.name,
      message: error instanceof Error ? error.message : String(error),
    });
    return { findings: [], diagnostics };
  }

  // Unique registry package versions; remember where each first appears.
  const byKey = new Map<string, LockedPackage[]>();
  for (const pkg of parsed.packages) {
    if (!pkg.registry) continue;
    const key = `${pkg.name}@${pkg.version}`;
    byKey.set(key, [...(byKey.get(key) ?? []), pkg]);
  }

  const cache = await loadCache(options.cacheDir);
  if (options.online) {
    try {
      const client = new OsvClient(
        options.fetchImpl ?? (globalThis.fetch as unknown as FetchLike),
        options.signal,
      );
      const stale = [...byKey.keys()].filter((key) => {
        const entry = cache.packages[key];
        return !entry || now() - entry.fetchedAt > REFRESH_AFTER_MS;
      });
      if (stale.length > 0) {
        const queried = await client.queryBatch(
          stale.map((key) => ({
            name: key.slice(0, key.lastIndexOf("@")),
            version: key.slice(key.lastIndexOf("@") + 1),
          })),
        );
        for (const [key, ids] of queried) cache.packages[key] = { ids, fetchedAt: now() };
      }
      const wanted = [...byKey.keys()].flatMap((key) => cache.packages[key]?.ids ?? []);
      const missing = wanted.filter((id) => !cache.vulns[id]);
      if (missing.length > 0) {
        const { vulns, skipped } = await client.getVulnerabilities(missing);
        for (const vuln of vulns) cache.vulns[vuln.id] = vuln;
        if (skipped > 0)
          diagnostics.push({
            source: "dependencies",
            message: `${skipped} advisory detail(s) were not downloaded (limit per run).`,
          });
      }
      await saveCache(options.cacheDir, cache);
    } catch (error) {
      diagnostics.push({
        source: "dependencies",
        message: `OSV request failed, using cached data only: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  const unknown = [...byKey.keys()].filter((key) => !cache.packages[key]).length;
  if (unknown > 0) {
    diagnostics.push({
      source: "dependencies",
      message: options.online
        ? `Vulnerability data is missing for ${unknown} of ${byKey.size} packages.`
        : `Vulnerability data is missing for ${unknown} of ${byKey.size} packages. Run with --online to download advisory data (only package names and versions are sent to api.osv.dev).`,
    });
  }

  const lines = indexLocations(lock.text);
  const findings: Finding[] = [];
  for (const [key, locations] of byKey) {
    const ids = cache.packages[key]?.ids ?? [];
    const first = locations[0] as LockedPackage;
    for (const id of ids) {
      const vuln: Vulnerability = cache.vulns[id] ?? {
        id,
        summary: "Advisory details are not cached",
        aliases: [],
        severity: "MEDIUM",
        severityKnown: false,
        fixed: {},
        references: [`https://osv.dev/vulnerability/${id}`],
      };
      const line = lines.get(first.location) ?? 1;
      const direct = locations.some((l) => l.direct);
      const devOnly = locations.every((l) => l.dev);
      const fixed = vuln.fixed[first.name] ?? [];
      const evidence = `${first.name}@${first.version}  ${vuln.id}${vuln.aliases.length ? ` (${vuln.aliases.slice(0, 3).join(", ")})` : ""}`;
      const print = fingerprint(DEPENDENCY_RULE.id, lock.name, `${key}:${vuln.id}`);
      findings.push({
        id: `${DEPENDENCY_RULE.id}-${print.slice(0, 8)}-L${line}`,
        ruleId: DEPENDENCY_RULE.id,
        engine: DEPENDENCY_RULE.engine,
        title: `${first.name}@${first.version}: ${vuln.summary}`,
        description: `${vuln.summary} (${vuln.id}). ${direct ? "Direct" : "Transitive"} dependency${devOnly ? " (development only)" : ""}${locations.length > 1 ? `, installed ${locations.length} times` : ""}.${vuln.severityKnown ? "" : " The advisory has no usable severity; MEDIUM is assumed."}`,
        severity: devOnly && vuln.severity === "CRITICAL" ? "HIGH" : vuln.severity,
        confidence: DEPENDENCY_RULE.confidence,
        category: DEPENDENCY_RULE.category,
        filePath: lock.name,
        startLine: line,
        endLine: line,
        evidence,
        remediation:
          fixed.length > 0
            ? `Upgrade ${first.name} to ${fixed.join(" or ")} (or later).`
            : DEPENDENCY_RULE.remediation,
        references:
          vuln.references.length > 0
            ? vuln.references
            : [`https://osv.dev/vulnerability/${vuln.id}`],
        limitations: DEPENDENCY_RULE.limitations,
        fingerprint: print,
        status: "open",
      });
    }
  }
  return { findings, diagnostics };
}
