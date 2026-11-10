import { mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { randomBytes } from "node:crypto";
import { FindingSchema, sha256Hex, type Finding } from "@devgu/shared";
import { z } from "zod";

const MAX_CACHE_BYTES = 64 * 1024 * 1024;

const CacheFileSchema = z.object({
  version: z.literal(1),
  configKey: z.string(),
  entries: z.record(z.string(), z.object({ hash: z.string(), findings: z.array(FindingSchema) })),
});

/**
 * The cache lives in the user's cache directory, never inside the scanned repository: a hostile
 * repository must not be able to plant files (or symlinks) that DEVGU would read or write.
 */
export function defaultCacheDir(): string {
  const override = process.env["DEVGU_CACHE_DIR"];
  if (override) return path.resolve(override);
  if (process.platform === "win32") {
    return path.join(
      process.env["LOCALAPPDATA"] ?? path.join(os.homedir(), "AppData", "Local"),
      "devgu",
      "cache",
    );
  }
  return path.join(process.env["XDG_CACHE_HOME"] ?? path.join(os.homedir(), ".cache"), "devgu");
}

export class ScanCache {
  private entries = new Map<string, { hash: string; findings: Finding[] }>();
  private dirty = false;
  private readonly file: string;

  constructor(
    private readonly dir: string,
    root: string,
    private readonly configKey: string,
  ) {
    this.file = path.join(dir, `${sha256Hex(root).slice(0, 32)}.json`);
  }

  async load(): Promise<void> {
    try {
      const info = await stat(this.file);
      if (!info.isFile() || info.size > MAX_CACHE_BYTES) return;
      const parsed = CacheFileSchema.safeParse(JSON.parse(await readFile(this.file, "utf8")));
      if (!parsed.success || parsed.data.configKey !== this.configKey) return;
      this.entries = new Map(Object.entries(parsed.data.entries));
    } catch {
      this.entries = new Map(); // missing or corrupt cache is simply a cold start
    }
  }

  get(relPath: string, hash: string): Finding[] | undefined {
    const entry = this.entries.get(relPath);
    return entry && entry.hash === hash ? entry.findings : undefined;
  }

  set(relPath: string, hash: string, findings: Finding[]): void {
    this.entries.set(relPath, { hash, findings });
    this.dirty = true;
  }

  /** Drops entries of files that no longer exist. */
  retainOnly(relPaths: Set<string>): void {
    for (const key of [...this.entries.keys()]) {
      if (!relPaths.has(key)) {
        this.entries.delete(key);
        this.dirty = true;
      }
    }
  }

  async save(): Promise<void> {
    if (!this.dirty) return;
    const payload = {
      version: 1 as const,
      configKey: this.configKey,
      entries: Object.fromEntries(this.entries),
    };
    await mkdir(this.dir, { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.${randomBytes(6).toString("hex")}.tmp`;
    await writeFile(tmp, JSON.stringify(payload), { mode: 0o600, flag: "wx" });
    await rename(tmp, this.file);
    this.dirty = false;
  }
}

export async function clearCache(dir: string = defaultCacheDir()): Promise<void> {
  await rm(dir, { recursive: true, force: true });
}
