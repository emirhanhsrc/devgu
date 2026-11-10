import { lstat, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import picomatch from "picomatch";
import type { SkippedFile } from "@devgu/shared";
import { DEFAULT_EXCLUDED_DIRS, type DevguConfig } from "./config.js";

export type FileKind = "script" | "text";

export interface DiscoveredFile {
  /** Repository-relative, forward slashes. */
  relPath: string;
  absPath: string;
  size: number;
  kind: FileKind;
}

export interface DiscoveryResult {
  /** Canonical absolute root. Used internally only; never written to reports. */
  root: string;
  files: DiscoveredFile[];
  skipped: SkippedFile[];
  /** Files that were seen but are not analysable (images, fonts, lockfiles, ...). */
  ignoredCount: number;
}

const SCRIPT_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const TEXT_EXTENSIONS = new Set([
  ".json",
  ".yml",
  ".yaml",
  ".toml",
  ".ini",
  ".env",
  ".properties",
  ".sh",
  ".html",
  ".htm",
  ".xml",
  ".cfg",
  ".conf",
]);
const TEXT_BASENAMES = new Set([".npmrc", ".yarnrc", ".netrc"]);
/** Lockfiles are machine generated; their integrity hashes only produce false positives. */
const IGNORED_BASENAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
]);

export function classifyFile(relPath: string): FileKind | null {
  const base = relPath.slice(relPath.lastIndexOf("/") + 1).toLowerCase();
  if (IGNORED_BASENAMES.has(base)) return null;
  if (base.endsWith(".min.js") || base.endsWith(".min.mjs") || base.endsWith(".map")) return null;
  if (base.startsWith(".env") || TEXT_BASENAMES.has(base)) return "text";
  const ext = path.posix.extname(base);
  if (SCRIPT_EXTENSIONS.has(ext)) return "script";
  if (TEXT_EXTENSIONS.has(ext)) return "text";
  return null;
}

export interface DiscoveryOptions {
  root: string;
  config: Pick<DevguConfig, "exclude" | "maxFileSizeBytes" | "maxFiles">;
  signal?: AbortSignal;
}

/**
 * Walks the tree with lstat. Symbolic links (files and directories) are never followed, so a
 * hostile repository cannot make the scanner read outside the root. Output order is deterministic.
 */
export async function discoverFiles(options: DiscoveryOptions): Promise<DiscoveryResult> {
  const rootInfo = await lstat(options.root).catch(() => null);
  if (!rootInfo || !rootInfo.isDirectory()) {
    throw new Error(`Not a directory: ${options.root}`);
  }
  const root = await realpath(options.root);
  const excludedDirs = new Set<string>(DEFAULT_EXCLUDED_DIRS);
  const isExcluded =
    options.config.exclude.length > 0 ? picomatch(options.config.exclude, { dot: true }) : null;

  const files: DiscoveredFile[] = [];
  const skipped: SkippedFile[] = [];
  let ignoredCount = 0;
  const pending: string[] = [root];

  while (pending.length > 0) {
    if (options.signal?.aborted) throw new Error("Scan cancelled");
    const dir = pending.pop() as string;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      skipped.push({ filePath: toRel(root, dir) || ".", reason: "unreadable" });
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const abs = path.join(dir, entry.name);
      const rel = toRel(root, abs);
      if (rel === null) continue; // never leaves the root
      if (entry.isSymbolicLink()) {
        skipped.push({ filePath: rel, reason: "symlink" });
        continue;
      }
      if (entry.isDirectory()) {
        if (excludedDirs.has(entry.name) || isExcluded?.(rel) || isExcluded?.(`${rel}/`)) continue;
        pending.push(abs);
        continue;
      }
      if (!entry.isFile() || isExcluded?.(rel)) continue;
      const kind = classifyFile(rel);
      if (!kind) {
        ignoredCount += 1;
        continue;
      }
      if (files.length >= options.config.maxFiles) {
        skipped.push({ filePath: rel, reason: "file-limit" });
        continue;
      }
      const info = await lstat(abs).catch(() => null);
      if (!info || !info.isFile()) {
        skipped.push({ filePath: rel, reason: "unreadable" });
        continue;
      }
      if (info.size > options.config.maxFileSizeBytes) {
        skipped.push({ filePath: rel, reason: "too-large" });
        continue;
      }
      files.push({ relPath: rel, absPath: abs, size: info.size, kind });
    }
  }

  files.sort((a, b) => (a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0));
  skipped.sort((a, b) => (a.filePath < b.filePath ? -1 : a.filePath > b.filePath ? 1 : 0));
  return { root, files, skipped, ignoredCount };
}

/** Relative posix path, or null if `abs` is not inside `root`. */
function toRel(root: string, abs: string): string | null {
  const rel = path.relative(root, abs);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return rel.split(path.sep).join("/");
}
