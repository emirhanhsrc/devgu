import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { SeveritySchema } from "@devgu/shared";
import { z } from "zod";

export const CONFIG_FILE_NAME = "devgu.config.json";
const MAX_CONFIG_BYTES = 256 * 1024;

export const DEFAULT_EXCLUDED_DIRS = [
  "node_modules",
  "dist",
  "build",
  "coverage",
  ".git",
  ".next",
  "vendor",
  "target",
  ".idea",
  ".vscode",
  ".devgu-cache",
] as const;

export const ConfigSchema = z
  .object({
    /** Glob patterns (picomatch syntax) relative to the scan root. */
    exclude: z.array(z.string().min(1).max(200)).max(100).default([]),
    rules: z
      .record(
        z.string().max(100),
        z.object({ enabled: z.boolean().optional(), severity: SeveritySchema.optional() }).strict(),
      )
      .default({}),
    maxFileSizeBytes: z.number().int().min(1024).max(10_000_000).default(1_000_000),
    maxFiles: z.number().int().min(1).max(500_000).default(50_000),
    /** Lowest severity that makes the CLI exit with code 1. */
    failOn: SeveritySchema.default("HIGH"),
    suppressions: z
      .array(
        z
          .object({
            fingerprint: z.string().min(8).max(64),
            justification: z.string().trim().min(3).max(500),
          })
          .strict(),
      )
      .max(1000)
      .default([]),
    secrets: z
      .object({ allowlist: z.array(z.string().min(8).max(64)).max(1000).default([]) })
      .strict()
      .default({}),
  })
  .strict();

export type DevguConfig = z.infer<typeof ConfigSchema>;

export function defaultConfig(): DevguConfig {
  return ConfigSchema.parse({});
}

/**
 * Loads configuration. The file is data only (JSON, strict schema, size limited): a hostile
 * repository can at worst narrow its own scan, never execute code or reach outside the root.
 * Returns the defaults when no file exists. Throws a readable Error on invalid configuration.
 */
export async function loadConfig(options: {
  root: string;
  configPath?: string;
}): Promise<DevguConfig> {
  const explicit = options.configPath !== undefined;
  const file = path.resolve(options.configPath ?? path.join(options.root, CONFIG_FILE_NAME));
  let info;
  try {
    info = await lstat(file);
  } catch {
    if (explicit) throw new Error(`Config file not found: ${file}`);
    return defaultConfig();
  }
  if (info.isSymbolicLink() || !info.isFile()) {
    throw new Error(`Config must be a regular file: ${file}`);
  }
  if (info.size > MAX_CONFIG_BYTES)
    throw new Error(`Config file is too large (> ${MAX_CONFIG_BYTES} bytes)`);
  let raw: unknown;
  try {
    raw = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(
      `Config is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`);
    throw new Error(`Invalid config: ${issues.join("; ")}`);
  }
  return parsed.data;
}
