import { open } from "node:fs/promises";
import path from "node:path";
import { createSourceFile } from "@devgu/parser";
import { isRuleEnabled, rulesetFingerprint, runRules, type Rule } from "@devgu/rule-engine";
import {
  DEFAULT_LANG,
  SEVERITIES,
  TOOL_VERSION,
  sha256Hex,
  type Diagnostic,
  type Finding,
  type Lang,
  type ScanResult,
  type SkippedFile,
} from "@devgu/shared";
import { ScanCache, defaultCacheDir } from "./cache.js";
import { defaultConfig, type DevguConfig } from "./config.js";
import { discoverFiles, type DiscoveredFile } from "./discovery.js";
import {
  applyConfigSuppressions,
  applyInlineSuppressions,
  dedupe,
  redactFinding,
  sortFindings,
} from "./postprocess.js";

/** A whole-project analysis that is not tied to a single file (e.g. dependency audit). */
export interface ProjectAnalyzer {
  name: string;
  run(context: {
    root: string;
    files: readonly DiscoveredFile[];
    lang: Lang;
    signal?: AbortSignal;
  }): Promise<{ findings: Finding[]; diagnostics: Diagnostic[] }>;
}

export interface ScanOptions {
  root: string;
  rules: readonly Rule[];
  config?: DevguConfig;
  analyzers?: readonly ProjectAnalyzer[];
  /** Language for all human-readable finding and report text. Defaults to English. */
  lang?: Lang;
  /** Removes secrets from any text that ends up in a finding. */
  redact?: (text: string) => string;
  useCache?: boolean;
  cacheDir?: string;
  signal?: AbortSignal;
  onProgress?: (progress: { done: number; total: number; file: string }) => void;
}

const BINARY_SNIFF_BYTES = 8000;
const MAX_LINE_LENGTH = 20_000;

async function readTextFile(file: DiscoveredFile): Promise<string | SkippedFile["reason"]> {
  let handle;
  try {
    handle = await open(file.absPath, "r");
    const buffer = Buffer.alloc(file.size);
    const { bytesRead } = await handle.read(buffer, 0, file.size, 0);
    const data = buffer.subarray(0, bytesRead);
    if (data.subarray(0, BINARY_SNIFF_BYTES).includes(0)) return "binary";
    const text = data.toString("utf8").replace(/^\uFEFF/, "");
    let longest = 0;
    let current = 0;
    for (let i = 0; i < text.length; i += 1) {
      if (text.charCodeAt(i) === 10) {
        longest = Math.max(longest, current);
        current = 0;
      } else current += 1;
    }
    return Math.max(longest, current) > MAX_LINE_LENGTH ? "minified-or-generated" : text;
  } catch {
    return "unreadable";
  } finally {
    await handle?.close();
  }
}

export async function scan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = performance.now();
  const config = options.config ?? defaultConfig();
  const redact = options.redact ?? ((text: string) => text);
  const settings = config.rules;
  const lang = options.lang ?? DEFAULT_LANG;
  const activeRules = options.rules.filter((rule) => isRuleEnabled(rule.meta, settings));

  const discovery = await discoverFiles({
    root: options.root,
    config,
    ...(options.signal ? { signal: options.signal } : {}),
  });
  const configKey = sha256Hex(
    `${TOOL_VERSION}|${lang}|${rulesetFingerprint(options.rules, settings)}|${config.secrets.allowlist.join(",")}`,
  ).slice(0, 32);
  const cache =
    options.useCache === false
      ? null
      : new ScanCache(options.cacheDir ?? defaultCacheDir(), discovery.root, configKey);
  await cache?.load();

  const findings: Finding[] = [];
  const diagnostics: Diagnostic[] = [];
  const skipped: SkippedFile[] = [...discovery.skipped];
  let cacheHits = 0;
  let cacheMisses = 0;
  let filesScanned = 0;
  let parseMs = 0;
  let ruleMs = 0;

  for (const [index, file] of discovery.files.entries()) {
    if (options.signal?.aborted) throw new Error("Scan cancelled");
    options.onProgress?.({ done: index, total: discovery.files.length, file: file.relPath });
    const content = await readTextFile(file);
    if (content === "binary" || content === "minified-or-generated" || content === "unreadable") {
      skipped.push({ filePath: file.relPath, reason: content });
      continue;
    }
    filesScanned += 1;
    const hash = sha256Hex(content);
    const cached = cache?.get(file.relPath, hash);
    if (cached) {
      cacheHits += 1;
      findings.push(...cached);
      continue;
    }
    cacheMisses += 1;

    const parseStart = performance.now();
    const source =
      file.kind === "script"
        ? createSourceFile(file.relPath, content)
        : createSourceFile(`${file.relPath}.txt`, content);
    // Text files keep their real path in findings; the ".txt" suffix only prevents parsing.
    const sourceFile = file.kind === "script" ? source : { ...source, relPath: file.relPath };
    parseMs += performance.now() - parseStart;
    if (sourceFile.parseError) {
      diagnostics.push({
        source: "parser",
        filePath: file.relPath,
        message: `Could not parse: ${sourceFile.parseError}`,
      });
    }

    const ruleStart = performance.now();
    const run = runRules(sourceFile, activeRules, settings, lang);
    ruleMs += performance.now() - ruleStart;
    diagnostics.push(...run.diagnostics);

    const processed = applyInlineSuppressions(
      run.findings.map((finding) => redactFinding(finding, redact)),
      sourceFile,
    );
    cache?.set(file.relPath, hash, processed);
    findings.push(...processed);
  }
  options.onProgress?.({ done: discovery.files.length, total: discovery.files.length, file: "" });

  if (cache) {
    cache.retainOnly(new Set(discovery.files.map((f) => f.relPath)));
    await cache.save().catch((error: unknown) => {
      diagnostics.push({
        source: "cache",
        message: `Cache not saved: ${error instanceof Error ? error.message : String(error)}`,
      });
    });
  }

  for (const analyzer of options.analyzers ?? []) {
    try {
      const result = await analyzer.run({
        root: discovery.root,
        files: discovery.files,
        lang,
        ...(options.signal ? { signal: options.signal } : {}),
      });
      findings.push(...result.findings.map((finding) => redactFinding(finding, redact)));
      diagnostics.push(...result.diagnostics);
    } catch (error) {
      diagnostics.push({
        source: analyzer.name,
        message: `Analyzer failed: ${error instanceof Error ? error.message : String(error)}`,
      });
    }
  }

  const finalized = sortFindings(
    dedupe(
      applyConfigSuppressions(findings, [
        ...config.suppressions,
        ...config.secrets.allowlist.map((fingerprint) => ({
          fingerprint,
          justification: "Allowlisted in configuration",
        })),
      ]),
    ),
  );
  const open = finalized.filter((f) => f.status === "open");
  const suppressed = finalized.filter((f) => f.status === "suppressed");
  const findingsBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
    (typeof SEVERITIES)[number],
    number
  >;
  for (const finding of open) findingsBySeverity[finding.severity] += 1;

  return {
    meta: {
      tool: "devgu",
      toolVersion: TOOL_VERSION,
      rulesetVersion: rulesetFingerprint(options.rules, settings),
      lang,
      scannedAt: new Date().toISOString(),
      rootName: path.basename(discovery.root) || "root",
      engines: [
        ...new Set(activeRules.map((r) => r.meta.engine)),
        ...(options.analyzers ?? []).map((a) => a.name),
      ].sort(),
      enabledRules: activeRules.map((r) => r.meta.id).sort(),
    },
    findings: open,
    suppressed,
    skipped,
    diagnostics,
    stats: {
      filesDiscovered: discovery.files.length,
      filesScanned,
      filesSkipped: skipped.length,
      cacheHits,
      cacheMisses,
      parseMs: Math.round(parseMs),
      ruleMs: Math.round(ruleMs),
      totalMs: Math.round(performance.now() - startedAt),
      heapUsedMb: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
      findingsBySeverity,
    },
  };
}
