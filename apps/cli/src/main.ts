import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";
import {
  CONFIG_FILE_NAME,
  TOOL_VERSION,
  clearCache,
  defaultAnalyzers,
  defaultCacheDir,
  defaultRedactor,
  defaultRules,
  loadConfig,
  scan,
} from "@devgu/core";
import { REPORT_FORMATS, renderReport, type ReportFormat } from "@devgu/report-engine";
import { SEVERITIES, SeveritySchema, meetsThreshold, stripControlChars } from "@devgu/shared";

export interface Io {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  isTTY?: boolean;
  cwd?: string;
}

export const EXIT = { OK: 0, FINDINGS: 1, USAGE: 2, ERROR: 3, CANCELLED: 130 } as const;

const HELP = `devgu - deterministic code security and architecture analysis

Usage:
  devgu scan [path] [options]    Scan a directory (default: current directory)
  devgu rules list               List all rules
  devgu rules explain <id>       Explain a rule
  devgu config init              Create ${CONFIG_FILE_NAME}
  devgu cache clear              Delete the scan cache
  devgu version

Scan options:
  -f, --format <fmt>     ${REPORT_FORMATS.join(" | ")} (default: text)
  -o, --output <file>    Write the report to a file instead of stdout
      --security         Run only security (pattern + taint) rules
      --secrets          Run only secret detection
      --dependencies     Run only dependency vulnerability analysis
      --online           Query api.osv.dev for new vulnerability data (sends package names and versions only)
      --config <file>    Use a specific configuration file
      --fail-on <level>  Exit with 1 at or above: ${SEVERITIES.join(" | ")} (default: HIGH)
      --no-cache         Do not read or write the scan cache
  -q, --quiet            No progress output

Exit codes: 0 ok, 1 findings at/above --fail-on, 2 usage error, 3 runtime error, 130 cancelled.
`;

export async function main(argv: string[], io: Io, signal?: AbortSignal): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        format: { type: "string", short: "f" },
        output: { type: "string", short: "o" },
        security: { type: "boolean" },
        secrets: { type: "boolean" },
        dependencies: { type: "boolean" },
        online: { type: "boolean" },
        config: { type: "string" },
        "fail-on": { type: "string" },
        "no-cache": { type: "boolean" },
        quiet: { type: "boolean", short: "q" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n\n${HELP}`);
    return EXIT.USAGE;
  }
  const { values, positionals } = parsed;
  const [command, ...rest] = positionals;

  if (values.help || command === undefined) {
    io.stdout(HELP);
    return command === undefined && !values.help ? EXIT.USAGE : EXIT.OK;
  }

  try {
    switch (command) {
      case "version":
        io.stdout(`${TOOL_VERSION}\n`);
        return EXIT.OK;
      case "rules":
        return runRulesCommand(rest, io);
      case "cache":
        if (rest[0] !== "clear") return usage(io, "Usage: devgu cache clear");
        await clearCache();
        io.stdout(`Cache cleared (${defaultCacheDir()})\n`);
        return EXIT.OK;
      case "config":
        if (rest[0] !== "init") return usage(io, "Usage: devgu config init");
        return await configInit(io);
      case "scan":
        return await runScan(rest, values, io, signal);
      default:
        return usage(io, `Unknown command: ${stripControlChars(command)}`);
    }
  } catch (error) {
    if (signal?.aborted) {
      io.stderr("Cancelled\n");
      return EXIT.CANCELLED;
    }
    io.stderr(
      `error: ${stripControlChars(error instanceof Error ? error.message : String(error))}\n`,
    );
    return EXIT.ERROR;
  }
}

function usage(io: Io, message: string): number {
  io.stderr(`${message}\n`);
  return EXIT.USAGE;
}

function runRulesCommand(args: string[], io: Io): number {
  const rules = defaultRules();
  if (args[0] === "list") {
    const rows = rules
      .map((r) => r.meta)
      .sort((a, b) => a.id.localeCompare(b.id))
      .map(
        (m) =>
          `${m.id.padEnd(16)} ${m.severity.padEnd(8)} ${m.confidence.padEnd(6)} ${m.engine.padEnd(9)} ${m.name}`,
      );
    io.stdout(`${rows.join("\n")}\n${rules.length} rule(s)\n`);
    return EXIT.OK;
  }
  if (args[0] === "explain" && args[1]) {
    const rule = rules.find((r) => r.meta.id.toLowerCase() === args[1]?.toLowerCase());
    if (!rule) return usage(io, `Unknown rule: ${stripControlChars(args[1])}`);
    const m = rule.meta;
    io.stdout(
      [
        `${m.id}  ${m.name}`,
        `Engine: ${m.engine}   Category: ${m.category}   Severity: ${m.severity}   Confidence: ${m.confidence}`,
        "",
        m.description,
        "",
        `Remediation: ${m.remediation}`,
        `Limitations: ${m.limitations}`,
        ...(m.references.length ? ["References:", ...m.references.map((r) => `  ${r}`)] : []),
        "",
      ].join("\n"),
    );
    return EXIT.OK;
  }
  return usage(io, "Usage: devgu rules list | devgu rules explain <id>");
}

async function configInit(io: Io): Promise<number> {
  const target = path.join(io.cwd ?? process.cwd(), CONFIG_FILE_NAME);
  const template = {
    exclude: [],
    rules: {},
    maxFileSizeBytes: 1_000_000,
    maxFiles: 50_000,
    failOn: "HIGH",
    suppressions: [],
    secrets: { allowlist: [] },
  };
  try {
    await writeFile(target, JSON.stringify(template, null, 2) + "\n", { flag: "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      return usage(io, `${CONFIG_FILE_NAME} already exists`);
    throw error;
  }
  io.stdout(`Created ${target}\n`);
  return EXIT.OK;
}

type ScanValues = {
  format?: string;
  output?: string;
  security?: boolean;
  secrets?: boolean;
  dependencies?: boolean;
  online?: boolean;
  config?: string;
  "fail-on"?: string;
  "no-cache"?: boolean;
  quiet?: boolean;
};

async function runScan(
  args: string[],
  values: ScanValues,
  io: Io,
  signal?: AbortSignal,
): Promise<number> {
  if (args.length > 1) return usage(io, "Usage: devgu scan [path]");
  const format = (values.format ?? "text") as ReportFormat;
  if (!REPORT_FORMATS.includes(format))
    return usage(io, `Unknown format: ${stripControlChars(values.format ?? "")}`);
  const failOnParsed =
    values["fail-on"] === undefined
      ? undefined
      : SeveritySchema.safeParse(values["fail-on"].toUpperCase());
  if (failOnParsed && !failOnParsed.success)
    return usage(io, `Invalid --fail-on: ${stripControlChars(values["fail-on"] ?? "")}`);

  const root = path.resolve(io.cwd ?? process.cwd(), args[0] ?? ".");
  const config = await loadConfig({
    root,
    ...(values.config ? { configPath: path.resolve(io.cwd ?? process.cwd(), values.config) } : {}),
  });
  const failOn = failOnParsed?.success ? failOnParsed.data : config.failOn;

  const selected = [
    values.security && "security",
    values.secrets && "secrets",
    values.dependencies && "dependencies",
  ].filter((x): x is string => typeof x === "string");
  const engineMatches = (engine: string): boolean =>
    selected.length === 0 || selected.includes(engine === "taint" ? "security" : engine);
  const rules = defaultRules().filter((r) => engineMatches(r.meta.engine));
  const analyzers = defaultAnalyzers({ online: values.online === true }).filter((a) =>
    engineMatches(a.name),
  );

  const showProgress = !values.quiet && io.isTTY === true && format !== "text";
  const result = await scan({
    root,
    rules,
    config,
    analyzers,
    redact: defaultRedactor(),
    useCache: !values["no-cache"],
    ...(signal ? { signal } : {}),
    ...(showProgress
      ? {
          onProgress: (p: { done: number; total: number }) =>
            io.stderr(`\rScanning ${p.done}/${p.total}`),
        }
      : {}),
  });
  if (showProgress) io.stderr("\r\u001b[K");

  const report = renderReport(format, result, { color: io.isTTY === true && !values.output });
  if (values.output) {
    const target = path.resolve(io.cwd ?? process.cwd(), values.output);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, report);
    if (!values.quiet) io.stderr(`Report written to ${target}\n`);
  } else {
    io.stdout(report);
  }
  return result.findings.some((f) => meetsThreshold(f.severity, failOn)) ? EXIT.FINDINGS : EXIT.OK;
}
