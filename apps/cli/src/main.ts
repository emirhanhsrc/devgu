import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import os from "node:os";
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
  ruleCatalog,
  scan,
} from "@devgu/core";
import {
  EDITOR_SCHEMES,
  REPORT_FORMATS,
  renderReport,
  type EditorScheme,
  type ReportFormat,
  type RuleDescriptor,
} from "@devgu/report-engine";
import {
  DEFAULT_LANG,
  SEVERITIES,
  SeveritySchema,
  isLang,
  loc,
  meetsThreshold,
  messages,
  stripControlChars,
  type Lang,
} from "@devgu/shared";

export interface Io {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  isTTY?: boolean;
  cwd?: string;
}

export const EXIT = { OK: 0, FINDINGS: 1, USAGE: 2, ERROR: 3, CANCELLED: 130 } as const;

const HELP_EN = `devgu - deterministic code security and architecture analysis

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
      --editor <name>    HTML: make file:line clickable in vscode | vscode-insiders | cursor | windsurf
                         (embeds the local project path; default with --open: vscode)
      --open             Write an HTML report and open it in the default browser
      --lang <tr|en>     Output language for findings and reports (default: en)
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

const HELP_TR = `devgu - deterministik kod güvenliği ve mimari analizi

Kullanım:
  devgu scan [yol] [seçenekler]  Bir dizini tara (varsayılan: geçerli dizin)
  devgu rules list               Tüm kuralları listele
  devgu rules explain <id>       Bir kuralı açıkla
  devgu config init              ${CONFIG_FILE_NAME} oluştur
  devgu cache clear              Tarama önbelleğini sil
  devgu version

Tarama seçenekleri:
  -f, --format <biçim>   ${REPORT_FORMATS.join(" | ")} (varsayılan: text)
  -o, --output <dosya>   Raporu stdout yerine bir dosyaya yaz
      --editor <ad>      HTML: dosya:satır tıklanınca editörde aç (vscode | vscode-insiders | cursor | windsurf)
                         (yerel proje yolunu rapora gömer; --open ile varsayılan: vscode)
      --open             HTML raporu yaz ve varsayılan tarayıcıda aç
      --lang <tr|en>     Bulgu ve raporların dili (varsayılan: en)
      --security         Yalnızca güvenlik (desen + taint) kurallarını çalıştır
      --secrets          Yalnızca gizli anahtar taraması
      --dependencies     Yalnızca bağımlılık zafiyet analizi
      --online           Yeni zafiyet verisi için api.osv.dev'i sorgula (yalnızca paket adı ve sürümü gönderilir)
      --config <dosya>   Belirli bir yapılandırma dosyası kullan
      --fail-on <düzey>  Şu düzey ve üstünde 1 ile çık: ${SEVERITIES.join(" | ")} (varsayılan: HIGH)
      --no-cache         Tarama önbelleğini okuma veya yazma
  -q, --quiet            İlerleme çıktısı yok

Çıkış kodları: 0 tamam, 1 --fail-on ve üstü bulgular, 2 kullanım hatası, 3 çalışma hatası, 130 iptal.
`;

function helpText(lang: Lang): string {
  return lang === "tr" ? HELP_TR : HELP_EN;
}

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
        lang: { type: "string" },
        open: { type: "boolean" },
        editor: { type: "string" },
        quiet: { type: "boolean", short: "q" },
        help: { type: "boolean", short: "h" },
      },
    });
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : String(error)}\n\n${HELP_EN}`);
    return EXIT.USAGE;
  }
  const { values, positionals } = parsed;
  const [command, ...rest] = positionals;

  // CLI-level language (flag only; scan additionally honours devgu.config.json).
  const flagLang = values.lang?.toLowerCase();
  if (flagLang !== undefined && !isLang(flagLang)) {
    io.stderr(`${messages(DEFAULT_LANG).cli.unknownLang(values.lang ?? "")}\n`);
    return EXIT.USAGE;
  }
  const cliLang: Lang = isLang(flagLang) ? flagLang : DEFAULT_LANG;

  if (values.help || command === undefined) {
    io.stdout(helpText(cliLang));
    return command === undefined && !values.help ? EXIT.USAGE : EXIT.OK;
  }

  try {
    switch (command) {
      case "version":
        io.stdout(`${TOOL_VERSION}\n`);
        return EXIT.OK;
      case "rules":
        return runRulesCommand(rest, io, cliLang);
      case "cache":
        if (rest[0] !== "clear") return usage(io, "Usage: devgu cache clear");
        await clearCache();
        io.stdout(`${messages(cliLang).cli.cacheCleared(defaultCacheDir())}\n`);
        return EXIT.OK;
      case "config":
        if (rest[0] !== "init") return usage(io, "Usage: devgu config init");
        return await configInit(io, cliLang);
      case "scan":
        return await runScan(rest, values, io, cliLang, signal);
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

function runRulesCommand(args: string[], io: Io, lang: Lang): number {
  const tr = lang === "tr";
  const rules = ruleCatalog();
  if (args[0] === "list") {
    const rows = rules.map(
      (m) =>
        `${m.id.padEnd(16)} ${m.severity.padEnd(8)} ${m.confidence.padEnd(6)} ${m.engine.padEnd(9)} ${loc(m.name, lang)}`,
    );
    io.stdout(`${rows.join("\n")}\n${rules.length} ${tr ? "kural" : "rule(s)"}\n`);
    return EXIT.OK;
  }
  if (args[0] === "explain" && args[1]) {
    const rule = rules.find((r) => r.id.toLowerCase() === args[1]?.toLowerCase());
    if (!rule)
      return usage(
        io,
        `${tr ? "Bilinmeyen kural" : "Unknown rule"}: ${stripControlChars(args[1])}`,
      );
    const m = rule;
    io.stdout(
      [
        `${m.id}  ${loc(m.name, lang)}`,
        tr
          ? `Motor: ${m.engine}   Kategori: ${m.category}   Şiddet: ${m.severity}   Güven: ${m.confidence}`
          : `Engine: ${m.engine}   Category: ${m.category}   Severity: ${m.severity}   Confidence: ${m.confidence}`,
        "",
        loc(m.description, lang),
        "",
        `${tr ? "Çözüm" : "Remediation"}: ${loc(m.remediation, lang)}`,
        `${tr ? "Sınırlamalar" : "Limitations"}: ${loc(m.limitations, lang)}`,
        ...(m.references.length
          ? [`${tr ? "Kaynaklar" : "References"}:`, ...m.references.map((r) => `  ${r}`)]
          : []),
        "",
      ].join("\n"),
    );
    return EXIT.OK;
  }
  return usage(io, "Usage: devgu rules list | devgu rules explain <id>");
}

async function configInit(io: Io, lang: Lang): Promise<number> {
  const tr = lang === "tr";
  const target = path.join(io.cwd ?? process.cwd(), CONFIG_FILE_NAME);
  const template = {
    exclude: [],
    rules: {},
    maxFileSizeBytes: 1_000_000,
    maxFiles: 50_000,
    failOn: "HIGH",
    lang,
    suppressions: [],
    secrets: { allowlist: [] },
  };
  try {
    await writeFile(target, JSON.stringify(template, null, 2) + "\n", { flag: "wx" });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST")
      return usage(io, `${CONFIG_FILE_NAME} ${tr ? "zaten var" : "already exists"}`);
    throw error;
  }
  io.stdout(`${tr ? "Oluşturuldu" : "Created"} ${target}\n`);
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
  lang?: string;
  open?: boolean;
  editor?: string;
  quiet?: boolean;
};

/** Rule metadata resolved to plain strings in `lang`, for SARIF rule descriptors. */
function localizedCatalog(lang: Lang): RuleDescriptor[] {
  return ruleCatalog().map((m) => ({
    id: m.id,
    name: loc(m.name, lang),
    description: loc(m.description, lang),
    remediation: loc(m.remediation, lang),
    limitations: loc(m.limitations, lang),
    references: m.references,
    severity: m.severity,
    category: m.category,
  }));
}

function openInBrowser(file: string): void {
  const [cmd, args]: [string, string[]] =
    process.platform === "darwin"
      ? ["open", [file]]
      : process.platform === "win32"
        ? ["cmd", ["/c", "start", "", file]]
        : ["xdg-open", [file]];
  const child = spawn(cmd, args, { stdio: "ignore", detached: true });
  child.on("error", () => undefined);
  child.unref();
}

async function runScan(
  args: string[],
  values: ScanValues,
  io: Io,
  cliLang: Lang,
  signal?: AbortSignal,
): Promise<number> {
  if (args.length > 1) return usage(io, "Usage: devgu scan [path]");
  const format = (values.format ?? (values.open ? "html" : "text")) as ReportFormat;
  if (!REPORT_FORMATS.includes(format))
    return usage(io, `Unknown format: ${stripControlChars(values.format ?? "")}`);
  const failOnParsed =
    values["fail-on"] === undefined
      ? undefined
      : SeveritySchema.safeParse(values["fail-on"].toUpperCase());
  if (failOnParsed && !failOnParsed.success)
    return usage(io, `Invalid --fail-on: ${stripControlChars(values["fail-on"] ?? "")}`);

  const editorName = values.editor ?? (values.open ? "vscode" : undefined);
  if (editorName !== undefined && !(EDITOR_SCHEMES as readonly string[]).includes(editorName))
    return usage(io, `Unknown editor: ${stripControlChars(editorName)}`);

  const root = path.resolve(io.cwd ?? process.cwd(), args[0] ?? ".");
  const config = await loadConfig({
    root,
    ...(values.config ? { configPath: path.resolve(io.cwd ?? process.cwd(), values.config) } : {}),
  });
  const failOn = failOnParsed?.success ? failOnParsed.data : config.failOn;
  // Flag wins; otherwise the config's language; otherwise the default.
  const lang: Lang = values.lang !== undefined ? cliLang : (config.lang ?? DEFAULT_LANG);

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
  const scanningWord = messages(lang).cli.scanning;
  const result = await scan({
    root,
    rules,
    config,
    analyzers,
    lang,
    redact: defaultRedactor(),
    useCache: !values["no-cache"],
    ...(signal ? { signal } : {}),
    ...(showProgress
      ? {
          onProgress: (p: { done: number; total: number }) =>
            io.stderr(`\r${scanningWord} ${p.done}/${p.total}`),
        }
      : {}),
  });
  if (showProgress) io.stderr("\r\u001b[K");

  const report = renderReport(format, result, {
    color: io.isTTY === true && !values.output && !values.open,
    rules: localizedCatalog(lang),
    ...(editorName ? { editor: { scheme: editorName as EditorScheme, root } } : {}),
  });
  const outputPath =
    values.output ??
    (values.open ? path.join(os.tmpdir(), `devgu-report-${Date.now()}.html`) : undefined);
  if (outputPath) {
    const target = path.resolve(io.cwd ?? process.cwd(), outputPath);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, report);
    if (!values.quiet)
      io.stderr(`${lang === "tr" ? "Rapor yazıldı" : "Report written to"} ${target}\n`);
    if (values.open) openInBrowser(target);
  } else {
    io.stdout(report);
  }
  return result.findings.some((f) => meetsThreshold(f.severity, failOn)) ? EXIT.FINDINGS : EXIT.OK;
}
