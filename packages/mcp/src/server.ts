import { mkdir, realpath, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createInterface } from "node:readline";
import type { Readable, Writable } from "node:stream";
import {
  TOOL_VERSION,
  defaultAnalyzers,
  defaultRedactor,
  defaultRules,
  loadConfig,
  ruleCatalog,
  scan,
} from "@devgu/core";
import { renderReport, type ReportFormat } from "@devgu/report-engine";
import {
  SEVERITIES,
  isLang,
  loc,
  meetsThreshold,
  stripControlChars,
  type Lang,
  type ScanResult,
  type Severity,
} from "@devgu/shared";
import { WEB_RULES, scanUrl } from "@devgu/web-scan";

export interface McpOptions {
  input: Readable;
  output: Writable;
  /** Directories the server may scan or write into. Defaults to the working directory. */
  roots?: string[];
  log?: (text: string) => void;
}

interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

const LANG_PROP = {
  type: "string",
  enum: ["en", "tr"],
  description: "Language of the findings (default en).",
};
const SEVERITY_PROP = {
  type: "string",
  enum: [...SEVERITIES],
  description: "Only report findings at or above this severity (default LOW).",
};

const TOOLS = [
  {
    name: "scan_project",
    description:
      "Scan a local project directory for security problems (XSS and other taint flows, hard-coded secrets, insecure endpoints, vulnerable dependencies). Deterministic and offline; no code leaves the machine. Returns findings with file:line, evidence (secrets masked) and how to fix each.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Directory to scan, absolute or relative to the server's root.",
        },
        lang: LANG_PROP,
        min_severity: SEVERITY_PROP,
        max_findings: { type: "number", description: "Maximum findings to list (default 30)." },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_url",
    description:
      "Passively scan a deployed website: downloads the page and its same-host JavaScript, recovers source maps if they are public, runs the same rules over them and checks security headers and exposed files (.env, .git). Only use on sites the user owns or is authorised to test.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", description: "http(s) URL of the page to scan." },
        authorized: {
          type: "boolean",
          description:
            "Must be true: the user has confirmed they own this site or are authorised to scan it.",
        },
        lang: LANG_PROP,
        min_severity: SEVERITY_PROP,
        max_findings: { type: "number" },
      },
      required: ["url", "authorized"],
    },
  },
  {
    name: "explain_rule",
    description: "Explain a DEVGU rule: what it detects, how to fix it, and what it cannot detect.",
    inputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Rule id, e.g. JS-XSS-001." },
        lang: LANG_PROP,
      },
      required: ["id"],
    },
  },
  {
    name: "list_rules",
    description: "List every DEVGU rule with its severity, confidence and engine.",
    inputSchema: { type: "object", properties: { lang: LANG_PROP } },
  },
  {
    name: "generate_report",
    description:
      "Scan a project directory or (with authorized=true) a URL and write a full report file. Returns the file path. html is a self-contained interactive page.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Directory to scan (use this or url)." },
        url: { type: "string" },
        authorized: { type: "boolean" },
        format: { type: "string", enum: ["html", "md", "json"], description: "Default html." },
        lang: LANG_PROP,
        output: {
          type: "string",
          description: "Output file inside an allowed root. Default: a temp file.",
        },
      },
    },
  },
];

function asLang(value: unknown): Lang {
  return isLang(value) ? value : "en";
}

function asString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`"${name}" is required`);
  return value;
}

function summarize(result: ScanResult, lang: Lang, min: Severity, max: number): string {
  const tr = lang === "tr";
  const shown = result.findings.filter((f) => meetsThreshold(f.severity, min));
  const s = result.stats.findingsBySeverity;
  const counts = SEVERITIES.filter((sev) => s[sev] > 0)
    .map((sev) => `${s[sev]} ${sev}`)
    .join(", ");
  const lines = [
    `DEVGU ${TOOL_VERSION} · ${result.meta.rootName} · ${tr ? "bulgu" : "findings"}: ${result.findings.length}${counts ? ` (${counts})` : ""} · ${result.stats.filesScanned} ${tr ? "dosya" : "files"}`,
  ];
  shown.slice(0, max).forEach((f, i) => {
    lines.push(
      "",
      `${i + 1}. [${f.severity}/${f.confidence}] ${f.ruleId}  ${f.filePath}:${f.startLine}`,
      `   ${f.title}`,
      `   ${tr ? "kanıt" : "evidence"}: ${f.evidence.slice(0, 160)}`,
      `   ${tr ? "çözüm" : "fix"}: ${f.remediation}`,
    );
  });
  if (shown.length > max)
    lines.push(
      "",
      tr
        ? `… ${shown.length - max} bulgu daha (max_findings artırın).`
        : `… ${shown.length - max} more (raise max_findings).`,
    );
  if (shown.length === 0)
    lines.push(
      "",
      tr
        ? "Bu eşikte bulgu yok. Bu, kodun güvenli olduğunu kanıtlamaz."
        : "No findings at this threshold. This does not prove the code is safe.",
    );
  for (const d of result.diagnostics.slice(0, 5))
    lines.push(`note: ${stripControlChars(d.message)}`);
  return lines.join("\n");
}

export async function runMcpServer(options: McpOptions): Promise<void> {
  const log = options.log ?? (() => undefined);
  const rootsInput = options.roots && options.roots.length > 0 ? options.roots : [process.cwd()];
  const roots = await Promise.all(rootsInput.map((r) => realpath(path.resolve(r))));

  const within = (target: string): boolean =>
    roots.some((root) => {
      const rel = path.relative(root, target);
      return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
    });

  async function resolveDir(input: string): Promise<string> {
    const outside = new Error(
      `Path is outside the allowed roots (${roots.join(", ")}). Set DEVGU_MCP_ROOTS to allow more.`,
    );
    // Check the lexical path first (so nothing is probed outside the roots), then the real path
    // to catch symlinks that point out of them.
    const lexical = path.resolve(roots[0] as string, input);
    if (!within(lexical)) throw outside;
    const resolved = await realpath(lexical);
    if (!within(resolved)) throw outside;
    return resolved;
  }

  async function runScan(args: Record<string, unknown>): Promise<ScanResult> {
    const lang = asLang(args.lang);
    if (typeof args.url === "string" && args.url) {
      if (args.authorized !== true)
        throw new Error(
          "Refusing to scan a URL without authorized=true. Ask the user to confirm they own the site or are authorised to test it.",
        );
      return scanUrl({ url: args.url, lang });
    }
    const root = await resolveDir(asString(args.path, "path"));
    const config = await loadConfig({ root });
    return scan({
      root,
      rules: defaultRules(),
      config,
      analyzers: defaultAnalyzers({ online: false }),
      lang,
      redact: defaultRedactor(),
      useCache: false,
    });
  }

  async function callTool(name: string, args: Record<string, unknown>): Promise<string> {
    const lang = asLang(args.lang);
    const min = (SEVERITIES as readonly string[]).includes(args.min_severity as string)
      ? (args.min_severity as Severity)
      : "LOW";
    const max =
      typeof args.max_findings === "number" ? Math.max(1, Math.min(200, args.max_findings)) : 30;
    switch (name) {
      case "scan_project":
        return summarize(await runScan(args), lang, min, max);
      case "scan_url":
        return summarize(await runScan({ ...args, path: undefined }), lang, min, max);
      case "list_rules":
        return [...ruleCatalog(), ...WEB_RULES]
          .map(
            (m) =>
              `${m.id.padEnd(16)} ${m.severity.padEnd(8)} ${m.confidence.padEnd(6)} ${m.engine.padEnd(9)} ${loc(m.name, lang)}`,
          )
          .join("\n");
      case "explain_rule": {
        const id = asString(args.id, "id").toUpperCase();
        const meta = [...ruleCatalog(), ...WEB_RULES].find((m) => m.id === id);
        if (!meta) throw new Error(`Unknown rule: ${stripControlChars(id)}`);
        return [
          `${meta.id}  ${loc(meta.name, lang)}`,
          `${meta.severity} / ${meta.confidence} confidence · ${meta.engine} · ${meta.category}`,
          "",
          loc(meta.description, lang),
          "",
          `${lang === "tr" ? "Çözüm" : "Remediation"}: ${loc(meta.remediation, lang)}`,
          `${lang === "tr" ? "Sınırlamalar" : "Limitations"}: ${loc(meta.limitations, lang)}`,
          ...(meta.references.length ? ["", ...meta.references] : []),
        ].join("\n");
      }
      case "generate_report": {
        const result = await runScan(args);
        const format = (
          ["html", "md", "json"].includes(args.format as string) ? args.format : "html"
        ) as ReportFormat;
        let target: string;
        if (typeof args.output === "string" && args.output) {
          target = path.resolve(roots[0] as string, args.output);
          if (!within(path.dirname(target)))
            throw new Error("output must be inside an allowed root");
        } else {
          const dir = path.join(os.tmpdir(), "devgu-reports");
          await mkdir(dir, { recursive: true });
          target = path.join(dir, `devgu-report-${Date.now()}.${format}`);
        }
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, renderReport(format, result, { color: false }));
        return `${summarize(result, lang, min, 5)}\n\nReport written to ${target}`;
      }
      default:
        throw new Error(`Unknown tool: ${stripControlChars(name)}`);
    }
  }

  const send = (message: unknown): void =>
    void options.output.write(`${JSON.stringify(message)}\n`);

  async function handle(message: {
    id?: number | string;
    method?: string;
    params?: Record<string, unknown>;
  }): Promise<void> {
    const { id, method, params } = message;
    if (method === undefined) return;
    if (id === undefined) return; // notification (e.g. notifications/initialized)
    try {
      switch (method) {
        case "initialize":
          send({
            jsonrpc: "2.0",
            id,
            result: {
              protocolVersion:
                typeof params?.protocolVersion === "string" ? params.protocolVersion : "2025-06-18",
              capabilities: { tools: {} },
              serverInfo: { name: "devgu", version: TOOL_VERSION },
              instructions:
                "DEVGU is a local, deterministic security scanner. Use scan_project for a directory; scan_url only for sites the user owns or is authorised to test.",
            },
          });
          return;
        case "ping":
          send({ jsonrpc: "2.0", id, result: {} });
          return;
        case "tools/list":
          send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
          return;
        case "tools/call": {
          let result: ToolResult;
          try {
            const text = await callTool(
              asString(params?.name, "name"),
              (params?.arguments as Record<string, unknown>) ?? {},
            );
            result = { content: [{ type: "text", text }] };
          } catch (error) {
            result = {
              isError: true,
              content: [
                {
                  type: "text",
                  text: stripControlChars(error instanceof Error ? error.message : String(error)),
                },
              ],
            };
          }
          send({ jsonrpc: "2.0", id, result });
          return;
        }
        default:
          send({
            jsonrpc: "2.0",
            id,
            error: { code: -32601, message: `Method not found: ${method}` },
          });
      }
    } catch (error) {
      send({
        jsonrpc: "2.0",
        id,
        error: { code: -32603, message: error instanceof Error ? error.message : String(error) },
      });
    }
  }

  log(`devgu MCP server ${TOOL_VERSION} ready; roots: ${roots.join(", ")}\n`);
  const rl = createInterface({ input: options.input });
  const pending: Promise<void>[] = [];
  rl.on("line", (line) => {
    if (!line.trim()) return;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
      return;
    }
    pending.push(handle(parsed));
  });
  await new Promise<void>((resolve) => rl.once("close", resolve));
  await Promise.all(pending);
}
