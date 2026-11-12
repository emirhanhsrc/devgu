import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { defaultConfig, defaultRedactor, defaultRules, scan, sortFindings } from "@devgu/core";
import type { RuleMeta } from "@devgu/rule-engine";
import {
  DEFAULT_LANG,
  SEVERITIES,
  TOOL_VERSION,
  fingerprint,
  loc,
  type Diagnostic,
  type Finding,
  type Lang,
  type ScanResult,
} from "@devgu/shared";
import { httpGet, isDisallowed, parseRobots, type HttpOptions } from "./http.js";
import { prettifyMinified } from "./prettify.js";
import { WEB_RULES } from "./rules.js";

export interface ScanUrlOptions {
  url: string;
  lang?: Lang;
  signal?: AbortSignal;
  /** Maximum number of same-host scripts to download. */
  maxResources?: number;
  /** Total download budget in bytes. */
  maxTotalBytes?: number;
  /** Try to download source maps and scan the recovered original sources. */
  sourceMaps?: boolean;
  /** Probe a few well-known sensitive paths (.env, .git). */
  probeSensitivePaths?: boolean;
}

const rule = (id: string): RuleMeta => WEB_RULES.find((r) => r.id === id) as RuleMeta;
const SCRIPT_EXT = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".json"]);
const MAX_SOURCEMAP_BYTES = 30 * 1024 * 1024;
const MAX_RECOVERED_FILES = 800;
const MAX_RECOVERED_FILE_BYTES = 1_000_000;
const CONCURRENCY = 4;

function makeFinding(
  meta: RuleMeta,
  lang: Lang,
  filePath: string,
  evidence: string,
  material = evidence,
): Finding {
  const print = fingerprint(meta.id, filePath, material);
  return {
    id: `${meta.id}-${print.slice(0, 8)}-L1`,
    ruleId: meta.id,
    engine: meta.engine,
    title: loc(meta.name, lang),
    description: loc(meta.description, lang),
    severity: meta.severity,
    confidence: meta.confidence,
    category: meta.category,
    filePath,
    startLine: 1,
    endLine: 1,
    evidence,
    remediation: loc(meta.remediation, lang),
    references: meta.references,
    limitations: loc(meta.limitations, lang),
    fingerprint: print,
    status: "open",
  };
}

function headerFindings(headers: Headers, pageUrl: string, lang: Lang): Finding[] {
  const out: Finding[] = [];
  const csp = headers.get("content-security-policy");
  if (!csp)
    out.push(makeFinding(rule("WEB-HDR-001"), lang, pageUrl, "Content-Security-Policy: (absent)"));
  if (new URL(pageUrl).protocol === "https:" && !headers.get("strict-transport-security"))
    out.push(
      makeFinding(rule("WEB-HDR-002"), lang, pageUrl, "Strict-Transport-Security: (absent)"),
    );
  if (!/nosniff/i.test(headers.get("x-content-type-options") ?? ""))
    out.push(makeFinding(rule("WEB-HDR-003"), lang, pageUrl, "X-Content-Type-Options: (absent)"));
  if (!headers.get("x-frame-options") && !/frame-ancestors/i.test(csp ?? ""))
    out.push(
      makeFinding(
        rule("WEB-HDR-004"),
        lang,
        pageUrl,
        "X-Frame-Options / frame-ancestors: (absent)",
      ),
    );
  const server = headers.get("server") ?? "";
  const powered = headers.get("x-powered-by");
  const disclosure = [
    /\d/.test(server) ? `Server: ${server}` : "",
    powered ? `X-Powered-By: ${powered}` : "",
  ]
    .filter(Boolean)
    .join("; ");
  if (disclosure) out.push(makeFinding(rule("WEB-HDR-005"), lang, pageUrl, disclosure));
  return out;
}

function attrOf(tag: string, name: string): string | undefined {
  const m = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
}

function cleanSourcePath(source: string): string {
  return source
    .replace(/^[a-z][a-z0-9+.-]*:\/\/\/?/i, "")
    .replace(/^(\.\.?\/)+/, "")
    .replace(/\?.*$/, "");
}

function decodeInlineMap(uri: string): string | null {
  const m = /^data:[^,]*?(;base64)?,(.*)$/s.exec(uri);
  if (!m) return null;
  try {
    return m[1]
      ? Buffer.from(m[2] as string, "base64").toString("utf8")
      : decodeURIComponent(m[2] as string);
  } catch {
    return null;
  }
}

export async function scanUrl(options: ScanUrlOptions): Promise<ScanResult> {
  const startedAt = performance.now();
  const target = new URL(options.url);
  if (target.protocol !== "http:" && target.protocol !== "https:")
    throw new Error(`Only http(s) URLs can be scanned: ${options.url}`);
  const lang = options.lang ?? DEFAULT_LANG;
  const maxResources = options.maxResources ?? 60;
  const totalBudget = options.maxTotalBytes ?? 40 * 1024 * 1024;
  const http: HttpOptions = {
    maxBytes: 8 * 1024 * 1024,
    timeoutMs: 15_000,
    userAgent: `devgu-web-scan/${TOOL_VERSION} (passive scan)`,
    ...(options.signal ? { signal: options.signal } : {}),
  };

  const dir = await mkdtemp(path.join(os.tmpdir(), "devgu-web-"));
  const display = new Map<string, string>();
  const extra: Finding[] = [];
  const diagnostics: Diagnostic[] = [];
  let counter = 0;
  let downloaded = 0;
  let reformatted = false;

  async function stash(shown: string, ext: string, content: string, prefix = ""): Promise<void> {
    counter += 1;
    const name = `${prefix}r${String(counter).padStart(4, "0")}${ext}`;
    await writeFile(path.join(dir, name), content);
    display.set(name, shown);
  }

  try {
    const page = await httpGet(target.href, http);
    if (page.status >= 400) throw new Error(`HTTP ${page.status} for ${target.href}`);
    const pageUrl = page.url;
    const origin = new URL(pageUrl).origin;
    downloaded += page.body.length;

    const robots = await httpGet(`${origin}/robots.txt`, { ...http, maxBytes: 200_000 }).catch(
      () => null,
    );
    const disallowed = robots && robots.status === 200 ? parseRobots(robots.body) : [];
    const allowed = (u: URL): boolean => {
      if (!isDisallowed(u.pathname, disallowed)) return true;
      diagnostics.push({
        source: "web-scan",
        filePath: u.href,
        message: "Skipped: disallowed by robots.txt",
      });
      return false;
    };

    extra.push(...headerFindings(page.headers, pageUrl, lang));
    await stash(pageUrl, ".html", page.body);

    // ---- discover scripts in the HTML ----
    const queue: URL[] = [];
    const seen = new Set<string>();
    let thirdParty = 0;
    const enqueue = (raw: string | undefined, base: URL): void => {
      if (!raw) return;
      let u: URL;
      try {
        u = new URL(raw, base);
      } catch {
        return;
      }
      u.hash = "";
      if (!/^https?:$/.test(u.protocol)) return;
      if (u.hostname !== new URL(pageUrl).hostname) {
        if (base.href === pageUrl) thirdParty += 1;
        return;
      }
      if (seen.has(u.href)) return;
      seen.add(u.href);
      queue.push(u);
    };

    let inline = 0;
    for (const m of page.body.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
      const attrs = m[1] as string;
      const src = attrOf(attrs, "src");
      if (src) {
        enqueue(src, new URL(pageUrl));
        if (new URL(pageUrl).protocol === "https:" && /^http:\/\//i.test(src))
          extra.push(makeFinding(rule("WEB-MIX-001"), lang, pageUrl, `<script src="${src}">`));
      } else if (
        (m[2] as string).trim() &&
        !/json|ld\+|template|text\/x-/i.test(attrOf(attrs, "type") ?? "")
      ) {
        inline += 1;
        await stash(`${pageUrl}#inline-script-${inline}`, ".js", prettifyMinified(m[2] as string));
      }
    }
    for (const m of page.body.matchAll(/<link\b[^>]*>/gi)) {
      const tag = m[0];
      const rel = (attrOf(tag, "rel") ?? "").toLowerCase();
      const href = attrOf(tag, "href");
      if (
        /modulepreload|preload/.test(rel) &&
        (rel.includes("module") || /script/i.test(attrOf(tag, "as") ?? ""))
      )
        enqueue(href, new URL(pageUrl));
      if (
        href &&
        /^http:\/\//i.test(href) &&
        /stylesheet|modulepreload/.test(rel) &&
        new URL(pageUrl).protocol === "https:"
      )
        extra.push(makeFinding(rule("WEB-MIX-001"), lang, pageUrl, `<link href="${href}">`));
    }
    for (const m of page.body.matchAll(/<iframe\b[^>]*>/gi)) {
      const src = attrOf(m[0], "src");
      if (src && /^http:\/\//i.test(src) && new URL(pageUrl).protocol === "https:")
        extra.push(makeFinding(rule("WEB-MIX-001"), lang, pageUrl, `<iframe src="${src}">`));
    }

    // ---- download scripts (+ chunks they reference) and source maps ----
    const mapsDone = new Set<string>();
    let fetched = 0;

    async function recoverMap(mapUrl: string, text: string): Promise<void> {
      if (mapsDone.has(mapUrl)) return;
      mapsDone.add(mapUrl);
      let json: { sources?: unknown; sourcesContent?: unknown };
      try {
        json = JSON.parse(text) as typeof json;
      } catch {
        return;
      }
      if (!Array.isArray(json.sources) || !Array.isArray(json.sourcesContent)) return;
      let recovered = 0;
      for (let i = 0; i < json.sources.length && recovered < MAX_RECOVERED_FILES; i += 1) {
        const source = String(json.sources[i]);
        const content = json.sourcesContent[i];
        if (typeof content !== "string" || content.length > MAX_RECOVERED_FILE_BYTES) continue;
        if (/node_modules|^webpack\/(runtime|bootstrap)|\(webpack\)/.test(source)) continue;
        const ext = path.posix.extname(cleanSourcePath(source)).toLowerCase();
        if (!SCRIPT_EXT.has(ext)) continue;
        recovered += 1;
        await stash(`${mapUrl}#${cleanSourcePath(source)}`, ext, content);
      }
      const count = json.sources.length;
      extra.push(
        makeFinding(
          rule("WEB-MAP-001"),
          lang,
          mapUrl,
          lang === "tr"
            ? `${count} kaynak dosyası haritada, ${recovered} tanesi taranmak üzere kurtarıldı`
            : `${count} source files in the map, ${recovered} recovered and scanned`,
          mapUrl,
        ),
      );
    }

    async function handleSourceMap(script: URL, body: string): Promise<void> {
      if (options.sourceMaps === false) return;
      const tail = body.slice(-2000);
      const comment = [...tail.matchAll(/[#@]\s*sourceMappingURL=(\S+)/g)].pop()?.[1];
      if (comment?.startsWith("data:")) {
        const decoded = decodeInlineMap(comment);
        if (decoded) await recoverMap(`${script.href} (inline source map)`, decoded);
        return;
      }
      const mapUrl = new URL(comment ?? `${script.pathname.split("/").pop()}.map`, script);
      if (mapUrl.hostname !== script.hostname || !allowed(mapUrl)) return;
      const res = await httpGet(mapUrl.href, { ...http, maxBytes: MAX_SOURCEMAP_BYTES }).catch(
        () => null,
      );
      if (res && res.status === 200 && !res.truncated) await recoverMap(mapUrl.href, res.body);
    }

    async function processScript(u: URL, depth: number): Promise<void> {
      if (!allowed(u)) return;
      const res = await httpGet(u.href, http).catch((error: unknown) => {
        diagnostics.push({
          source: "web-scan",
          filePath: u.href,
          message: `Download failed: ${error instanceof Error ? error.message : String(error)}`,
        });
        return null;
      });
      if (!res || res.status !== 200) return;
      downloaded += res.body.length;
      fetched += 1;
      if (res.body.split("\n").some((l) => l.length > 2000)) reformatted = true;
      await stash(u.href, ".js", prettifyMinified(res.body));
      await handleSourceMap(u, res.body);
      if (depth < 1) {
        let n = 0;
        for (const m of res.body.matchAll(/["'`]((?:\.\/|\/)[\w\-./@]+\.m?js)["'`]/g)) {
          if (n++ >= 150) break;
          if (seen.size < maxResources) enqueue(m[1], u);
        }
      }
    }

    const depthOf = new Map<string, number>();
    for (const u of queue) depthOf.set(u.href, 0);
    while (queue.length > 0 && fetched < maxResources && downloaded < totalBudget) {
      if (options.signal?.aborted) throw new Error("Cancelled");
      const batch = queue.splice(0, CONCURRENCY);
      const before = new Set(seen);
      await Promise.all(batch.map((u) => processScript(u, depthOf.get(u.href) ?? 1)));
      for (const href of seen) if (!before.has(href)) depthOf.set(href, 1);
    }
    if (thirdParty > 0)
      diagnostics.push({
        source: "web-scan",
        message:
          lang === "tr"
            ? `${thirdParty} üçüncü taraf betik indirilmedi (yalnızca aynı alan adındaki dosyalar taranır)`
            : `${thirdParty} third-party script(s) not downloaded (only same-host files are scanned)`,
      });

    // ---- well-known sensitive paths ----
    if (options.probeSensitivePaths !== false) {
      const probes: Array<{
        path: string;
        ok: (body: string, type: string) => boolean;
        ext: string;
        prefix: string;
      }> = [
        {
          path: "/.env",
          ok: (b, t) => !/html/i.test(t) && /^\s*[A-Za-z_][A-Za-z0-9_.]*\s*=\s*\S/m.test(b),
          ext: "",
          prefix: ".env.",
        },
        {
          path: "/.git/HEAD",
          ok: (b) => /^ref:\s*refs\/heads\//m.test(b),
          ext: ".conf",
          prefix: "",
        },
        { path: "/.git/config", ok: (b) => /^\[core\]/m.test(b), ext: ".conf", prefix: "" },
      ];
      for (const probe of probes) {
        const u = new URL(probe.path, origin);
        if (!allowed(u)) continue;
        const res = await httpGet(u.href, { ...http, maxBytes: 200_000 }).catch(() => null);
        if (
          !res ||
          res.status !== 200 ||
          !probe.ok(res.body, res.headers.get("content-type") ?? "")
        )
          continue;
        extra.push(
          makeFinding(
            rule("WEB-EXP-001"),
            lang,
            u.href,
            `GET ${probe.path} → HTTP 200 (${res.body.length} bytes)`,
            u.href,
          ),
        );
        await stash(u.href, probe.ext, res.body, probe.prefix);
      }
    }

    // ---- scan everything that was collected with the normal rule set ----
    const result = await scan({
      root: dir,
      rules: defaultRules(),
      config: { ...defaultConfig(), maxFileSizeBytes: 10_000_000 },
      lang,
      redact: defaultRedactor(),
      useCache: false,
      ...(options.signal ? { signal: options.signal } : {}),
    });

    const re = (p: string): string => display.get(p) ?? p;
    const remap = (f: Finding): Finding => ({
      ...f,
      filePath: re(f.filePath),
      ...(f.dataFlow
        ? { dataFlow: f.dataFlow.map((s) => ({ ...s, filePath: re(s.filePath) })) }
        : {}),
    });
    const findings = sortFindings([...result.findings.map(remap), ...extra]);
    const findingsBySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<
      (typeof SEVERITIES)[number],
      number
    >;
    for (const f of findings) findingsBySeverity[f.severity] += 1;
    if (reformatted)
      diagnostics.push({
        source: "web-scan",
        message:
          lang === "tr"
            ? "Küçültülmüş paketler taranmadan önce satırlara bölündü; bu dosyalardaki satır numaraları yeniden biçimlendirilmiş koda aittir. Güven düzeyi kaynak koda göre daha düşüktür."
            : "Minified bundles were re-wrapped before scanning; line numbers in those files refer to the reformatted code. Confidence is lower than for real source code.",
      });

    return {
      ...result,
      meta: {
        ...result.meta,
        rootName: new URL(pageUrl).host,
        engines: [...new Set([...result.meta.engines, "web"])].sort(),
        enabledRules: [...result.meta.enabledRules, ...WEB_RULES.map((r) => r.id)].sort(),
      },
      findings,
      suppressed: result.suppressed.map(remap),
      skipped: result.skipped.map((s) => ({ ...s, filePath: re(s.filePath) })),
      diagnostics: [
        ...result.diagnostics.map((d) => (d.filePath ? { ...d, filePath: re(d.filePath) } : d)),
        ...diagnostics,
      ],
      stats: {
        ...result.stats,
        totalMs: Math.round(performance.now() - startedAt),
        findingsBySeverity,
      },
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
