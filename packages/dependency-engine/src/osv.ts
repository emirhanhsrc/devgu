import { z } from "zod";
import type { Severity } from "@devgu/shared";
import { cvss3BaseScore, severityFromScore } from "./cvss.js";

/** The only host DEVGU ever contacts. It is not configurable on purpose. */
export const OSV_BASE_URL = "https://api.osv.dev";

const MAX_RESPONSE_CHARS = 5_000_000;
const REQUEST_TIMEOUT_MS = 20_000;
const BATCH_SIZE = 1000;
const MAX_VULN_DETAIL_FETCHES = 500;
const DETAIL_CONCURRENCY = 8;

export interface FetchResponse {
  ok: boolean;
  status: number;
  text(): Promise<string>;
}
export type FetchLike = (
  url: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => Promise<FetchResponse>;

export interface Vulnerability {
  id: string;
  summary: string;
  aliases: string[];
  severity: Severity;
  severityKnown: boolean;
  /** Fixed versions per package name, from the advisory's affected ranges. */
  fixed: Record<string, string[]>;
  references: string[];
}

const BatchResponseSchema = z.object({
  results: z.array(z.object({ vulns: z.array(z.object({ id: z.string().max(100) })).optional() })),
});

const VulnResponseSchema = z.object({
  id: z.string().max(100),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string().max(100)).optional(),
  withdrawn: z.string().optional(),
  severity: z.array(z.object({ type: z.string(), score: z.string() })).optional(),
  database_specific: z.object({ severity: z.string().optional() }).passthrough().optional(),
  affected: z
    .array(
      z.object({
        package: z.object({ name: z.string(), ecosystem: z.string() }).optional(),
        ranges: z
          .array(
            z.object({
              events: z.array(z.object({ fixed: z.string().optional() }).passthrough()).optional(),
            }),
          )
          .optional(),
      }),
    )
    .optional(),
  references: z.array(z.object({ url: z.string() })).optional(),
});

function severityOf(raw: z.infer<typeof VulnResponseSchema>): {
  severity: Severity;
  known: boolean;
} {
  if (raw.id.startsWith("MAL-")) return { severity: "CRITICAL", known: true };
  const label = raw.database_specific?.severity?.toUpperCase();
  if (label === "CRITICAL" || label === "HIGH" || label === "LOW")
    return { severity: label, known: true };
  if (label === "MODERATE" || label === "MEDIUM") return { severity: "MEDIUM", known: true };
  for (const entry of raw.severity ?? []) {
    const score = cvss3BaseScore(entry.score);
    if (score !== null) return { severity: severityFromScore(score), known: true };
  }
  return { severity: "MEDIUM", known: false };
}

export function normalizeVulnerability(input: unknown): Vulnerability | null {
  const parsed = VulnResponseSchema.safeParse(input);
  if (!parsed.success || parsed.data.withdrawn) return null;
  const raw = parsed.data;
  const { severity, known } = severityOf(raw);
  const fixed: Record<string, string[]> = {};
  for (const affected of raw.affected ?? []) {
    if (affected.package?.ecosystem !== "npm") continue;
    const versions = (affected.ranges ?? []).flatMap((r) =>
      (r.events ?? []).map((e) => e.fixed).filter((v): v is string => !!v),
    );
    if (versions.length > 0)
      fixed[affected.package.name] = [
        ...new Set([...(fixed[affected.package.name] ?? []), ...versions]),
      ];
  }
  return {
    id: raw.id,
    summary: (raw.summary ?? raw.details ?? "No summary provided").split("\n")[0]!.slice(0, 300),
    aliases: (raw.aliases ?? []).slice(0, 10),
    severity,
    severityKnown: known,
    fixed,
    references: (raw.references ?? [])
      .map((r) => r.url)
      .filter((u) => /^https:\/\//i.test(u))
      .slice(0, 5),
  };
}

export class OsvClient {
  constructor(
    private readonly fetchImpl: FetchLike,
    private readonly signal?: AbortSignal,
  ) {}

  private async request(path: string, init: { method: string; body?: string }): Promise<unknown> {
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
    const signal = this.signal ? AbortSignal.any([timeout, this.signal]) : timeout;
    const response = await this.fetchImpl(`${OSV_BASE_URL}${path}`, {
      ...init,
      headers: { "content-type": "application/json", "user-agent": "devgu" },
      signal,
    });
    if (!response.ok) throw new Error(`OSV responded with HTTP ${response.status}`);
    const text = await response.text();
    if (text.length > MAX_RESPONSE_CHARS) throw new Error("OSV response is too large");
    return JSON.parse(text);
  }

  /** Returns the advisory ids per "name@version". Only package names and versions are sent. */
  async queryBatch(
    packages: ReadonlyArray<{ name: string; version: string }>,
  ): Promise<Map<string, string[]>> {
    const result = new Map<string, string[]>();
    for (let start = 0; start < packages.length; start += BATCH_SIZE) {
      const chunk = packages.slice(start, start + BATCH_SIZE);
      const body = JSON.stringify({
        queries: chunk.map((p) => ({
          package: { name: p.name, ecosystem: "npm" },
          version: p.version,
        })),
      });
      const parsed = BatchResponseSchema.parse(
        await this.request("/v1/querybatch", { method: "POST", body }),
      );
      if (parsed.results.length !== chunk.length)
        throw new Error("OSV batch response does not match the request");
      chunk.forEach((p, i) =>
        result.set(
          `${p.name}@${p.version}`,
          (parsed.results[i]?.vulns ?? []).map((v) => v.id),
        ),
      );
    }
    return result;
  }

  async getVulnerabilities(
    ids: readonly string[],
  ): Promise<{ vulns: Vulnerability[]; skipped: number }> {
    const unique = [...new Set(ids)].filter((id) => /^[A-Za-z0-9._-]{1,100}$/.test(id));
    const limited = unique.slice(0, MAX_VULN_DETAIL_FETCHES);
    const vulns: Vulnerability[] = [];
    for (let start = 0; start < limited.length; start += DETAIL_CONCURRENCY) {
      const chunk = limited.slice(start, start + DETAIL_CONCURRENCY);
      const results = await Promise.all(
        chunk.map((id) => this.request(`/v1/vulns/${encodeURIComponent(id)}`, { method: "GET" })),
      );
      for (const raw of results) {
        const vuln = normalizeVulnerability(raw);
        if (vuln) vulns.push(vuln);
      }
    }
    return { vulns, skipped: unique.length - limited.length };
  }
}
