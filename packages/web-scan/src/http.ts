export interface HttpResult {
  url: string;
  status: number;
  headers: Headers;
  body: string;
  truncated: boolean;
}

export interface HttpOptions {
  maxBytes: number;
  timeoutMs: number;
  userAgent: string;
  signal?: AbortSignal;
}

const MAX_REDIRECTS = 4;

/**
 * GET with a size cap and a timeout. Redirects are followed manually and only within the same
 * host, so a page can never steer the scanner to other machines (internal addresses included).
 */
export async function httpGet(url: string, options: HttpOptions): Promise<HttpResult> {
  let current = new URL(url);
  const host = current.hostname;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop += 1) {
    const timeout = AbortSignal.timeout(options.timeoutMs);
    const signal = options.signal ? AbortSignal.any([timeout, options.signal]) : timeout;
    const response = await fetch(current, {
      redirect: "manual",
      signal,
      headers: { "user-agent": options.userAgent, accept: "*/*" },
    });
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      await response.body?.cancel();
      if (!location)
        return {
          url: current.href,
          status: response.status,
          headers: response.headers,
          body: "",
          truncated: false,
        };
      const next = new URL(location, current);
      if (next.hostname !== host || !/^https?:$/.test(next.protocol)) {
        return {
          url: current.href,
          status: response.status,
          headers: response.headers,
          body: "",
          truncated: false,
        };
      }
      current = next;
      continue;
    }
    const chunks: Uint8Array[] = [];
    let size = 0;
    let truncated = false;
    if (response.body) {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > options.maxBytes) {
          truncated = true;
          await reader.cancel();
          break;
        }
        chunks.push(value);
      }
    }
    return {
      url: current.href,
      status: response.status,
      headers: response.headers,
      body: Buffer.concat(chunks).toString("utf8"),
      truncated,
    };
  }
  throw new Error(`Too many redirects: ${url}`);
}

/** Minimal robots.txt reader: the Disallow prefixes that apply to every user agent. */
export function parseRobots(text: string): string[] {
  const disallowed: string[] = [];
  let applies = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    const match = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
    if (!match) continue;
    const key = (match[1] as string).toLowerCase();
    const value = (match[2] as string).trim();
    if (key === "user-agent") applies = value === "*";
    else if (key === "disallow" && applies && value) disallowed.push(value);
  }
  return disallowed;
}

export function isDisallowed(pathname: string, rules: readonly string[]): boolean {
  return rules.some((rule) => pathname.startsWith(rule.replace(/\*.*$/, "")));
}
