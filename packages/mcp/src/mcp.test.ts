import path from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { runMcpServer } from "./server.js";

const fixtures = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../../fixtures");

async function session(
  requests: unknown[],
  roots = [fixtures],
): Promise<Array<Record<string, any>>> {
  const input = new PassThrough();
  const output = new PassThrough();
  let out = "";
  output.on("data", (chunk) => (out += String(chunk)));
  const done = runMcpServer({ input, output, roots });
  for (const request of requests) input.write(`${JSON.stringify(request)}\n`);
  input.end();
  await done;
  // Replies may arrive out of order (slow scans finish last), so sort them back by request id.
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line))
    .sort((a, b) => Number(a.id) - Number(b.id));
}

const call = (id: number, name: string, args: unknown) => ({
  jsonrpc: "2.0",
  id,
  method: "tools/call",
  params: { name, arguments: args },
});

describe("MCP server", () => {
  it("negotiates, lists tools and ignores notifications", async () => {
    const replies = await session([
      {
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: { protocolVersion: "2025-03-26", capabilities: {} },
      },
      { jsonrpc: "2.0", method: "notifications/initialized" },
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      { jsonrpc: "2.0", id: 3, method: "nope" },
    ]);
    expect(replies).toHaveLength(3);
    expect(replies[0]?.result.protocolVersion).toBe("2025-03-26");
    expect(replies[0]?.result.serverInfo.name).toBe("devgu");
    expect(replies[1]?.result.tools.map((t: { name: string }) => t.name)).toEqual([
      "scan_project",
      "scan_url",
      "explain_rule",
      "list_rules",
      "generate_report",
    ]);
    expect(replies[2]?.error.code).toBe(-32601);
  });

  it("explains rules, including web rules, in Turkish", async () => {
    const replies = await session([
      call(1, "explain_rule", { id: "js-xss-001", lang: "tr" }),
      call(2, "explain_rule", { id: "WEB-MAP-001" }),
      call(3, "explain_rule", { id: "NOPE-1" }),
    ]);
    expect(replies[0]?.result.content[0].text).toContain("Çözüm");
    expect(replies[1]?.result.content[0].text).toContain("WEB-MAP-001");
    expect(replies[2]?.result.isError).toBe(true);
  });

  it("scans a project inside the allowed roots and refuses paths outside them", async () => {
    const replies = await session([
      call(1, "scan_project", { path: "vulnerable", min_severity: "HIGH" }),
      call(2, "scan_project", { path: "/etc" }),
      call(3, "scan_project", { path: ".." }),
    ]);
    expect(replies[0]?.result.isError).toBeUndefined();
    expect(replies[0]?.result.content[0].text).toMatch(/\[(HIGH|CRITICAL)\//);
    expect(replies[1]?.result.isError).toBe(true);
    expect(replies[1]?.result.content[0].text).toContain("outside the allowed roots");
    expect(replies[2]?.result.isError).toBe(true);
  });

  it("refuses URL scans without explicit authorization", async () => {
    const replies = await session([call(1, "scan_url", { url: "http://127.0.0.1:9/" })]);
    expect(replies[0]?.result.isError).toBe(true);
    expect(replies[0]?.result.content[0].text).toContain("authorized");
  });

  it("answers garbage input with a parse error instead of crashing", async () => {
    const input = new PassThrough();
    const output = new PassThrough();
    let out = "";
    output.on("data", (c) => (out += String(c)));
    const done = runMcpServer({ input, output, roots: [fixtures] });
    input.write("not json\n");
    input.end();
    await done;
    expect(JSON.parse(out).error.code).toBe(-32700);
  });
});
