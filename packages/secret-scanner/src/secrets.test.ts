import { describe, expect, it } from "vitest";
import { createSourceFile } from "@devgu/parser";
import { runRules } from "@devgu/rule-engine";
import { SECRET_PATTERNS, redactSecretsInText, secretRules, shannonEntropy } from "./index.js";

// Fake credentials are assembled at runtime so this repository does not contain real-looking literals.
const awsKey = "AKIA" + "ZXCVBNMASDFGHJKL";
const ghToken = "ghp_" + "Ab3dEf6hIj9lMn2pQr5tUv8xYz1BcDeFgHiJ";
const stripe = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const slack = "xoxb-" + "123456789012-abcdefghijklmnop";
const google = "AIza" + "SyA1234567890abcdefghijklmnopqrstuv";
const jwt = "eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0." + "abcdefghijklmnopqrstuv";
const pem = "-----BEGIN " + "RSA PRIVATE KEY-----";

function scan(code: string, file = "a.js") {
  const result = runRules(createSourceFile(file, code), secretRules, {});
  expect(result.diagnostics).toEqual([]);
  return result.findings;
}
const ids = (code: string, file?: string): string[] => scan(code, file).map((f) => f.ruleId);

describe("provider patterns", () => {
  it("detects provider credentials", () => {
    expect(ids(`const k = "${awsKey}";`)).toEqual(["SEC-AWS-001"]);
    expect(ids(`token: '${ghToken}'`)).toEqual(["SEC-GITHUB-001"]);
    expect(ids(`stripe("${stripe}")`)).toEqual(["SEC-STRIPE-001"]);
    expect(ids(`SLACK=${slack}`, ".env")).toEqual(["SEC-SLACK-001"]);
    expect(ids(`key="${google}"`)).toEqual(["SEC-GOOGLE-001"]);
    expect(ids(`const t = "${jwt}";`)).toEqual(["SEC-JWT-001"]);
    expect(ids(pem, "id_rsa.json")).toEqual(["SEC-PRIVKEY-001"]);
  });
  it("detects connection strings with passwords", () => {
    expect(ids('const url = "postgres://app:s3cr3tPw@db.internal:5432/app";')).toEqual([
      "SEC-CONNSTR-001",
    ]);
  });
  it("detects AWS secret keys with context", () => {
    expect(ids(`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzXzXqPlSnR"`)).toEqual([
      "SEC-AWS-002",
    ]);
  });
  it("ignores documented example keys and placeholders", () => {
    expect(ids('const k = "AKIAIOSFODNN7EXAMPLE";')).toEqual([]);
    expect(ids('const url = "postgres://user:${PASSWORD}@host/db";')).toEqual([]);
    expect(ids('const url = "postgres://user:<password>@host/db";')).toEqual([]);
  });
});

describe("generic rules", () => {
  it("detects hardcoded passwords", () => {
    expect(ids('const db = { password: "Tr0ub4dor&3xx" };')).toEqual(["SEC-PASSWORD-001"]);
    expect(ids("DB_PASSWORD=hunter2hunter2", ".env")).toEqual([]); // unquoted env values are not matched
  });
  it("ignores labels, placeholders and plain words", () => {
    expect(ids('const s = { password: "password" };')).toEqual([]);
    expect(ids('const s = { password: "changeme123" };')).toEqual([]);
    expect(ids('label = { password: "Enter" };')).toEqual([]);
    expect(ids('const s = { password: "passwordField" };')).toEqual([]);
    expect(ids('const s = { password: "xxxxxxxx" };')).toEqual([]);
  });
  it("detects high-entropy tokens assigned to secret-like names", () => {
    expect(ids('const apiKey = "q8Zr1xT7vB3nK9mW2pL5";')).toEqual(["SEC-TOKEN-001"]);
  });
  it("does not double report provider keys as generic tokens", () => {
    expect(ids(`const apiKey = "${ghToken}";`)).toEqual(["SEC-GITHUB-001"]);
  });
  it("ignores low entropy and short values", () => {
    expect(ids('const apiKey = "aaaaaaaaaaaaaaaaaaaa";')).toEqual([]);
    expect(ids('const apiKey = "short";')).toEqual([]);
  });
});

describe("redaction", () => {
  it("never leaves the secret in evidence, fingerprint or JSON", () => {
    const findings = scan(`const k = "${awsKey}"; const g = "${ghToken}";`);
    const dump = JSON.stringify(findings);
    for (const secret of [awsKey, ghToken]) expect(dump).not.toContain(secret);
    expect(findings[0]?.evidence).toContain("(20 chars)");
  });
  it("redactSecretsInText masks any secret in free text", () => {
    const masked = redactSecretsInText(`a ${awsKey} b\nc ${stripe}`);
    expect(masked).not.toContain(awsKey);
    expect(masked).not.toContain(stripe);
    expect(masked.startsWith("a ")).toBe(true);
  });
  it("gives the same secret in two files a different fingerprint per file but stable over time", () => {
    const a = scan(`const k = "${awsKey}";`, "a.js")[0];
    const b = scan(`  const k = "${awsKey}";`, "a.js")[0];
    expect(a?.fingerprint).toBe(b?.fingerprint);
    expect(scan(`const k = "${awsKey}";`, "b.js")[0]?.fingerprint).not.toBe(a?.fingerprint);
  });
});

describe("robustness", () => {
  it("handles very long lines quickly (no catastrophic backtracking)", () => {
    const hostile = "a".repeat(200_000) + 'password="' + "b".repeat(100_000);
    const started = performance.now();
    scan(hostile);
    scan('"'.repeat(100_000));
    scan("postgres://" + "a:".repeat(50_000));
    expect(performance.now() - started).toBeLessThan(2000);
  });
  it("has unique ids and documented limitations", () => {
    const all = SECRET_PATTERNS.map((p) => p.id);
    expect(new Set(all).size).toBe(all.length);
    expect(SECRET_PATTERNS.every((p) => p.limitations.length > 20)).toBe(true);
  });
  it("computes entropy", () => {
    expect(shannonEntropy("aaaa")).toBe(0);
    expect(shannonEntropy("abcd")).toBe(2);
  });
});
