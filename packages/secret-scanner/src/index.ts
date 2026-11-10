import type { Rule } from "@devgu/rule-engine";
import { redactValue, type Confidence, type Severity } from "@devgu/shared";

/** Lines longer than this are only scanned up to this length (bounds regex work on hostile input). */
const MAX_SCANNED_LINE_LENGTH = 4096;

export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

const PLACEHOLDER_HINTS = [
  "example",
  "placeholder",
  "changeme",
  "change_me",
  "your_",
  "your-",
  "yourpassword",
  "xxxx",
  "****",
  "dummy",
  "sample",
  "todo",
  "<",
  ">",
  "${",
  "{{",
  "process.env",
  "undefined",
  "password",
];

function looksLikePlaceholder(value: string): boolean {
  const lower = value.toLowerCase();
  return PLACEHOLDER_HINTS.some((hint) => lower.includes(hint)) || /^(.)\1+$/.test(value);
}

function characterClasses(value: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(value)).length;
}

/** Heuristic for hardcoded passwords: not a label/placeholder and not a plain dictionary-like word. */
function isPlausiblePassword(value: string): boolean {
  if (looksLikePlaceholder(value)) return false;
  if (/^[A-Za-z]+$/.test(value)) return value.length >= 16 && shannonEntropy(value) >= 3.5;
  return characterClasses(value) >= 2 || shannonEntropy(value) >= 3.5;
}

function isPlausibleToken(value: string): boolean {
  return !looksLikePlaceholder(value) && value.length >= 16 && shannonEntropy(value) >= 3.5;
}

const PROVIDER_PREFIX = /^(AKIA|ASIA|gh[pousr]_|AIza|xox[baprs]-|[sr]k_live_|eyJ)/;

export interface SecretPattern {
  id: string;
  name: string;
  description: string;
  /** Must be a global regex ("g") with linear-time structure; "d" is added internally. */
  regex: RegExp;
  /** Capture group that holds the secret; 0 = whole match. */
  group: number;
  severity: Severity;
  confidence: Confidence;
  remediation: string;
  limitations: string;
  validate?: (secret: string) => boolean;
}

const COMMON_REMEDIATION =
  "Revoke and rotate the credential, remove it from the code and its git history, and load it from a secret manager or environment at runtime.";
const COMMON_LIMITATION =
  "Detected by pattern. The value may be a revoked, test or example credential; the scanner cannot check whether it is still valid.";
const REF = ["https://cwe.mitre.org/data/definitions/798.html"];

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: "SEC-AWS-001",
    name: "AWS access key ID",
    description: "An AWS access key identifier is present in the source.",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    group: 0,
    severity: "HIGH",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
    validate: (s) => !s.endsWith("EXAMPLE"),
  },
  {
    id: "SEC-AWS-002",
    name: "AWS secret access key",
    description: "An AWS secret access key is assigned in the source.",
    regex: /aws_?secret_?(?:access_?)?key["']?\s{0,3}[:=]\s{0,3}["']?([A-Za-z0-9/+=]{40})\b/gi,
    group: 1,
    severity: "CRITICAL",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
    validate: (s) => !looksLikePlaceholder(s),
  },
  {
    id: "SEC-GITHUB-001",
    name: "GitHub token",
    description: "A GitHub personal access, OAuth or app token is present in the source.",
    regex: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g,
    group: 0,
    severity: "CRITICAL",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
  },
  {
    id: "SEC-GOOGLE-001",
    name: "Google API key",
    description: "A Google API key is present in the source.",
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    group: 0,
    severity: "MEDIUM",
    confidence: "HIGH",
    remediation: `${COMMON_REMEDIATION} Restrict the key by HTTP referrer or API in the Google Cloud console.`,
    limitations: `${COMMON_LIMITATION} Browser keys are designed to be public when properly restricted.`,
  },
  {
    id: "SEC-SLACK-001",
    name: "Slack token",
    description: "A Slack API token is present in the source.",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,72}\b/g,
    group: 0,
    severity: "HIGH",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
  },
  {
    id: "SEC-STRIPE-001",
    name: "Stripe live key",
    description: "A Stripe live secret or restricted key is present in the source.",
    regex: /\b[sr]k_live_[0-9a-zA-Z]{24,99}\b/g,
    group: 0,
    severity: "CRITICAL",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
  },
  {
    id: "SEC-PRIVKEY-001",
    name: "Private key",
    description: "A PEM encoded private key block starts here.",
    regex:
      /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----[^\n]{0,4000}/g,
    group: 0,
    severity: "CRITICAL",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations:
      "Only the header is matched; the file may contain an intentionally public test key.",
  },
  {
    id: "SEC-JWT-001",
    name: "JSON Web Token",
    description:
      "A JWT-like token is hardcoded. Tokens can carry identity and grant access until they expire.",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    group: 0,
    severity: "MEDIUM",
    confidence: "MEDIUM",
    remediation: COMMON_REMEDIATION,
    limitations: `${COMMON_LIMITATION} The token may already be expired.`,
  },
  {
    id: "SEC-CONNSTR-001",
    name: "Credentials in connection string",
    description: "A database or broker connection string contains an inline password.",
    regex:
      /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/[^\s:/@'"`]{1,100}:([^\s@'"`]{3,100})@/gi,
    group: 1,
    severity: "HIGH",
    confidence: "HIGH",
    remediation: COMMON_REMEDIATION,
    limitations: COMMON_LIMITATION,
    validate: (s) => !looksLikePlaceholder(s),
  },
  {
    id: "SEC-PASSWORD-001",
    name: "Hardcoded password",
    description:
      "A string literal that looks like a real password is assigned to a password-like name.",
    regex: /(?:password|passwd|pwd)["']?\s{0,3}[:=]\s{0,3}["']([^"'\s\\]{6,100})["']/gi,
    group: 1,
    severity: "HIGH",
    confidence: "MEDIUM",
    remediation: COMMON_REMEDIATION,
    limitations:
      "Heuristic: values that look like labels, placeholders or plain words are skipped, so weak real passwords can be missed.",
    validate: (s) => !PROVIDER_PREFIX.test(s) && isPlausiblePassword(s),
  },
  {
    id: "SEC-TOKEN-001",
    name: "Hardcoded API key or token",
    description:
      "A high-entropy string literal is assigned to a name such as apiKey, secret or token.",
    regex:
      /(?:api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key)["']?\s{0,3}[:=]\s{0,3}["']([A-Za-z0-9+/=_-]{16,200})["']/gi,
    group: 1,
    severity: "HIGH",
    confidence: "MEDIUM",
    remediation: COMMON_REMEDIATION,
    limitations:
      "Entropy based: random-looking identifiers (hashes, ids) can be reported, and low-entropy real secrets are missed.",
    validate: (s) => !PROVIDER_PREFIX.test(s) && isPlausibleToken(s),
  },
];

export interface SecretMatch {
  start: number;
  end: number;
  secret: string;
}

/** All matches of a pattern in one line, after validation. Linear in the (capped) line length. */
export function findSecrets(pattern: SecretPattern, line: string): SecretMatch[] {
  const text =
    line.length > MAX_SCANNED_LINE_LENGTH ? line.slice(0, MAX_SCANNED_LINE_LENGTH) : line;
  const regex = new RegExp(pattern.regex.source, `${pattern.regex.flags.replace("d", "")}d`);
  const matches: SecretMatch[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    if (match[0].length === 0) {
      regex.lastIndex += 1;
      continue;
    }
    const secret = match[pattern.group];
    const range = (match as RegExpExecArray & { indices?: Array<[number, number] | undefined> })
      .indices?.[pattern.group];
    if (secret === undefined || !range) continue;
    if (pattern.validate && !pattern.validate(secret)) continue;
    matches.push({ start: range[0], end: range[1], secret });
  }
  return matches;
}

function maskRanges(line: string, ranges: SecretMatch[]): string {
  let result = "";
  let cursor = 0;
  for (const range of [...ranges].sort((a, b) => a.start - b.start)) {
    if (range.start < cursor) continue;
    result += line.slice(cursor, range.start) + redactValue(range.secret);
    cursor = range.end;
  }
  return result + line.slice(cursor);
}

/** Masks every secret recognised by any pattern in arbitrary text. Used on all evidence. */
export function redactSecretsInText(text: string): string {
  return text
    .split("\n")
    .map((line) => {
      const ranges = SECRET_PATTERNS.flatMap((p) => findSecrets(p, line));
      return ranges.length > 0 ? maskRanges(line, ranges) : line;
    })
    .join("\n");
}

function toRule(pattern: SecretPattern): Rule {
  return {
    meta: {
      id: pattern.id,
      name: pattern.name,
      description: pattern.description,
      category: "secrets",
      severity: pattern.severity,
      confidence: pattern.confidence,
      targets: "text",
      remediation: pattern.remediation,
      references: REF,
      limitations: pattern.limitations,
      version: 1,
      engine: "secrets",
    },
    check(context) {
      context.file.lines.forEach((line, index) => {
        const matches = findSecrets(pattern, line);
        for (const match of matches) {
          context.report({
            line: index + 1,
            evidence: redactSecretsInText(line),
            // The secret itself is hashed into the fingerprint but never stored.
            fingerprintMaterial: match.secret,
          });
        }
      });
    },
  };
}

export const secretRules: Rule[] = SECRET_PATTERNS.map(toRule);
