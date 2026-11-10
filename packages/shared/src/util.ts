import { createHash } from "node:crypto";

export const TOOL_VERSION = "0.1.0";

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Stable identity of a finding. It deliberately excludes line numbers so that unrelated edits
 * above the finding do not change it. `material` is the evidence, or for secrets the secret value
 * itself (it is hashed, never stored).
 */
export function fingerprint(ruleId: string, filePath: string, material: string): string {
  const normalized = material.replace(/\s+/g, " ").trim();
  return sha256Hex(`${ruleId}\u0000${filePath}\u0000${normalized}`).slice(0, 32);
}

/** Masks a sensitive value so it can be shown without being usable. */
export function redactValue(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 2)}${"*".repeat(8)}(${value.length} chars)`;
}

/** Removes control characters (terminal escape sequences included) except tab and newline. */
export function stripControlChars(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/g, "?");
}

export function truncate(text: string, max: number): string {
  return text.length <= max ? text : `${text.slice(0, max - 1)}…`;
}
