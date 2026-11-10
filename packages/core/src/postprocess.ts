import { confidenceRank, severityRank, type Finding } from "@devgu/shared";
import type { SourceFile } from "@devgu/parser";

const INLINE_SUPPRESSION = /devgu-ignore\s+([A-Za-z0-9._-]{1,64})\s*:\s*(\S.{0,300})$/;

/**
 * `// devgu-ignore RULE-ID: justification` on the finding's line or the line above.
 * A justification is mandatory; a bare ignore comment suppresses nothing.
 */
export function applyInlineSuppressions(findings: Finding[], file: SourceFile): Finding[] {
  return findings.map((finding) => {
    for (const lineNumber of [finding.startLine, finding.startLine - 1]) {
      const line = file.lines[lineNumber - 1];
      if (!line) continue;
      const match = INLINE_SUPPRESSION.exec(line);
      if (match && match[1] === finding.ruleId) {
        return {
          ...finding,
          status: "suppressed" as const,
          suppression: {
            kind: "inline" as const,
            justification: (match[2] ?? "").replace(/\s*(\*\/|-->)\s*$/, "").trim(),
          },
        };
      }
    }
    return finding;
  });
}

export function applyConfigSuppressions(
  findings: Finding[],
  suppressions: readonly { fingerprint: string; justification: string }[],
): Finding[] {
  if (suppressions.length === 0) return findings;
  const byPrint = new Map(suppressions.map((s) => [s.fingerprint, s.justification]));
  return findings.map((finding) => {
    const justification = byPrint.get(finding.fingerprint);
    if (justification === undefined || finding.status === "suppressed") return finding;
    return {
      ...finding,
      status: "suppressed" as const,
      suppression: { kind: "config" as const, justification },
    };
  });
}

/**
 * Removes exact duplicates and lets a data-flow (taint) finding replace the generic pattern
 * finding reported for the same sink line and category.
 */
export function dedupe(findings: Finding[]): Finding[] {
  const taintKeys = new Set(
    findings
      .filter((f) => f.engine === "taint")
      .map((f) => `${f.filePath}:${f.startLine}:${f.category}`),
  );
  const seen = new Set<string>();
  const result: Finding[] = [];
  for (const finding of findings) {
    if (
      finding.engine !== "taint" &&
      taintKeys.has(`${finding.filePath}:${finding.startLine}:${finding.category}`)
    ) {
      continue;
    }
    const key = `${finding.ruleId}:${finding.filePath}:${finding.startLine}:${finding.fingerprint}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      confidenceRank(b.confidence) - confidenceRank(a.confidence) ||
      (a.filePath < b.filePath ? -1 : a.filePath > b.filePath ? 1 : 0) ||
      a.startLine - b.startLine ||
      (a.ruleId < b.ruleId ? -1 : a.ruleId > b.ruleId ? 1 : 0),
  );
}

export function redactFinding(finding: Finding, redact: (text: string) => string): Finding {
  return {
    ...finding,
    evidence: redact(finding.evidence),
    description: redact(finding.description),
    ...(finding.dataFlow
      ? { dataFlow: finding.dataFlow.map((s) => ({ ...s, description: redact(s.description) })) }
      : {}),
  };
}
