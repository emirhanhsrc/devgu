import {
  messages,
  SEVERITIES,
  stripControlChars,
  type Finding,
  type ScanResult,
} from "@devgu/shared";

const COLORS: Record<string, string> = {
  CRITICAL: "\u001b[1;31m",
  HIGH: "\u001b[31m",
  MEDIUM: "\u001b[33m",
  LOW: "\u001b[34m",
  INFO: "\u001b[90m",
};
const RESET = "\u001b[0m";

/**
 * Terminal output. Every string that comes from the scanned repository is stripped of control
 * characters first, so a hostile file cannot inject terminal escape sequences.
 */
export function renderText(result: ScanResult, options: { color?: boolean } = {}): string {
  const paint = (severity: string, text: string): string =>
    options.color ? `${COLORS[severity] ?? ""}${text}${RESET}` : text;
  const safe = stripControlChars;
  const out: string[] = [];

  const byFile = new Map<string, Finding[]>();
  for (const finding of result.findings) {
    const list = byFile.get(finding.filePath) ?? [];
    list.push(finding);
    byFile.set(finding.filePath, list);
  }

  for (const [file, findings] of [...byFile].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    out.push(safe(file));
    for (const f of findings) {
      out.push(
        `  ${f.startLine}  ${paint(f.severity, f.severity.padEnd(8))} ${f.confidence.padEnd(6)} ${f.ruleId}  ${safe(f.title)}`,
      );
      out.push(`      ${safe(f.evidence)}`);
      for (const step of f.dataFlow ?? []) {
        out.push(`      -> ${safe(step.filePath)}:${step.line} ${safe(step.description)}`);
      }
    }
    out.push("");
  }

  const m = messages(result.meta.lang).text;
  const counts = SEVERITIES.filter((s) => result.stats.findingsBySeverity[s] > 0)
    .map((s) => `${result.stats.findingsBySeverity[s]} ${s.toLowerCase()}`)
    .join(", ");
  out.push(m.findingsLine(result.findings.length, counts, result.suppressed.length));
  out.push(
    m.filesLine(
      result.stats.filesScanned,
      result.stats.filesSkipped,
      result.stats.cacheHits,
      result.stats.cacheHits + result.stats.cacheMisses,
      result.stats.totalMs,
    ),
  );
  for (const d of result.diagnostics) {
    out.push(
      `${m.warning}: ${safe(d.source)}${d.filePath ? ` ${safe(d.filePath)}` : ""}: ${safe(d.message)}`,
    );
  }
  return out.join("\n") + "\n";
}
