import { SEVERITIES, stripControlChars, type Finding, type ScanResult } from "@devgu/shared";

/** Escapes Markdown/HTML metacharacters in text that comes from the scanned repository. */
export function mdEscape(text: string): string {
  return stripControlChars(text)
    .replace(/[\r\n]+/g, " ")
    .replace(/([\\`*_{}[\]<>()#+\-.!|~&])/g, "\\$1");
}

/** Code fence long enough to contain any backtick run inside the content. */
function fenced(content: string): string {
  const safe = stripControlChars(content);
  const longest = Math.max(0, ...(safe.match(/`+/g) ?? []).map((run) => run.length));
  const fence = "`".repeat(Math.max(3, longest + 1));
  return `${fence}\n${safe}\n${fence}`;
}

function findingBlock(finding: Finding): string[] {
  const lines: string[] = [];
  lines.push(`#### ${mdEscape(finding.title)}`);
  lines.push("");
  lines.push(
    `- **Rule:** ${mdEscape(finding.ruleId)} (${mdEscape(finding.category)}, engine ${mdEscape(finding.engine)})`,
  );
  lines.push(`- **Severity / confidence:** ${finding.severity} / ${finding.confidence}`);
  lines.push(`- **Location:** ${mdEscape(`${finding.filePath}:${finding.startLine}`)}`);
  if (finding.status === "suppressed" && finding.suppression) {
    lines.push(
      `- **Suppressed (${finding.suppression.kind}):** ${mdEscape(finding.suppression.justification)}`,
    );
  }
  lines.push("", mdEscape(finding.description), "", "Evidence:", "", fenced(finding.evidence));
  if (finding.dataFlow?.length) {
    lines.push("", "Data flow:", "");
    finding.dataFlow.forEach((step, index) => {
      lines.push(
        `${index + 1}. ${mdEscape(`${step.filePath}:${step.line}`)} - ${mdEscape(step.description)}`,
      );
    });
  }
  lines.push("", `**How to fix:** ${mdEscape(finding.remediation)}`, "");
  lines.push(`**Limitations:** ${mdEscape(finding.limitations)}`, "");
  return lines;
}

export function renderMarkdown(result: ScanResult): string {
  const { meta, stats } = result;
  const out: string[] = [];
  out.push("# DEVGU report", "");
  out.push(`| | |`, `|---|---|`);
  out.push(`| Repository | ${mdEscape(meta.rootName)} |`);
  out.push(`| Scanned at | ${mdEscape(meta.scannedAt)} |`);
  out.push(`| Scanner version | ${mdEscape(meta.toolVersion)} |`);
  out.push(`| Rule set | ${mdEscape(meta.rulesetVersion)} |`);
  out.push(`| Engines | ${mdEscape(meta.engines.join(", ") || "-")} |`);
  out.push(`| Files scanned | ${stats.filesScanned} (${stats.filesSkipped} skipped) |`);
  out.push(`| Duration | ${stats.totalMs} ms |`, "");

  out.push("## Summary", "", "| Severity | Findings |", "|---|---|");
  for (const severity of SEVERITIES)
    out.push(`| ${severity} | ${stats.findingsBySeverity[severity]} |`);
  out.push(
    "",
    `${result.findings.length} open finding(s), ${result.suppressed.length} suppressed.`,
    "",
  );

  out.push("## Findings", "");
  if (result.findings.length === 0) {
    out.push("No findings. This does not prove the code is safe; see each rule's limitations.", "");
  }
  for (const severity of SEVERITIES) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    out.push(`### ${severity} (${group.length})`, "");
    for (const finding of group) out.push(...findingBlock(finding));
  }

  if (result.suppressed.length > 0) {
    out.push("## Suppressed findings", "");
    for (const finding of result.suppressed) out.push(...findingBlock(finding));
  }

  if (result.diagnostics.length > 0) {
    out.push("## Diagnostics", "");
    for (const d of result.diagnostics) {
      out.push(
        `- ${mdEscape(d.source)}${d.filePath ? ` ${mdEscape(d.filePath)}` : ""}: ${mdEscape(d.message)}`,
      );
    }
    out.push("");
  }
  return out.join("\n");
}
