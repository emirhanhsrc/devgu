import type { ScanResult } from "@devgu/shared";
import { renderHtml } from "./html.js";
import { renderMarkdown } from "./markdown.js";
import { renderSarif, type RuleDescriptor } from "./sarif.js";
import { renderText } from "./text.js";

export { renderText } from "./text.js";
export { renderSarif, type RuleDescriptor } from "./sarif.js";
export { renderHtml, embedJson } from "./html.js";
export { renderMarkdown, mdEscape } from "./markdown.js";

export const REPORT_FORMATS = ["text", "json", "sarif", "html", "md"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export interface RenderOptions {
  color?: boolean;
  rules?: readonly RuleDescriptor[];
}

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2) + "\n";
}

export function renderReport(
  format: ReportFormat,
  result: ScanResult,
  options: RenderOptions = {},
): string {
  switch (format) {
    case "json":
      return renderJson(result);
    case "sarif":
      return renderSarif(result, options.rules);
    case "html":
      return renderHtml(result);
    case "md":
      return renderMarkdown(result);
    case "text":
      return renderText(result, options);
  }
}
