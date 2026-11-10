import type { ScanResult } from "@devgu/shared";
import { renderText } from "./text.js";

export { renderText } from "./text.js";

export const REPORT_FORMATS = ["text", "json"] as const;
export type ReportFormat = (typeof REPORT_FORMATS)[number];

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2) + "\n";
}

export function renderReport(
  format: ReportFormat,
  result: ScanResult,
  options: { color?: boolean } = {},
): string {
  switch (format) {
    case "json":
      return renderJson(result);
    case "text":
      return renderText(result, options);
  }
}
