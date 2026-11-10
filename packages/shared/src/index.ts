export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export type Confidence = "HIGH" | "MEDIUM" | "LOW";

export interface Finding {
  id: string;
  ruleId: string;
  engine: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  category: string;
  filePath: string;
  startLine: number;
  endLine: number;
  evidence: string;
  remediation: string;
  references: string[];
  fingerprint: string;
  status: "open" | "suppressed";
}
