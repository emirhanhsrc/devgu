import { z } from "zod";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
export const CONFIDENCES = ["HIGH", "MEDIUM", "LOW"] as const;

export const SeveritySchema = z.enum([...SEVERITIES]);
export const ConfidenceSchema = z.enum([...CONFIDENCES]);

export type Severity = z.infer<typeof SeveritySchema>;
export type Confidence = z.infer<typeof ConfidenceSchema>;

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_RANK[severity];
}

export function confidenceRank(confidence: Confidence): number {
  return confidence === "HIGH" ? 2 : confidence === "MEDIUM" ? 1 : 0;
}

/** True when `severity` is at least as severe as `threshold`. */
export function meetsThreshold(severity: Severity, threshold: Severity): boolean {
  return severityRank(severity) >= severityRank(threshold);
}

export const FlowStepSchema = z.object({
  filePath: z.string(),
  line: z.number().int().min(1),
  description: z.string(),
});
export type FlowStep = z.infer<typeof FlowStepSchema>;

export const SuppressionSchema = z.object({
  kind: z.enum(["inline", "config"]),
  justification: z.string(),
});
export type Suppression = z.infer<typeof SuppressionSchema>;

export const FindingSchema = z.object({
  id: z.string(),
  ruleId: z.string(),
  engine: z.string(),
  title: z.string(),
  description: z.string(),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  category: z.string(),
  /** Repository-relative path using forward slashes. Never absolute. */
  filePath: z.string(),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  /** Source excerpt. Secrets are always redacted before it is stored. */
  evidence: z.string(),
  remediation: z.string(),
  references: z.array(z.string()),
  /** What the detection can and cannot prove. */
  limitations: z.string(),
  fingerprint: z.string(),
  status: z.enum(["open", "suppressed"]),
  dataFlow: z.array(FlowStepSchema).optional(),
  suppression: SuppressionSchema.optional(),
});
export type Finding = z.infer<typeof FindingSchema>;
