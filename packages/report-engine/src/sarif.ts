import type { Finding, ScanResult, Severity } from "@devgu/shared";

/** Rule information that SARIF viewers show next to a result. */
export interface RuleDescriptor {
  id: string;
  name: string;
  description: string;
  remediation: string;
  limitations: string;
  references: string[];
  severity: Severity;
  category: string;
}

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  CRITICAL: "error",
  HIGH: "error",
  MEDIUM: "warning",
  LOW: "note",
  INFO: "note",
};

/** GitHub Code Scanning uses this numeric score to rank security alerts. */
const SECURITY_SEVERITY: Record<Severity, string> = {
  CRITICAL: "9.5",
  HIGH: "8.0",
  MEDIUM: "5.5",
  LOW: "3.0",
  INFO: "0.0",
};

const CONFIDENCE_PRECISION = { HIGH: "high", MEDIUM: "medium", LOW: "low" } as const;

/** SARIF requires a URI reference: percent-encode every path segment. */
function toUri(filePath: string): string {
  return filePath.split("/").map(encodeURIComponent).join("/");
}

function location(finding: Pick<Finding, "filePath" | "startLine" | "endLine">, snippet?: string) {
  return {
    physicalLocation: {
      artifactLocation: { uri: toUri(finding.filePath), uriBaseId: "%SRCROOT%" },
      region: {
        startLine: finding.startLine,
        endLine: finding.endLine,
        ...(snippet ? { snippet: { text: snippet } } : {}),
      },
    },
  };
}

function resultFor(finding: Finding, ruleIndex: number) {
  return {
    ruleId: finding.ruleId,
    ruleIndex,
    level: LEVEL[finding.severity],
    message: { text: `${finding.title}: ${finding.description}` },
    locations: [location(finding, finding.evidence)],
    partialFingerprints: { "devgu/v1": finding.fingerprint },
    properties: {
      confidence: finding.confidence,
      severity: finding.severity,
      category: finding.category,
      engine: finding.engine,
    },
    ...(finding.dataFlow && finding.dataFlow.length > 0
      ? {
          codeFlows: [
            {
              threadFlows: [
                {
                  locations: finding.dataFlow.map((step) => ({
                    location: {
                      ...location({
                        filePath: step.filePath,
                        startLine: step.line,
                        endLine: step.line,
                      }),
                      message: { text: step.description },
                    },
                  })),
                },
              ],
            },
          ],
        }
      : {}),
    ...(finding.status === "suppressed" && finding.suppression
      ? {
          suppressions: [
            {
              kind: finding.suppression.kind === "inline" ? "inSource" : "external",
              justification: finding.suppression.justification,
            },
          ],
        }
      : {}),
  };
}

/**
 * SARIF 2.1.0 log. Suppressed findings are included with a `suppressions` entry so that
 * GitHub shows them as dismissed instead of dropping them.
 */
export function renderSarif(
  result: ScanResult,
  descriptors: readonly RuleDescriptor[] = [],
): string {
  const all = [...result.findings, ...result.suppressed];
  const byId = new Map(descriptors.map((d) => [d.id, d]));
  const usedIds = [...new Set(all.map((f) => f.ruleId))].sort();
  const rules = usedIds.map((id) => {
    const descriptor = byId.get(id);
    const sample = all.find((f) => f.ruleId === id) as Finding;
    const text = descriptor?.description ?? sample.description;
    const severity = descriptor?.severity ?? sample.severity;
    return {
      id,
      name: (descriptor?.name ?? sample.title).replace(/[^A-Za-z0-9]+/g, ""),
      shortDescription: { text: descriptor?.name ?? sample.title },
      fullDescription: { text },
      help: {
        text: `${descriptor?.remediation ?? sample.remediation}\n\nLimitations: ${descriptor?.limitations ?? sample.limitations}`,
      },
      helpUri: (descriptor?.references ?? sample.references)[0],
      defaultConfiguration: { level: LEVEL[severity] },
      properties: {
        category: descriptor?.category ?? sample.category,
        tags: ["security", descriptor?.category ?? sample.category],
        "security-severity": SECURITY_SEVERITY[severity],
        precision: CONFIDENCE_PRECISION[sample.confidence],
      },
    };
  });
  const indexOf = new Map(usedIds.map((id, index) => [id, index]));

  const log = {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "DEVGU",
            version: result.meta.toolVersion,
            semanticVersion: result.meta.toolVersion,
            informationUri: "https://github.com/emirhanhsrc/devgu",
            rules,
          },
        },
        originalUriBaseIds: {
          "%SRCROOT%": { description: { text: "Root of the scanned repository" } },
        },
        automationDetails: { id: `devgu/${result.meta.rulesetVersion}` },
        invocations: [{ executionSuccessful: true, endTimeUtc: result.meta.scannedAt }],
        results: all.map((finding) => resultFor(finding, indexOf.get(finding.ruleId) ?? 0)),
      },
    ],
  };
  return JSON.stringify(log, null, 2) + "\n";
}
