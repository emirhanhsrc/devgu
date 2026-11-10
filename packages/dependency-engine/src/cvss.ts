import type { Severity } from "@devgu/shared";

const WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  CIA: { H: 0.56, L: 0.22, N: 0 },
} as const;

function roundUp(value: number): number {
  const int = Math.round(value * 100000);
  return int % 10000 === 0 ? int / 100000 : (Math.floor(int / 10000) + 1) / 10;
}

/** CVSS v3.x base score from a vector string, or null if it is not a valid v3 vector. */
export function cvss3BaseScore(vector: string): number | null {
  if (!/^CVSS:3\.[01]\//.test(vector)) return null;
  const metrics = new Map<string, string>();
  for (const part of vector.split("/").slice(1)) {
    const [key, value] = part.split(":");
    if (key && value) metrics.set(key, value);
  }
  const av = WEIGHTS.AV[metrics.get("AV") as keyof typeof WEIGHTS.AV];
  const ac = WEIGHTS.AC[metrics.get("AC") as keyof typeof WEIGHTS.AC];
  const ui = WEIGHTS.UI[metrics.get("UI") as keyof typeof WEIGHTS.UI];
  const scope = metrics.get("S");
  const c = WEIGHTS.CIA[metrics.get("C") as keyof typeof WEIGHTS.CIA];
  const i = WEIGHTS.CIA[metrics.get("I") as keyof typeof WEIGHTS.CIA];
  const a = WEIGHTS.CIA[metrics.get("A") as keyof typeof WEIGHTS.CIA];
  const privilege = metrics.get("PR");
  if ([av, ac, ui, c, i, a].some((v) => v === undefined) || (scope !== "U" && scope !== "C"))
    return null;
  const changed = scope === "C";
  const pr =
    privilege === "N"
      ? 0.85
      : privilege === "L"
        ? changed
          ? 0.68
          : 0.62
        : privilege === "H"
          ? changed
            ? 0.5
            : 0.27
          : undefined;
  if (pr === undefined) return null;
  const iss = 1 - (1 - c!) * (1 - i!) * (1 - a!);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av! * ac! * pr * ui!;
  return roundUp(
    Math.min(changed ? 1.08 * (impact + exploitability) : impact + exploitability, 10),
  );
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
}
