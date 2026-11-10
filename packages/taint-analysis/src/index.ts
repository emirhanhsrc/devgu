import type { Rule, RuleMeta } from "@devgu/rule-engine";
import type { SourceFile } from "@devgu/parser";
import { analyzeTaint, type SinkKind, type SourceReliability, type TaintFlow } from "./engine.js";

export { analyzeTaint } from "./engine.js";
export type { SinkKind, TaintFlow, TaintInfo, FlowStep } from "./engine.js";

const SHARED_LIMITATIONS =
  "Intra-procedural: only flows inside one file are followed, through assignments, destructuring, string operations and a small set of known sources/sanitizers. Values returned from functions, passed as arguments, fetched over the network or guarded by custom validation are not tracked, so a missing finding does not prove safety.";

const CONFIDENCE: Record<SourceReliability, "HIGH" | "MEDIUM" | "LOW"> = {
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
};

const META: Record<SinkKind, Omit<RuleMeta, "engine" | "targets" | "version" | "confidence">> = {
  html: {
    id: "JS-TAINT-001",
    name: "DOM-based XSS: untrusted data reaches an HTML sink",
    description:
      "Data from an attacker-controllable source (URL, window.name, postMessage, input field) flows into an HTML-parsing sink such as innerHTML, document.write or dangerouslySetInnerHTML without a sanitizer for HTML.",
    category: "xss",
    severity: "HIGH",
    remediation:
      "Do not insert untrusted data as HTML. Use textContent / React text nodes, or sanitize with DOMPurify immediately before the sink.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/79.html",
    ],
    limitations: SHARED_LIMITATIONS,
  },
  code: {
    id: "JS-TAINT-002",
    name: "Code injection: untrusted data reaches a code execution sink",
    description:
      "Data from an attacker-controllable source flows into eval(), the Function constructor or a string-based timer, which allows arbitrary script execution.",
    category: "code-execution",
    severity: "CRITICAL",
    remediation:
      "Never evaluate untrusted strings. Parse data with JSON.parse and dispatch with explicit lookup tables.",
    references: ["https://cwe.mitre.org/data/definitions/95.html"],
    limitations: SHARED_LIMITATIONS,
  },
  url: {
    id: "JS-TAINT-003",
    name: "Untrusted data reaches a navigation or link sink",
    description:
      "Data from an attacker-controllable source decides a link or navigation target. This enables open redirects and javascript: URL script execution.",
    category: "url",
    severity: "MEDIUM",
    remediation:
      "Validate the target against an allow-list of paths or origins, and reject any scheme other than http(s), before navigating.",
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/601.html",
    ],
    limitations: `${SHARED_LIMITATIONS} Allow-list checks written as conditions around the sink are not recognised and can cause false positives.`,
  },
};

const cache = new WeakMap<SourceFile, TaintFlow[]>();

function flowsFor(file: SourceFile): TaintFlow[] {
  let flows = cache.get(file);
  if (!flows) {
    flows = analyzeTaint(file);
    cache.set(file, flows);
  }
  return flows;
}

function makeRule(kind: SinkKind): Rule {
  const meta = META[kind];
  return {
    meta: { ...meta, engine: "taint", targets: "ast", version: 1, confidence: "HIGH" },
    check(context) {
      for (const flow of flowsFor(context.file)) {
        if (flow.kind !== kind) continue;
        const steps = [...flow.info.steps, { line: flow.line, description: `Sink: ${flow.sink}` }];
        context.report({
          line: flow.line,
          endLine: flow.endLine,
          confidence: CONFIDENCE[flow.info.reliability],
          title: `${meta.name} (source: ${flow.info.source})`,
          description: `${meta.description} Source: ${flow.info.source}. Sink: ${flow.sink}.`,
          dataFlow: steps.map((step) => ({
            filePath: context.file.relPath,
            line: step.line,
            description: step.description,
          })),
        });
      }
    },
  };
}

export const taintRules: Rule[] = (["html", "code", "url"] as const).map(makeRule);
