import type { Rule, RuleMeta } from "@devgu/rule-engine";
import type { SourceFile } from "@devgu/parser";
import { loc, messages, type FlowStep as ReportFlowStep, type Lang } from "@devgu/shared";
import {
  analyzeTaint,
  type FlowStep,
  type SinkKind,
  type SourceReliability,
  type TaintFlow,
} from "./engine.js";

export { analyzeTaint } from "./engine.js";
export type { SinkKind, TaintFlow, TaintInfo, FlowStep, StepDescriptor } from "./engine.js";

const SHARED_LIMITATIONS = {
  en: "Intra-procedural: only flows inside one file are followed, through assignments, destructuring, string operations and a small set of known sources/sanitizers. Values returned from functions, passed as arguments, fetched over the network or guarded by custom validation are not tracked, so a missing finding does not prove safety.",
  tr: "Prosedür içi (intra-procedural): yalnızca tek dosya içindeki akışlar izlenir; atamalar, yapı bozma, dizge işlemleri ve küçük bir bilinen kaynak/temizleyici kümesi üzerinden. Fonksiyonlardan dönen, argüman olarak geçirilen, ağ üzerinden getirilen veya özel doğrulamayla korunan değerler izlenmez; bu yüzden eksik bir bulgu güvenliği kanıtlamaz.",
};

const CONFIDENCE: Record<SourceReliability, "HIGH" | "MEDIUM" | "LOW"> = {
  HIGH: "HIGH",
  MEDIUM: "MEDIUM",
  LOW: "LOW",
};

const META: Record<SinkKind, Omit<RuleMeta, "engine" | "targets" | "version" | "confidence">> = {
  html: {
    id: "JS-TAINT-001",
    name: {
      en: "DOM-based XSS: untrusted data reaches an HTML sink",
      tr: "DOM tabanlı XSS: güvenilmez veri bir HTML hedefine ulaşıyor",
    },
    description: {
      en: "Data from an attacker-controllable source (URL, window.name, postMessage, input field) flows into an HTML-parsing sink such as innerHTML, document.write or dangerouslySetInnerHTML without a sanitizer for HTML.",
      tr: "Saldırgan denetimindeki bir kaynaktan (URL, window.name, postMessage, girdi alanı) gelen veri, HTML için temizleyici olmadan innerHTML, document.write veya dangerouslySetInnerHTML gibi HTML ayrıştıran bir hedefe akıyor.",
    },
    category: "xss",
    severity: "HIGH",
    remediation: {
      en: "Do not insert untrusted data as HTML. Use textContent / React text nodes, or sanitize with DOMPurify immediately before the sink.",
      tr: "Güvenilmez veriyi HTML olarak eklemeyin. textContent / React metin düğümleri kullanın ya da hedeften hemen önce DOMPurify ile temizleyin.",
    },
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/79.html",
    ],
    limitations: SHARED_LIMITATIONS,
  },
  code: {
    id: "JS-TAINT-002",
    name: {
      en: "Code injection: untrusted data reaches a code execution sink",
      tr: "Kod enjeksiyonu: güvenilmez veri bir kod yürütme hedefine ulaşıyor",
    },
    description: {
      en: "Data from an attacker-controllable source flows into eval(), the Function constructor or a string-based timer, which allows arbitrary script execution.",
      tr: "Saldırgan denetimindeki bir kaynaktan gelen veri eval(), Function yapıcısı veya dizge tabanlı bir zamanlayıcıya akıyor; bu, keyfi betik yürütülmesine olanak tanır.",
    },
    category: "code-execution",
    severity: "CRITICAL",
    remediation: {
      en: "Never evaluate untrusted strings. Parse data with JSON.parse and dispatch with explicit lookup tables.",
      tr: "Güvenilmez dizgeleri asla değerlendirmeyin. Veriyi JSON.parse ile ayrıştırın ve açık arama tablolarıyla yönlendirin.",
    },
    references: ["https://cwe.mitre.org/data/definitions/95.html"],
    limitations: SHARED_LIMITATIONS,
  },
  url: {
    id: "JS-TAINT-003",
    name: {
      en: "Untrusted data reaches a navigation or link sink",
      tr: "Güvenilmez veri bir gezinme veya bağlantı hedefine ulaşıyor",
    },
    description: {
      en: "Data from an attacker-controllable source decides a link or navigation target. This enables open redirects and javascript: URL script execution.",
      tr: "Saldırgan denetimindeki bir kaynaktan gelen veri, bir bağlantı veya gezinme hedefini belirliyor. Bu, açık yönlendirmelere ve javascript: URL betik yürütülmesine olanak tanır.",
    },
    category: "url",
    severity: "MEDIUM",
    remediation: {
      en: "Validate the target against an allow-list of paths or origins, and reject any scheme other than http(s), before navigating.",
      tr: "Gezinmeden önce hedefi bir yol/origin izin listesiyle doğrulayın ve http(s) dışındaki her şemayı reddedin.",
    },
    references: [
      "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
      "https://cwe.mitre.org/data/definitions/601.html",
    ],
    limitations: {
      en: `${SHARED_LIMITATIONS.en} Allow-list checks written as conditions around the sink are not recognised and can cause false positives.`,
      tr: `${SHARED_LIMITATIONS.tr} Hedefin çevresinde koşul olarak yazılan izin listesi denetimleri tanınmaz ve yanlış pozitiflere yol açabilir.`,
    },
  },
};

/** Renders one language-neutral flow step into human text for `lang`. */
function renderStep(step: FlowStep, lang: Lang): string {
  const m = messages(lang).flow;
  switch (step.kind) {
    case "source":
      return m.source(step.label);
    case "sink":
      return m.sink(step.label);
    case "interpolated":
      return m.interpolated;
    case "concatenated":
      return m.concatenated;
    case "passedThrough":
      return m.passedThrough(step.name);
    case "sanitized":
      return m.sanitized(step.name, step.neutralizes);
    case "resultOf":
      return m.resultOf(step.method);
    case "assignedTo":
      return m.assignedTo(step.name);
    case "storedIn":
      return m.storedIn(step.name);
  }
}

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
      const lang = context.lang;
      const name = loc(meta.name, lang);
      const description = loc(meta.description, lang);
      for (const flow of flowsFor(context.file)) {
        if (flow.kind !== kind) continue;
        const steps: FlowStep[] = [
          ...flow.info.steps,
          { line: flow.line, kind: "sink", label: flow.sink },
        ];
        const dataFlow: ReportFlowStep[] = steps.map((step) => ({
          filePath: context.file.relPath,
          line: step.line,
          description: renderStep(step, lang),
        }));
        context.report({
          line: flow.line,
          endLine: flow.endLine,
          confidence: CONFIDENCE[flow.info.reliability],
          title: `${name} (${lang === "tr" ? "kaynak" : "source"}: ${flow.info.source})`,
          description: messages(lang).taintSummary(description, flow.info.source, flow.sink),
          dataFlow,
        });
      }
    },
  };
}

export const taintRules: Rule[] = (["html", "code", "url"] as const).map(makeRule);
