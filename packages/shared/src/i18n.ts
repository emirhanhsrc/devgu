/**
 * Internationalisation (i18n) for DEVGU output.
 *
 * Two kinds of text are localised:
 *  - Rule metadata (name / description / remediation / limitations) lives next to each rule as a
 *    {@link LocalizedString} so a rule and its translations never drift apart.
 *  - Dynamic fragments and report/CLI chrome live in the central {@link MESSAGES} catalogue below.
 *
 * The chosen language is fixed at scan time: findings store already-resolved strings, which keeps
 * the output deterministic and the serialized result self-describing (see `ScanMeta.lang`).
 */

export const LANGS = ["en", "tr"] as const;
export type Lang = (typeof LANGS)[number];

/** Language used whenever none is given or an unknown value is resolved. */
export const DEFAULT_LANG: Lang = "en";

export function isLang(value: unknown): value is Lang {
  return typeof value === "string" && (LANGS as readonly string[]).includes(value);
}

/** Coerces arbitrary input (CLI flag, config value) to a supported language. */
export function normalizeLang(value: unknown): Lang {
  if (typeof value === "string") {
    const lower = value.toLowerCase().split(/[-_]/)[0];
    if (isLang(lower)) return lower;
  }
  return DEFAULT_LANG;
}

/**
 * A string that is either language-independent (a plain string) or a per-language map. A partial
 * map is allowed; {@link loc} falls back to English and then to any available translation, so a
 * missing locale degrades gracefully instead of printing `undefined`.
 */
export type LocalizedString = string | Partial<Record<Lang, string>>;

/** Resolves a {@link LocalizedString} for `lang`, falling back to English then any other locale. */
export function loc(value: LocalizedString, lang: Lang): string {
  if (typeof value === "string") return value;
  const direct = value[lang];
  if (direct !== undefined) return direct;
  if (value.en !== undefined) return value.en;
  for (const l of LANGS) {
    const v = value[l];
    if (v !== undefined) return v;
  }
  return "";
}

interface Messages {
  /** Taint data-flow step descriptions. */
  flow: {
    source: (label: string) => string;
    sink: (label: string) => string;
    interpolated: string;
    concatenated: string;
    passedThrough: (name: string) => string;
    sanitized: (name: string, neutralizes: string) => string;
    resultOf: (method: string) => string;
    assignedTo: (name: string) => string;
    storedIn: (name: string) => string;
  };
  /** Taint composed finding description: base description + source/sink summary. */
  taintSummary: (description: string, source: string, sink: string) => string;
  /** Dependency-audit composed finding description. */
  dep: {
    direct: string;
    transitive: string;
    devOnly: string;
    installedTimes: (n: number) => string;
    severityAssumed: string;
    upgrade: (name: string, versions: string) => string;
    /** Builds the full description from its parts. */
    description: (parts: {
      summary: string;
      id: string;
      direct: boolean;
      devOnly: boolean;
      installCount: number;
      severityKnown: boolean;
    }) => string;
  };
  /** Single-file HTML / Markdown / text report chrome. */
  report: {
    tagline: string;
    repository: string;
    scannedAt: string;
    scannerVersion: string;
    ruleSet: string;
    engines: string;
    enabledRules: string;
    findings: string;
    search: string;
    searchPlaceholder: string;
    severity: string;
    confidence: string;
    category: string;
    engine: string;
    all: string;
    showSuppressed: string;
    showingCount: (shown: number, total: number) => string;
    noFindingsMatch: string;
    confidenceLabel: (c: string) => string;
    whatWasDetected: string;
    evidence: string;
    dataFlow: string;
    remediation: string;
    references: string;
    limitations: string;
    suppressed: string;
    noFindings: string;
    reportTitle: (name: string) => string;
    summaryHeading: string;
    fileHeading: string;
    severityCounts: string;
    // Markdown report chrome
    reportHeading: string;
    filesScanned: string;
    filesScannedValue: (scanned: number, skipped: number) => string;
    duration: string;
    findingsColumn: string;
    openSuppressed: (open: number, suppressed: number) => string;
    location: string;
    rule: string;
    ruleLine: (id: string, category: string, engine: string) => string;
    severityConfidence: string;
    suppressedHeading: string;
    diagnosticsHeading: string;
    suppressedKind: (kind: string) => string;
    evidenceLabel: string;
    dataFlowLabel: string;
  };
  /** Terminal (text) report summary lines. */
  text: {
    findingsLine: (count: number, counts: string, suppressed: number) => string;
    filesLine: (
      scanned: number,
      skipped: number,
      hits: number,
      total: number,
      ms: number,
    ) => string;
    warning: string;
  };
  /** CLI help, messages and exit reasons. */
  cli: {
    help: string;
    notADirectory: (p: string) => string;
    noRulesMatch: string;
    cacheCleared: (p: string) => string;
    configWritten: (p: string) => string;
    configExists: (p: string) => string;
    scanning: string;
    unknownLang: (v: string) => string;
    rulesHeading: string;
    ruleNotFound: (id: string) => string;
  };
}

const EN: Messages = {
  flow: {
    source: (label) => `Source: ${label}`,
    sink: (label) => `Sink: ${label}`,
    interpolated: "Interpolated into a template string",
    concatenated: "Concatenated into a string",
    passedThrough: (name) => `Passed through ${name}()`,
    sanitized: (name, neutralizes) => `Passed through ${name}() (neutralizes ${neutralizes})`,
    resultOf: (method) => `Result of .${method}()`,
    assignedTo: (name) => `Assigned to '${name}'`,
    storedIn: (name) => `Stored in '${name}'`,
  },
  taintSummary: (description, source, sink) => `${description} Source: ${source}. Sink: ${sink}.`,
  dep: {
    direct: "Direct",
    transitive: "Transitive",
    devOnly: " (development only)",
    installedTimes: (n) => `, installed ${n} times`,
    severityAssumed: " The advisory has no usable severity; MEDIUM is assumed.",
    upgrade: (name, versions) => `Upgrade ${name} to ${versions} (or later).`,
    description: ({ summary, id, direct, devOnly, installCount, severityKnown }) =>
      `${summary} (${id}). ${direct ? "Direct" : "Transitive"} dependency` +
      `${devOnly ? " (development only)" : ""}` +
      `${installCount > 1 ? `, installed ${installCount} times` : ""}.` +
      `${severityKnown ? "" : " The advisory has no usable severity; MEDIUM is assumed."}`,
  },
  report: {
    tagline: "Understand Your Code. Secure Your Software.",
    repository: "Repository",
    scannedAt: "Scanned at",
    scannerVersion: "Scanner version",
    ruleSet: "Rule set",
    engines: "Engines",
    enabledRules: "Enabled rules",
    findings: "Findings",
    search: "Search",
    searchPlaceholder: "rule, file, text",
    severity: "Severity",
    confidence: "Confidence",
    category: "Category",
    engine: "Engine",
    all: "All",
    showSuppressed: "Show suppressed",
    showingCount: (shown, total) => `Showing ${shown} of ${total} finding(s)`,
    noFindingsMatch: "No findings match the current filters.",
    confidenceLabel: (c) => `${c} confidence`,
    whatWasDetected: "What was detected",
    evidence: "Evidence",
    dataFlow: "Data flow (source to sink)",
    remediation: "How to fix",
    references: "References",
    limitations: "Limitations",
    suppressed: "Suppressed",
    noFindings:
      "No findings. This does not prove the code is secure; see each engine's limitations.",
    reportTitle: (name) => `DEVGU report - ${name}`,
    summaryHeading: "Summary",
    fileHeading: "Findings by file",
    severityCounts: "Severity",
    reportHeading: "DEVGU report",
    filesScanned: "Files scanned",
    filesScannedValue: (scanned, skipped) => `${scanned} (${skipped} skipped)`,
    duration: "Duration",
    findingsColumn: "Findings",
    openSuppressed: (open, suppressed) => `${open} open finding(s), ${suppressed} suppressed.`,
    location: "Location",
    rule: "Rule",
    ruleLine: (id, category, engine) => `${id} (${category}, engine ${engine})`,
    severityConfidence: "Severity / confidence",
    suppressedHeading: "Suppressed findings",
    diagnosticsHeading: "Diagnostics",
    suppressedKind: (kind) => `Suppressed (${kind})`,
    evidenceLabel: "Evidence:",
    dataFlowLabel: "Data flow:",
  },
  text: {
    findingsLine: (count, counts, suppressed) =>
      `${count} finding(s)${counts ? ` (${counts})` : ""}, ${suppressed} suppressed`,
    filesLine: (scanned, skipped, hits, total, ms) =>
      `${scanned} file(s) scanned, ${skipped} skipped, cache ${hits}/${total}, ${ms} ms`,
    warning: "warning",
  },
  cli: {
    help: "",
    notADirectory: (p) => `Not a directory: ${p}`,
    noRulesMatch: "No rules match.",
    cacheCleared: (p) => `Cache cleared: ${p}`,
    configWritten: (p) => `Wrote ${p}`,
    configExists: (p) => `${p} already exists; not overwriting.`,
    scanning: "Scanning",
    unknownLang: (v) => `Unknown language '${v}'. Supported: ${LANGS.join(", ")}.`,
    rulesHeading: "Rules",
    ruleNotFound: (id) => `Rule not found: ${id}`,
  },
};

const TR: Messages = {
  flow: {
    source: (label) => `Kaynak: ${label}`,
    sink: (label) => `Hedef (sink): ${label}`,
    interpolated: "Şablon dizgesine (template string) yerleştirildi",
    concatenated: "Dizgeye birleştirildi",
    passedThrough: (name) => `${name}() fonksiyonundan geçti`,
    sanitized: (name, neutralizes) =>
      `${name}() fonksiyonundan geçti (${neutralizes} için etkisizleştirir)`,
    resultOf: (method) => `.${method}() çağrısının sonucu`,
    assignedTo: (name) => `'${name}' değişkenine atandı`,
    storedIn: (name) => `'${name}' içinde saklandı`,
  },
  taintSummary: (description, source, sink) => `${description} Kaynak: ${source}. Hedef: ${sink}.`,
  dep: {
    direct: "Doğrudan",
    transitive: "Dolaylı",
    devOnly: " (yalnızca geliştirme bağımlılığı)",
    installedTimes: (n) => `, ${n} kez kurulu`,
    severityAssumed: " Danışma kaydında kullanılabilir şiddet yok; MEDIUM varsayıldı.",
    upgrade: (name, versions) => `${name} paketini ${versions} (veya sonrasına) yükseltin.`,
    description: ({ summary, id, direct, devOnly, installCount, severityKnown }) =>
      `${summary} (${id}). ${direct ? "Doğrudan" : "Dolaylı"} bağımlılık` +
      `${devOnly ? " (yalnızca geliştirme bağımlılığı)" : ""}` +
      `${installCount > 1 ? `, ${installCount} kez kurulu` : ""}.` +
      `${severityKnown ? "" : " Danışma kaydında kullanılabilir şiddet yok; MEDIUM varsayıldı."}`,
  },
  report: {
    tagline: "Kodunuzu Anlayın. Yazılımınızı Güvenceye Alın.",
    repository: "Depo",
    scannedAt: "Tarama zamanı",
    scannerVersion: "Tarayıcı sürümü",
    ruleSet: "Kural seti",
    engines: "Motorlar",
    enabledRules: "Etkin kural",
    findings: "Bulgular",
    search: "Ara",
    searchPlaceholder: "kural, dosya, metin",
    severity: "Şiddet",
    confidence: "Güven",
    category: "Kategori",
    engine: "Motor",
    all: "Tümü",
    showSuppressed: "Bastırılanları göster",
    showingCount: (shown, total) => `${total} bulgunun ${shown} tanesi gösteriliyor`,
    noFindingsMatch: "Geçerli filtrelerle eşleşen bulgu yok.",
    confidenceLabel: (c) => `${c} güven`,
    whatWasDetected: "Ne tespit edildi",
    evidence: "Kanıt",
    dataFlow: "Veri akışı (kaynaktan hedefe)",
    remediation: "Nasıl düzeltilir",
    references: "Kaynaklar",
    limitations: "Sınırlamalar",
    suppressed: "Bastırıldı",
    noFindings:
      "Bulgu yok. Bu, kodun güvenli olduğunu kanıtlamaz; her motorun sınırlamalarına bakın.",
    reportTitle: (name) => `DEVGU raporu - ${name}`,
    summaryHeading: "Özet",
    fileHeading: "Dosyaya göre bulgular",
    severityCounts: "Şiddet",
    reportHeading: "DEVGU raporu",
    filesScanned: "Taranan dosya",
    filesScannedValue: (scanned, skipped) => `${scanned} (${skipped} atlandı)`,
    duration: "Süre",
    findingsColumn: "Bulgu",
    openSuppressed: (open, suppressed) => `${open} açık bulgu, ${suppressed} bastırıldı.`,
    location: "Konum",
    rule: "Kural",
    ruleLine: (id, category, engine) => `${id} (${category}, ${engine} motoru)`,
    severityConfidence: "Şiddet / güven",
    suppressedHeading: "Bastırılan bulgular",
    diagnosticsHeading: "Tanılama",
    suppressedKind: (kind) => `Bastırıldı (${kind})`,
    evidenceLabel: "Kanıt:",
    dataFlowLabel: "Veri akışı:",
  },
  text: {
    findingsLine: (count, counts, suppressed) =>
      `${count} bulgu${counts ? ` (${counts})` : ""}, ${suppressed} bastırıldı`,
    filesLine: (scanned, skipped, hits, total, ms) =>
      `${scanned} dosya tarandı, ${skipped} atlandı, önbellek ${hits}/${total}, ${ms} ms`,
    warning: "uyarı",
  },
  cli: {
    help: "",
    notADirectory: (p) => `Bir dizin değil: ${p}`,
    noRulesMatch: "Eşleşen kural yok.",
    cacheCleared: (p) => `Önbellek temizlendi: ${p}`,
    configWritten: (p) => `${p} yazıldı`,
    configExists: (p) => `${p} zaten var; üzerine yazılmadı.`,
    scanning: "Taranıyor",
    unknownLang: (v) => `Bilinmeyen dil '${v}'. Desteklenen: ${LANGS.join(", ")}.`,
    rulesHeading: "Kurallar",
    ruleNotFound: (id) => `Kural bulunamadı: ${id}`,
  },
};

const CATALOGUE: Record<Lang, Messages> = { en: EN, tr: TR };

/** Returns the message catalogue for `lang`. */
export function messages(lang: Lang): Messages {
  return CATALOGUE[lang] ?? EN;
}

/**
 * Chrome for the single-file HTML report. Split into labels baked into the static document and
 * labels serialized to the embedded client (templates use `{placeholder}` tokens the client
 * replaces, since it cannot run format functions).
 */
export interface HtmlStrings {
  htmlLang: string;
  titlePrefix: string;
  tagline: string;
  // Meta labels
  repository: string;
  scannedAt: string;
  scannerVersion: string;
  ruleSet: string;
  engines: string;
  enabledRules: string;
  // Section headings and filters
  findings: string;
  search: string;
  searchPlaceholder: string;
  severity: string;
  confidence: string;
  category: string;
  engine: string;
  all: string;
  showSuppressed: string;
  diagnosticsHeading: string;
  statsHeading: string;
  footer: string;
  scanInfoAria: string;
  findingsAria: string;
  // Client-rendered (serialized into data.strings)
  client: {
    whatDetected: string;
    evidence: string;
    dataFlow: string;
    howToFix: string;
    limitationsDetail: string;
    references: string;
    filesScanned: string;
    filesSkipped: string;
    cacheHits: string;
    parseTime: string;
    ruleTime: string;
    totalTime: string;
    heapUsed: string;
    fingerprintLabel: string;
    /** `{c}` → confidence level. */
    confidenceTpl: string;
    /** `{shown}`, `{total}`. */
    showingTpl: string;
    /** `{kind}`. */
    suppressedTpl: string;
    /** `{file}`, `{reason}`. */
    skippedTpl: string;
    noFindings: string;
    noMatch: string;
  };
}

const HTML_EN: HtmlStrings = {
  htmlLang: "en",
  titlePrefix: "DEVGU report",
  tagline: "Understand Your Code. Secure Your Software.",
  repository: "Repository",
  scannedAt: "Scanned at",
  scannerVersion: "Scanner version",
  ruleSet: "Rule set",
  engines: "Engines",
  enabledRules: "Enabled rules",
  findings: "Findings",
  search: "Search",
  searchPlaceholder: "rule, file, text",
  severity: "Severity",
  confidence: "Confidence",
  category: "Category",
  engine: "Engine",
  all: "All",
  showSuppressed: "Show suppressed",
  diagnosticsHeading: "Diagnostics and skipped files",
  statsHeading: "Scan statistics",
  footer:
    "Generated by DEVGU. Findings come from deterministic rules; each lists its limitations. No data left this machine to produce this report.",
  scanInfoAria: "Scan information",
  findingsAria: "Findings",
  client: {
    whatDetected: "What was detected",
    evidence: "Evidence",
    dataFlow: "Data flow (source to sink)",
    howToFix: "How to fix",
    limitationsDetail: "Limitations of this detection",
    references: "References",
    filesScanned: "Files scanned",
    filesSkipped: "Files skipped",
    cacheHits: "Cache hits",
    parseTime: "Parse time",
    ruleTime: "Rule time",
    totalTime: "Total time",
    heapUsed: "Heap used",
    fingerprintLabel: "Fingerprint",
    confidenceTpl: "{c} confidence",
    showingTpl: "Showing {shown} of {total} finding(s)",
    suppressedTpl: "Suppressed ({kind})",
    skippedTpl: "Skipped {file} ({reason})",
    noFindings: "No findings. This does not prove the code is safe; see each rule's limitations.",
    noMatch: "No findings match the current filters.",
  },
};

const HTML_TR: HtmlStrings = {
  htmlLang: "tr",
  titlePrefix: "DEVGU raporu",
  tagline: "Kodunuzu Anlayın. Yazılımınızı Güvenceye Alın.",
  repository: "Depo",
  scannedAt: "Tarama zamanı",
  scannerVersion: "Tarayıcı sürümü",
  ruleSet: "Kural seti",
  engines: "Motorlar",
  enabledRules: "Etkin kural",
  findings: "Bulgular",
  search: "Ara",
  searchPlaceholder: "kural, dosya, metin",
  severity: "Şiddet",
  confidence: "Güven",
  category: "Kategori",
  engine: "Motor",
  all: "Tümü",
  showSuppressed: "Bastırılanları göster",
  diagnosticsHeading: "Tanılama ve atlanan dosyalar",
  statsHeading: "Tarama istatistikleri",
  footer:
    "DEVGU tarafından üretildi. Bulgular deterministik kurallardan gelir; her biri sınırlamalarını listeler. Bu raporu üretmek için hiçbir veri bu makineden çıkmadı.",
  scanInfoAria: "Tarama bilgisi",
  findingsAria: "Bulgular",
  client: {
    whatDetected: "Ne tespit edildi",
    evidence: "Kanıt",
    dataFlow: "Veri akışı (kaynaktan hedefe)",
    howToFix: "Nasıl düzeltilir",
    limitationsDetail: "Bu tespitin sınırlamaları",
    references: "Kaynaklar",
    filesScanned: "Taranan dosya",
    filesSkipped: "Atlanan dosya",
    cacheHits: "Önbellek isabeti",
    parseTime: "Ayrıştırma süresi",
    ruleTime: "Kural süresi",
    totalTime: "Toplam süre",
    heapUsed: "Kullanılan bellek",
    fingerprintLabel: "Parmak izi",
    confidenceTpl: "{c} güven",
    showingTpl: "{total} bulgunun {shown} tanesi gösteriliyor",
    suppressedTpl: "Bastırıldı ({kind})",
    skippedTpl: "Atlandı: {file} ({reason})",
    noFindings:
      "Bulgu yok. Bu, kodun güvenli olduğunu kanıtlamaz; her kuralın sınırlamalarına bakın.",
    noMatch: "Geçerli filtrelerle eşleşen bulgu yok.",
  },
};

const HTML_CATALOGUE: Record<Lang, HtmlStrings> = { en: HTML_EN, tr: HTML_TR };

/** Returns the HTML report chrome for `lang`. */
export function htmlStrings(lang: Lang): HtmlStrings {
  return HTML_CATALOGUE[lang] ?? HTML_EN;
}
