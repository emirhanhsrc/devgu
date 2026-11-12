import { describe, expect, it } from "vitest";
import {
  DEFAULT_LANG,
  htmlStrings,
  isLang,
  LANGS,
  loc,
  messages,
  normalizeLang,
  type LocalizedString,
} from "./i18n.js";

describe("i18n core", () => {
  it("recognises supported languages", () => {
    expect(isLang("en")).toBe(true);
    expect(isLang("tr")).toBe(true);
    expect(isLang("de")).toBe(false);
    expect(isLang(42)).toBe(false);
  });

  it("normalises arbitrary input to a supported language", () => {
    expect(normalizeLang("TR")).toBe("tr");
    expect(normalizeLang("tr-TR")).toBe("tr");
    expect(normalizeLang("en_US")).toBe("en");
    expect(normalizeLang("fr")).toBe(DEFAULT_LANG);
    expect(normalizeLang(undefined)).toBe(DEFAULT_LANG);
  });

  it("resolves a plain string for any language", () => {
    expect(loc("same", "tr")).toBe("same");
    expect(loc("same", "en")).toBe("same");
  });

  it("resolves per-language maps and falls back to English", () => {
    const value: LocalizedString = { en: "hello", tr: "merhaba" };
    expect(loc(value, "tr")).toBe("merhaba");
    expect(loc(value, "en")).toBe("hello");
    // Missing locale falls back to English, then to any available translation.
    expect(loc({ en: "only-en" }, "tr")).toBe("only-en");
    expect(loc({ tr: "only-tr" }, "en")).toBe("only-tr");
    expect(loc({}, "en")).toBe("");
  });

  it("provides a catalogue for every language, distinct from English", () => {
    for (const lang of LANGS) {
      expect(messages(lang).report.findings.length).toBeGreaterThan(0);
      expect(htmlStrings(lang).client.evidence.length).toBeGreaterThan(0);
    }
    expect(messages("tr").report.findings).not.toBe(messages("en").report.findings);
    expect(htmlStrings("tr").tagline).not.toBe(htmlStrings("en").tagline);
  });

  it("keeps template placeholders in both languages so the client can fill them", () => {
    for (const lang of LANGS) {
      const c = htmlStrings(lang).client;
      expect(c.showingTpl).toContain("{shown}");
      expect(c.showingTpl).toContain("{total}");
      expect(c.confidenceTpl).toContain("{c}");
      expect(c.suppressedTpl).toContain("{kind}");
      expect(c.skippedTpl).toContain("{file}");
      expect(c.skippedTpl).toContain("{reason}");
    }
  });
});
