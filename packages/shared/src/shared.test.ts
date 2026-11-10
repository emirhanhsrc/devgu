import { describe, expect, it } from "vitest";
import {
  FindingSchema,
  fingerprint,
  meetsThreshold,
  redactValue,
  stripControlChars,
  truncate,
} from "./index.js";

describe("fingerprint", () => {
  it("is stable and ignores whitespace differences", () => {
    expect(fingerprint("R-1", "a.js", "x  =  1")).toBe(fingerprint("R-1", "a.js", "x = 1"));
  });
  it("changes with rule, file and material", () => {
    const base = fingerprint("R-1", "a.js", "x");
    expect(fingerprint("R-2", "a.js", "x")).not.toBe(base);
    expect(fingerprint("R-1", "b.js", "x")).not.toBe(base);
    expect(fingerprint("R-1", "a.js", "y")).not.toBe(base);
  });
});

describe("redactValue", () => {
  it("never returns the full value", () => {
    const secret = "sk_live_abcdefghijklmnop";
    expect(redactValue(secret)).not.toContain(secret);
    expect(redactValue("short")).toBe("*****");
  });
});

describe("helpers", () => {
  it("compares severities", () => {
    expect(meetsThreshold("HIGH", "MEDIUM")).toBe(true);
    expect(meetsThreshold("LOW", "MEDIUM")).toBe(false);
  });
  it("strips terminal control characters", () => {
    expect(stripControlChars("a\u001b[31mred\u001b[0m\tb\n")).not.toContain("\u001b");
    expect(stripControlChars("a\tb\n")).toBe("a\tb\n");
  });
  it("truncates", () => {
    expect(truncate("abcdef", 4)).toBe("abc…");
    expect(truncate("abc", 4)).toBe("abc");
  });
  it("validates findings strictly", () => {
    expect(FindingSchema.safeParse({ id: "x" }).success).toBe(false);
  });
});
