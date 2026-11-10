import { parse, type ParserPlugin } from "@babel/parser";
import type { File } from "@babel/types";

export type Language = "js" | "jsx" | "ts" | "tsx";

/** A file that has been read and (if it is a script) parsed. Treated as read-only by rules. */
export interface SourceFile {
  /** Repository-relative path with forward slashes. */
  relPath: string;
  source: string;
  lines: string[];
  language: Language | null;
  ast: File | null;
  /** Set when parsing failed completely (ast is null). */
  parseError?: string;
  /** Number of syntax errors Babel recovered from while still producing an AST. */
  recoveredErrors: number;
}

const EXTENSION_LANGUAGE: Record<string, Language> = {
  ".js": "js",
  ".mjs": "js",
  ".cjs": "js",
  ".jsx": "jsx",
  ".ts": "ts",
  ".mts": "ts",
  ".cts": "ts",
  ".tsx": "tsx",
};

export function languageOf(relPath: string): Language | null {
  const dot = relPath.lastIndexOf(".");
  if (dot < 0) return null;
  return EXTENSION_LANGUAGE[relPath.slice(dot).toLowerCase()] ?? null;
}

function pluginsFor(language: Language): ParserPlugin[] {
  switch (language) {
    case "ts":
      return ["typescript"];
    case "tsx":
      return ["typescript", "jsx"];
    default:
      // Plain .js files in React projects routinely contain JSX.
      return ["jsx"];
  }
}

export function splitLines(source: string): string[] {
  return source.split(/\r\n|\r|\n/);
}

/** Never throws. Syntax errors are recovered where possible, otherwise reported in parseError. */
export function createSourceFile(relPath: string, source: string): SourceFile {
  const language = languageOf(relPath);
  const base: SourceFile = {
    relPath,
    source,
    lines: splitLines(source),
    language,
    ast: null,
    recoveredErrors: 0,
  };
  if (!language) return base;
  try {
    const ast = parse(source, {
      sourceType: "unambiguous",
      errorRecovery: true,
      allowReturnOutsideFunction: true,
      allowAwaitOutsideFunction: true,
      plugins: pluginsFor(language),
    });
    const errors = (ast as File & { errors?: unknown[] }).errors;
    return { ...base, ast, recoveredErrors: Array.isArray(errors) ? errors.length : 0 };
  } catch (error) {
    return { ...base, parseError: error instanceof Error ? error.message : String(error) };
  }
}
