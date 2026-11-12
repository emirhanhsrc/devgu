/**
 * Minified bundles are a handful of enormous lines, which the scanner's line-based rules cannot
 * cope with (and its secret detector only reads the first few KB of a line). This inserts line
 * breaks after `;`, `,` and `}` that are outside strings and comments. A line break at those
 * points never changes how JavaScript parses, except right after return/throw, which are never
 * followed directly by one of those characters.
 */
const LONG_LINE = 2000;
const WRAP_AT = 200;

function splitLine(line: string): string {
  let out = "";
  let quote = "";
  let col = 0;
  let mode: "code" | "line-comment" | "block-comment" = "code";
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i] as string;
    out += ch;
    col += 1;
    if (mode === "line-comment") continue;
    if (mode === "block-comment") {
      if (ch === "*" && line[i + 1] === "/") {
        out += "/";
        i += 1;
        mode = "code";
      }
      continue;
    }
    if (quote) {
      if (ch === "\\") {
        out += line[i + 1] ?? "";
        i += 1;
        col += 1;
      } else if (ch === quote) quote = "";
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") quote = ch;
    else if (ch === "/" && line[i + 1] === "/") mode = "line-comment";
    else if (ch === "/" && line[i + 1] === "*") mode = "block-comment";
    else if (col >= WRAP_AT && (ch === ";" || ch === "," || ch === "}")) {
      out += "\n";
      col = 0;
    }
  }
  return out;
}

export function prettifyMinified(text: string): string {
  if (!text.split("\n").some((l) => l.length > LONG_LINE)) return text;
  return text
    .split("\n")
    .map((l) => (l.length > LONG_LINE ? splitLine(l) : l))
    .join("\n");
}
