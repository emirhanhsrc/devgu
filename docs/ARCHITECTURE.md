# DEVGU Architecture

DEVGU is a local-first, deterministic static analysis tool. There is no backend, no AI and no
telemetry. Every finding comes from an explicit rule, a data-flow algorithm or a vulnerability
database entry, and carries the evidence that produced it.

## Package layout

| Package                    | Responsibility                                                             | Depends on                  |
| -------------------------- | -------------------------------------------------------------------------- | --------------------------- |
| `@devgu/shared`            | `Finding` model + Zod schemas, severity/confidence, fingerprint, redaction | -                           |
| `@devgu/parser`            | Babel based parsing of JS/TS/JSX/TSX into a `SourceFile` (never throws)    | shared                      |
| `@devgu/rule-engine`       | `Rule` contract, registry, runner, pattern/AST rules (XSS, exec, URL, ...) | shared, parser              |
| `@devgu/secret-scanner`    | Pattern + entropy secret rules, redaction of free text                     | shared, rule-engine         |
| `@devgu/taint-analysis`    | Intra-procedural taint engine and its rules (JS-TAINT-\*)                  | shared, parser, rule-engine |
| `@devgu/dependency-engine` | Lockfile parsing, OSV client, offline vulnerability cache                  | shared                      |
| `@devgu/report-engine`     | JSON, SARIF 2.1.0, Markdown, HTML renderers                                | shared                      |
| `@devgu/core`              | Discovery, config, cache, pipeline, suppression, dedup, stats              | all of the above            |
| `@devgu/cli` (`devgu`)     | Command line interface; thin layer over core                               | core, report-engine         |

Analysis logic never lives in the CLI. Engines never import `core`; `core` composes them.

## Pipeline

1. **Config** - load `devgu.config.json` (JSON only, strict Zod schema, size limited).
2. **Discovery** - walk the root with `lstat`; symlinks are never followed; default and user
   exclusions, size limit, file-count limit, text-only filter.
3. **Cache lookup** - key = SHA-256(content) + configuration fingerprint (tool version, rule-set
   version, enabled rules). Hits skip parsing and rule execution.
4. **Parse** - Babel with error recovery; parse failures become diagnostics, not crashes.
5. **Rule execution** - every enabled rule receives a read-only `SourceFile` and reports through
   a `report()` callback. A throwing rule is isolated and reported as a diagnostic.
6. **Post-processing** - evidence redaction, inline suppression, deduplication
   (taint findings replace the generic pattern finding on the same line), stable sort.
7. **Dependency analysis** - lockfile -> package list -> OSV (cache, optionally online).
8. **Result** - `ScanResult` (findings, suppressed findings, stats, diagnostics, skipped files)
   consumed by the report engine and the CLI exit code logic.

## Finding model

`Finding` fields: `id, ruleId, engine, title, description, severity, confidence, category,
filePath (repo-relative), startLine, endLine, evidence (redacted), remediation, references,
limitations, fingerprint, status, dataFlow?, suppression?`.

- `fingerprint` is `sha256(ruleId | filePath | normalized evidence)` and does not contain line
  numbers, so it survives unrelated edits. For secrets the secret value is part of the hash input
  and is never stored.
- `confidence` expresses how sure the _detection_ is, `severity` how bad the issue would be if
  real. A dangerous-looking API without proven untrusted input is reported with LOW confidence.

## Taint analysis (summary)

Single traversal in source order. A map `Babel Binding -> TaintInfo` is updated by declarations,
assignments, destructuring, object/array literals and property writes (field-insensitive,
may-analysis). `TaintInfo` keeps the flow path and the set of sink kinds it has been sanitized
for (`html`, `url`, `code`). Sinks check the taint and the sanitized set. Straight-line
re-assignment at function-body level is a strong update; anything conditional is a union.

Not modelled: inter-procedural flows (return values, arguments), cross-file flows, aliasing
through containers beyond field-insensitive propagation, async/promise data (`fetch().then`),
getters/proxies, `eval`-ed code. Findings therefore mean "a flow was proven inside one scope
chain", and the absence of a finding does not prove safety.

## Dependency intelligence

`package-lock.json` (v1, v2, v3) -> package list (direct/transitive/dev). OSV `querybatch` for
IDs, `/v1/vulns/{id}` for details. Network access is **off by default**; `--online` enables it for
the single host `api.osv.dev`. Responses are validated, size limited and stored in the local
cache directory, so later offline runs reuse them.

## Reports

JSON (full fidelity), SARIF 2.1.0 (GitHub Code Scanning), Markdown, single-file HTML. The HTML
report is generated defensively because its content originates from untrusted repositories: data
is embedded as escaped JSON, rendered with `textContent` only, and protected by a strict CSP.

## Testing architecture

- Unit tests per package (`*.test.ts` next to the source).
- Every rule has positive, negative and false-positive cases.
- `fixtures/vulnerable` and `fixtures/safe` are scanned end to end with golden assertions; the
  safe fixture must produce no findings.
- Security tests: path traversal, symlinks, hostile report content, secret leakage in output.

## Known limitations

See each rule's `limitations` (`devgu rules explain <id>`). Frontend analysis cannot establish
backend authorization or server-side security.
