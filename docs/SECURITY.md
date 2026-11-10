# DEVGU Threat Model

Scanned repositories are **untrusted input**. DEVGU must never be exploitable by the code it analyses.

| Threat                                     | Mitigation                                                                                   |
| ------------------------------------------ | -------------------------------------------------------------------------------------------- |
| Code execution through scanned project     | Files are only parsed as text. No `require`/`import` of scanned code, no scripts, no shell.  |
| Path traversal / symlink escape            | `lstat` based walk, symlinks are skipped, relative paths verified against the real root.     |
| Resource exhaustion (huge/minified files)  | File-size, file-count, total-size and line-length limits; per-file parse failures isolated.  |
| ReDoS                                      | Linear regexes (no nested quantifiers), bounded quantifiers, per-line length cap.            |
| Malicious config (`devgu.config.json`)     | JSON only, strict schema, size limit, pattern length limit. No code in config.               |
| Cache poisoning / arbitrary file write     | Cache lives in the user cache dir, never in the scanned repo; contents validated by Zod.     |
| XSS via the HTML report                    | Escaped JSON data, `textContent` rendering, CSP with script hash, no external resources.     |
| Terminal escape injection                  | Control characters stripped from every string printed by the text formatter.                 |
| Secret leakage                             | Secrets are redacted at detection time and again on all evidence before output.              |
| Data exfiltration                          | No network access unless `--online`; then only package name/version pairs go to api.osv.dev. |
| Malicious vulnerability database responses | Responses validated with Zod, size and time limited.                                         |
