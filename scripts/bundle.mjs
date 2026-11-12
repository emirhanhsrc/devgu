// Builds the publishable package in dist-bundle/: one self-contained file plus package metadata.
//   npm run build && npm run bundle && npm pack ./dist-bundle --dry-run
import { build } from "esbuild";
import { copyFile, readFile, writeFile } from "node:fs/promises";

const root = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

await build({
  entryPoints: ["apps/cli/src/index.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: "dist-bundle/devgu.mjs",
  legalComments: "none",
  banner: {
    js: [
      "import { createRequire as __devguCreateRequire } from 'node:module';",
      "const require = __devguCreateRequire(import.meta.url);",
    ].join("\n"),
  },
  logLevel: "info",
});

const manifest = {
  name: "devgu",
  version: root.version,
  description: root.description,
  license: "MIT",
  type: "module",
  bin: { devgu: "devgu.mjs" },
  files: ["devgu.mjs", "README.md", "LICENSE"],
  engines: { node: ">=20" },
  repository: root.repository,
  keywords: [
    "security",
    "sast",
    "static-analysis",
    "taint-analysis",
    "xss",
    "secrets",
    "sarif",
    "react",
    "mcp",
    "model-context-protocol",
  ],
};
await writeFile(
  new URL("../dist-bundle/package.json", import.meta.url),
  JSON.stringify(manifest, null, 2) + "\n",
);
await copyFile(
  new URL("../README.md", import.meta.url),
  new URL("../dist-bundle/README.md", import.meta.url),
);
await copyFile(
  new URL("../LICENSE", import.meta.url),
  new URL("../dist-bundle/LICENSE", import.meta.url),
);
