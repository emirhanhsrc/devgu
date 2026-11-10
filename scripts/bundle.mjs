// Bundles the CLI and all workspace packages into one self-contained file: dist-bundle/devgu.mjs
import { build } from "esbuild";

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
