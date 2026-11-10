// Measures real scan performance on generated repositories. Prints a Markdown table.
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { defaultRedactor, defaultRules, scan } from "../packages/core/dist/index.js";

const SIZES = (process.env.BENCH_SIZES ?? "200,1000,3000").split(",").map(Number);

function fileContent(index) {
  const body = [];
  body.push(`import React from "react";`, `import { helper${index} } from "./f${index}.js";`);
  for (let i = 0; i < 40; i += 1) {
    body.push(
      `export function fn${i}(a, b) { const v = a + b * ${i}; return v > ${i} ? v : helper${index}(v); }`,
    );
  }
  body.push(
    `export const View${index} = ({ items }) => <ul>{items.map((x) => <li key={x.id}>{x.name}</li>)}</ul>;`,
  );
  if (index % 10 === 0)
    body.push(`export function bad(el) { el.innerHTML = location.hash; } // vulnerable on purpose`);
  if (index % 25 === 0) body.push(`const db = { password: "Tr0ub4dor&3xx" };`);
  return body.join("\n") + "\n";
}

async function generate(count) {
  const root = await mkdtemp(path.join(os.tmpdir(), "devgu-bench-"));
  let lines = 0;
  for (let i = 0; i < count; i += 1) {
    const dir = path.join(root, "src", `m${i % 20}`);
    await mkdir(dir, { recursive: true });
    const text = fileContent(i);
    lines += text.split("\n").length;
    await writeFile(path.join(dir, `f${i}.jsx`), text);
  }
  return { root, lines };
}

const cacheDir = await mkdtemp(path.join(os.tmpdir(), "devgu-bench-cache-"));
const rows = [];
for (const count of SIZES) {
  const { root, lines } = await generate(count);
  const options = { root, rules: defaultRules(), redact: defaultRedactor(), cacheDir };
  const cold = await scan({ ...options, useCache: true });
  const warm = await scan({ ...options, useCache: true });
  rows.push({ count, lines, cold, warm });
  await rm(root, { recursive: true, force: true });
}
await rm(cacheDir, { recursive: true, force: true });

console.log(
  `Node ${process.version}, ${os.cpus()[0]?.model.trim()} (${os.cpus().length} logical CPUs), ${os.platform()} ${os.arch()}\n`,
);
console.log(
  "| Files | Lines | Findings | Cold total | Parse | Rules | Heap | Warm total | Cache hits |",
);
console.log("|---:|---:|---:|---:|---:|---:|---:|---:|---:|");
for (const { count, lines, cold, warm } of rows) {
  const s = cold.stats;
  const w = warm.stats;
  console.log(
    `| ${count} | ${lines} | ${cold.findings.length} | ${s.totalMs} ms | ${s.parseMs} ms | ${s.ruleMs} ms | ${s.heapUsedMb} MB | ${w.totalMs} ms | ${w.cacheHits}/${w.cacheHits + w.cacheMisses} |`,
  );
}
