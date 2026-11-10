#!/usr/bin/env node
import { main } from "./main.js";

const controller = new AbortController();
process.once("SIGINT", () => controller.abort());

process.exitCode = await main(
  process.argv.slice(2),
  {
    stdout: (text) => void process.stdout.write(text),
    stderr: (text) => void process.stderr.write(text),
    isTTY: process.stdout.isTTY === true,
  },
  controller.signal,
);
