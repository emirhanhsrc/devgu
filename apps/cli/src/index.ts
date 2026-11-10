#!/usr/bin/env node
import { VERSION } from "@devgu/core";

const [command] = process.argv.slice(2);
if (command === "version") {
  console.log(VERSION);
} else {
  console.error("Kullanım: devgu version");
  process.exit(command ? 2 : 0);
}
