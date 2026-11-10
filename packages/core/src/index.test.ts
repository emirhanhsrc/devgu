import { expect, it } from "vitest";
import { VERSION } from "./index.js";

it("sürüm tanımlı", () => {
  expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
});
