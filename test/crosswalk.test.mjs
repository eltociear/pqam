// The ap2-evidence-pack crosswalk covers every vector and is regenerated from them (no drift).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";

test("crosswalk is up to date with the vectors and covers every case", () => {
  const before = readFileSync(new URL("../interop/ap2-evidence-pack/crosswalk.json", import.meta.url), "utf8");
  execFileSync(process.execPath, [new URL("../interop/ap2-evidence-pack/crosswalk.mjs", import.meta.url).pathname]);
  assert.equal(readFileSync(new URL("../interop/ap2-evidence-pack/crosswalk.json", import.meta.url), "utf8"), before);
  const c = JSON.parse(before);
  const V = JSON.parse(readFileSync(new URL("../vectors/pqam-0.1.json", import.meta.url), "utf8"));
  assert.equal(c.summary.rows, V.verify.length + V.admission.length + V.policy.length);
});
