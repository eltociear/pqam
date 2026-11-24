// Independent implementation of the AP2 PQC v1 construction (chopmob-cloud/ap2-pq-conformance) and the
// cross-implementor cases generated with it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { verifyV1, jcs } from "../interop/ap2-pq-conformance/ap2pqc-v1.mjs";

const R = (f) => JSON.parse(readFileSync(new URL(`../interop/ap2-pq-conformance/${f}`, import.meta.url), "utf8"));

test("their v1 fixture: same 501 JCS bytes, all three signatures (ES256, Ed25519, Falcon-1024) verify", () => {
  const a = R("upstream/ap2-pqc-v1-algovoi-side.json");
  assert.equal(Buffer.from(jcs(a.mandate_body)).toString("hex"), a.expected_jcs_bytes_hex);
  const r = verifyV1(a);
  assert.ok(r.ok, r.errors.join("; "));
  assert.deepEqual(r.required.sort(), ["ES256", "Ed25519", "Falcon-1024"]);
});

test("their v0 fixture is refused by the v1 rules (no signed descriptor)", () => {
  assert.equal(verifyV1(R("upstream/ap2-pqc-v0-algovoi-side.json")).ok, false);
});

test("cross cases are reproduced byte for byte", () => {
  const before = readFileSync(new URL("../interop/ap2-pq-conformance/pqam-cross-v1.json", import.meta.url), "utf8");
  execFileSync(process.execPath, [new URL("../interop/ap2-pq-conformance/build-cases.mjs", import.meta.url).pathname]);
  assert.equal(readFileSync(new URL("../interop/ap2-pq-conformance/pqam-cross-v1.json", import.meta.url), "utf8"), before);
});

for (const c of R("pqam-cross-v1.json").cases) {
  test(`cross case ${c.id}`, () => {
    const r = verifyV1(c.artefact);
    assert.equal(r.ok, c.expect.ok, r.errors.join("; "));
    if (c.expect.error_contains) assert.ok(r.errors.some((e) => e.includes(c.expect.error_contains)), r.errors.join("; "));
    if (c.expect_verify_v1_without_mldsa65) {
      const w = verifyV1(c.artefact, { can: ["ES256", "Ed25519", "Falcon-1024"] });
      assert.equal(w.ok, false);
      assert.ok(w.errors.some((e) => e.includes(c.expect_verify_v1_without_mldsa65.error_contains)));
    }
  });
}
