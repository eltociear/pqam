import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { buildVectors, serialise } from "../scripts/vectors.mjs";
import * as P from "../src/index.mjs";

const FILE = new URL("../vectors/pqam-0.1.json", import.meta.url);
const V = JSON.parse(readFileSync(FILE, "utf8"));
const keysOf = (names) => names.map((n) => ({ alg: V.keys[n].alg, pub: V.keys[n].pub }));

test("vectors file is reproduced byte for byte from the seeds", () => {
  assert.equal(serialise(buildVectors()), readFileSync(FILE, "utf8"));
});

test("canonical form, hash and signing message of every object", () => {
  for (const [name, d] of Object.entries(V.objects)) {
    if (!d.object) continue;
    assert.equal(P.canonicalize(P.body(d.object)), d.canonical, name);
    assert.equal(P.hashHex(d.object), d.hash, name);
    assert.equal(Buffer.from(P.signingMessage(d.object.type, P.hash(d.object), d.signers)).toString("hex"), d.message, name);
  }
});

for (const t of V.verify) {
  test(`verify: ${t.name}`, () => {
    const r = t.kind === "mandate" ? P.verifyMandate(t.object) : t.kind === "issued" ? P.verifyIssued(t.object, V.objects[t.mandate].object) : P.verifyBy(t.object, keysOf(t.keys));
    assert.equal(r.ok, t.expect.ok, r.why);
    if (!t.expect.ok) assert.equal(r.code, t.expect.code, r.why);
    if (t.expect.accepted !== undefined) assert.equal(r.accepted, t.expect.accepted);
    if (t.expect.pq_level !== undefined) assert.equal(r.pq_level, t.expect.pq_level);
  });
}

for (const t of V.policy) {
  test(`policy: ${t.name}`, () => {
    const { verified_payees, ...ctx } = t.ctx;
    const r = P.evaluate(V.objects[t.mandate].object, t.request, { ...ctx, payeeRule: (p) => verified_payees.some((x) => P.sameAccount(x, p)) });
    assert.deepEqual({ decision: r.decision, reason: r.reason }, t.expect);
  });
}

const verifyOf = (t) => (t.kind === "mandate" ? P.verifyMandate(t.object) : t.kind === "issued" ? P.verifyIssued(t.object, V.objects[t.mandate].object) : P.verifyBy(t.object, keysOf(t.keys)));
for (const t of V.admission) {
  test(`admission: ${t.name}`, () => {
    const base = V.verify.find((x) => x.name === t.verify);
    assert.ok(base, `verify vector ${t.verify}`);
    const v = verifyOf(base);
    const r = P.admit(v, { policy: t.policy, time: t.time });
    assert.equal(r.admitted, t.expect.admitted);
    assert.equal(r.policy.verdict, t.expect.verdict);
    assert.equal(r.policy.reason, t.expect.reason);
    assert.equal(r.verification.ok, base.expect.ok, "the verification layer is reported unchanged");
  });
}
