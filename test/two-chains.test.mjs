// Re-verifies the evidence recorded by examples/two-chains/run.mjs, offline.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../src/index.mjs";

const R = (f) => JSON.parse(readFileSync(new URL(`../examples/two-chains/runs/${f}`, import.meta.url), "utf8"));
const run = R("two-chains.json");

for (const chain of ["mehub", "evm"]) {
  test(`${chain}: the recorded mandate and revoke verify, and match the run`, () => {
    const m = R(`mandate-${chain}.json`);
    const v = P.verifyMandate(m);
    assert.ok(v.ok, v.why);
    assert.equal(v.hash, run.chains[chain].mandateHash);
    assert.equal(m.enforcer, run.chains[chain].enforcer);
    assert.ok(P.verifyIssued(R(`revoke-${chain}.json`), m).ok);
    assert.ok(run.chains[chain].revoke.pqamRevokeVerified);
  });
  test(`${chain}: every attempt agreed with the reference evaluator`, () => {
    const a = run.chains[chain].attempts;
    assert.ok(a.length >= 8);
    for (const x of a) assert.equal(x.chain.decision, x.expected.decision, x.name);
    assert.ok(a.some((x) => x.chain.decision === "refuse") && a.some((x) => x.chain.decision === "pay"));
  });
}

test("both mandates: same issuer keys, same agent key, different enforcers", () => {
  const a = R("mandate-mehub.json");
  const b = R("mandate-evm.json");
  assert.deepEqual(a.issuer.keys, b.issuer.keys);
  assert.deepEqual(a.agent.keys, b.agent.keys);
  assert.notEqual(a.enforcer, b.enforcer);
  assert.equal(run.summary.disagreements, 0);
});
