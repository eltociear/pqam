import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../src/index.mjs";

const V = JSON.parse(readFileSync(new URL("../vectors/pqam-0.1.json", import.meta.url), "utf8"));
const M1 = V.objects.M1.object;
const signer = (n) => P.signerFromSeed(V.keys[n].alg, Buffer.from(V.keys[n].seed, "hex"));

test("every algorithm signs and verifies, deterministic and hedged", () => {
  for (const alg of Object.keys(P.ALGS)) {
    const s = P.signerFromSeed(alg, new Uint8Array(alg === "ES256K" ? 48 : 32).fill(9));
    const m = new TextEncoder().encode("pqam");
    const a = P.ALGS[alg].sign(m, s.secretKey);
    assert.ok(P.ALGS[alg].verify(a, m, s.publicKey), alg);
    assert.deepEqual(P.ALGS[alg].sign(m, s.secretKey), a, `${alg} deterministic`);
    if (P.ALGS[alg].pq) assert.ok(P.ALGS[alg].verify(P.ALGS[alg].sign(m, s.secretKey, { hedged: true }), m, s.publicKey), `${alg} hedged`);
    assert.equal(P.ALGS[alg].verify(a, new TextEncoder().encode("pqaM"), s.publicKey), false);
    assert.equal(P.ALGS[alg].verify(new Uint8Array(3), m, s.publicKey), false, "short sig is false, not a throw");
  }
});

test("re-signing the vector mandate gives the same object", () => {
  const re = P.accept(P.sign(P.body(M1), [signer("issuer.pq"), signer("issuer.classical")]), [signer("agent.cosmos")]);
  assert.deepEqual(re, M1);
});

test("the agent's acceptance can't be replayed onto another mandate", () => {
  const other = P.sign({ ...P.body(M1), id: "other" }, [signer("issuer.pq"), signer("issuer.classical")]);
  const r = P.verifyMandate({ ...other, accept: M1.accept });
  assert.equal(r.code, "BadSignature");
});

test("sign() refuses a malformed object", () => {
  assert.throws(() => P.sign({ ...P.body(M1), limits: { ...M1.limits, per_payment: 5 } }, [signer("issuer.pq")]), /Malformed/);
});

test("duplicate signature entries are refused", () => {
  const r = P.verifyMandate({ ...M1, sig: [...M1.sig, M1.sig[0]] });
  assert.equal(r.code, "Malformed");
});

test("verifyIssued refuses a malformed mandate argument", () => {
  assert.equal(P.verifyIssued(V.objects.revoke.object, { type: "mandate" }).code, "Malformed");
});

test("public key length is checked against the algorithm", () => {
  const bad = { ...P.body(M1), agent: { keys: [{ alg: "Ed25519", pub: V.keys["agent.cosmos"].pub }] } };
  assert.match(P.check(bad).join(), /needs 32/);
});

test("evaluate refuses a malformed request before anything else", () => {
  for (const amount of [5, "1.5", "-1", "01", undefined]) {
    const r = P.evaluate(M1, { payee: M1.scope.payees[0], asset: M1.scope.assets[0], amount }, { now: 1797000000, accepted: true });
    assert.equal(r.reason, "MalformedRequest", String(amount));
  }
});

test("an expired pending payment stops counting against the window", () => {
  const m = { ...M1, limits: { ...M1.limits, pending_ttl: 600 } };
  const req = { payee: M1.scope.payees[0], asset: M1.scope.assets[0], amount: "60000000" };
  const history = [{ at: 1797000000 - 601, amount: "200000000", status: "pending" }];
  assert.equal(P.evaluate(m, req, { now: 1797000000, accepted: true, history }).decision, "hold");
  assert.equal(P.evaluate(m, req, { now: 1797000000, accepted: true, history: [{ ...history[0], at: 1797000000 - 599 }] }).reason, "OverWindow");
});

test("a payee_rule without a lookup admits nobody", () => {
  const r = P.evaluate(M1, { payee: "cosmos:mechain_400-1:me1someoneelse", asset: M1.scope.assets[0], amount: "1" }, { now: 1797000000, accepted: true });
  assert.equal(r.reason, "PayeeNotInScope");
});

test("index.d.ts declares exactly the runtime exports", () => {
  const dts = readFileSync(new URL("../index.d.ts", import.meta.url), "utf8");
  const declared = [...dts.matchAll(/^export (?:function|const|class) (\w+)/gm)].map((m) => m[1]).sort();
  assert.deepEqual([...new Set(declared)], Object.keys(P).sort());
});
