// pqam's ML-DSA-87 is the one QoreChain uses: @qorechain/sdk (the chain's own client, whose
// precompile 0x…0a01 verifies the same way) checks pqam signatures, and pqam checks its keys.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../src/index.mjs";

let sdk;
try {
  sdk = await import("@qorechain/sdk");
} catch {}
const V = JSON.parse(readFileSync(new URL("../vectors/pqam-0.1.json", import.meta.url), "utf8"));

test("QoreChain SDK verifies the enforcer's pqam receipt signature", { skip: !sdk && "@qorechain/sdk not installed" }, () => {
  const r = V.objects.receipt;
  const pub = P.b64u.dec(V.keys["enforcer.pq"].pub);
  const sig = P.b64u.dec(r.object.sig[0].sig);
  assert.equal(sdk.pqcVerify(pub, Buffer.from(r.message, "hex"), sig), true);
  assert.equal(sdk.pqcVerify(pub, Buffer.from(V.objects.M1.message, "hex"), sig), false);
});

test("same seed, same ML-DSA-87 key in both libraries", { skip: !sdk && "@qorechain/sdk not installed" }, () => {
  const seed = Buffer.from(V.keys["issuer.pq"].seed, "hex");
  assert.equal(P.b64u.enc(sdk.generatePqcKeypair(seed).publicKey), V.keys["issuer.pq"].pub);
});
