// Generates vectors/pqam-0.1.json: keys from fixed seeds, deterministic signatures, so the file is
// reproduced byte for byte (test/vectors.test.mjs checks that, then runs every vector).
//
//   node scripts/vectors.mjs            write the file
//   buildVectors()                      the same object, for the test
import { writeFileSync, mkdirSync } from "node:fs";
import { shake256 } from "@noble/hashes/sha3.js";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils.js";
import { canonicalize, signerFromSeed, publicKey, sign, accept, hashHex, hash, signingMessage, kid, b64u, ALGS, body as P_body } from "../src/index.mjs";

const SEED_LEN = { "ML-DSA-44": 32, "ML-DSA-65": 32, "ML-DSA-87": 32, Ed25519: 32, ES256K: 48 };
const seedOf = (label, alg) => shake256(utf8ToBytes(`pqam/0.1 test vector key: ${label}`), { dkLen: SEED_LEN[alg] });

export function buildVectors() {
  const K = {};
  const key = (name, alg) => (K[name] = { alg, seed: seedOf(name, alg), ...signerFromSeed(alg, seedOf(name, alg)) });
  key("issuer.pq", "ML-DSA-87");
  key("issuer.classical", "ES256K");
  key("agent.cosmos", "ES256K");
  key("agent.ed25519", "Ed25519");
  key("payee.pq", "ML-DSA-65");
  key("enforcer.pq", "ML-DSA-87");
  key("attacker.pq", "ML-DSA-87");
  key("attacker.classical", "ES256K");
  key("weak.mldsa44", "ML-DSA-44");
  key("payee.classical", "ES256K");
  const pub = (n) => publicKey(K[n]);

  const T = 1797000000; // "now" for policy vectors (2026-12-12T13:20:00Z)
  const ISSUER = { id: "did:me:vector-owner", keys: [pub("issuer.pq"), pub("issuer.classical")] };

  // M1: a Leash ID-style mandate (ME Hub, rolling 24 h, hold above 50 MEC... in umec, DID-verified payees).
  const M1u = {
    v: "pqam/0.1", type: "mandate", id: "vector-m1",
    issuer: ISSUER,
    agent: { keys: [pub("agent.cosmos")] },
    enforcer: "cosmos:mechain_400-1:me1f2wumnwd4f0jjj9nzun9esvmjmcntv6dur9y7ewet965dt3n6paq4t3cej",
    scope: { assets: ["cosmos:mechain_400-1/slip44:umec"], payees: ["cosmos:mechain_400-1:me1vendoraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], payee_rule: "did-verified:kyc>=2", invoice: "none" },
    limits: { per_payment: "100000000", window: { seconds: 86400, max: "250000000", kind: "rolling" }, approve_above: "50000000", max_pending: 50, pending_ttl: 604800 },
    not_before: 1795000000, expires: 1797600000,
    revocation: { where: "cosmos:mechain_400-1:me1f2wumnwd4f0jjj9nzun9esvmjmcntv6dur9y7ewet965dt3n6paq4t3cej", sticky: true },
  };
  // M2: an Invoice Leash-style mandate (QoreChain EVM, UTC day, payee-signed invoices, one call).
  const DESK = "eip155:9800:0x00000000000000000000000000000000DE5C0001";
  const M2u = {
    v: "pqam/0.1", type: "mandate", id: "vector-m2",
    issuer: ISSUER,
    agent: { keys: [pub("agent.ed25519")] },
    enforcer: DESK,
    scope: {
      assets: ["eip155:9800/erc20:0x97143B771D34ddb9130b807b135Ae675A5a963CA"],
      payees: ["eip155:9800:0x0000000000000000000000000000000000004057", "eip155:9800:0x0000000000000000000000000000000000007011"],
      calls: [{ target: DESK, selector: "0xf19ff4ff" }],
      invoice: "required-signed",
    },
    limits: { per_payment: "100000000", window: { seconds: 86400, max: "250000000", kind: "calendar" }, max_pending: 0, pending_ttl: 0 },
    not_before: 1795000000, expires: 1797600000,
    revocation: { where: DESK, sticky: true },
  };
  const I = [K["issuer.pq"], K["issuer.classical"]];
  const M1 = accept(sign(M1u, I), [K["agent.cosmos"]]);
  const M2 = accept(sign(M2u, I), [K["agent.ed25519"]]);
  const h1 = hashHex(M1);

  const revoke = sign({ v: "pqam/0.1", type: "revoke", mandate: h1, at: T }, I);
  const approve = sign({ v: "pqam/0.1", type: "approve", mandate: h1, payment: { payee: M1u.scope.payees[0], asset: M1u.scope.assets[0], amount: "60000000" }, until: T + 3600 }, I);
  const invoice = sign({ v: "pqam/0.1", type: "invoice", id: "HOSTLINE-0042", payer: "eip155:9800:0x0000000000000000000000000000000000000A1E", payee: M2u.scope.payees[0], enforcer: DESK, asset: M2u.scope.assets[0], amount: "80000000", due: 1830297600 }, [K["payee.pq"]]);
  const receipt = sign({ v: "pqam/0.1", type: "receipt", mandate: hashHex(M2), payment: { payee: invoice.payee, asset: invoice.asset, amount: invoice.amount, invoice: hashHex(invoice), status: "paid", tx: "eip155:9800:0x" + "ab".repeat(32) }, window_used: "80000000", at: T }, [K["enforcer.pq"]]);

  // ---- negative objects ----
  const clone = (o) => structuredClone(o);
  const tampered = clone(M1);
  tampered.limits.per_payment = "1000000000";
  const noPq = clone(M1);
  noPq.sig = noPq.sig.filter((e) => e.alg !== "ML-DSA-87");
  // Q-Day forgery: the attacker has the issuer's classical key (Shor) and signs a raised limit, with
  // its own ML-DSA-87 key placed under the issuer's kid.
  const raised = { ...clone(M1u), limits: { ...M1u.limits, per_payment: "1000000000", window: { ...M1u.limits.window, max: "5000000000" } } };
  const qday = sign(raised, [K["attacker.pq"], K["issuer.classical"]]);
  qday.sig[0].kid = kid("ML-DSA-87", K["issuer.pq"].publicKey);
  const qdayAccepted = accept(qday, [K["agent.cosmos"]]);
  const strangerSig = accept(sign(raised, [K["attacker.pq"], K["issuer.classical"]]), [K["agent.cosmos"]]);
  const unknownAlg = clone(M1);
  unknownAlg.sig.push({ alg: "SLH-DSA-SHAKE-256f", kid: "00".repeat(8), sig: "AA" });
  const unaccepted = sign(M1u, I);
  const wrongAgent = accept(sign(M1u, I), [K["attacker.classical"]]);
  // Domain separation: the issuer's signature over the right hash, but made under the "accept" tag.
  const crossType = clone(M1);
  crossType.sig = crossType.sig.map((e) => e.alg === "ML-DSA-87" ? { ...e, sig: b64u.enc(ALGS["ML-DSA-87"].sign(signingMessage("accept", hash(M1), ISSUER.keys.map((k) => kid(k.alg, k.pub))), K["issuer.pq"].secretKey)) } : e);
  const classicalOnly = accept(sign({ ...M1u, issuer: { id: ISSUER.id, keys: [pub("issuer.classical")] } }, [K["issuer.classical"]]), [K["agent.cosmos"]]);
  const mldsa44Only = accept(sign({ ...M1u, issuer: { id: ISSUER.id, keys: [pub("weak.mldsa44")] } }, [K["weak.mldsa44"]]), [K["agent.cosmos"]]);
  const floatAmount = clone(M1);
  floatAmount.limits.per_payment = 100000000;
  const extraField = clone(M1);
  extraField.limits.per_hour = "1";
  const tooLong = clone(M1);
  tooLong.expires = tooLong.not_before + 367 * 86400;
  const revokeOther = sign({ v: "pqam/0.1", type: "revoke", mandate: hashHex(M2), at: T }, I);
  const approveByAgent = sign({ ...clone(approve), sig: undefined }, [K["agent.cosmos"]]);
  // Stripping: a hybrid invoice (ML-DSA-65 + ES256K); the attacker removes the classical signature and
  // offers the PQ key alone. The PQ signature was made for the pair, so it fails on its own.
  const invoiceHybrid = sign({ ...P_body(invoice), id: "HOSTLINE-0043" }, [K["payee.pq"], K["payee.classical"]]);
  const invoiceStripped = { ...clone(invoiceHybrid), sig: invoiceHybrid.sig.filter((e) => e.alg !== "ES256K") };
  const invoiceEdited = clone(invoice);
  invoiceEdited.amount = "95000000";

  const objects = { M1, M2, revoke, approve, invoice, receipt };
  const kidsOf = (entries) => entries.map((e) => e.kid);
  const describe = (o) => ({ object: o, canonical: canonicalize(P_body(o)), hash: hashHex(o), signers: kidsOf(o.sig), message: bytesToHex(signingMessage(o.type, hash(o), kidsOf(o.sig))) });

  const verify = [
    { name: "M1 is valid (hybrid issuer, accepted)", kind: "mandate", object: M1, expect: { ok: true, accepted: true, pq_level: 5 } },
    { name: "M2 is valid", kind: "mandate", object: M2, expect: { ok: true, accepted: true } },
    { name: "edited limit after signing", kind: "mandate", object: tampered, expect: { ok: false, code: "BadSignature" } },
    { name: "PQ signature removed (classical half only)", kind: "mandate", object: noPq, expect: { ok: false, code: "MissingSignature" } },
    { name: "Q-Day forgery: real classical signature + attacker's ML-DSA under the issuer's kid", kind: "mandate", object: qdayAccepted, expect: { ok: false, code: "BadSignature" } },
    { name: "Q-Day forgery with the attacker's own kid", kind: "mandate", object: strangerSig, expect: { ok: false, code: "UnexpectedSigner" } },
    { name: "unknown algorithm in the signature list", kind: "mandate", object: unknownAlg, expect: { ok: false, code: "UnknownAlgorithm" } },
    { name: "not accepted by the agent", kind: "mandate", object: unaccepted, expect: { ok: false, code: "NotAccepted" } },
    { name: "accepted by a key that is not the agent's", kind: "mandate", object: wrongAgent, expect: { ok: false, code: "UnexpectedSigner" } },
    { name: "issuer signature made under the accept tag", kind: "mandate", object: crossType, expect: { ok: false, code: "BadSignature" } },
    { name: "issuer with a classical key only (verifies; admission decides)", kind: "mandate", object: classicalOnly, expect: { ok: true, accepted: true, pq_level: 0 } },
    { name: "issuer with ML-DSA-44 only (verifies; admission decides)", kind: "mandate", object: mldsa44Only, expect: { ok: true, accepted: true, pq_level: 2 } },
    { name: "amount as a JSON number", kind: "mandate", object: floatAmount, expect: { ok: false, code: "Malformed" } },
    { name: "a field pqam/0.1 does not define", kind: "mandate", object: extraField, expect: { ok: false, code: "Malformed" } },
    { name: "mandate longer than 366 days", kind: "mandate", object: tooLong, expect: { ok: false, code: "Malformed" } },
    { name: "revoke of M1", kind: "issued", object: revoke, mandate: "M1", expect: { ok: true } },
    { name: "revoke of M2 checked against M1", kind: "issued", object: revokeOther, mandate: "M1", expect: { ok: false, code: "WrongMandate" } },
    { name: "approval by the issuer", kind: "issued", object: approve, mandate: "M1", expect: { ok: true } },
    { name: "approval signed by the agent", kind: "issued", object: approveByAgent, mandate: "M1", expect: { ok: false, code: "UnexpectedSigner" } },
    { name: "invoice by the payee", kind: "by", object: invoice, keys: ["payee.pq"], expect: { ok: true } },
    { name: "invoice amount edited", kind: "by", object: invoiceEdited, keys: ["payee.pq"], expect: { ok: false, code: "BadSignature" } },
    { name: "invoice checked against another payee's key", kind: "by", object: invoice, keys: ["attacker.pq"], expect: { ok: false, code: "UnexpectedSigner" } },
    { name: "receipt by the enforcer", kind: "by", object: receipt, keys: ["enforcer.pq"], expect: { ok: true } },
    { name: "hybrid invoice, both payee keys", kind: "by", object: invoiceHybrid, keys: ["payee.pq", "payee.classical"], expect: { ok: true } },
    { name: "stripping: classical signature removed, PQ key offered alone", kind: "by", object: invoiceStripped, keys: ["payee.pq"], expect: { ok: false, code: "BadSignature" } },
    { name: "stripping: classical signature removed, both keys expected", kind: "by", object: invoiceStripped, keys: ["payee.pq", "payee.classical"], expect: { ok: false, code: "MissingSignature" } },
  ];

  // ---- policy ----
  const V = M1u.scope.payees[0];
  const VERIFIED = "cosmos:mechain_400-1:me1verifiedbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const STRANGER = "cosmos:mechain_400-1:me1strangercccccccccccccccccccccccccccccccc";
  const A1 = M1u.scope.assets[0];
  const r1 = (amount, o = {}) => ({ payee: V, asset: A1, amount, ...o });
  const c1 = (o = {}) => ({ now: T, accepted: true, revoked: false, history: [], verified_payees: [VERIFIED], ...o });
  const many = Array.from({ length: 50 }, () => ({ at: T - 10, amount: "1", status: "pending" }));
  const H2 = M2u.scope.payees[0];
  const A2 = M2u.scope.assets[0];
  const call = { target: DESK, selector: "0xf19ff4ff" };
  const r2 = (amount, o = {}) => ({ payee: H2, asset: A2, amount, call, invoiceVerified: true, ...o });
  const DAY = Math.floor(T / 86400) * 86400;
  const policy = [
    ["within the mandate", "M1", r1("40000000"), c1(), "pay", "WithinMandate"],
    ["above approve_above: held", "M1", r1("60000000"), c1(), "hold", "NeedsApproval"],
    ["exactly per_payment: held", "M1", r1("100000000"), c1(), "hold", "NeedsApproval"],
    ["one unit over per_payment", "M1", r1("100000001"), c1(), "refuse", "OverPerPayment"],
    ["zero amount", "M1", r1("0"), c1(), "refuse", "ZeroAmount"],
    ["window: 200 paid an hour ago, 40 more fits", "M1", r1("40000000"), c1({ history: [{ at: T - 3600, amount: "200000000", status: "paid" }] }), "pay", "WithinMandate"],
    ["window: 200 paid an hour ago, 60 more does not", "M1", r1("60000000"), c1({ history: [{ at: T - 3600, amount: "200000000", status: "paid" }] }), "refuse", "OverWindow"],
    ["rolling edge: paid exactly 24 h ago no longer counts", "M1", r1("60000000"), c1({ history: [{ at: T - 86400, amount: "200000000", status: "paid" }] }), "hold", "NeedsApproval"],
    ["pending payments count against the window", "M1", r1("60000000"), c1({ history: [{ at: T - 100, amount: "200000000", status: "pending" }] }), "refuse", "OverWindow"],
    ["refused payments do not count", "M1", r1("40000000"), c1({ history: [{ at: T - 100, amount: "250000000", status: "refused" }] }), "pay", "WithinMandate"],
    ["50 pending: another hold is refused", "M1", r1("60000000"), c1({ history: many }), "refuse", "TooManyPending"],
    ["50 pending: a payment below the hold line still goes", "M1", r1("40000000"), c1({ history: many }), "pay", "WithinMandate"],
    ["payee neither listed nor verified", "M1", r1("1", { payee: STRANGER }), c1(), "refuse", "PayeeNotInScope"],
    ["payee admitted by payee_rule", "M1", r1("1", { payee: VERIFIED }), c1(), "pay", "WithinMandate"],
    ["asset not in scope", "M1", r1("1", { asset: "cosmos:mechain_400-1/slip44:uatom" }), c1(), "refuse", "AssetNotInScope"],
    ["revoked", "M1", r1("1"), c1({ revoked: true }), "refuse", "Revoked"],
    ["revoked and expired: Revoked comes first", "M1", r1("1"), c1({ revoked: true, now: 1797600000 }), "refuse", "Revoked"],
    ["before not_before", "M1", r1("1"), c1({ now: 1794999999 }), "refuse", "NotYetValid"],
    ["at expires", "M1", r1("1"), c1({ now: 1797600000 }), "refuse", "Expired"],
    ["not accepted", "M1", r1("1"), c1({ accepted: false }), "refuse", "NotAccepted"],
    ["M2: genuine signed invoice", "M2", r2("80000000"), c1({ verified_payees: [] }), "pay", "WithinMandate"],
    ["M2: invoice signature not verified", "M2", r2("80000000", { invoiceVerified: false }), c1({ verified_payees: [] }), "refuse", "InvoiceRequired"],
    ["M2: another function on the desk", "M2", r2("1", { call: { target: DESK, selector: "0xa9059cbb" } }), c1({ verified_payees: [] }), "refuse", "CallNotInScope"],
    ["M2: EVM address in another letter case still matches (checksums)", "M2", r2("1", { call: { target: DESK.toLowerCase(), selector: "0xF19FF4FF" } }), c1({ verified_payees: [] }), "pay", "WithinMandate"],
    ["M2 calendar: 240 paid yesterday at 23:59, 100 today fits", "M2", r2("100000000"), c1({ verified_payees: [], history: [{ at: DAY - 60, amount: "240000000", status: "paid" }] }), "pay", "WithinMandate"],
    ["M2 calendar: 240 paid today, 100 more does not", "M2", r2("100000000"), c1({ verified_payees: [], history: [{ at: DAY + 60, amount: "240000000", status: "paid" }] }), "refuse", "OverWindow"],
  ].map(([name, mandate, request, ctx, decision, reason]) => ({ name, mandate, request, ctx, expect: { decision, reason } }));

  // ---- admission: the policy verdict, over a verify vector's result ----
  const TRANS = 1830297600; // a transition date for the vectors (2028-01-01T00:00:00Z)
  const P = { pq_required_from: TRANS };
  const admission = [
    ["PQ-signed mandate, no transition date", "M1 is valid (hybrid issuer, accepted)", {}, undefined, true, "admitted", undefined],
    ["PQ-signed mandate after the date, even on local time", "M1 is valid (hybrid issuer, accepted)", P, { at: TRANS + 1, source: "local" }, true, "admitted", undefined],
    ["classical-only, no transition date: warned", "issuer with a classical key only (verifies; admission decides)", {}, undefined, true, "admitted-with-warning", "NoPqIssuance"],
    ["classical-only, anchored before the date: warned", "issuer with a classical key only (verifies; admission decides)", P, { at: TRANS - 1, source: "anchor" }, true, "admitted-with-warning", "NoPqIssuance"],
    ["classical-only, anchored at the date: refused (signature still verifies)", "issuer with a classical key only (verifies; admission decides)", P, { at: TRANS, source: "anchor" }, false, "refused", "NoPqIssuance"],
    ["classical-only, block time after the date: refused", "issuer with a classical key only (verifies; admission decides)", P, { at: TRANS + 86400, source: "block" }, false, "refused", "NoPqIssuance"],
    ["classical-only, verifier's own clock: refused as untrusted time", "issuer with a classical key only (verifies; admission decides)", P, { at: TRANS - 1, source: "local" }, false, "refused", "UntrustedTime"],
    ["classical-only, no time at all: refused as untrusted time", "issuer with a classical key only (verifies; admission decides)", P, undefined, false, "refused", "UntrustedTime"],
    ["ML-DSA-44 only, after the date: refused", "issuer with ML-DSA-44 only (verifies; admission decides)", P, { at: TRANS, source: "anchor" }, false, "refused", "NoPqIssuance"],
    ["Q-Day forgery: fails verification, policy never reached", "Q-Day forgery: real classical signature + attacker's ML-DSA under the issuer's kid", P, { at: TRANS - 1, source: "anchor" }, false, "not-reached", undefined],
  ].map(([name, verify, policy, time, admitted, verdict, reason]) => ({ name, verify, policy, ...(time ? { time } : {}), expect: { admitted, verdict, ...(reason ? { reason } : {}) } }));

  return {
    v: "pqam/0.1",
    about: "Conformance vectors for pqam/0.1. Keys: seed = SHAKE256('pqam/0.1 test vector key: ' + name), 32 bytes (48 for ES256K). ML-DSA is FIPS 204 pure, empty context, deterministic (rnd = 0). Each object lists `signers` (the kids its signing message binds). ctx.verified_payees stands in for an on-chain payee_rule lookup.",
    keys: Object.fromEntries(Object.entries(K).map(([n, k]) => [n, { alg: k.alg, seed: bytesToHex(k.seed), pub: b64u.enc(k.publicKey), kid: kid(k.alg, k.publicKey) }])),
    objects: { M1: describe(M1), M1_accept: { signers: kidsOf(M1.accept), message: bytesToHex(signingMessage("accept", hash(M1), kidsOf(M1.accept))) }, M2: describe(M2), revoke: describe(revoke), approve: describe(approve), invoice: describe(invoice), receipt: describe(receipt) },
    verify,
    policy,
    admission,
  };
}

export function serialise(v) {
  return JSON.stringify(v, null, 1) + "\n";
}

if (import.meta.url === `file://${process.argv[1]}`) {
  mkdirSync(new URL("../vectors/", import.meta.url), { recursive: true });
  const v = buildVectors();
  writeFileSync(new URL("../vectors/pqam-0.1.json", import.meta.url), serialise(v));
  console.log(`vectors/pqam-0.1.json: ${Object.keys(v.keys).length} keys, ${v.verify.length} verify, ${v.policy.length} policy, ${v.admission.length} admission vectors`);
}
