// pqam/0.1 objects: shape checks, hashing, signing and verification.
//
// Every object is {"v":"pqam/0.1","type":<type>, ...fields, "sig":[...]}; a mandate also carries
// "accept":[...] (the agent key's co-signature). The BODY is the object without "sig" and
// "accept". A signature covers
//
//   M = UTF-8("pqam/0.1/<type>") || 0x00 || SHA3-256(JCS(body)) || SHA3-256(UTF-8(kids))
//
// (acceptance: type "accept", over the mandate's hash). `kids` is the sorted, comma-joined kid list
// of EVERY key expected to co-sign. So a signature made for one type can never pass as another, and
// a hybrid can't be separated: a PQ signature made alongside a classical one is bound to that pair,
// so it fails when a verifier is offered the PQ key alone (the "stripping" attack; IETF
// draft-uppalapati-wimse-pq-agent-identity PQ-R3). Signature entries are
// {"alg","kid","sig"}: kid = first 8 bytes (hex) of SHA3-256(UTF-8(alg) || 0x00 || publicKey).
// Verification is hybrid-AND: every key in the list must have exactly one valid signature, a
// signature by a key not in the list is refused, and an unknown algorithm is refused.
import { sha3_256 } from "@noble/hashes/sha3.js";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils.js";
import { canonicalize } from "./jcs.mjs";
import { ALGS, MIN_EVIDENCE_LEVEL, alg } from "./algs.mjs";

export const VERSION = "pqam/0.1";
export const TYPES = ["mandate", "revoke", "approve", "invoice", "receipt"];
export const MAX_MANDATE_SECONDS = 366 * 86400;

// ---------- encoding ----------
export const b64u = {
  enc: (b) => Buffer.from(b).toString("base64url"),
  dec: (s) => {
    if (typeof s !== "string" || !/^[A-Za-z0-9_-]*$/.test(s)) throw new PqamError("Malformed", "not base64url");
    return new Uint8Array(Buffer.from(s, "base64url"));
  },
};

export class PqamError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.code = code;
  }
}

export function kid(algName, pub) {
  const pk = typeof pub === "string" ? b64u.dec(pub) : pub;
  return bytesToHex(sha3_256(concatBytes(utf8ToBytes(algName), new Uint8Array([0]), pk)).subarray(0, 8));
}

/** Public form of a key: {alg, pub}. */
export function publicKey(k) {
  return { alg: k.alg, pub: typeof k.pub === "string" ? k.pub : b64u.enc(k.publicKey ?? k.pub) };
}

/** Make a signer from an algorithm name and a seed (ML-DSA: 32 bytes, Ed25519: 32, ES256K: 48). */
export function signerFromSeed(algName, seed) {
  const { secretKey, publicKey: pk } = alg(algName).keygen(seed);
  return { alg: algName, publicKey: pk, secretKey };
}

// ---------- hashing ----------
export function body(obj) {
  const { sig, accept, ...rest } = obj;
  return rest;
}

export function hash(obj) {
  return sha3_256(utf8ToBytes(canonicalize(body(obj))));
}

export function hashHex(obj) {
  return bytesToHex(hash(obj));
}

export function signingMessage(type, digest, kids) {
  if (!Array.isArray(kids) || kids.length === 0) throw new PqamError("Malformed", "signingMessage needs the co-signers' kids");
  const set = sha3_256(utf8ToBytes([...kids].sort().join(",")));
  return concatBytes(utf8ToBytes(`${VERSION}/${type}`), new Uint8Array([0]), digest, set);
}

// ---------- signing ----------
function signEntries(type, digest, signers, opts) {
  const msg = signingMessage(type, digest, signers.map((s) => kid(s.alg, s.publicKey)));
  return signers.map((s) => ({ alg: s.alg, kid: kid(s.alg, s.publicKey), sig: b64u.enc(alg(s.alg).sign(msg, s.secretKey, opts)) }));
}

/** Return a copy of `obj` signed by every signer (replaces any existing "sig"). */
export function sign(obj, signers, opts) {
  const problems = check(body(obj));
  if (problems.length) throw new PqamError("Malformed", problems.join("; "));
  return { ...obj, sig: signEntries(obj.type, hash(obj), signers, opts) };
}

/** The agent key(s) accept a mandate: return a copy with "accept" set. */
export function accept(mandate, agentSigners, opts) {
  return { ...mandate, accept: signEntries("accept", hash(mandate), agentSigners, opts) };
}

// ---------- verification ----------
const ok = (extra = {}) => ({ ok: true, ...extra });
const fail = (code, why, extra = {}) => ({ ok: false, code, why, ...extra });

/** Hybrid-AND check of `entries` against `keys` ({alg,pub} list) for `type` over `digest`. */
export function verifyEntries(entries, keys, type, digest) {
  if (!Array.isArray(entries)) return fail("MissingSignature", `no ${type === "accept" ? "accept" : "sig"} list`);
  if (!Array.isArray(keys) || keys.length === 0) return fail("Malformed", "no keys to verify against");
  const want = new Map();
  for (const k of keys) {
    if (!Object.hasOwn(ALGS, k.alg)) return fail("UnknownAlgorithm", `key algorithm ${JSON.stringify(k.alg)}`);
    want.set(kid(k.alg, k.pub), k);
  }
  const msg = signingMessage(type, digest, [...want.keys()]);
  const seen = new Set();
  for (const e of entries) {
    if (!e || typeof e !== "object" || Object.keys(e).sort().join() !== "alg,kid,sig") return fail("Malformed", "signature entry must be {alg,kid,sig}");
    if (!Object.hasOwn(ALGS, e.alg)) return fail("UnknownAlgorithm", `signature algorithm ${JSON.stringify(e.alg)}`);
    const k = want.get(e.kid);
    if (!k || k.alg !== e.alg) return fail("UnexpectedSigner", `signature by ${e.alg} key ${e.kid}, which is not in the key list`);
    if (seen.has(e.kid)) return fail("Malformed", `two signatures by key ${e.kid}`);
    seen.add(e.kid);
    let sig;
    try {
      sig = b64u.dec(e.sig);
    } catch {
      return fail("Malformed", `signature by ${e.kid} is not base64url`);
    }
    if (!alg(e.alg).verify(sig, msg, b64u.dec(k.pub))) return fail("BadSignature", `${e.alg} signature by ${e.kid} does not verify`);
  }
  for (const [id, k] of want) if (!seen.has(id)) return fail("MissingSignature", `no signature by ${k.alg} key ${id}`);
  return ok();
}

/** Keys used as evidence (issuer, payee, enforcer) need at least one ML-DSA key of level >= 3. */
export function evidenceKeysProblem(keys, who) {
  if (!keys.some((k) => ALGS[k.alg]?.pq && ALGS[k.alg].level >= MIN_EVIDENCE_LEVEL)) return `${who} has no ML-DSA-65 or ML-DSA-87 key`;
  return null;
}

/**
 * Verify a mandate: shape, issuer signatures (all issuer keys, at least one ML-DSA-65/87), and,
 * unless `{ requireAccept: false }`, the agent's acceptance (all agent keys).
 * Returns { ok, code?, why?, hash, accepted }.
 */
export function verifyMandate(m, { requireAccept = true } = {}) {
  const problems = check(body(m));
  if (problems.length) return fail("Malformed", problems.join("; "));
  if (m.type !== "mandate") return fail("Malformed", `type is ${m.type}, not mandate`);
  const weak = evidenceKeysProblem(m.issuer.keys, "issuer");
  if (weak) return fail("WeakKey", weak);
  const digest = hash(m);
  const h = bytesToHex(digest);
  const s = verifyEntries(m.sig, m.issuer.keys, "mandate", digest);
  if (!s.ok) return { ...s, hash: h, accepted: false };
  if (m.accept === undefined) return requireAccept ? fail("NotAccepted", "the agent key has not accepted this mandate", { hash: h, accepted: false }) : ok({ hash: h, accepted: false });
  const a = verifyEntries(m.accept, m.agent.keys, "accept", digest);
  if (!a.ok) return { ...a, why: `acceptance: ${a.why}`, hash: h, accepted: false };
  return ok({ hash: h, accepted: true });
}

/** Verify an object issued under a mandate by its issuer (revoke, approve). */
export function verifyIssued(obj, mandate) {
  const problems = check(body(obj));
  if (problems.length) return fail("Malformed", problems.join("; "));
  if (obj.type !== "revoke" && obj.type !== "approve") return fail("Malformed", `type ${obj.type} is not issued by the issuer`);
  const mp = check(body(mandate));
  if (mp.length || mandate.type !== "mandate") return fail("Malformed", "the mandate passed in is not a well-formed pqam mandate");
  const mh = hashHex(mandate);
  if (obj.mandate !== mh) return fail("WrongMandate", `refers to mandate ${obj.mandate}, not ${mh}`);
  return verifyEntries(obj.sig, mandate.issuer.keys, obj.type, hash(obj));
}

/** Verify an invoice against the payee's keys, or a receipt against the enforcer's keys. */
export function verifyBy(obj, keys) {
  const problems = check(body(obj));
  if (problems.length) return fail("Malformed", problems.join("; "));
  const who = obj.type === "invoice" ? "payee" : obj.type === "receipt" ? "enforcer" : null;
  if (!who) return fail("Malformed", `use verifyMandate/verifyIssued for type ${obj.type}`);
  const weak = evidenceKeysProblem(keys, who);
  if (weak) return fail("WeakKey", weak);
  return verifyEntries(obj.sig, keys, obj.type, hash(obj));
}

// ---------- shapes ----------
const DEC = /^(0|[1-9][0-9]{0,77})$/; // up to uint256
const HEX32 = /^[0-9a-f]{64}$/;
const CAIP10 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$/;
const CAIP19 = /^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}\/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}$/;
const SELECTOR = /^0x[0-9a-f]{8}$/;
const PAYEE_RULE = /^did-verified:kyc>=[0-9]$/;
// RegExp.test() coerces: /^[0-9]+$/.test(100) is true. Every pattern check requires a string first.
const is = (re, x) => typeof x === "string" && re.test(x);

function shape(o, path, required, optional, out) {
  if (!o || typeof o !== "object" || Array.isArray(o)) {
    out.push(`${path} must be an object`);
    return false;
  }
  for (const k of required) if (!(k in o)) out.push(`${path}.${k} is missing`);
  for (const k of Object.keys(o)) if (!required.includes(k) && !optional.includes(k)) out.push(`${path}.${k} is not a pqam/0.1 field`);
  return true;
}
const isInt = (x) => Number.isSafeInteger(x) && x >= 0;
const isStr = (x) => typeof x === "string" && x.length > 0 && x.length <= 512;

function keysProblems(keys, path, out) {
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 4) return out.push(`${path} must list 1 to 4 keys`);
  const ids = new Set();
  keys.forEach((k, i) => {
    if (!shape(k, `${path}[${i}]`, ["alg", "pub"], [], out)) return;
    if (!Object.hasOwn(ALGS, k.alg)) return out.push(`${path}[${i}].alg ${JSON.stringify(k.alg)} is unknown`);
    let pk;
    try {
      pk = b64u.dec(k.pub);
    } catch {
      return out.push(`${path}[${i}].pub is not base64url`);
    }
    if (pk.length !== ALGS[k.alg].sizes.publicKey) out.push(`${path}[${i}].pub is ${pk.length} bytes, ${k.alg} needs ${ALGS[k.alg].sizes.publicKey}`);
    const id = kid(k.alg, pk);
    if (ids.has(id)) out.push(`${path}[${i}] repeats a key`);
    ids.add(id);
  });
}

function paymentProblems(p, path, out, { receipt = false } = {}) {
  const opt = receipt ? ["invoice", "reason", "tx"] : ["invoice"];
  const req = receipt ? ["payee", "asset", "amount", "status"] : ["payee", "asset", "amount"];
  if (!shape(p, path, req, opt, out)) return;
  if (!is(CAIP10, p.payee ?? "")) out.push(`${path}.payee must be a CAIP-10 account id`);
  if (!is(CAIP19, p.asset ?? "")) out.push(`${path}.asset must be a CAIP-19 asset id`);
  if (!is(DEC, p.amount ?? "")) out.push(`${path}.amount must be a decimal string in base units`);
  if (p.invoice !== undefined && !is(HEX32, p.invoice)) out.push(`${path}.invoice must be the invoice's hash (64 lowercase hex)`);
  if (receipt && !["paid", "pending", "refused", "unknown"].includes(p.status)) out.push(`${path}.status must be paid, pending, refused or unknown`);
  if (receipt && p.reason !== undefined && !isStr(p.reason)) out.push(`${path}.reason must be a string`);
  if (receipt && p.tx !== undefined && !isStr(p.tx)) out.push(`${path}.tx must be a string`);
}

/** Return a list of shape problems (empty = well-formed). Signatures are not checked here. */
export function check(o) {
  const out = [];
  if (!o || typeof o !== "object") return ["object expected"];
  if (o.v !== VERSION) out.push(`v must be "${VERSION}"`);
  if (!TYPES.includes(o.type)) return [...out, `type must be one of ${TYPES.join(", ")}`];
  const common = ["v", "type"];
  switch (o.type) {
    case "mandate": {
      shape(o, "$", [...common, "id", "issuer", "agent", "enforcer", "scope", "limits", "not_before", "expires", "revocation"], [], out);
      if (!isStr(o.id)) out.push("$.id must be a string");
      if (shape(o.issuer, "$.issuer", ["id", "keys"], [], out)) {
        if (!isStr(o.issuer.id)) out.push("$.issuer.id must be a string");
        keysProblems(o.issuer.keys, "$.issuer.keys", out);
      }
      if (shape(o.agent, "$.agent", ["keys"], [], out)) keysProblems(o.agent.keys, "$.agent.keys", out);
      if (!is(CAIP10, o.enforcer ?? "")) out.push("$.enforcer must be a CAIP-10 account id");
      const s = o.scope;
      if (shape(s, "$.scope", ["assets", "invoice"], ["payees", "payee_rule", "calls"], out)) {
        if (!Array.isArray(s.assets) || !s.assets.length || !s.assets.every((a) => is(CAIP19, a))) out.push("$.scope.assets must be a non-empty list of CAIP-19 ids");
        if (s.payees === undefined && s.payee_rule === undefined) out.push("$.scope needs payees, payee_rule, or both");
        if (s.payees !== undefined && (!Array.isArray(s.payees) || !s.payees.every((a) => is(CAIP10, a)))) out.push("$.scope.payees must be a list of CAIP-10 ids");
        if (s.payee_rule !== undefined && !is(PAYEE_RULE, s.payee_rule)) out.push('$.scope.payee_rule must look like "did-verified:kyc>=N"');
        if (s.calls !== undefined && (!Array.isArray(s.calls) || !s.calls.every((c) => c && is(CAIP10, c.target ?? "") && is(SELECTOR, c.selector ?? "") && Object.keys(c).length === 2)))
          out.push("$.scope.calls must be a list of {target: CAIP-10, selector: 0x + 8 lowercase hex}");
        if (!["required-signed", "none"].includes(s.invoice)) out.push('$.scope.invoice must be "required-signed" or "none"');
      }
      const l = o.limits;
      if (shape(l, "$.limits", ["per_payment", "window", "max_pending", "pending_ttl"], ["approve_above"], out)) {
        if (!is(DEC, l.per_payment ?? "") || l.per_payment === "0") out.push("$.limits.per_payment must be a positive decimal string");
        if (shape(l.window, "$.limits.window", ["seconds", "max", "kind"], [], out)) {
          if (!isInt(l.window.seconds) || l.window.seconds === 0) out.push("$.limits.window.seconds must be a positive integer");
          if (!is(DEC, l.window.max ?? "")) out.push("$.limits.window.max must be a decimal string");
          if (!["rolling", "calendar"].includes(l.window.kind)) out.push('$.limits.window.kind must be "rolling" or "calendar"');
        }
        if (l.approve_above !== undefined && (!is(DEC, l.approve_above) || (is(DEC, l.per_payment ?? "") && BigInt(l.approve_above) >= BigInt(l.per_payment))))
          out.push("$.limits.approve_above must be a decimal string below per_payment");
        if (!isInt(l.max_pending)) out.push("$.limits.max_pending must be an integer");
        if (!isInt(l.pending_ttl)) out.push("$.limits.pending_ttl must be an integer (seconds)");
      }
      if (!isInt(o.not_before) || !isInt(o.expires)) out.push("$.not_before and $.expires must be integers (unix seconds)");
      else if (o.expires <= o.not_before || o.expires - o.not_before > MAX_MANDATE_SECONDS) out.push("$.expires must be after not_before and at most 366 days later");
      if (shape(o.revocation, "$.revocation", ["where", "sticky"], [], out)) {
        if (!isStr(o.revocation.where)) out.push("$.revocation.where must be a string");
        if (o.revocation.sticky !== true) out.push("$.revocation.sticky must be true in pqam/0.1 (a pause is not a revoke)");
      }
      break;
    }
    case "revoke":
      shape(o, "$", [...common, "mandate", "at"], [], out);
      if (!is(HEX32, o.mandate ?? "")) out.push("$.mandate must be the mandate hash (64 lowercase hex)");
      if (!isInt(o.at)) out.push("$.at must be an integer");
      break;
    case "approve":
      shape(o, "$", [...common, "mandate", "payment", "until"], [], out);
      if (!is(HEX32, o.mandate ?? "")) out.push("$.mandate must be the mandate hash (64 lowercase hex)");
      paymentProblems(o.payment, "$.payment", out);
      if (!isInt(o.until)) out.push("$.until must be an integer");
      break;
    case "invoice":
      shape(o, "$", [...common, "id", "payer", "payee", "enforcer", "asset", "amount", "due"], [], out);
      if (!isStr(o.id)) out.push("$.id must be a string");
      for (const k of ["payer", "payee", "enforcer"]) if (!is(CAIP10, o[k] ?? "")) out.push(`$.${k} must be a CAIP-10 account id`);
      if (!is(CAIP19, o.asset ?? "")) out.push("$.asset must be a CAIP-19 asset id");
      if (!is(DEC, o.amount ?? "")) out.push("$.amount must be a decimal string in base units");
      if (!isInt(o.due)) out.push("$.due must be an integer");
      break;
    case "receipt":
      shape(o, "$", [...common, "mandate", "payment", "window_used", "at"], [], out);
      if (!is(HEX32, o.mandate ?? "")) out.push("$.mandate must be the mandate hash (64 lowercase hex)");
      paymentProblems(o.payment, "$.payment", out, { receipt: true });
      if (!is(DEC, o.window_used ?? "")) out.push("$.window_used must be a decimal string");
      if (!isInt(o.at)) out.push("$.at must be an integer");
      break;
  }
  return out;
}

export { bytesToHex, hexToBytes };
