// An independent JavaScript implementation of the AP2 PQC v1 signed-input construction from
// chopmob-cloud/ap2-pq-conformance (algovoi-side/README.md "v1 signed input", verify_v1.py), written
// from their text for cross-implementor testing on AP2 #250. Not pqam's own format (pqam uses its own
// message, SHA3-256 and kid sets); this module follows theirs exactly:
//
//   signed_input = "AP2PQC/1.0/" + object_type + 0x00 + JCS(mandate_body) + 0x00 + JCS(signer_set)
//   key_id       = SHA-256(public key bytes)   (ES256: the SPKI DER; others: the raw key)
//
// Fail-closed rules, as theirs: every listed signer present with a matching key_id; a signature for an
// unlisted signer is an error; an unknown algorithm or object type is an error, never a skip.
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { p256 } from "@noble/curves/nist.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { falcon1024 } from "@noble/post-quantum/falcon.js";

export const DOMAIN = utf8ToBytes("AP2PQC/1.0/");
export const KNOWN_ALGORITHMS = ["ES256", "Ed25519", "Falcon-1024", "ML-DSA-65"];
export const KNOWN_OBJECT_TYPES = ["PaymentMandate", "Approval", "Receipt"];
const SEP = new Uint8Array([0]);
const b64 = { enc: (b) => Buffer.from(b).toString("base64"), dec: (s) => new Uint8Array(Buffer.from(s, "base64")) };

/** Full RFC 8785 for JSON values (finite numbers serialised as ECMAScript does, which JCS adopts). */
export function jcs(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("JCS: non-finite number");
    return Object.is(v, -0) ? "0" : JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}";
  throw new Error(`JCS: ${typeof v}`);
}

export function signedInput(art) {
  return concatBytes(DOMAIN, utf8ToBytes(art.object_type), SEP, utf8ToBytes(jcs(art.mandate_body)), SEP, utf8ToBytes(jcs(art.signer_set)));
}

// P-256 SubjectPublicKeyInfo for an uncompressed point (fixed 26-byte prefix + 65-byte point).
const SPKI_P256 = Uint8Array.from(Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex"));
export const spkiFromPoint = (point65) => concatBytes(SPKI_P256, point65);
function pointFromSpki(der) {
  if (der.length !== 91 || bytesToHex(der.subarray(0, 26)) !== bytesToHex(SPKI_P256)) throw new Error("ES256 publicKeyDer is not a P-256 uncompressed SPKI");
  return der.subarray(26);
}

export function publicKeyBytes(alg, entry) {
  return alg === "ES256" ? b64.dec(entry.publicKeyDer) : b64.dec(entry.publicKey_b64);
}
export const keyId = (alg, entry) => bytesToHex(sha256(publicKeyBytes(alg, entry)));

function verifyOne(alg, e, msg) {
  try {
    switch (alg) {
      case "ES256": return p256.verify(b64.dec(e.signature_der), msg, pointFromSpki(b64.dec(e.publicKeyDer)), { format: "der", lowS: false }) ? null : "ES256 verification failed";
      case "Ed25519": return ed25519.verify(b64.dec(e.signature_b64), msg, b64.dec(e.publicKey_b64)) ? null : "Ed25519 verification failed";
      case "ML-DSA-65": return ml_dsa65.verify(b64.dec(e.signature_b64), msg, b64.dec(e.publicKey_b64)) ? null : "ML-DSA-65 verification failed";
      case "Falcon-1024": return falcon1024.verify(b64.dec(e.signature_b64), msg, b64.dec(e.publicKey_b64)) ? null : "Falcon-1024 verification failed";
      default: return `algorithm ${alg} not verifiable`;
    }
  } catch (err) {
    return `${alg} verification failed: ${err.message}`;
  }
}

/** Mirror of verify_v1.verify(): { ok, errors, required, present }. `can` limits the algorithms this verifier checks. */
export function verifyV1(art, { can = KNOWN_ALGORITHMS } = {}) {
  const errors = [];
  if (!KNOWN_OBJECT_TYPES.includes(art.object_type)) errors.push(`unknown_object_type: ${JSON.stringify(art.object_type)}`);
  let ss = art.signer_set;
  if (!ss || typeof ss !== "object" || Array.isArray(ss)) { errors.push("signer_set is not an object"); ss = {}; }
  const signers = Array.isArray(ss.signers) ? ss.signers : [];
  if (!signers.length || !signers.every((s) => KNOWN_ALGORITHMS.includes(s?.algorithm))) errors.push("signer_set lists no signers, or an unknown algorithm");
  const required = signers.map((s) => s?.algorithm);
  let sigs = art.signatures;
  if (!sigs || typeof sigs !== "object" || Array.isArray(sigs)) { errors.push("signatures is not an object"); sigs = {}; }
  const present = Object.keys(sigs);
  for (const a of required) {
    if (a == null) errors.push("signer_set entry with no algorithm");
    else if (!(a in sigs)) errors.push(`missing signature for required signer: ${a}`);
  }
  for (const a of present) {
    if (!required.includes(a)) errors.push(`signature present for unlisted signer: ${a}`);
    if (!KNOWN_ALGORITHMS.includes(a)) errors.push(`unknown algorithm in signatures: ${a}`);
  }
  for (const s of signers) {
    const e = sigs[s?.algorithm];
    if (!e) continue;
    try {
      if (s.key_id && s.key_id !== keyId(s.algorithm, e)) errors.push(`key_id mismatch for ${s.algorithm}`);
    } catch (err) {
      errors.push(`malformed signature entry for ${s.algorithm}: ${err.message}`);
    }
  }
  let msg = null;
  if (KNOWN_OBJECT_TYPES.includes(art.object_type)) {
    try { msg = signedInput(art); } catch (err) { errors.push(`malformed artefact: ${err.message}`); }
  }
  if (msg) {
    for (const [a, e] of Object.entries(sigs)) {
      const err = can.includes(a) ? verifyOne(a, e, msg) : `algorithm ${a} listed but not verifiable by this verifier`;
      if (err) errors.push(err);
    }
    const expected = String(art.expected_signed_input_sha256 ?? "").replace(/^sha256:/, "");
    if (expected && expected !== bytesToHex(sha256(msg))) errors.push("signed_input digest mismatch against expected_signed_input_sha256");
  }
  return { ok: errors.length === 0, errors, required, present };
}

// ---------- signing (for the cross-implementor cases) ----------
/** Keys from seed strings, AlgoVoi's derivation (private key = SHA-256(seed)) for ES256/Ed25519; ML-DSA-65 keygen(SHA-256(seed)). */
export function keyFromSeed(alg, seedString) {
  const sk = sha256(utf8ToBytes(seedString));
  switch (alg) {
    case "ES256": return { alg, secretKey: sk, entry: (sig) => ({ algorithm: "ES256", curve: "P-256", hash: "SHA-256", publicKeyDer: b64.enc(spkiFromPoint(p256.getPublicKey(sk, false))), signature_der: b64.enc(sig) }), sign: (m) => p256.sign(m, sk, { format: "der" }) };
    case "Ed25519": return { alg, secretKey: sk, entry: (sig) => ({ algorithm: "Ed25519", publicKey_b64: b64.enc(ed25519.getPublicKey(sk)), signature_b64: b64.enc(sig) }), sign: (m) => ed25519.sign(m, sk) };
    case "ML-DSA-65": {
      const k = ml_dsa65.keygen(sk);
      return { alg, secretKey: k.secretKey, entry: (sig) => ({ algorithm: "ML-DSA-65", family: "PQC (FIPS 204, pure, empty context, deterministic)", publicKey_b64: b64.enc(k.publicKey), signature_b64: b64.enc(sig) }), sign: (m) => ml_dsa65.sign(m, k.secretKey, { extraEntropy: false }) };
    }
    default: throw new Error(`cannot sign with ${alg}`);
  }
}

/** Build a v1 artefact: signer_set from `keys` (with key_ids), every key signs the signed input. */
export function buildV1({ object_type = "PaymentMandate", mandate_body, keys, extra = {} }) {
  const signer_set = { signers: keys.map((k) => ({ algorithm: k.alg, key_id: bytesToHex(sha256(publicKeyBytes(k.alg, k.entry(new Uint8Array(0))))) })) };
  const art = { object_type, mandate_body, signer_set, ...extra };
  const msg = signedInput(art);
  art.signatures = Object.fromEntries(keys.map((k) => [k.alg, k.entry(k.sign(msg))]));
  art.expected_signed_input_sha256 = "sha256:" + bytesToHex(sha256(msg));
  return art;
}
