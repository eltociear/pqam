// Signature algorithms pqam knows. A verifier that meets any other name rejects the object.
//
// ML-DSA is FIPS 204 "pure" ML-DSA with an empty context string, the variant QoreChain's
// precompile and @qorechain/sdk use (checked: same keys from the same seed, same deterministic
// signatures). Signing is deterministic (rnd = 0) unless the caller asks for hedged signing,
// so test vectors reproduce byte for byte.
// Ed25519 is RFC 8032. ES256K is ECDSA on secp256k1 over SHA-256 of the message, RFC 6979 nonces,
// low-S, 64-byte compact r||s, 33-byte compressed public key.
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";

const mldsa = (impl, level) => ({
  pq: true,
  level,
  keygen: (seed) => impl.keygen(seed),
  sign: (msg, sk, { hedged = false } = {}) => impl.sign(msg, sk, hedged ? {} : { extraEntropy: false }),
  verify: (sig, msg, pk) => {
    try {
      return impl.verify(sig, msg, pk);
    } catch {
      return false;
    }
  },
  sizes: { publicKey: impl.lengths.publicKey, signature: impl.lengths.signature },
});

export const ALGS = Object.freeze({
  "ML-DSA-44": mldsa(ml_dsa44, 2),
  "ML-DSA-65": mldsa(ml_dsa65, 3),
  "ML-DSA-87": mldsa(ml_dsa87, 5),
  Ed25519: {
    pq: false,
    keygen: (seed) => ed25519.keygen(seed),
    sign: (msg, sk) => ed25519.sign(msg, sk),
    verify: (sig, msg, pk) => {
      try {
        return ed25519.verify(sig, msg, pk);
      } catch {
        return false;
      }
    },
    sizes: { publicKey: 32, signature: 64 },
  },
  ES256K: {
    pq: false,
    keygen: (seed) => secp256k1.keygen(seed),
    sign: (msg, sk) => secp256k1.sign(msg, sk),
    verify: (sig, msg, pk) => {
      try {
        return secp256k1.verify(sig, msg, pk);
      } catch {
        return false;
      }
    },
    sizes: { publicKey: 33, signature: 64 },
  },
});

/** Lowest ML-DSA level an issuer, payee or enforcer key may use (spec section 5). */
export const MIN_EVIDENCE_LEVEL = 3;

export function alg(name) {
  const a = Object.hasOwn(ALGS, name) ? ALGS[name] : undefined;
  if (!a) throw new Error(`unknown algorithm ${JSON.stringify(name)}`);
  return a;
}
