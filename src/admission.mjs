// Admission: the POLICY verdict, kept apart from cryptographic verification.
//
//   verify*()  -> did these keys sign these bytes?            (BadSignature, MissingSignature, ...)
//   admit()    -> given that, does this verifier accept it?   (NoPqIssuance, UntrustedTime)
//
// A valid mandate signed only classically (or only with ML-DSA-44) verifies. Before the policy's
// transition date it is admitted with a warning; from that date on it is REFUSED, and the result still
// says the signature verified. A forged mandate never gets this far: it fails verification. The two
// outcomes stay distinguishable in the record.
//
// The transition check runs against a time the verifier can trust, never its own clock: "anchor" (an
// RFC 3161 or similar timestamp over the object, e.g. an evidence pack's gen_time) or "block" (the
// enforcer's block time when it acted). A refusal keyed to local wall-clock time could be set by the
// party doing the refusing, so a policy with a transition date refuses on "local" time (UntrustedTime).
import { MIN_EVIDENCE_LEVEL } from "./algs.mjs";

export const DEFAULT_POLICY = Object.freeze({
  min_pq_level: MIN_EVIDENCE_LEVEL, // ML-DSA-65 or -87
  pq_required_from: null, // unix seconds; null = no transition date set yet (warn only)
  trusted_time_sources: Object.freeze(["anchor", "block"]),
});

/**
 * @param verification  a result of verifyMandate / verifyIssued / verifyBy
 * @param opts { policy?: Partial<DEFAULT_POLICY>, time?: { at: number, source: "anchor"|"block"|"local" } }
 * @returns {{ admitted: boolean,
 *             verification: { ok: boolean, code?: string, pq_level?: number },
 *             policy: { verdict: "admitted"|"admitted-with-warning"|"refused"|"not-reached", reason?: string, why?: string, time?: object } }}
 */
export function admit(verification, { policy = {}, time } = {}) {
  const P = { ...DEFAULT_POLICY, ...policy };
  const v = { ok: verification.ok === true, ...(verification.code ? { code: verification.code } : {}), ...(verification.pq_level !== undefined ? { pq_level: verification.pq_level } : {}) };
  if (!v.ok) return { admitted: false, verification: v, policy: { verdict: "not-reached" } };
  const strong = (verification.pq_level ?? 0) >= P.min_pq_level;
  if (strong) return { admitted: true, verification: v, policy: { verdict: "admitted", ...(time ? { time } : {}) } };
  const weak = `signed without an ML-DSA key of level >= ${P.min_pq_level} (pq_level ${verification.pq_level ?? 0})`;
  if (P.pq_required_from === null) return { admitted: true, verification: v, policy: { verdict: "admitted-with-warning", reason: "NoPqIssuance", why: `${weak}; no transition date set` } };
  if (!time || !Number.isSafeInteger(time.at) || !P.trusted_time_sources.includes(time.source))
    return { admitted: false, verification: v, policy: { verdict: "refused", reason: "UntrustedTime", why: `the transition check needs a time from ${P.trusted_time_sources.join(" or ")}${time ? `, got ${time.source}` : ""}`, ...(time ? { time } : {}) } };
  if (time.at < P.pq_required_from) return { admitted: true, verification: v, policy: { verdict: "admitted-with-warning", reason: "NoPqIssuance", why: `${weak}; before the transition date ${P.pq_required_from}`, time } };
  return { admitted: false, verification: v, policy: { verdict: "refused", reason: "NoPqIssuance", why: `${weak}; at or after the transition date ${P.pq_required_from}`, time } };
}
