// Reference evaluator: what an enforcer must decide for one payment request under a verified mandate.
//
// This is the semantics the conformance vectors pin down, not an enforcer: a real enforcer holds
// the money and keeps the history itself. The checks run in this fixed order, and the first
// failing one is the reason, so two implementations give the same answer for the same input:
//
//   MalformedRequest, NotAccepted, Revoked, NotYetValid, Expired,
//   AssetNotInScope, PayeeNotInScope, CallNotInScope, InvoiceRequired,
//   ZeroAmount, OverPerPayment, OverWindow, (then, if it would be held) TooManyPending
//
// Decisions: "pay", "hold" (above approve_above: waits for a pqam approve from the issuer), or
// "refuse". Refused requests never use up the window; paid and live pending ones do. A pending
// entry stops counting once it is older than pending_ttl (it has expired and can't be paid).
//
// Window kinds: "rolling" counts entries with at > now - seconds. "calendar" counts entries in the
// same aligned bucket: floor(at / seconds) == floor(now / seconds) (seconds = 86400 is the UTC day).

const parseCaip10 = (s) => {
  const [ns, ref, ...rest] = s.split(":");
  return { chain: `${ns}:${ref}`, address: rest.join(":") };
};

/** Same CAIP-10 account? Addresses compare case-insensitively on eip155 (checksums), exactly elsewhere. */
export function sameAccount(a, b) {
  const x = parseCaip10(a);
  const y = parseCaip10(b);
  if (x.chain !== y.chain) return false;
  return x.chain.startsWith("eip155:") ? x.address.toLowerCase() === y.address.toLowerCase() : x.address === y.address;
}

function sameAsset(a, b) {
  return a.startsWith("eip155:") ? a.toLowerCase() === b.toLowerCase() : a === b;
}

/**
 * @param m        a mandate that verifyMandate() accepted
 * @param req      { payee, asset, amount, call?: {target, selector}, invoiceVerified?: boolean }
 * @param ctx      { now, accepted, revoked?, history?: [{at, amount, status: "paid"|"pending"}],
 *                   payeeRule?: (payee, rule) => boolean }   payeeRule answers payee_rule checks
 *                   (e.g. an on-chain DID lookup); without it, a rule never admits anyone.
 * @returns { decision: "pay"|"hold"|"refuse", reason, window_used }  (window_used before this request)
 */
export function evaluate(m, req, ctx) {
  const { now, accepted, revoked = false, history = [], payeeRule } = ctx;
  const L = m.limits;
  const live = history.filter((h) => (h.status === "paid" || (h.status === "pending" && h.at + L.pending_ttl > now)) && inWindow(L.window, h.at, now));
  const used = live.reduce((s, h) => s + BigInt(h.amount), 0n);
  const r = (decision, reason) => ({ decision, reason, window_used: used.toString() });

  if (!req || typeof req.payee !== "string" || typeof req.asset !== "string" || typeof req.amount !== "string" || !/^(0|[1-9][0-9]{0,77})$/.test(req.amount))
    return r("refuse", "MalformedRequest");
  if (!accepted) return r("refuse", "NotAccepted");
  if (revoked) return r("refuse", "Revoked");
  if (now < m.not_before) return r("refuse", "NotYetValid");
  if (now >= m.expires) return r("refuse", "Expired");
  if (!m.scope.assets.some((a) => sameAsset(a, req.asset))) return r("refuse", "AssetNotInScope");
  const listed = (m.scope.payees ?? []).some((p) => sameAccount(p, req.payee));
  const byRule = !listed && m.scope.payee_rule !== undefined && typeof payeeRule === "function" && payeeRule(req.payee, m.scope.payee_rule) === true;
  if (!listed && !byRule) return r("refuse", "PayeeNotInScope");
  if (m.scope.calls !== undefined) {
    const c = req.call;
    if (!c || !m.scope.calls.some((x) => sameAccount(x.target, c.target) && x.selector === String(c.selector).toLowerCase())) return r("refuse", "CallNotInScope");
  }
  if (m.scope.invoice === "required-signed" && req.invoiceVerified !== true) return r("refuse", "InvoiceRequired");
  const amount = BigInt(req.amount);
  if (amount === 0n) return r("refuse", "ZeroAmount");
  if (amount > BigInt(L.per_payment)) return r("refuse", "OverPerPayment");
  if (used + amount > BigInt(L.window.max)) return r("refuse", "OverWindow");
  if (L.approve_above !== undefined && amount > BigInt(L.approve_above)) {
    const pending = history.filter((h) => h.status === "pending" && h.at + L.pending_ttl > now).length;
    if (pending >= L.max_pending) return r("refuse", "TooManyPending");
    return r("hold", "NeedsApproval");
  }
  return r("pay", "WithinMandate");
}

function inWindow(w, at, now) {
  if (at > now) return false;
  return w.kind === "rolling" ? at > now - w.seconds : Math.floor(at / w.seconds) === Math.floor(now / w.seconds);
}
