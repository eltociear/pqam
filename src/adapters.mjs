// Compile a verified pqam/0.1 mandate into the native configuration of an enforcer.
//
// Rule (spec 4.1): a mandate that asks for something the enforcer cannot enforce is rejected at
// install time. Each adapter returns { ok: true, config } or { ok: false, problems: [...] }.
// Adapters never loosen: where an enforcer has a fixed value, the mandate must ask for exactly it.

const caip10 = (s) => {
  const [ns, ref, ...rest] = s.split(":");
  return { ns, ref, address: rest.join(":") };
};
const caip19 = (s) => {
  const [chain, asset] = s.split("/");
  const [ns, ref] = chain.split(":");
  const [assetNs, ...assetRef] = asset.split(":");
  return { ns, ref, assetNs, assetRef: assetRef.join(":") };
};

const done = (problems, config) => (problems.length ? { ok: false, problems } : { ok: true, config });

/**
 * Leash ID (CosmWasm on ME Hub): contract `PolicyMsg` for `RegisterAgent` (then the agent's
 * `AcceptLeash` mirrors pqam acceptance).
 * Fixed in the contract: rolling 24 h window, at most 50 pending payments, pending TTL 7 days,
 * one native denom, vendors by address or by a live ME ID at the contract's `min_kyc_level`.
 * @param opts { chainId: "mechain_400-1", denom: "umec", minKycLevel: 2, label?: string }
 */
export function toLeashId(m, { chainId, denom, minKycLevel, label = m.id } = {}) {
  const p = [];
  if (!chainId || !denom || minKycLevel === undefined) return { ok: false, problems: ["opts.chainId, opts.denom and opts.minKycLevel are required"] };
  const e = caip10(m.enforcer);
  if (e.ns !== "cosmos" || e.ref !== chainId) p.push(`enforcer ${m.enforcer} is not on cosmos:${chainId}`);
  const want = `cosmos:${chainId}/slip44:${denom}`;
  if (m.scope.assets.length !== 1 || m.scope.assets[0] !== want) p.push(`Leash ID moves one native denom: scope.assets must be exactly ["${want}"]`);
  if (m.scope.calls !== undefined) p.push("Leash ID has no call scope (the agent can only call Pay); drop scope.calls");
  if (m.scope.invoice === "required-signed") p.push("Leash ID checks invoice ids, not payee signatures: scope.invoice must be \"none\" on this profile");
  const w = m.limits.window;
  if (w.kind !== "rolling" || w.seconds !== 86400) p.push("Leash ID's window is rolling 24 h: limits.window must be {kind: rolling, seconds: 86400}");
  if (m.limits.max_pending !== 50) p.push("Leash ID holds at most 50 pending payments: limits.max_pending must be 50");
  if (m.limits.pending_ttl !== 604800) p.push("Leash ID expires pending payments after 7 days: limits.pending_ttl must be 604800");
  const vendors = [];
  for (const v of m.scope.payees ?? []) {
    const c = caip10(v);
    if (c.ns !== "cosmos" || c.ref !== chainId) p.push(`payee ${v} is not on cosmos:${chainId}`);
    else vendors.push(c.address);
  }
  let anyVerified = false;
  if (m.scope.payee_rule !== undefined) {
    const n = Number(m.scope.payee_rule.split(">=")[1]);
    if (n !== minKycLevel) p.push(`payee_rule asks for kyc>=${n}, the contract checks kyc>=${minKycLevel}`);
    anyVerified = true;
  }
  return done(p, {
    install_after: m.not_before, // Leash ID has no start time: send RegisterAgent once this has passed
    register_agent: {
      agent: null, // the agent's address is chain-derived from its key; the caller fills it in
      policy: {
        label: String(label).slice(0, 64),
        per_tx_limit: m.limits.per_payment,
        daily_limit: w.max,
        approve_above: m.limits.approve_above ?? null,
        vendors,
        any_verified_vendor: anyVerified,
        expires_at: m.expires,
      },
    },
  });
}

/**
 * Invoice Leash (InvoiceDeskV3 on QoreChain EVM): desk limits for the payer, the vendor list, and
 * the agent key's account-abstraction spending rule (one call: the desk's pay()).
 * Fixed in the desk: UTC-day window, payee-signed ML-DSA-87 invoices, no hold (larger invoices are
 * refused and a person pays them), one ERC-20.
 */
export const DESK_PAY_SELECTOR = "0x" + "f19ff4ff";
export function toInvoiceDesk(m) {
  const p = [];
  const e = caip10(m.enforcer);
  if (e.ns !== "eip155") p.push(`enforcer ${m.enforcer} is not an EVM contract`);
  if (m.scope.assets.length !== 1) p.push("the desk pays in one token per limit: scope.assets must have one entry");
  const a = caip19(m.scope.assets[0]);
  if (a.assetNs !== "erc20" || a.ns !== e.ns || a.ref !== e.ref) p.push("scope.assets[0] must be an ERC-20 on the enforcer's chain");
  if (m.scope.invoice !== "required-signed") p.push('the desk pays only payee-signed invoices: scope.invoice must be "required-signed"');
  if (m.scope.payee_rule !== undefined) p.push("the desk has no payee rule; list the vendors in scope.payees");
  const w = m.limits.window;
  if (w.kind !== "calendar" || w.seconds !== 86400) p.push("the desk's window is the UTC day: limits.window must be {kind: calendar, seconds: 86400}");
  if (m.limits.approve_above !== undefined) p.push("the desk cannot hold a payment for approval: drop limits.approve_above (set per_payment to the hold line; a person pays larger invoices)");
  if (m.scope.calls !== undefined) {
    const only = m.scope.calls.length === 1 && m.scope.calls[0].target.toLowerCase() === m.enforcer.toLowerCase() && m.scope.calls[0].selector === DESK_PAY_SELECTOR;
    if (!only) p.push(`scope.calls may only be [{target: enforcer, selector: ${DESK_PAY_SELECTOR}}]`);
  }
  const vendors = [];
  for (const v of m.scope.payees ?? []) {
    const c = caip10(v);
    if (c.ns !== e.ns || c.ref !== e.ref) p.push(`payee ${v} is not on ${e.ns}:${e.ref}`);
    else vendors.push(c.address);
  }
  return done(p, {
    chainId: Number(e.ref),
    desk: e.address,
    token: a.assetRef,
    limit: { perPayment: m.limits.per_payment, daily: w.max },
    vendors,
    // QoreChain account-abstraction rule for the agent key. allowedDenoms must name a real token the
    // agent account does NOT hold (Invoice Leash uses fBTC, 1 satoshi): a rule-bound key can move any
    // denom its rule lists, whatever allowedEvmCalls says (spec section 8.1).
    agentRule: { allowedEvmCalls: [`${e.address.toLowerCase()}/${DESK_PAY_SELECTOR}`], allowedDenoms: null, expiresAt: m.expires },
  });
}
