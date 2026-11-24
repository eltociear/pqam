# PQ Agent Mandate (draft 0.1)

**Status:** working draft, 2026-11-24. Not a standard, not yet proposed anywhere. Reference
library and conformance vectors: [eltociear/pqam](https://github.com/eltociear/pqam). Written from two
running systems, [Invoice Leash](https://github.com/eltociear/invoice-leash) (QoreChain) and
[Leash ID](https://github.com/eltociear/leash-id) (ME Network, CosmWasm). The same file sits in
both repositories. Neither one implements the object format below yet (see the last section). What
they do implement are the semantics: limits, scope, approval, revocation, and the refusals.

## 1. The problem in one paragraph

AI agents are getting spending power through mandates: Google's AP2, ERC-7715/7710 permissions,
x402 budgets, and custom vaults like the two above. Every one of these signs the mandate with
ECDSA, EdDSA or Schnorr. A payment is over in seconds. **The mandate, and the receipt that says the
agent stayed inside it, are evidence that must hold up for years**, in a dispute, an audit or a
court case. After a cryptographically relevant quantum computer exists, anyone holding the issuer's
public key can forge a mandate that says the human allowed a payment they never allowed. That
attack is *harvest now, forge later*. Payment rails can migrate when Q-Day gets close. Evidence
signed today cannot be re-signed later by a key that is already broken. So the mandate layer has
to be post-quantum first, before the rails.

No published profile covers this. NIST FIPS 204 (ML-DSA) gives the signature. The IETF draft
`draft-uppalapati-wimse-pq-agent-identity` asks for PQ signing on credentials kept as evidence. AP2
defines the mandates. Nothing ties the three together for agent payments.

## 2. Goals and non-goals

Goals:

1. A mandate is a signed, chain-neutral object that says **who** lets **which agent key** spend
   **what, where, how much, until when**, and how it is revoked.
2. Every signature that could ever be used as evidence (mandate, revocation, receipt, approval)
   is post-quantum, or hybrid while the transition lasts.
3. Enforcement is done by whoever holds the money: a contract, a chain module or a payment
   processor. It is **never done by the agent**. The agent is assumed fooled or stolen.
4. The same mandate can be enforced on more than one chain through thin profiles (section 7).

Non-goals: deciding *whether* a payment is wise (that is the agent's and the policy's job),
identity proofing (we reference a DID, we don't issue one), and replacing AP2 or ERC-7710. This
is meant to be a profile they can carry.

## 3. Roles

| Role | Holds | Example in Invoice Leash | Example in Leash ID |
|---|---|---|---|
| **Issuer** | the money, the issuer key (PQ or hybrid) | the company account, hybrid secp256k1 + ML-DSA-87 | the owner, an ME ID holder |
| **Agent key** | the key that asks for payments | ed25519 linked by account abstraction | a Cosmos key that accepted the leash |
| **Enforcer** | the escrow or the spending path | InvoiceDeskV3 + QoreChain spending rules | the Leash ID contract |
| **Payee** | the receiving address, optionally a PQ invoice key | vendor with an on-chain ML-DSA-87 key | vendor on the allowlist or with a live ME ID |
| **Verifier** | nothing; reads evidence later | `npm run verify` | `scripts/verify.mjs` |

## 4. The mandate object

Encoded as JSON, canonicalised with RFC 8785 (JCS) before hashing and signing. Hash: SHA3-256.
pqam restricts JCS to safe integers: amounts are decimal strings, so floats never appear. Every
object has `"v": "pqam/0.1"` and a `type` (`mandate`, `revoke`, `approve`, `invoice`, `receipt`).
Fields not defined here are refused, which closes off parser-confusion tricks.

```jsonc
{
  "v": "pqam/0.1",
  "type": "mandate",
  "id": "b64url(16 random bytes)",
  "issuer": {
    "id": "did:… | caip10:…",              // who stands behind the money
    "keys": [                               // all must verify (section 5)
      { "alg": "ML-DSA-65", "pub": "b64url" },
      { "alg": "ES256K",    "pub": "b64url" } // optional classical half while migrating
    ]
  },
  "agent": {
    "keys": [{ "alg": "Ed25519", "pub": "b64url" }]
  },
  "enforcer": "caip10:<chain>:<contract or module>",
  "scope": {
    "assets":  ["caip19:…"],                // what may leave; nothing else may
    "payees":  ["caip10:…"],                // explicit allowlist, or…
    "payee_rule": "did-verified:kyc>=2",    // …a rule the enforcer can check on chain
    "calls":   [{ "target": "caip10:…", "selector": "0xf19ff4ff" }],
    "invoice": "required-signed"            // payee-signed invoice needed for each payment
  },
  "limits": {
    "per_payment": "100000000",             // asset base units, as a string
    "window": { "seconds": 86400, "max": "250000000", "kind": "rolling" },
    "approve_above": "50000000",            // above this: held for the issuer
    "max_pending": 50,
    "pending_ttl": 604800
  },
  "not_before": 1795000000,
  "expires":   1797600000,                  // required; no open-ended mandates
  "revocation": {
    "where": "caip10:… | https://…",        // where the enforcer looks
    "sticky": true                          // a revoked mandate never comes back; issue a new one
  },
  "sig":    [{ "alg": "ML-DSA-65", "kid": "…", "sig": "b64url" }, { "alg": "ES256K", … }],
  "accept": [{ "alg": "Ed25519",   "kid": "…", "sig": "b64url" }]   // section 4.2
}
```

The **body** is the object without `sig` and `accept`. Each signature covers

```
M = UTF-8("pqam/0.1/" + type) || 0x00 || SHA3-256(JCS(body))
```

and `kid` is the first 8 bytes (hex) of `SHA3-256(UTF-8(alg) || 0x00 || publicKey)`.

### 4.1 Rules for the fields

- **Everything not listed is refused.** An asset, a payee, a call target or a selector outside
  `scope` is a refusal, not a warning.
- **Amounts are signed in base units with the asset id next to them.** A label next to a signed
  amount means nothing (Invoice Leash: `fusd: "5"` next to a signed 95 is flagged, the 95 is shown).
- `limits.window.kind`: `rolling` (Leash ID: 24 buckets of an hour) or `calendar` (Invoice Leash:
  UTC day). The enforcer must say which one it uses. A mandate that asks for one the enforcer
  doesn't have is rejected when it is installed, not when it is used.
- **Refused payments don't use up limits.** Pending ones do. Otherwise an agent can flood the
  approval queue and take the whole window once the approvals come in (Leash ID counts pending
  payments against the 24 h limit).
- `expires` is required, at most 366 days after `not_before`.

### 4.2 Offer and accept

A mandate takes effect only when the agent key co-signs it. That signature (the `accept` list) is
`M` with type `accept` over the mandate's hash, by every agent key. Before that, it is an offer and can be withdrawn. This stops
an issuer from pinning a mandate on a key without that key's consent, and it proves the agent key
is held by someone (Leash ID v0.2: `RegisterAgent` → `AcceptLeash`).

## 5. Signature suite

| Use | Minimum | Recommended |
|---|---|---|
| Issuer: mandate, revocation, approval | ML-DSA-65 | ML-DSA-87, hybrid with the chain's classical key |
| Payee: invoice | ML-DSA-65 | ML-DSA-87 |
| Enforcer: receipt (off-chain enforcers) | ML-DSA-65 | ML-DSA-87 |
| Agent key | anything the enforcer accepts | PQ once the chain lets accounts link PQ keys |

- **Hybrid means AND.** Every key in `issuer.keys` must verify. A Q-Day attacker who has the
  classical half still fails (Invoice Leash drill: 16 of 16 attacks refused with four accounts'
  secp256k1 keys and no ML-DSA-87 key).
- **The algorithm is named, never implied.** Every signature carries `alg`. A verifier that
  doesn't know an `alg` rejects it. It doesn't skip it.
- **Domain separation.** Each signed message starts with its own tag: `pqam/0.1/mandate`,
  `/accept`, `/revoke`, `/approve`, `/invoice`, `/receipt`, plus the enforcer id and the chain id.
  An invoice signature can never pass as an approval.
- **Proof of possession.** A PQ key is registered only with a signature over a challenge (QoreChain
  does this for its PQ keys). The key is read at the moment of use, so a rotated key stops old
  signatures right away.
- **Why the agent key may stay classical:** the agent key is treated as already stolen. Whatever it
  holds (classical or quantum-broken) gets what a hostile agent gets: payments inside the mandate.
  It can never change the mandate. This is what Invoice Leash does on QoreChain today, because
  account abstraction there links only `ed25519 | secp256k1`.

## 6. Receipts and revocation

```jsonc
{ "v": "pqam/0.1", "type": "receipt", "mandate": "sha3-256 hex", "payment": {
    "payee": "caip10:…", "asset": "caip19:…", "amount": "…", "invoice": "sha3-256 hex",
    "status": "paid | pending | refused | unknown", "reason": "OverDailyLimit",
    "tx": "caip2:…:<hash>" },
  "window_used": "…", "at": 1797000000, "sig": [{ "alg": "ML-DSA-87", "kid": "…", "sig": "b64url" }] }
```

Payment decisions are pinned down by the reference evaluator, which checks in a fixed order and
reports the first failure: `MalformedRequest, NotAccepted, Revoked, NotYetValid, Expired,
AssetNotInScope, PayeeNotInScope, CallNotInScope, InvoiceRequired, ZeroAmount, OverPerPayment,
OverWindow`, then `TooManyPending` for a payment that would be held. The result is `pay`, `hold`
(`NeedsApproval`) or `refuse`.

- On-chain enforcers can rely on the chain itself for the receipt (tx plus an event), *as long as
  the chain's own consensus signatures are PQ or the record is anchored somewhere that is*. If they
  aren't, the enforcer or a witness signs a receipt like the one above. Invoice Leash's live agent
  signs its SHA3-256 hash-chained log every day with the relayer's on-chain ML-DSA-87 key.
- `unknown` is a real status. A timeout after sending is reported as unknown, never as refused or
  not sent, and is settled later by reading the enforcer's state.
- **Revocation** is a signed `revoke` object (`{"mandate": <hash>, "at": …}`). It takes effect at the
  enforcer as soon as it lands. It rejects everything pending. It can't be undone (`sticky`). There
  is also a one-step freeze that does everything at once: agent off, key unlinked, windows closed
  (`desk.mjs freeze`). A *pause* that can be lifted is a different thing and must not be
  encoded as a revoke: Leash ID's `RevokeAgent` is lifted by `ResumeAgent`, so in `pqam` terms it
  is a pause (its "sticky" part is narrower: `UpdatePolicy` can't lift it, only `ResumeAgent` can).

## 7. Enforcement profiles

| Profile | Scope and limits enforced by | Issuer PQ signature checked by | State |
|---|---|---|---|
| **QoreChain** | account-abstraction spending rule (denoms, calls, expiry) + desk contract (limits, payees) | the chain: hybrid account, ML-DSA-87 precompile `0x…0a01` for invoices | running (Invoice Leash V2/V3) |
| **CosmWasm / ME Hub** | the Leash ID contract (policy, rolling window, approvals, pending cap) | **not yet**: ME Hub accounts are secp256k1. Payee identity is checked live through the x/did Stargate query | running (Leash ID v0.3), PQ part missing |
| **EVM + ERC-7710** | a caveat enforcer per scope/limit field | off-chain or a precompile. Pure-Solidity ML-DSA verification costs too much gas on chains without one | design only |
| **Off-chain (AP2, x402 facilitator)** | the processor | a verifier library, receipts signed by the processor | design only |

On a chain that can't verify ML-DSA itself, the profile must say so plainly. In that case the
on-chain record holds the mandate *hash*, and the PQ signatures live with it in the evidence
bundle. That bundle still protects the evidence, but **it does not protect the money** from a
quantum attacker who controls the classical owner key. Profiles have to say which of the two they
give.

## 8. Security considerations, from real failures

These come from building and attacking the two systems above, not from theory.

1. **A scoped key can move whatever its rule lists, by any route.** On QoreChain, a key bound to a
   spending rule could move any denom the rule allowed directly (value tx, ERC-20 `transfer`),
   whatever `allowed_evm_calls` said. Invoice Leash v1's claim that the agent could "only pay" was
   false for that reason. The fix: the agent acts as its own *empty* account, and an escrow pulls
   from the payer through an allowance. **Profiles must test the bare asset paths, not only the
   allowed calls.**
2. **Settings keyed by `msg.sender`, not by a parameter.** A desk that took `payer` as an argument
   for settings would let the agent configure the payer. Store settings per caller.
3. **Check the signature before the replay check.** Then an edited copy of a paid invoice is
   reported as a forgery, not as "already paid", and the logs stay honest.
4. **The model sees the signed fields, not the email text.** Prompt injection is in every test inbox.
   It has never moved money in these systems, because the enforcer doesn't read prose. Tested
   with Claude Haiku, Sonnet and Opus told to obey a forged CFO, with an "obey everything" MCP
   client, and with a randomized campaign (2,000 random + 23 signed attempts, 0 paid).
5. **Instructions are mandates too.** "Approved by the CFO" counts only as a signed
   `pqam/0.1/approve` (Invoice Leash: QoreSign messages verified against the account's on-chain
   ML-DSA-87 key, with a validity end). A Q-Day forgery (the real classical key plus the
   attacker's PQ key) must fail.
6. **Sealing is not authenticity.** ML-KEM-encrypted invoices protect them from being read later;
   a sealed forgery is still a forgery.
7. **Rotation must not create a back door.** Replacing a payee's PQ key is an issuer-level act
   (the drill tries to swap a vendor's ML-DSA-87 key with the classical key only: refused).
8. **What this does not stop:** a compromised *approved* payee can invoice up to the limits, paid
   only to its own address. Limits and approvals are the answer, not cryptography.

## 9. Where the two implementations stand

| Section | Invoice Leash | Leash ID |
|---|---|---|
| 4 object format (JCS, `pqam/0.1`) | no, its own ABI encoding (`LEASH-INVOICE-v2`) | no, CosmWasm `PolicyMsg` |
| 4 scope / limits / approve_above / expiry | yes (per payment, UTC day, link expiry) | yes (rolling 24 h, approve_above, max_pending 50, TTL 7 d) |
| 4.2 offer + accept | no | yes |
| 5 hybrid issuer signature | yes (chain-enforced) | no (secp256k1 only) |
| 5 PQ payee invoices | yes (ML-DSA-87 on chain) | no |
| 6 PQ-signed receipts / log | yes (daily ML-DSA-87 signed log) | no |
| 6 sticky revoke + freeze | freeze yes; revoke = unlink the key | pause only (`RevokeAgent` / `ResumeAgent`); no permanent revoke |

## 10. Next steps

1. **Done (0.1.0):** [eltociear/pqam](https://github.com/eltociear/pqam), a JavaScript library with
   TypeScript types. It canonicalises, signs and verifies `pqam/0.1` objects (ML-DSA-44/65/87,
   Ed25519, ES256K) and evaluates payments. Its conformance vectors are 23 verify cases and 26
   policy cases, reproduced byte for byte from seeds. QoreChain's `@qorechain/sdk` verifies its
   ML-DSA-87 signatures.
2. **Done (0.1.0), compile step only:** the adapters turn a mandate into Leash ID's `PolicyMsg` or
   InvoiceDesk limits plus the agent's spending rule, and refuse what the target can't enforce.
   Still to do: install those configs on chain from these repositories, so that one mandate
   actually runs on both chains.
3. Proposals: a PQ extension issue to AP2, a post on the Ethereum Magicians agent-mandate thread, and
   feedback to the IETF WIMSE PQ agent identity draft.

## Open questions

- Composite signatures: carry two signatures side by side (as here) or use the IETF LAMPS
  composite ML-DSA encoding? Side by side is simpler to verify on chains that have only one half.
- Should `scope.payee_rule` be a small fixed vocabulary (`did-verified:kyc>=N`, `allowlist`) or a
  policy language? Fixed is easier to enforce on chain; we lean that way.
- Where receipts are anchored when neither the chain nor the processor is PQ.
- Agents that delegate to other agents: does a sub-mandate need to be a strict subset (the way
  ERC-7710 delegations narrow), and who checks that?

## References

- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard (ML-DSA)
- IETF draft-uppalapati-wimse-pq-agent-identity-00
- Google Agent Payments Protocol (AP2)
- ERC-7715 (wallet permissions request), ERC-7710 (delegation), both Draft
- RFC 8785, JSON Canonicalization Scheme
