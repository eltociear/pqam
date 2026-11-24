# pqam: PQ Agent Mandate

Signed spending mandates for AI agents that will still hold up as evidence after Q-Day.

An agent's payment is over in seconds. The mandate behind it, the record that a person let *this*
key spend *this much* on *these* payees until *then*, has to stand up in a dispute or an audit years
later. If that mandate is signed with ECDSA or EdDSA only, then once a cryptographically relevant
quantum computer exists, anyone holding the issuer's public key can forge one. **pqam** signs
mandates, revocations, approvals, invoices and receipts with ML-DSA (FIPS 204). During the
transition it signs hybrid, and hybrid means **every** key must verify. Each signature is bound to
the whole signer set, so the classical half can't be stripped off.

- **Spec:** [SPEC.md](SPEC.md) (draft 0.1). The same text is `MANDATE.md` in
  [Invoice Leash](https://github.com/eltociear/invoice-leash) and
  [Leash ID](https://github.com/eltociear/leash-id), the two running systems it was written from.
- **Conformance vectors:** [vectors/pqam-0.1.json](vectors/pqam-0.1.json), with 26 signature cases
  (including Q-Day forgeries, hybrid stripping, cross-type replays and malformed objects), 26 policy
  cases (limits, windows, holds, scope, revocation, and the order of checks), and 10 admission cases.
  Admission is the policy verdict, kept apart from verification: a genuine classical-only mandate
  *verifies*, and is refused after a transition date, checked against a trusted time. Every key comes from
  a published seed and every signature is deterministic, so the file is rebuilt byte for byte
  (`npm run vectors`, and CI checks it).
- **Interop:** ML-DSA here is FIPS 204 "pure" with an empty context. That is the variant QoreChain
  uses: `@qorechain/sdk` verifies pqam signatures (see `test/interop.test.mjs`).

## Use

```js
import { signerFromSeed, publicKey, sign, accept, verifyMandate, evaluate, toLeashId } from "pqam";
import { randomBytes } from "node:crypto";

const issuerPq = signerFromSeed("ML-DSA-87", randomBytes(32));
const issuerEc = signerFromSeed("ES256K", randomBytes(48));
const agent = signerFromSeed("Ed25519", randomBytes(32));

let m = sign({
  v: "pqam/0.1", type: "mandate", id: "ops-agent-2026-12",
  issuer: { id: "did:example:acme", keys: [publicKey(issuerPq), publicKey(issuerEc)] },
  agent: { keys: [publicKey(agent)] },
  enforcer: "eip155:9800:0x00000000000000000000000000000000DE5C0001",
  scope: { assets: ["eip155:9800/erc20:0x97143B771D34ddb9130b807b135Ae675A5a963CA"],
           payees: ["eip155:9800:0x0000000000000000000000000000000000004057"], invoice: "required-signed" },
  limits: { per_payment: "100000000", window: { seconds: 86400, max: "250000000", kind: "calendar" },
            max_pending: 0, pending_ttl: 0 },
  not_before: 1795000000, expires: 1797600000,
  revocation: { where: "eip155:9800:0x00000000000000000000000000000000DE5C0001", sticky: true },
}, [issuerPq, issuerEc]);
m = accept(m, [agent]);              // nothing is in force until the agent key accepts

verifyMandate(m);                    // { ok: true, hash, accepted: true }
evaluate(m, { payee: m.scope.payees[0], asset: m.scope.assets[0], amount: "80000000", invoiceVerified: true },
         { now: 1797000000, accepted: true, history: [] });
// { decision: "pay", reason: "WithinMandate", window_used: "0" }
```

`toLeashId(m, {...})` and `toInvoiceDesk(m)` compile a mandate into those enforcers' native
configuration: a CosmWasm `PolicyMsg`, or desk limits plus the agent key's QoreChain spending rule.
If the target can't enforce something the mandate asks for (a rolling window on a UTC-day desk, a
hold on a desk that can't hold), the adapter refuses and says why. It never loosens a mandate.

## Two chains

[examples/two-chains](examples/two-chains) installs mandates on two running enforcers: Leash ID on a
private ME Hub node, and InvoiceDeskV3 on anvil. The issuer keys and the agent key are the same on
both. Then it makes 16 payment attempts. The chain agreed with `evaluate()` on every one: pay, hold,
refuse, both window kinds, a payee admitted only by its on-chain ME ID, an edited invoice, and both
revokes. That README also lists what a local run does not show.

## What it is and isn't

- It **is** the signed objects, their verification, and a reference evaluator. The evaluator
  defines what an enforcer must decide, and the vectors pin that down.
- It **is not** an enforcer. Whoever holds the money (a contract, a chain module, a processor) has
  to enforce the mandate. The agent is assumed to be fooled or stolen, so it never enforces its own
  limits.
- Draft 0.1, written by one team from two hackathon systems. It has not been reviewed, audited or
  proposed to any standards body yet. The cryptography is
  [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) and
  [@noble/curves](https://github.com/paulmillr/noble-curves). pqam adds no cryptography of its own.

```
npm test          # 113 tests: vectors, JCS, objects, adapters, QoreChain interop, two-chain evidence, AP2 interop
npm run vectors   # rebuild vectors/pqam-0.1.json (must not change)
```

Apache-2.0
