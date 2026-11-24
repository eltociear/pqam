# Two chains, one issuer, one agent key

`run.mjs` installs pqam/0.1 mandates on two real enforcers and checks, attempt by attempt, that the
chain does what pqam's reference evaluator says it must.

| | A. ME Hub (CosmWasm) | B. EVM |
|---|---|---|
| Enforcer | Leash ID v0.4.0, the canonical wasm deployed on ME Hub testnet (`sha256 8854a4e2…`) | InvoiceDeskV3, the bytecode Invoice Leash runs on QoreChain |
| Node | a private single ME Hub node built from openmetaearth/me-hub (`mehub.sh`, ports 46xxx) | anvil, chain id 9800, port 48600 |
| Mandate compiled by | `toLeashId`: `RegisterAgent` policy, then the agent's `AcceptLeash` | `toInvoiceDesk`: `setLimit`, `approveVendor`, `setAgent`, allowance |
| Window | rolling 24 h, hold above 0.5 MEC | UTC day, payee-signed ML-DSA-87 invoices |
| Revoke | pqam revoke + `revoke_agent` | pqam revoke + `setAgent(agent, false)` |

Both mandates are signed by the **same issuer keys** (ML-DSA-87 + one secp256k1 key, which is the owner
account on ME Hub and the company account on the EVM). Both are accepted by the **same agent key** (one
secp256k1 key: a bech32 address on ME Hub, a 0x address on the EVM).

Result of the recorded run ([runs/two-chains.json](runs/two-chains.json)): **16 attempts, 0
disagreements.** Every pay, hold and refuse matched, including the hold line, both window kinds, a
payee admitted only by its on-chain ME ID, an edited invoice, a stranger with a valid invoice of its
own, the next UTC day, and both revokes. The signed mandates and revokes are in `runs/`, and
`test/two-chains.test.mjs` re-verifies them offline.

What is *not* shown here, said plainly:

- **These are local chains, not testnets.** Nothing was sent to a public network, on purpose: the
  testnet wallets belong to the two live projects.
- **The EVM has no QoreChain precompile.** `run.mjs` verifies each ML-DSA-87 invoice signature with
  real ML-DSA-87 (the same answers as `@qorechain/sdk`) and records only what it checked in a
  fail-closed stand-in at `0x…0a01`. Invoice Leash's Foundry tests do the same. QoreChain's
  account-abstraction spending rule (`agentRule` in the adapter output) has no local equivalent, so
  only the desk's own limits are enforced here.
- **The ME Hub chain doesn't check the pqam signatures.** It verifies secp256k1 transactions only.
  The pqam mandate is the evidence of what the owner allowed. The contract enforces the compiled
  policy (spec section 7: this profile protects the evidence, not the money, from a quantum
  attacker).
- The example keys come from seeds written in `run.mjs`. They are test keys for local chains, and
  anyone can derive them.

```
npm install
node examples/two-chains/compile.mjs   # stand-ins -> artifacts/StandIns.json (already committed)
node examples/two-chains/run.mjs       # needs ME_HUB_DIR (default ~/workspace/harbor/vendor/me-hub, with build/med) and Foundry's anvil
```
