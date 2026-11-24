// One issuer, one agent key, two chains, two enforcers, the same pqam/0.1 format and verifier.
//
//   A. ME Hub (CosmWasm): the Leash ID contract (v0.4.0, the canonical wasm deployed on testnet).
//   B. EVM: InvoiceDeskV3 (the bytecode Invoice Leash runs on QoreChain).
//
// For each chain: the issuer signs a mandate (hybrid ML-DSA-87 + ES256K), the agent key accepts it,
// pqam verifies it, an adapter compiles it into the enforcer's own configuration, and that is
// installed on chain. Then the agent tries a series of payments. For every attempt we record what
// pqam's reference evaluator says should happen and what the chain did. The run fails if they
// disagree even once. Finally the issuer signs a pqam revoke, the enforcer is told, and the agent
// is refused.
//
// Both chains are local and private (ports 46xxx and 48600). Nothing here touches a testnet or a
// wallet that holds real or shared funds. Keys come from fixed seeds and are printed nowhere.
//   node examples/two-chains/run.mjs [--keep]      (--keep leaves both nodes running)
import { spawn, execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { shake256 } from "@noble/hashes/sha3.js";
import { utf8ToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { DirectSecp256k1Wallet } from "@cosmjs/proto-signing";
import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import { GasPrice } from "@cosmjs/stargate";
import { ethers } from "ethers";
import * as P from "../../src/index.mjs";

const HERE = new URL(".", import.meta.url);
const path = (p) => new URL(p, HERE).pathname;
const KEEP = process.argv.includes("--keep");
const seed = (name, n) => shake256(utf8ToBytes(`pqam two-chains example: ${name}`), { dkLen: n });
const signer = (name, alg) => P.signerFromSeed(alg, seed(name, alg === "ES256K" ? 48 : 32));

// ---------- keys ----------
// The issuer's classical key and the agent's key are each ONE secp256k1 key, used on both chains
// (a bech32 address on ME Hub, a 0x address on the EVM). The issuer's ML-DSA-87 key is the same too.
const K = {
  issuerPq: signer("issuer ML-DSA-87", "ML-DSA-87"),
  issuerEc: signer("issuer secp256k1", "ES256K"),
  agent: signer("agent secp256k1", "ES256K"),
  meVendor: signer("ME Hub vendor", "ES256K"),
  meVerified: signer("ME Hub vendor with an ME ID", "ES256K"),
  meStranger: signer("ME Hub stranger", "ES256K"),
  evmVendor: signer("EVM vendor", "ES256K"),
  evmVendorPq: signer("EVM vendor invoice key", "ML-DSA-87"),
  evmStranger: signer("EVM stranger", "ES256K"),
  evmStrangerPq: signer("EVM stranger invoice key", "ML-DSA-87"),
};
const ISSUER = [K.issuerPq, K.issuerEc];
const hex = (b) => "0x" + bytesToHex(b);
const meAddr = async (s) => (await (await DirectSecp256k1Wallet.fromKey(s.secretKey, "me")).getAccounts())[0].address;
const evmAddr = (s) => ethers.computeAddress(hex(s.publicKey));

const report = { about: "pqam/0.1 two-chain run: reference evaluator vs. the chain, attempt by attempt", startedAt: new Date().toISOString(), chains: {} };
let disagreements = 0;
const line = (s) => process.stdout.write(s + "\n");

function record(chain, row) {
  const agree = row.expected.decision === row.chain.decision;
  if (!agree) disagreements++;
  report.chains[chain].attempts.push({ ...row, agree });
  line(`  ${agree ? "ok  " : "DIFF"} ${row.name.padEnd(46)} pqam: ${(row.expected.decision + " " + row.expected.reason).padEnd(28)} chain: ${row.chain.decision}${row.chain.detail ? " (" + row.chain.detail + ")" : ""}`);
}

function signMandate(body) {
  const m = P.accept(P.sign(body, ISSUER), [K.agent]);
  const v = P.verifyMandate(m);
  if (!v.ok) throw new Error(`mandate did not verify: ${v.why}`);
  return { m, hash: v.hash };
}

// ======================= A. ME Hub + Leash ID =======================
async function meHub() {
  const CHAIN = "mechain_2401-1";
  const RPC = "http://127.0.0.1:46657";
  const sh = (...a) => execFileSync(path("mehub.sh"), a, { encoding: "utf8" }).trim();
  const A = {
    owner: await meAddr(K.issuerEc), agent: await meAddr(K.agent), vendor: await meAddr(K.meVendor),
    verified: await meAddr(K.meVerified), stranger: await meAddr(K.meStranger),
  };
  const ids = [
    { did: "2000000000201", address: A.owner, pubkey: Buffer.from(K.issuerEc.publicKey).toString("base64"), kycLevel: "KYC_LEVEL_TWO" },
    { did: "2000000000202", address: A.verified, pubkey: Buffer.from(K.meVerified.publicKey).toString("base64"), kycLevel: "KYC_LEVEL_TWO" },
  ];
  mkdirSync(path("runs"), { recursive: true });
  writeFileSync(path("runs/mehub-ids.json"), JSON.stringify(ids));
  line(sh("init", path("runs/mehub-ids.json")));
  line(sh("start"));
  for (const a of [A.owner, A.agent]) line(sh("fund", a, a === A.owner ? "20000000000" : "1000000000"));

  const client = async (s) => SigningCosmWasmClient.connectWithSigner(RPC, await DirectSecp256k1Wallet.fromKey(s.secretKey, "me"), { gasPrice: GasPrice.fromString("0.1umec") });
  const owner = await client(K.issuerEc);
  const agent = await client(K.agent);
  const up = await owner.upload(A.owner, readFileSync(path("artifacts/leash_id.wasm")), "auto");
  const init = await owner.instantiate(A.owner, up.codeId, { min_kyc_level: 2, denom: "umec" }, "leash-id 0.4.0 (pqam example)", "auto");
  const contract = init.contractAddress;
  const now = async () => Math.floor(Date.parse((await owner.getBlock()).header.time) / 1000);
  const t0 = await now();

  const { m, hash } = signMandate({
    v: "pqam/0.1", type: "mandate", id: "two-chains-mehub",
    issuer: { id: "did:me:2000000000201", keys: ISSUER.map(P.publicKey) },
    agent: { keys: [P.publicKey(K.agent)] },
    enforcer: `cosmos:${CHAIN}:${contract}`,
    scope: { assets: [`cosmos:${CHAIN}/slip44:umec`], payees: [`cosmos:${CHAIN}:${A.vendor}`], payee_rule: "did-verified:kyc>=2", invoice: "none" },
    limits: { per_payment: "100000000", window: { seconds: 86400, max: "250000000", kind: "rolling" }, approve_above: "50000000", max_pending: 50, pending_ttl: 604800 },
    not_before: t0 - 120, expires: t0 + 30 * 86400,
    revocation: { where: `cosmos:${CHAIN}:${contract}`, sticky: true },
  });
  const compiled = P.toLeashId(m, { chainId: CHAIN, denom: "umec", minKycLevel: 2 });
  if (!compiled.ok) throw new Error(compiled.problems.join("; "));
  const policy = compiled.config.register_agent.policy;
  const reg = await owner.execute(A.owner, contract, { register_agent: { agent: A.agent, policy } }, "auto");
  const dep = await owner.execute(A.owner, contract, { deposit: {} }, "auto", undefined, [{ denom: "umec", amount: "1000000000" }]);
  const acc = await agent.execute(A.agent, contract, { accept_leash: { owner: A.owner } }, "auto");
  report.chains.mehub = {
    enforcer: m.enforcer, codeId: up.codeId, wasmSha256: execFileSync("shasum", ["-a", "256", path("artifacts/leash_id.wasm")], { encoding: "utf8" }).split(" ")[0],
    mandateHash: hash, installed: { policy, registerTx: reg.transactionHash, depositTx: dep.transactionHash, acceptTx: acc.transactionHash }, attempts: [],
  };
  writeFileSync(path("runs/mandate-mehub.json"), JSON.stringify(m, null, 1) + "\n");
  line(`A. ME Hub: Leash ID ${contract}, mandate ${hash.slice(0, 16)}… installed (register, deposit, accept)`);

  const history = [];
  let revoked = false;
  const verified = new Set([`cosmos:${CHAIN}:${A.verified}`]);
  let n = 0;
  const attempt = async (name, payee, amount) => {
    const req = { payee: `cosmos:${CHAIN}:${payee}`, asset: `cosmos:${CHAIN}/slip44:umec`, amount };
    const at = await now();
    const expected = P.evaluate(m, req, { now: at, accepted: true, revoked, history, payeeRule: (p) => verified.has(p) });
    let chain;
    try {
      const r = await agent.execute(A.agent, contract, { pay: { vendor: payee, amount, invoice: `INV-${++n}` } }, "auto");
      const status = r.events.flatMap((e) => e.attributes).find((x) => x.key === "status")?.value;
      chain = { decision: status === "paid" ? "pay" : status === "pending" ? "hold" : `?${status}`, tx: r.transactionHash };
      if (status === "paid" || status === "pending") history.push({ at, amount, status });
    } catch (e) {
      chain = { decision: "refuse", detail: String(e.message).match(/(?:execute wasm contract failed|failed to execute message; message index: 0): (.*?)(?:: execute wasm contract failed|$)/)?.[1]?.slice(0, 90) ?? String(e.message).slice(0, 90) };
    }
    record("mehub", { name, request: req, expected, chain });
  };
  await attempt("0.4 MEC to the listed vendor", A.vendor, "40000000");
  await attempt("0.6 MEC: above the hold line", A.vendor, "60000000");
  await attempt("1.00000001 MEC: over per_payment", A.vendor, "100000001");
  await attempt("to an account with no ME ID, not listed", A.stranger, "1000000");
  await attempt("0.3 MEC to a vendor admitted by its ME ID", A.verified, "30000000");
  await attempt("1 MEC: window 1.3 + 1 = 2.3 of 2.5, held", A.vendor, "100000000");
  await attempt("0.3 MEC: window 2.3 + 0.3 > 2.5", A.vendor, "30000000");

  const rv = P.sign({ v: "pqam/0.1", type: "revoke", mandate: hash, at: await now() }, ISSUER);
  const rvOk = P.verifyIssued(rv, m);
  const rtx = await owner.execute(A.owner, contract, { revoke_agent: { agent: A.agent } }, "auto");
  revoked = true;
  for (const h of history) if (h.status === "pending") h.status = "refused"; // the contract rejects pending payments on revoke
  writeFileSync(path("runs/revoke-mehub.json"), JSON.stringify(rv, null, 1) + "\n");
  report.chains.mehub.revoke = { pqamRevokeVerified: rvOk.ok, revokeTx: rtx.transactionHash };
  line(`  pqam revoke signed and verified (${rvOk.ok}), revoke_agent sent`);
  await attempt("after the revoke: 0.01 MEC", A.vendor, "1000000");
}

// ======================= B. EVM + InvoiceDeskV3 =======================
async function evm() {
  const PORT = 48600;
  const anvil = spawn(`${process.env.HOME}/.foundry/bin/anvil`, ["--port", String(PORT), "--chain-id", "9800", "--silent"], { stdio: "ignore" });
  const provider = new ethers.JsonRpcProvider(`http://127.0.0.1:${PORT}`, 9800, { staticNetwork: true, polling: true, pollingInterval: 100, cacheTimeout: -1 });
  for (let i = 0; ; i++) {
    try { await provider.getBlockNumber(); break; } catch { if (i > 50) throw new Error("anvil did not start"); await new Promise((r) => setTimeout(r, 200)); }
  }
  try {
    // Plain wallets (nonce read from the node each time). ethers' NonceManager counts a nonce even when
    // gas estimation reverts, which leaves a gap and every later transaction waits forever.
    const wallet = (s) => new ethers.Wallet(hex(s.secretKey), provider);
    const company = wallet(K.issuerEc);
    const agentW = wallet(K.agent);
    const A = { company: evmAddr(K.issuerEc), agent: evmAddr(K.agent), vendor: evmAddr(K.evmVendor), stranger: evmAddr(K.evmStranger) };
    for (const a of [A.company, A.agent]) await provider.send("anvil_setBalance", [a, "0x56BC75E2D63100000"]);

    const S = JSON.parse(readFileSync(path("artifacts/StandIns.json"), "utf8"));
    const D = JSON.parse(readFileSync(path("artifacts/InvoiceDeskV3.json"), "utf8"));
    const PQC_VERIFY = "0x0000000000000000000000000000000000000a01";
    const PQC_STATUS = "0x0000000000000000000000000000000000000a02";
    for (const at of [PQC_VERIFY, PQC_STATUS]) await provider.send("anvil_setCode", [at, S.PqcStandIn.deployedBytecode]);
    const pqcV = new ethers.Contract(PQC_VERIFY, S.PqcStandIn.abi, company);
    const pqcS = new ethers.Contract(PQC_STATUS, S.PqcStandIn.abi, company);
    const token = await (await new ethers.ContractFactory(S.TestUSD.abi, S.TestUSD.bytecode, company).deploy(A.company, 1000_000000n)).waitForDeployment();
    const desk = await (await new ethers.ContractFactory(D.abi, D.bytecode, company).deploy()).waitForDeployment();
    const deskAddr = await desk.getAddress();
    const tokenAddr = await token.getAddress();
    await (await pqcS.setKey(A.vendor, K.evmVendorPq.publicKey)).wait();
    await (await pqcS.setKey(A.stranger, K.evmStrangerPq.publicKey)).wait();
    const now = async () => (await provider.getBlock("latest")).timestamp;
    const t0 = await now();

    const { m, hash } = signMandate({
      v: "pqam/0.1", type: "mandate", id: "two-chains-evm",
      issuer: { id: "did:me:2000000000201", keys: ISSUER.map(P.publicKey) },
      agent: { keys: [P.publicKey(K.agent)] },
      enforcer: `eip155:9800:${deskAddr}`,
      scope: { assets: [`eip155:9800/erc20:${tokenAddr}`], payees: [`eip155:9800:${A.vendor}`], calls: [{ target: `eip155:9800:${deskAddr}`, selector: P.DESK_PAY_SELECTOR }], invoice: "required-signed" },
      limits: { per_payment: "100000000", window: { seconds: 86400, max: "250000000", kind: "calendar" }, max_pending: 0, pending_ttl: 0 },
      not_before: t0 - 120, expires: t0 + 30 * 86400,
      revocation: { where: `eip155:9800:${deskAddr}`, sticky: true },
    });
    const c = P.toInvoiceDesk(m);
    if (!c.ok) throw new Error(c.problems.join("; "));
    const cfg = c.config;
    const deskC = desk.connect(company);
    const txs = {};
    txs.setLimit = (await (await deskC.setLimit(cfg.token, cfg.limit.perPayment, cfg.limit.daily)).wait()).hash;
    for (const v of cfg.vendors) txs[`approveVendor ${v}`] = (await (await deskC.approveVendor(v)).wait()).hash;
    txs.setAgent = (await (await deskC.setAgent(A.agent, true)).wait()).hash;
    txs.allowance = (await (await token.connect(company).approve(deskAddr, ethers.MaxUint256)).wait()).hash;
    report.chains.evm = { enforcer: m.enforcer, mandateHash: hash, installed: { ...cfg, txs }, attempts: [], note: "Local EVM: ML-DSA-87 invoice signatures are verified off-chain with real ML-DSA-87 and recorded in a fail-closed stand-in at 0x…0a01 (QoreChain verifies them in its precompile). QoreChain's account-abstraction spending rule (agentRule) has no local equivalent, so only the desk's limits are enforced here." };
    writeFileSync(path("runs/mandate-evm.json"), JSON.stringify(m, null, 1) + "\n");
    line(`B. EVM: InvoiceDeskV3 ${deskAddr}, mandate ${hash.slice(0, 16)}… installed (limit, vendor, agent, allowance)`);

    const history = [];
    let revoked = false;
    let n = 0;
    const deskA = desk.connect(agentW);
    // An invoice in the desk's own signed format (LEASH-INVOICE-v2), signed with the vendor's ML-DSA-87
    // key. `claim` lets a test lie about the amount while reusing a genuine signature.
    const invoice = async (vendor, vendorPq, amount, claim = amount) => {
      const id = ethers.id(`INV-${++n}`);
      const dueBy = (await now()) + 7 * 86400;
      const msg = ethers.getBytes(await desk.invoiceMessage(A.company, vendor, tokenAddr, amount, id, dueBy));
      const sig = ml_dsa87.sign(msg, vendorPq.secretKey, { extraEntropy: false });
      const claimed = ethers.getBytes(await desk.invoiceMessage(A.company, vendor, tokenAddr, claim, id, dueBy));
      const valid = ml_dsa87.verify(sig, claimed, vendorPq.publicKey); // the agent's own off-chain check
      if (valid) await (await pqcV.record(vendorPq.publicKey, sig, claimed)).wait();
      return { id, dueBy, sig, amount: claim, valid };
    };
    const attempt = async (name, vendor, inv) => {
      const req = { payee: `eip155:9800:${vendor}`, asset: `eip155:9800/erc20:${tokenAddr}`, amount: String(inv.amount), call: { target: m.enforcer, selector: P.DESK_PAY_SELECTOR }, invoiceVerified: inv.valid };
      const at = await now();
      const expected = P.evaluate(m, req, { now: at, accepted: true, revoked, history });
      let chain;
      try {
        const r = await (await deskA.pay(A.company, tokenAddr, vendor, inv.amount, inv.id, inv.dueBy, inv.sig)).wait();
        chain = { decision: "pay", tx: r.hash };
        history.push({ at, amount: String(inv.amount), status: "paid" });
      } catch (e) {
        const data = e.data ?? e.info?.error?.data ?? e.error?.data;
        let detail = e.shortMessage ?? String(e.message).slice(0, 80);
        try { detail = desk.interface.parseError(data)?.name ?? detail; } catch {}
        chain = { decision: "refuse", detail };
      }
      record("evm", { name, request: req, expected, chain });
    };
    const V = [A.vendor, K.evmVendorPq];
    await attempt("80 tUSD, genuine invoice", A.vendor, await invoice(...V, 80_000000n));
    await attempt("120 tUSD: over per_payment", A.vendor, await invoice(...V, 120_000000n));
    await attempt("90 tUSD: window 80 + 90 of 250", A.vendor, await invoice(...V, 90_000000n));
    await attempt("genuine signature, amount edited 50 -> 95", A.vendor, await invoice(...V, 50_000000n, 95_000000n));
    await attempt("stranger with its own valid invoice", A.stranger, await invoice(A.stranger, K.evmStrangerPq, 10_000000n));
    await attempt("90 tUSD: window 170 + 90 > 250", A.vendor, await invoice(...V, 90_000000n));
    await provider.send("evm_increaseTime", [86400]);
    await provider.send("evm_mine", []);
    await attempt("next UTC day: 90 tUSD fits again", A.vendor, await invoice(...V, 90_000000n));

    const rv = P.sign({ v: "pqam/0.1", type: "revoke", mandate: hash, at: await now() }, ISSUER);
    const rvOk = P.verifyIssued(rv, m);
    const rtx = (await (await deskC.setAgent(A.agent, false)).wait()).hash;
    revoked = true;
    writeFileSync(path("runs/revoke-evm.json"), JSON.stringify(rv, null, 1) + "\n");
    report.chains.evm.revoke = { pqamRevokeVerified: rvOk.ok, setAgentFalseTx: rtx };
    line(`  pqam revoke signed and verified (${rvOk.ok}), setAgent(agent, false) sent`);
    await attempt("after the revoke: 10 tUSD", A.vendor, await invoice(...V, 10_000000n));
  } finally {
    if (!KEEP) anvil.kill();
  }
}

try {
  await meHub();
  await evm();
} finally {
  if (!KEEP) execFileSync(path("mehub.sh"), ["stop"], { stdio: "ignore" });
}
const total = Object.values(report.chains).reduce((s, c) => s + c.attempts.length, 0);
report.summary = { attempts: total, disagreements, sameIssuerKeys: true, sameAgentKey: true };
writeFileSync(path("runs/two-chains.json"), JSON.stringify(report, null, 1) + "\n");
line(`\n${total} attempts on two chains, ${disagreements} disagreement(s) between pqam and the chain. runs/two-chains.json`);
process.exit(disagreements ? 1 : 0);
