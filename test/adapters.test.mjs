import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as P from "../src/index.mjs";

const V = JSON.parse(readFileSync(new URL("../vectors/pqam-0.1.json", import.meta.url), "utf8"));
const M1 = V.objects.M1.object;
const M2 = V.objects.M2.object;
const ME = { chainId: "mechain_400-1", denom: "umec", minKycLevel: 2 };

test("M1 compiles to a Leash ID PolicyMsg", () => {
  const r = P.toLeashId(M1, ME);
  assert.ok(r.ok, r.problems?.join("\n"));
  assert.deepEqual(r.config.register_agent.policy, {
    label: "vector-m1", per_tx_limit: "100000000", daily_limit: "250000000", approve_above: "50000000",
    vendors: ["me1vendoraaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"], any_verified_vendor: true, expires_at: 1797600000,
  });
  assert.equal(r.config.install_after, M1.not_before);
});

test("M1 with a different KYC level or a calendar window is refused by the Leash ID profile", () => {
  assert.match(P.toLeashId(M1, { ...ME, minKycLevel: 1 }).problems.join(), /kyc>=2/);
  const cal = { ...M1, limits: { ...M1.limits, window: { ...M1.limits.window, kind: "calendar" } } };
  assert.match(P.toLeashId(cal, ME).problems.join(), /rolling 24 h/);
  assert.match(P.toLeashId({ ...M1, limits: { ...M1.limits, max_pending: 10 } }, ME).problems.join(), /50 pending/);
});

test("M2 compiles to an InvoiceDesk config and the agent's spending rule", () => {
  const r = P.toInvoiceDesk(M2);
  assert.ok(r.ok, r.problems?.join("\n"));
  assert.equal(r.config.chainId, 9800);
  assert.deepEqual(r.config.limit, { perPayment: "100000000", daily: "250000000" });
  assert.equal(r.config.vendors.length, 2);
  assert.deepEqual(r.config.agentRule.allowedEvmCalls, ["0x00000000000000000000000000000000de5c0001/0xf19ff4ff"]);
});

test("each mandate is refused by the other profile, with reasons", () => {
  const a = P.toInvoiceDesk(M1);
  assert.equal(a.ok, false);
  assert.ok(a.problems.length >= 4, a.problems.join("\n"));
  const b = P.toLeashId(M2, ME);
  assert.equal(b.ok, false);
  assert.ok(b.problems.length >= 4, b.problems.join("\n"));
});

test("the desk profile refuses approve_above (it cannot hold a payment)", () => {
  const m = { ...M2, limits: { ...M2.limits, approve_above: "1" } };
  assert.match(P.toInvoiceDesk(m).problems.join(), /cannot hold/);
});
