// Crosswalk: every pqam/0.1 conformance case read against the layers of ap2-evidence-pack
// (SPEC_AP2_EVIDENCE.md, revision 1.10.0, 2026-11-22) and, where a time is involved, the AER-1 anchor
// outcomes (verified / verification failed / rejected: unresolvable record / not checked / absent).
//
// Written for the cross-test offered on AP2 issue #338. It is OUR reading of the pack's text, to be
// checked by the pack's side. A pack cannot carry a pqam object today: its schema is closed (§9.1), so a
// pqam member would be refused as `unknown_member`. Rows therefore say what the pack reports for the
// AP2-shaped analogue TODAY, and what it would report with the issuance member proposed on #338.
//
//   node interop/ap2-evidence-pack/crosswalk.mjs   -> crosswalk.json, CROSSWALK.md (beside this file)
import { readFileSync, writeFileSync } from "node:fs";
import * as P from "../../src/index.mjs";

const V = JSON.parse(readFileSync(new URL("../../vectors/pqam-0.1.json", import.meta.url), "utf8"));
const keysOf = (names) => names.map((n) => ({ alg: V.keys[n].alg, pub: V.keys[n].pub }));
const verifyOf = (t) => (t.kind === "mandate" ? P.verifyMandate(t.object) : t.kind === "issued" ? P.verifyIssued(t.object, V.objects[t.mandate].object) : P.verifyBy(t.object, keysOf(t.keys)));

// Pack reading per verify vector, by name. `today` = the AP2-shaped analogue in a 1.10.0 pack;
// `proposed` = with an issuer PQ issuance signature as a peer of the mandate (record layer, as agreed on #338).
const VERIFY = {
  "M1 is valid (hybrid issuer, accepted)": { maps: "yes", today: "sealed_content verified; holder_binding verified (KB-JWT)", proposed: "same, plus the issuance signature verified at the mandate" },
  "M2 is valid": { maps: "yes", today: "sealed_content verified; holder_binding verified", proposed: "same" },
  "edited limit after signing": { maps: "yes", today: "sealed_content contradicted (artifact_invalid: issuer signature)", proposed: "same" },
  "PQ signature removed (classical half only)": { maps: "partial", today: "no issuer-PQ member exists, so the ES256 mandate alone reads sealed_content verified", proposed: "the mandate's own verification fails (a required issuance signature is missing), where its ES256 failure would land" },
  "Q-Day forgery: real classical signature + attacker's ML-DSA under the issuer's kid": { maps: "partial", today: "the forged ES256 mandate verifies: sealed_content verified. A fresh pack and a fresh anchor verify too. This is the gap.", proposed: "contradicted at the mandate: the PQ half fails" },
  "Q-Day forgery with the attacker's own kid": { maps: "partial", today: "as above: verified", proposed: "contradicted (a signer outside the signed key list)" },
  "unknown algorithm in the signature list": { maps: "partial", today: "the nearest rule is the producer block's: an unknown sig_alg is a GAP (not_evaluated), and the block is never ok", proposed: "pqam refuses an unknown algorithm outright (UnknownAlgorithm). Neither accepts it, but the words differ: not_evaluated vs. a failure" },
  "not accepted by the agent": { maps: "yes", today: "holder_binding not_evaluated (not_present): no KB-JWT. That is a failure only if the relying party requires holder binding", proposed: "pqam: NotAccepted is a verification failure. Acceptance is required, not a relying-party option" },
  "accepted by a key that is not the agent's": { maps: "yes", today: "holder_binding contradicted (kb_signature_invalid)", proposed: "same" },
  "issuer signature made under the accept tag": { maps: "yes", today: "sealed_content contradicted (issuer signature)", proposed: "same (domain separation; the pack's analogue is the typ check of the JOSE header profile, §13)" },
  "issuer with a classical key only (verifies; admission decides)": { maps: "yes", today: "sealed_content verified", proposed: "verified. Whether it is acceptable is policy: see the admission rows" },
  "issuer with ML-DSA-44 only (verifies; admission decides)": { maps: "partial", today: "no ML-DSA-44 in the pack's algorithm set", proposed: "verified (pq_level 2). Admission refuses it under min_pq_level 3" },
  "amount as a JSON number": { maps: "yes", today: "admission refused, refusal_class malformed", proposed: "same" },
  "a field pqam/0.1 does not define": { maps: "yes", today: "admission refused, refusal_class unknown_member (§9.1 closed schema)", proposed: "same" },
  "mandate longer than 366 days": { maps: "no", today: "a pqam semantic limit. The pack has no mandate-lifetime rule", proposed: "pqam: Malformed" },
  "revoke of M1": { maps: "partial", today: "no revocation artifact. The nearest is an artifact with a §4 binding to the mandate", proposed: "a revocation as an artifact bound to the mandate hash" },
  "revoke of M2 checked against M1": { maps: "partial", today: "a §4 binding that does not hold: bindings_ok false, or require_binding unmet", proposed: "WrongMandate" },
  "approval by the issuer": { maps: "no", today: "no approval artifact (a held payment released by the issuer)", proposed: "an issuer-signed artifact bound to the mandate" },
  "approval signed by the agent": { maps: "no", today: "no analogue", proposed: "UnexpectedSigner" },
  "invoice by the payee": { maps: "partial", today: "nearest: the merchant-signed checkout_jwt / checkout_hash of a closed checkout mandate", proposed: "a payee-signed invoice, PQ" },
  "invoice amount edited": { maps: "partial", today: "the checkout_hash binding fails", proposed: "BadSignature" },
  "invoice checked against another payee's key": { maps: "partial", today: "issuer_identity: the key is not the one the relying party resolves", proposed: "UnexpectedSigner" },
  "receipt by the enforcer": { maps: "partial", today: "AP2 Payment Receipt artifact (ES256)", proposed: "the enforcer's receipt, PQ-signed" },
  "hybrid invoice, both payee keys": { maps: "partial", today: "nearest: the producer block, scheme hybrid (one classical and one ml-dsa-65 entry)", proposed: "verified" },
  "stripping: classical signature removed, PQ key offered alone": { maps: "partial", today: "our reading of §5: a lone ml-dsa-65 entry matches neither scheme, so the block is not ok", proposed: "BadSignature: the PQ signature is bound to the pair" },
  "stripping: classical signature removed, both keys expected": { maps: "partial", today: "our reading of §5: the block's signatures are outside the digest (§3), so the opposite strip (drop the ml-dsa-65 entry, relabel scheme classical-only) gives an ok block with pq_protected false. Only require_pq catches it. Please confirm", proposed: "MissingSignature: the required key set is in the signed data, not a relabelable field" },
};

// Admission rows: the policy verdict. AER-1 outcomes only where a time anchor is the question.
const AER = { anchor: "verified (assuming the anchor itself checked; the vector supplies its time)", local: "absent (a verifier's clock is not an anchor)", block: "n/a: block time is the enforcer's record, not an anchor", none: "absent" };
const ADMISSION_PACK = {
  admitted: "policy met",
  "admitted-with-warning": "policy met. The pack has no warning state, so this row does not map exactly",
  refused: { NoPqIssuance: "states unchanged (sealed_content verified); policy unmet: require_pq, as a property of the mandate (proposed)", UntrustedTime: "policy unmet: require_anchor. The transition check has no trusted time" },
  "not-reached": "sealed_content contradicted. Policy is evaluated but cannot make the pack valid",
};

const rows = [];
for (const t of V.verify) {
  const r = verifyOf(t);
  const m = VERIFY[t.name];
  if (!m) throw new Error(`no crosswalk row for verify vector "${t.name}"`);
  rows.push({ set: "verify", name: t.name, pqam: r.ok ? `verified (pq_level ${r.pq_level})` : r.code, maps: m.maps, pack_today: m.today, pack_with_issuance_member: m.proposed, aer1_anchor: "n/a" });
}
for (const t of V.admission) {
  const base = V.verify.find((x) => x.name === t.verify);
  const a = P.admit(verifyOf(base), { policy: t.policy, time: t.time });
  const pack = typeof ADMISSION_PACK[a.policy.verdict] === "string" ? ADMISSION_PACK[a.policy.verdict] : ADMISSION_PACK[a.policy.verdict][a.policy.reason];
  rows.push({
    set: "admission", name: t.name,
    pqam: `verification ${a.verification.ok ? "ok" : a.verification.code}; policy ${a.policy.verdict}${a.policy.reason ? " " + a.policy.reason : ""}`,
    maps: a.policy.verdict === "admitted-with-warning" ? "partial" : "yes",
    pack_today: pack, pack_with_issuance_member: pack,
    aer1_anchor: AER[t.time?.source ?? "none"],
  });
}
for (const t of V.policy) {
  const { verified_payees, ...ctx } = t.ctx;
  const r = P.evaluate(V.objects[t.mandate].object, t.request, { ...ctx, payeeRule: (p) => verified_payees.some((x) => P.sameAccount(x, p)) });
  rows.push({ set: "policy", name: t.name, pqam: `${r.decision} ${r.reason}`, maps: "no", pack_today: "an enforcement decision, not evidence. At most it shows up as a Payment Receipt status (Success / Error)", pack_with_issuance_member: "same", aer1_anchor: "n/a" });
}

const count = (k, v) => rows.filter((r) => r[k] === v).length;
const out = {
  about: "pqam/0.1 conformance cases read against ap2-evidence-pack 1.10.0 (SPEC_AP2_EVIDENCE.md, 2026-11-22) and the AER-1 anchor outcomes. Our reading, for review on AP2 #338.",
  pqam_vectors: "https://github.com/eltociear/pqam/blob/main/vectors/pqam-0.1.json",
  summary: { rows: rows.length, verify: count("set", "verify"), admission: count("set", "admission"), policy: count("set", "policy"), maps_yes: count("maps", "yes"), maps_partial: count("maps", "partial"), maps_no: count("maps", "no") },
  rows,
};
writeFileSync(new URL("crosswalk.json", import.meta.url), JSON.stringify(out, null, 1) + "\n");

const esc = (s) => String(s).replaceAll("|", "\\|");
const table = (set) => ["| # | pqam case | pqam result | maps | pack 1.10.0 today | with an issuance member | AER-1 anchor |", "|---|---|---|---|---|---|---|",
  ...rows.filter((r) => r.set === set).map((r, i) => `| ${i + 1} | ${esc(r.name)} | ${esc(r.pqam)} | ${r.maps} | ${esc(r.pack_today)} | ${esc(r.pack_with_issuance_member)} | ${esc(r.aer1_anchor)} |`)].join("\n");
const s = out.summary;
writeFileSync(new URL("CROSSWALK.md", import.meta.url), `# pqam/0.1 against ap2-evidence-pack 1.10.0

Every pqam conformance case (${s.verify} verify, ${s.admission} admission, ${s.policy} policy = ${s.rows}), read against the layers of
[ap2-evidence-pack](https://github.com/robertolocatelli81-dev/ap2-evidence-pack) (SPEC_AP2_EVIDENCE.md revision 1.10.0,
2026-11-22) and, where a time is the question, the AER-1 anchor outcomes. Written for the cross-test on
[AP2 #338](https://github.com/google-agentic-commerce/AP2/issues/338). **This is our reading of the pack's text, not the pack's
verdict**, and the rows marked partial or no are the ones to check. Generated by \`crosswalk.mjs\` from the vectors, so it
cannot drift from them.

A pack can't carry a pqam object today: its schema is closed (§9.1), so a pqam member is refused as \`unknown_member\`.
Each row therefore gives what a 1.10.0 pack reports for the AP2-shaped analogue now, and what it would report with the
issuance member proposed on #338. That member would be a PQ issuance signature as a peer of the mandate, in the record
layer.

Maps: **${s.maps_yes} yes, ${s.maps_partial} partial, ${s.maps_no} no.** All ${s.policy} policy cases are "no" by design: they are enforcement
decisions, not evidence.

The rows that matter most:

- **Verify 5/6 (Q-Day forgery).** Today a mandate forged with the issuer's classical key verifies, in a fresh pack under a fresh
  anchor. With an issuance member, the mandate itself fails.
- **Verify 26 (stripping).** Our reading of §5: the producer block's signatures are outside the digest (§3), so dropping the
  ml-dsa-65 entry and relabelling \`scheme\` as \`classical-only\` gives an ok block with \`pq_protected\` false, and only
  \`require_pq\` catches it. Please confirm or correct.
- **Admission 5-8.** A genuine classical-only mandate stays \`verified\`. Only the policy refuses it, and only on a trusted time.
  A verifier's own clock reads as an *absent* anchor.

## Verify

${table("verify")}

## Admission (policy verdict, kept apart from verification)

${table("admission")}

## Policy (enforcement decisions)

${table("policy")}
`);
console.log(`crosswalk: ${s.rows} rows (${s.maps_yes} yes / ${s.maps_partial} partial / ${s.maps_no} no)`);
