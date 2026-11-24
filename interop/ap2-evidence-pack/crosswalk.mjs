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
  "issuer signature made under the accept tag": { maps: "partial", today: "a mandate with typ kb+jwt reads valid: true. typ is checked on the KB-JWT (§6 step 2, §9.2) and on delegation-chain hops after the first (§2.1), not on a mandate outside a chain", proposed: "contradicted at the mandate: pqam's type tag is inside the signed bytes" },
  "issuer with a classical key only (verifies; admission decides)": { maps: "yes", today: "sealed_content verified", proposed: "verified. Whether it is acceptable is policy: see the admission rows" },
  "issuer with ML-DSA-44 only (verifies; admission decides)": { maps: "partial", today: "no ML-DSA-44 in the pack's algorithm set", proposed: "verified (pq_level 2). Admission refuses it under min_pq_level 3" },
  "amount as a JSON number": { maps: "partial", today: "depends on where the number sits. Inside the mandate an integer amount is admitted and reads valid: true, and a fraction reads sealed_content contradicted (artifact_invalid, sd_number_fraction). admission refused / malformed applies only to a fraction in the pack file itself", proposed: "pqam: Malformed (amounts are decimal strings)" },
  "a field pqam/0.1 does not define": { maps: "partial", today: "depends on where the field sits. In a format object it is admission refused / unknown_member (§9.1). An unknown claim inside the mandate is admitted", proposed: "pqam: Malformed (the mandate's own fields are closed too)" },
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
  "stripping: classical signature removed, both keys expected": { maps: "partial", today: "the opposite strip in the producer block: drop the ml-dsa-65 entry and relabel scheme classical-only. This reads valid: true with no policy, and also with both producer keys pinned (producer_signature verified), --trust-set-complete and --require-producer. The same holds when the content is changed and the block re-signed with the classical key alone. It shows only as pq_protected: false and scheme: classical-only. Refused under --require-pq, or when the pinned set holds the ml-dsa-65 key alone. Control: leaving scheme hybrid after the strip reads contradicted. To be fixed in 1.11.0 (a pinned ml-dsa-65 key will require an ml-dsa-65 signature)", proposed: "MissingSignature: the required key set is in the signed data, not a relabelable field" },
};

// Admission rows: the policy verdict. AER-1 outcomes only where a time anchor is the question.
// `today` is strictly what a 1.10.0 pack reports for the AP2-shaped analogue (as run on #338); `proposed` is
// with a mandate-level issuance member and a mandate-level require_pq. The first crosswalk mixed them on rows
// 5, 6 and 9, which the run caught.
const AER = { anchor: "verified (assuming the anchor itself checked; the vector supplies its time)", local: "absent (a verifier's clock is not an anchor)", block: "n/a: block time is the enforcer's record, not an anchor", none: "absent" };
const REQ_PQ_TODAY = "require_pq is a test on the producer block only. A classical-only mandate inside a pack with a pinned hybrid producer block and --require-pq reads require_pq met, valid: true";
const NO_ANCHOR_TODAY = "time_anchor not_evaluated / not_present. require_anchor is unmet only when --require-anchor is given and no anchor is counted";
const ADMISSION = {
  "PQ-signed mandate, no transition date": { maps: "yes", today: "policy met", proposed: "policy met" },
  "PQ-signed mandate after the date, even on local time": { maps: "yes", today: "policy met", proposed: "policy met: a PQ-issued mandate needs no time" },
  "classical-only, no transition date: warned": { maps: "partial", today: "policy met (the pack has no warning state)", proposed: "policy met, with a recorded warning" },
  "classical-only, anchored before the date: warned": { maps: "partial", today: "policy met (the pack has no warning state)", proposed: "policy met, with a recorded warning" },
  "classical-only, anchored at the date: refused (signature still verifies)": { maps: "partial", today: REQ_PQ_TODAY, proposed: "states unchanged (sealed_content verified). Policy unmet: require_pq, as a property of the mandate, on the anchor's gen_time" },
  "classical-only, block time after the date: refused": { maps: "partial", today: REQ_PQ_TODAY, proposed: "as above, on the enforcer's block time" },
  "classical-only, verifier's own clock: refused as untrusted time": { maps: "partial", today: NO_ANCHOR_TODAY, proposed: "policy refused: no trusted time for the transition check (pqam UntrustedTime)" },
  "classical-only, no time at all: refused as untrusted time": { maps: "partial", today: NO_ANCHOR_TODAY, proposed: "policy refused: no trusted time for the transition check (pqam UntrustedTime)" },
  "ML-DSA-44 only, after the date: refused": { maps: "partial", today: REQ_PQ_TODAY + " (and ML-DSA-44 is not in the pack's algorithm set)", proposed: "policy unmet: below min_pq_level" },
  "Q-Day forgery: fails verification, policy never reached": { maps: "partial", today: "sealed_content verified, valid: true. The forged ES256 mandate verifies, as in verify 5", proposed: "contradicted at the mandate (the PQ half fails). Policy is never reached" },
};

// What the 1.10.0 run on AP2 #338 (robertolocatelli81-dev, 2026-11-24, wheel sha256 36a176df…, vectors at tag
// v1.10.0, crosswalk at d41f78a) established per row. Rows not listed were read, not run.
const RUN_SRC = "https://github.com/google-agentic-commerce/AP2/issues/338#issuecomment-7130575583";
const RUN = {
  verify: { matched: [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 17, 25, 26], corrected: [10, 13, 14, 26] },
  admission: { matched: [1, 2, 3, 4, 7], corrected: [5, 6, 7, 8, 9, 10] },
};
const runOf = (set, i) => {
  const r = RUN[set];
  if (!r) return "not applicable";
  if (r.corrected.includes(i)) return "run 1.10.0: corrected from the first reading";
  if (r.matched.includes(i)) return "run 1.10.0: as read";
  return "read only";
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
  const m = ADMISSION[t.name];
  if (!m) throw new Error(`no crosswalk row for admission vector "${t.name}"`);
  rows.push({
    set: "admission", name: t.name,
    pqam: `verification ${a.verification.ok ? "ok" : a.verification.code}; policy ${a.policy.verdict}${a.policy.reason ? " " + a.policy.reason : ""}`,
    maps: m.maps, pack_today: m.today, pack_with_issuance_member: m.proposed,
    aer1_anchor: AER[t.time?.source ?? "none"],
  });
}
for (const t of V.policy) {
  const { verified_payees, ...ctx } = t.ctx;
  const r = P.evaluate(V.objects[t.mandate].object, t.request, { ...ctx, payeeRule: (p) => verified_payees.some((x) => P.sameAccount(x, p)) });
  rows.push({ set: "policy", name: t.name, pqam: `${r.decision} ${r.reason}`, maps: "no", pack_today: "an enforcement decision, not evidence. At most it shows up as a Payment Receipt status (Success / Error)", pack_with_issuance_member: "same", aer1_anchor: "n/a" });
}

for (const set of ["verify", "admission", "policy"]) rows.filter((r) => r.set === set).forEach((r, i) => (r.run = runOf(set, i + 1)));
const count = (k, v) => rows.filter((r) => r[k] === v).length;
const out = {
  about: "pqam/0.1 conformance cases against ap2-evidence-pack 1.10.0 (SPEC_AP2_EVIDENCE.md, 2026-11-22) and the AER-1 anchor outcomes. Revision 2: corrected from a 1.10.0 run on AP2 #338.",
  pqam_vectors: "https://github.com/eltociear/pqam/blob/main/vectors/pqam-0.1.json",
  run: { by: "robertolocatelli81-dev (Noûs), AP2 #338", source: RUN_SRC, release: "ap2-evidence-pack 1.10.0 (PyPI wheel sha256 36a176df58f3d35698a572647cc3399382dbd526aa2356213051ce4f1288accc)", against: "crosswalk revision 1 (pqam d41f78a)", date: "2026-11-24" },
  summary: { rows: rows.length, verify: count("set", "verify"), admission: count("set", "admission"), policy: count("set", "policy"), maps_yes: count("maps", "yes"), maps_partial: count("maps", "partial"), maps_no: count("maps", "no"), run_as_read: count("run", "run 1.10.0: as read"), run_corrected: count("run", "run 1.10.0: corrected from the first reading"), read_only: count("run", "read only") },
  rows,
};
writeFileSync(new URL("crosswalk.json", import.meta.url), JSON.stringify(out, null, 1) + "\n");

const esc = (s) => String(s).replaceAll("|", "\\|");
const table = (set) => ["| # | pqam case | pqam result | maps | pack 1.10.0 today | with an issuance member | AER-1 anchor | checked by |", "|---|---|---|---|---|---|---|---|",
  ...rows.filter((r) => r.set === set).map((r, i) => `| ${i + 1} | ${esc(r.name)} | ${esc(r.pqam)} | ${r.maps} | ${esc(r.pack_today)} | ${esc(r.pack_with_issuance_member)} | ${esc(r.aer1_anchor)} | ${esc(r.run)} |`)].join("\n");
const s = out.summary;
writeFileSync(new URL("CROSSWALK.md", import.meta.url), `# pqam/0.1 against ap2-evidence-pack 1.10.0

Every pqam conformance case (${s.verify} verify, ${s.admission} admission, ${s.policy} policy = ${s.rows}), set against the layers of
[ap2-evidence-pack](https://github.com/robertolocatelli81-dev/ap2-evidence-pack) (SPEC_AP2_EVIDENCE.md revision 1.10.0,
2026-11-22) and, where a time is the question, the AER-1 anchor outcomes. Written for the cross-test on
[AP2 #338](https://github.com/google-agentic-commerce/AP2/issues/338). Generated by \`crosswalk.mjs\` from the vectors, so it
cannot drift from them.

**Revision 2.** The first revision (pqam \`d41f78a\`) was a reading of the pack's text. robertolocatelli81-dev then ran the
rows that state a 1.10.0 output with the released 1.10.0 (PyPI wheel sha256 \`36a176df…\`, vectors at tag \`v1.10.0\`,
2026-11-24; [the run](${RUN_SRC})). That run corrected six kinds of rows, which revision 2 takes over: **${s.run_as_read} rows ran
as read, ${s.run_corrected} were corrected, ${s.read_only} are still read only**. Most of the corrections teach the same thing: a
check binds at a *placement*, and reading the text flattened that. A fraction is treated differently inside the mandate
than in the pack file. A typ is checked differently in a chain than outside one. An unknown member is treated differently
in a format object than in the claim set. And on admission 5, 6 and 9 the first "today" column described the proposed
behaviour. Now \`today\` is strictly what 1.10.0 does, and \`with an issuance member\` is strictly the proposal.

A pack can't carry a pqam object today: its schema is closed (§9.1), so a pqam member is refused as \`unknown_member\`.
Each row therefore gives what a 1.10.0 pack reports for the AP2-shaped analogue now, and what it would report with a PQ
issuance signature as a peer of the mandate, in the record layer (proposed on #338).

Maps: **${s.maps_yes} yes, ${s.maps_partial} partial, ${s.maps_no} no.** All ${s.policy} policy cases are "no" by design: they are
enforcement decisions, not evidence.

The rows that matter most:

- **Verify 5/6 and admission 10 (Q-Day forgery).** Run on 1.10.0, the forged mandate reads \`valid: true\`,
  \`sealed_content: verified\`. Its fresh anchor verifies under the forger's own TSA certificate. With an issuance member,
  the mandate itself fails.
- **Verify 26 (stripping the producer block).** Run on 1.10.0, and wider than the first reading. Drop the \`ml-dsa-65\`
  entry and relabel \`scheme\` as \`classical-only\`, and the pack reads \`valid: true\` even with both producer keys
  pinned, \`--trust-set-complete\` and \`--require-producer\`. It shows only in \`pq_protected\` and \`scheme\`. It is
  refused under \`--require-pq\`. The pack's authors will fix it in 1.11.0: a pinned \`ml-dsa-65\` key will require an
  \`ml-dsa-65\` signature. Until then, pass \`--require-pq\` with the pins.
- **Admission 5-9.** Today \`require_pq\` tests the producer block only, so a classical-only mandate inside a hybrid-signed
  pack meets it. A mandate-level \`require_pq\` is what the proposal adds. A verifier's own clock reads as an *absent* anchor
  (AER-1; agreed on #338).

## Verify

${table("verify")}

## Admission (policy verdict, kept apart from verification)

${table("admission")}

## Policy (enforcement decisions)

${table("policy")}
`);
console.log(`crosswalk: ${s.rows} rows (${s.maps_yes} yes / ${s.maps_partial} partial / ${s.maps_no} no)`);
