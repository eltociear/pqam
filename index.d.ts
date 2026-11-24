// Types for pqam/0.1. The implementation is plain ES modules (src/); these declarations cover the public API.

export type AlgName = "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87" | "Ed25519" | "ES256K";
export interface PublicKey { alg: AlgName; pub: string }
export interface Signer { alg: AlgName; publicKey: Uint8Array; secretKey: Uint8Array }
export interface SigEntry { alg: AlgName; kid: string; sig: string }
export type Caip10 = string;
export type Caip19 = string;
export type Decimal = string;

export interface Mandate {
  v: "pqam/0.1"; type: "mandate"; id: string;
  issuer: { id: string; keys: PublicKey[] };
  agent: { keys: PublicKey[] };
  enforcer: Caip10;
  scope: { assets: Caip19[]; payees?: Caip10[]; payee_rule?: string; calls?: { target: Caip10; selector: string }[]; invoice: "required-signed" | "none" };
  limits: { per_payment: Decimal; window: { seconds: number; max: Decimal; kind: "rolling" | "calendar" }; approve_above?: Decimal; max_pending: number; pending_ttl: number };
  not_before: number; expires: number;
  revocation: { where: string; sticky: true };
  sig?: SigEntry[]; accept?: SigEntry[];
}
export interface Payment { payee: Caip10; asset: Caip19; amount: Decimal; invoice?: string }
export interface Revoke { v: "pqam/0.1"; type: "revoke"; mandate: string; at: number; sig?: SigEntry[] }
export interface Approve { v: "pqam/0.1"; type: "approve"; mandate: string; payment: Payment; until: number; sig?: SigEntry[] }
export interface Invoice { v: "pqam/0.1"; type: "invoice"; id: string; payer: Caip10; payee: Caip10; enforcer: Caip10; asset: Caip19; amount: Decimal; due: number; sig?: SigEntry[] }
export interface Receipt {
  v: "pqam/0.1"; type: "receipt"; mandate: string;
  payment: Payment & { status: "paid" | "pending" | "refused" | "unknown"; reason?: string; tx?: string };
  window_used: Decimal; at: number; sig?: SigEntry[];
}
export type PqamObject = Mandate | Revoke | Approve | Invoice | Receipt;

export type VerifyCode = "Malformed" | "UnknownAlgorithm" | "MissingSignature" | "BadSignature" | "UnexpectedSigner" | "NotAccepted" | "WrongMandate";
/** Cryptographic verification only. pq_level = highest ML-DSA category among the verified keys (0 = none). */
export type VerifyResult = { ok: true; hash?: string; accepted?: boolean; pq_level: number } | { ok: false; code: VerifyCode; why: string; hash?: string; accepted?: boolean; pq_level?: number };

export const VERSION: "pqam/0.1";
export const TYPES: readonly PqamObject["type"][];
export const MAX_MANDATE_SECONDS: number;
export const MIN_EVIDENCE_LEVEL: number;
export const ALGS: Readonly<Record<AlgName, { pq: boolean; level?: number; keygen(seed: Uint8Array): { secretKey: Uint8Array; publicKey: Uint8Array }; sign(msg: Uint8Array, sk: Uint8Array, opts?: { hedged?: boolean }): Uint8Array; verify(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean; sizes: { publicKey: number; signature: number } }>>;

export class CanonicalizationError extends Error {}
export class PqamError extends Error { code: string }
export function canonicalize(value: unknown): string;
export const b64u: { enc(b: Uint8Array): string; dec(s: string): Uint8Array };
export function kid(alg: AlgName, pub: Uint8Array | string): string;
export function publicKey(k: Signer | PublicKey): PublicKey;
export function signerFromSeed(alg: AlgName, seed: Uint8Array): Signer;
export function body<T extends PqamObject>(o: T): Omit<T, "sig" | "accept">;
export function hash(o: PqamObject): Uint8Array;
export function hashHex(o: PqamObject): string;
export function signingMessage(type: PqamObject["type"] | "accept", digest: Uint8Array, kids: string[]): Uint8Array;
export function sign<T extends PqamObject>(o: T, signers: Signer[], opts?: { hedged?: boolean }): T & { sig: SigEntry[] };
export function accept(m: Mandate, agentSigners: Signer[], opts?: { hedged?: boolean }): Mandate & { accept: SigEntry[] };
export function check(o: unknown): string[];
export function verifyEntries(entries: SigEntry[], keys: PublicKey[], type: string, digest: Uint8Array): VerifyResult;
export function verifyMandate(m: Mandate, opts?: { requireAccept?: boolean }): VerifyResult & { hash?: string; accepted?: boolean };
export function verifyIssued(o: Revoke | Approve, m: Mandate): VerifyResult;
export function verifyBy(o: Invoice | Receipt, keys: PublicKey[]): VerifyResult;

export type Reason = "MalformedRequest" | "NotAccepted" | "Revoked" | "NotYetValid" | "Expired" | "AssetNotInScope" | "PayeeNotInScope" | "CallNotInScope" | "InvoiceRequired" | "ZeroAmount" | "OverPerPayment" | "OverWindow" | "TooManyPending" | "NeedsApproval" | "WithinMandate";
export function evaluate(
  m: Mandate,
  req: { payee: Caip10; asset: Caip19; amount: Decimal; call?: { target: Caip10; selector: string }; invoiceVerified?: boolean },
  ctx: { now: number; accepted: boolean; revoked?: boolean; history?: { at: number; amount: Decimal; status: "paid" | "pending" | "refused" }[]; payeeRule?: (payee: Caip10, rule: string) => boolean },
): { decision: "pay" | "hold" | "refuse"; reason: Reason; window_used: Decimal };
export function sameAccount(a: Caip10, b: Caip10): boolean;

export type AdapterResult<C> = { ok: true; config: C } | { ok: false; problems: string[] };
export function toLeashId(m: Mandate, opts: { chainId: string; denom: string; minKycLevel: number; label?: string }): AdapterResult<{
  install_after: number;
  register_agent: { agent: null; policy: { label: string; per_tx_limit: Decimal; daily_limit: Decimal; approve_above: Decimal | null; vendors: string[]; any_verified_vendor: boolean; expires_at: number } };
}>;
export const DESK_PAY_SELECTOR: "0xf19ff4ff";
export function toInvoiceDesk(m: Mandate): AdapterResult<{
  chainId: number; desk: string; token: string; limit: { perPayment: Decimal; daily: Decimal }; vendors: string[];
  agentRule: { allowedEvmCalls: string[]; allowedDenoms: null; expiresAt: number };
}>;
export function bytesToHex(b: Uint8Array): string;
export function hexToBytes(h: string): Uint8Array;
export function pqLevel(keys: PublicKey[]): number;

/** Policy verdict, kept apart from verification (src/admission.mjs). */
export interface AdmissionPolicy { min_pq_level: number; pq_required_from: number | null; trusted_time_sources: readonly ("anchor" | "block" | "local")[] }
export const DEFAULT_POLICY: Readonly<AdmissionPolicy>;
export interface TrustedTime { at: number; source: "anchor" | "block" | "local" }
export function admit(verification: VerifyResult, opts?: { policy?: Partial<AdmissionPolicy>; time?: TrustedTime }): {
  admitted: boolean;
  verification: { ok: boolean; code?: VerifyCode; pq_level?: number };
  policy: { verdict: "admitted" | "admitted-with-warning" | "refused" | "not-reached"; reason?: "NoPqIssuance" | "UntrustedTime"; why?: string; time?: TrustedTime };
};
