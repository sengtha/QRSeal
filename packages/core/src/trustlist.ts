/**
 * Trust list validation: Root signature, monotonic version, expiry, cache
 * staleness, and the separate timestamp statement that provides freeze
 * protection.
 *
 * The freeze problem: an attacker who can withhold updates (a hostile network,
 * a captive portal, a compromised mirror) can pin a verifier to an old but
 * still-unexpired trust list, so a key revoked yesterday keeps verifying. The
 * defence is TUF's timestamp role: a small, separately signed, short-lived
 * statement naming the current trust list version and digest. A verifier that
 * cannot obtain a fresh timestamp statement stops verifying rather than
 * falling back on what it holds.
 *
 * Serialisation note: signatures cover the exact UTF-8 bytes of the
 * `statement` string as it appears in the artifact, and the verifier parses
 * that same string. There is no canonicalisation step, and therefore no
 * canonicalisation bug — the same reasoning that shapes the Profile A signing
 * input.
 *
 * Dependency note: Web Crypto only. No CBOR, no streams.
 */

import {
  AcquirerKeyMismatchError,
  KeyExpiredError,
  KhSqrError,
  RevocationsMalformedError,
  RevocationsRollbackError,
  RevocationsSignatureInvalidError,
  RevocationsStaleError,
  KeyNotYetValidError,
  KeyProfileMismatchError,
  KeyRevokedError,
  TimestampExpiredError,
  TimestampMalformedError,
  TimestampMissingError,
  TimestampSignatureInvalidError,
  TimestampTargetMismatchError,
  TrustlistExpiredError,
  TrustlistMalformedError,
  TrustlistRollbackError,
  TrustlistSignatureInvalidError,
  TrustlistStaleError,
  UnknownKidError,
} from './errors.js';
import { bytesToHex, constantTimeEqual, isUppercaseHex } from './hex.js';
import { KID_HEX_LENGTH, importVerificationKeyFromCoordinates, verifyEs256 } from './kid.js';
import { hexToBytes } from './hex.js';

/** A verifier MUST stop verifying once its cached trust list is this old. */
export const MAX_TRUSTLIST_CACHE_AGE_SECONDS = 30 * 24 * 60 * 60;
/** A timestamp statement is valid for seven days from issuance. */
export const TIMESTAMP_VALIDITY_SECONDS = 7 * 24 * 60 * 60;

export type KhSqrProfile = 'A' | 'B';
export type KeyStatus = 'active' | 'revoked';

export interface TrustedKeyRecord {
  readonly kid: string;
  /** P-256 public X, 64 uppercase hex characters. */
  readonly x: string;
  /** P-256 public Y, 64 uppercase hex characters. */
  readonly y: string;
  readonly profiles: readonly KhSqrProfile[];
  readonly status: KeyStatus;
  readonly notBefore: number;
  readonly notAfter: number;
  /**
   * Who the key is registered to. `name` is for people and is never used in a
   * trust decision. `organisationId` is the issuer identifier a Profile B
   * credential's issuer claim must equal (SPEC.md §3.1): without that binding
   * any enrolled key could sign a credential in any institution's name, and
   * the only defence would be a reader noticing two names that differ.
   */
  readonly subject: { readonly name: string; readonly organisationId: string };
  /**
   * The merchant-account identifiers a Profile A key may sign for (SPEC.md
   * §2.10): each is either an exact value for sub-tag 00 of a merchant-account
   * template, or, beginning with `@`, a suffix that an account-style
   * identifier such as `merchant@bank` must end with. A payment code whose
   * account templates name anything else is refused, so a compromised or
   * rogue issuer key can sign codes only for its own institution's accounts.
   * Absent on a key that is not enrolled for Profile A; a Profile A key with
   * none registered can sign nothing that verifies.
   */
  readonly acquirers?: readonly string[];
}

/** Whether a registered acquirer entry binds a merchant-account identifier. */
export function acquirerBinds(entry: string, guid: string): boolean {
  if (entry.startsWith('@')) return guid.length > entry.length && guid.endsWith(entry);
  return entry === guid;
}

/**
 * Enforce the Profile A binding: at least one merchant-account template, and
 * every one of them naming an identifier the signing key is registered for.
 * Called after the signature has verified, because the binding is only
 * meaningful once the signer is known.
 */
export function assertAcquirerBinding(record: TrustedKeyRecord, guids: readonly (string | null)[]): void {
  if (guids.length === 0) throw new AcquirerKeyMismatchError('payload carries no merchant-account template');
  const registered = record.acquirers ?? [];
  for (const guid of guids) {
    if (guid === null || !registered.some((entry) => acquirerBinds(entry, guid))) throw new AcquirerKeyMismatchError();
  }
}

export interface TrustListStatement {
  readonly type: 'kh-sqr/trustlist/1';
  /** Monotonic. A verifier rejects any list numbered below the one it holds. */
  readonly version: number;
  readonly issuedAt: number;
  readonly expires: number;
  readonly keys: readonly TrustedKeyRecord[];
}

export interface TimestampStatement {
  readonly type: 'kh-sqr/timestamp/1';
  /** The trust list version this statement attests as current. */
  readonly trustListVersion: number;
  /** SHA-256 over the UTF-8 bytes of the trust list's `statement` string. */
  readonly trustListDigest: string;
  readonly issuedAt: number;
  readonly expires: number;
  /**
   * The current revocation list of each issuer that publishes one, so that a
   * withheld or rolled-back revocation list is caught the way a withheld
   * trust list is. Absent when no issuer publishes one.
   */
  readonly revocations?: readonly { readonly issuer: string; readonly version: number; readonly digest: string }[];
}

/* ------------------------------------------------------------------ *
 * Revocation lists — per-credential withdrawal, published like the trust list
 * ------------------------------------------------------------------ *
 *
 * Key revocation invalidates everything a key ever signed, which is right for
 * a compromised key and wrong for one withdrawn diploma. A revocation list is
 * the per-credential instrument: a signed statement by the issuer, published
 * beside the trust list, refreshed on the same cadence and verified offline
 * against the same trust anchor. It is not a live service, and it is not the
 * dependency the offline design exists to remove.
 *
 * Entries are hashes, not document identifiers: a public list of withdrawn
 * identifiers would tell the world which named person lost a degree. Only a
 * party holding the credential can compute the entry to look for.
 */

export type RevocationReason = 'withdrawn' | 'corrected';

export interface RevocationEntry {
  /** `revocationEntryId(issuer, documentId)`: 64 uppercase hex characters. */
  readonly id: string;
  readonly revokedAt: number;
  readonly reason: RevocationReason;
}

export interface RevocationStatement {
  readonly type: 'kh-sqr/revocations/1';
  /** The `organisationId` of the issuer, which the signing key must be registered to. */
  readonly issuer: string;
  /** Monotonic per issuer. */
  readonly version: number;
  readonly issuedAt: number;
  readonly entries: readonly RevocationEntry[];
}

/** Domain separator for revocation entry identifiers. */
export const REVOCATION_ID_DOMAIN = 'kh-sqr/revocation/1';

/** The entry a revocation list carries for one credential: SHA-256 over the domain, issuer and document identifier. */
export async function revocationEntryId(issuer: string, documentId: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    encoder.encode(`${REVOCATION_ID_DOMAIN}\n${issuer}\n${documentId}`) as BufferSource,
  );
  return bytesToHex(new Uint8Array(digest));
}

/** What the trust anchor knows about one credential's standing. */
export type RevocationStatus =
  | { readonly state: 'unchecked' }
  | { readonly state: 'withheld'; readonly declaredVersion: number }
  | { readonly state: 'clear'; readonly listVersion: number; readonly listIssuedAt: number }
  | { readonly state: 'revoked'; readonly revokedAt: number; readonly reason: RevocationReason; readonly listVersion: number };

interface HeldRevocationList {
  readonly version: number;
  readonly issuedAt: number;
  readonly entries: ReadonlyMap<string, RevocationEntry>;
}

/** A signed artifact: an opaque statement string plus a detached signature. */
export interface SignedArtifact {
  readonly statement: string;
  readonly signature: { readonly alg: 'ES256'; readonly kid: string; readonly value: string };
}

/** A public key the verifier trusts a priori, pinned out of band. */
export interface PinnedKey {
  readonly kid: string;
  readonly x: string;
  readonly y: string;
}

const encoder = new TextEncoder();

function parseStatement<T>(artifact: SignedArtifact, expectedType: string, onMalformed: () => never): T {
  let parsed: unknown;
  try {
    parsed = JSON.parse(artifact.statement) as unknown;
  } catch {
    onMalformed();
  }
  if (typeof parsed !== 'object' || parsed === null) onMalformed();
  if ((parsed as { type?: unknown }).type !== expectedType) onMalformed();
  return parsed as T;
}

function assertSignedArtifact(value: unknown, onMalformed: () => never): SignedArtifact {
  if (typeof value !== 'object' || value === null) onMalformed();
  const candidate = value as Partial<SignedArtifact>;
  const signature = candidate.signature;
  if (typeof candidate.statement !== 'string' || typeof signature !== 'object' || signature === null) onMalformed();
  if (signature.alg !== 'ES256') onMalformed();
  if (!isUppercaseHex(signature.kid, KID_HEX_LENGTH) || !isUppercaseHex(signature.value, 128)) onMalformed();
  return candidate as SignedArtifact;
}

async function verifyArtifact(artifact: SignedArtifact, pinned: readonly PinnedKey[]): Promise<boolean> {
  const candidates = pinned.filter((k) => constantTimeEqual(k.kid, artifact.signature.kid));
  const message = encoder.encode(artifact.statement);
  const rawSignature = hexToBytes(artifact.signature.value);
  // A kid is a lookup hint, not an authenticator: on collision, try every
  // candidate and accept only if one actually verifies.
  for (const key of candidates) {
    const cryptoKey = await importVerificationKeyFromCoordinates(key.x, key.y);
    if (await verifyEs256(cryptoKey, rawSignature, message)) return true;
  }
  return false;
}

export async function digestStatement(statement: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(statement) as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

export interface OpenTrustAnchorOptions {
  /** The signed trust list artifact as served. */
  readonly trustList: unknown;
  /** The signed timestamp statement. Required unless `allowMissingTimestamp`. */
  readonly timestamp?: unknown;
  /** Root public keys, pinned in the verifier, never fetched. */
  readonly rootKeys: readonly PinnedKey[];
  /**
   * Public keys of the timestamp signer. Separate from the Root by design: the
   * timestamp signer is online and short-lived, the Root is offline.
   */
  readonly timestampKeys: readonly PinnedKey[];
  /** Version of the trust list the verifier already holds, for rollback protection. */
  readonly heldVersion?: number;
  /** When the held copy was fetched. Cache age is measured from here. */
  readonly fetchedAt?: number;
  /** Verification time, Unix seconds. */
  readonly now: number;
  /**
   * Permit operation without a timestamp statement. Off by default and
   * intended only for offline conformance testing; a deployed verifier that
   * sets this has removed its freeze protection.
   */
  readonly allowMissingTimestamp?: boolean;
  /**
   * Signed revocation lists held, one per issuer, as served. Each is
   * validated against the trust list opened here: signed by a key registered
   * to the issuer it names, within cache age, not rolled back, and matching
   * what the timestamp statement declares for that issuer.
   */
  readonly revocations?: readonly unknown[];
  /** Highest revocation list version held per issuer, for rollback protection. */
  readonly heldRevocationVersions?: Readonly<Record<string, number>>;
}

/**
 * A validated trust list, ready to resolve key identifiers.
 *
 * Construction performs every list-level check. If `open` returns, the list's
 * Root signature verified, its version did not go backwards, it has not
 * expired, its cache age is within bounds, and a valid timestamp statement
 * attests this exact version and digest.
 */
export class TrustAnchor {
  private readonly keys: ReadonlyMap<string, readonly TrustedKeyRecord[]>;
  private readonly revocations = new Map<string, HeldRevocationList>();
  /** Issuers whose current revocation list the timestamp statement declares. */
  private readonly declaredRevocations = new Map<string, { version: number; digest: string }>();

  public readonly version: number;
  public readonly issuedAt: number;
  public readonly expires: number;
  public readonly digest: string;

  private constructor(statement: TrustListStatement, digest: string) {
    this.version = statement.version;
    this.issuedAt = statement.issuedAt;
    this.expires = statement.expires;
    this.digest = digest;
    const index = new Map<string, TrustedKeyRecord[]>();
    for (const record of statement.keys) {
      const bucket = index.get(record.kid);
      if (bucket === undefined) index.set(record.kid, [record]);
      else bucket.push(record);
    }
    this.keys = index;
  }

  public static async open(options: OpenTrustAnchorOptions): Promise<TrustAnchor> {
    const malformed = (): never => {
      throw new TrustlistMalformedError();
    };
    const artifact = assertSignedArtifact(options.trustList, malformed);
    if (!(await verifyArtifact(artifact, options.rootKeys))) throw new TrustlistSignatureInvalidError();

    const statement = parseStatement<TrustListStatement>(artifact, 'kh-sqr/trustlist/1', malformed);
    if (!Number.isSafeInteger(statement.version) || statement.version < 1) malformed();
    if (!Number.isSafeInteger(statement.issuedAt) || !Number.isSafeInteger(statement.expires)) malformed();
    if (!Array.isArray(statement.keys)) malformed();

    if (options.heldVersion !== undefined && statement.version < options.heldVersion) {
      throw new TrustlistRollbackError(
        `offered version ${statement.version} is below held version ${options.heldVersion}`,
      );
    }
    if (options.now > statement.expires) throw new TrustlistExpiredError();

    const referenceTime = options.fetchedAt ?? statement.issuedAt;
    if (options.now - referenceTime > MAX_TRUSTLIST_CACHE_AGE_SECONDS) throw new TrustlistStaleError();

    const digest = await digestStatement(artifact.statement);

    let timestamp: TimestampStatement | null = null;
    if (options.timestamp === undefined || options.timestamp === null) {
      if (options.allowMissingTimestamp !== true) throw new TimestampMissingError();
    } else {
      timestamp = await TrustAnchor.checkTimestamp(options, statement, digest);
    }

    const anchor = new TrustAnchor(statement, digest);
    if (timestamp?.revocations !== undefined) {
      if (!Array.isArray(timestamp.revocations)) throw new TimestampMalformedError();
      for (const d of timestamp.revocations) {
        if (typeof d.issuer !== 'string' || !Number.isSafeInteger(d.version) || !isUppercaseHex(d.digest, 64)) {
          throw new TimestampMalformedError();
        }
        anchor.declaredRevocations.set(d.issuer, { version: d.version, digest: d.digest });
      }
    }
    for (const list of options.revocations ?? []) await anchor.holdRevocationList(list, options);
    return anchor;
  }

  private static async checkTimestamp(
    options: OpenTrustAnchorOptions,
    statement: TrustListStatement,
    digest: string,
  ): Promise<TimestampStatement> {
    const malformed = (): never => {
      throw new TimestampMalformedError();
    };
    const artifact = assertSignedArtifact(options.timestamp, malformed);
    if (!(await verifyArtifact(artifact, options.timestampKeys))) throw new TimestampSignatureInvalidError();

    const ts = parseStatement<TimestampStatement>(artifact, 'kh-sqr/timestamp/1', malformed);
    if (!Number.isSafeInteger(ts.expires) || !Number.isSafeInteger(ts.issuedAt)) malformed();
    if (!isUppercaseHex(ts.trustListDigest, 64)) malformed();
    if (options.now > ts.expires) throw new TimestampExpiredError();
    if (ts.trustListVersion !== statement.version) {
      throw new TimestampTargetMismatchError('timestamp attests a different trust list version');
    }
    if (!constantTimeEqual(ts.trustListDigest, digest)) {
      throw new TimestampTargetMismatchError('timestamp attests a different trust list digest');
    }
    return ts;
  }

  /**
   * Validate one revocation list against this anchor and keep it.
   *
   * The signer must be a key registered, for Profile B, to the very issuer the
   * list names — the same binding a credential's issuer claim is held to — so
   * that one institution cannot publish withdrawals in another's name.
   */
  private async holdRevocationList(value: unknown, options: OpenTrustAnchorOptions): Promise<void> {
    const malformed = (): never => {
      throw new RevocationsMalformedError();
    };
    const artifact = assertSignedArtifact(value, malformed);
    const statement = parseStatement<RevocationStatement>(artifact, 'kh-sqr/revocations/1', malformed);
    if (typeof statement.issuer !== 'string' || statement.issuer.length === 0) malformed();
    if (!Number.isSafeInteger(statement.version) || statement.version < 1) malformed();
    if (!Number.isSafeInteger(statement.issuedAt)) malformed();
    if (!Array.isArray(statement.entries)) malformed();
    const entries = new Map<string, RevocationEntry>();
    for (const e of statement.entries) {
      if (typeof e !== 'object' || e === null) malformed();
      if (!isUppercaseHex(e.id, 64) || !Number.isSafeInteger(e.revokedAt)) malformed();
      if (e.reason !== 'withdrawn' && e.reason !== 'corrected') malformed();
      entries.set(e.id, { id: e.id, revokedAt: e.revokedAt, reason: e.reason });
    }
    if (this.revocations.has(statement.issuer)) malformed();

    // Signed by a key registered to the issuer named, usable now, for Profile B.
    let candidates: { key: CryptoKey; record: TrustedKeyRecord }[];
    try {
      candidates = await this.resolveRecords(artifact.signature.kid, 'B', options.now);
    } catch (error) {
      if (error instanceof KhSqrError) throw new RevocationsSignatureInvalidError();
      throw error;
    }
    const message = encoder.encode(artifact.statement);
    const rawSignature = hexToBytes(artifact.signature.value);
    let signed = false;
    for (const { key, record } of candidates) {
      if (record.subject.organisationId !== statement.issuer) continue;
      if (await verifyEs256(key, rawSignature, message)) { signed = true; break; }
    }
    if (!signed) throw new RevocationsSignatureInvalidError();

    if (options.now - statement.issuedAt > MAX_TRUSTLIST_CACHE_AGE_SECONDS) throw new RevocationsStaleError();
    const held = options.heldRevocationVersions?.[statement.issuer];
    if (held !== undefined && statement.version < held) {
      throw new RevocationsRollbackError(`offered version ${statement.version} is below held version ${held}`);
    }
    const declared = this.declaredRevocations.get(statement.issuer);
    if (declared !== undefined) {
      const digest = await digestStatement(artifact.statement);
      if (declared.version !== statement.version || !constantTimeEqual(declared.digest, digest)) {
        throw new TimestampTargetMismatchError('timestamp attests a different revocation list for this issuer');
      }
    }
    this.revocations.set(statement.issuer, { version: statement.version, issuedAt: statement.issuedAt, entries });
  }

  /**
   * The standing of one credential, by the entry identifier a revocation list
   * would carry for it. `withheld` means the timestamp statement declares a
   * list for this issuer that this anchor was not given — the freeze case —
   * and a verifier must refuse rather than report the credential as unchecked.
   */
  public revocationStatus(issuer: string, entryId: string): RevocationStatus {
    const list = this.revocations.get(issuer);
    if (list === undefined) {
      const declared = this.declaredRevocations.get(issuer);
      return declared === undefined ? { state: 'unchecked' } : { state: 'withheld', declaredVersion: declared.version };
    }
    const entry = list.entries.get(entryId);
    if (entry !== undefined) {
      return { state: 'revoked', revokedAt: entry.revokedAt, reason: entry.reason, listVersion: list.version };
    }
    return { state: 'clear', listVersion: list.version, listIssuedAt: list.issuedAt };
  }

  /** Every record carrying this key identifier, in list order. */
  public recordsFor(kid: string): readonly TrustedKeyRecord[] {
    return this.keys.get(kid) ?? [];
  }

  /**
   * Resolve a key identifier to usable verification keys.
   *
   * Returns every candidate that is active, in its validity window and
   * authorised for the profile; the caller tries each and accepts only on a
   * verifying signature. Throws the most specific reason when nothing is
   * usable, so that "revoked" is distinguishable from "unknown" — an operator
   * needs to tell a key that was withdrawn from a key that never existed.
   */
  public async resolve(kid: string, profile: KhSqrProfile, now: number): Promise<CryptoKey[]> {
    return (await this.resolveRecords(kid, profile, now)).map((r) => r.key);
  }

  /**
   * As `resolve`, but each key comes with the record it was resolved from, for
   * a verifier that must bind something in the payload to the registration —
   * Profile B's issuer claim to `subject.organisationId`.
   */
  public async resolveRecords(
    kid: string,
    profile: KhSqrProfile,
    now: number,
  ): Promise<{ readonly key: CryptoKey; readonly record: TrustedKeyRecord }[]> {
    const records = this.recordsFor(kid);
    if (records.length === 0) throw new UnknownKidError();

    const usable: TrustedKeyRecord[] = [];
    let sawRevoked = false;
    let sawNotYetValid = false;
    let sawExpired = false;
    let sawWrongProfile = false;

    for (const record of records) {
      if (record.status === 'revoked') { sawRevoked = true; continue; }
      if (!record.profiles.includes(profile)) { sawWrongProfile = true; continue; }
      if (now < record.notBefore) { sawNotYetValid = true; continue; }
      if (now > record.notAfter) { sawExpired = true; continue; }
      usable.push(record);
    }

    if (usable.length === 0) {
      if (sawRevoked) throw new KeyRevokedError();
      if (sawExpired) throw new KeyExpiredError();
      if (sawNotYetValid) throw new KeyNotYetValidError();
      if (sawWrongProfile) throw new KeyProfileMismatchError();
      throw new UnknownKidError();
    }

    return Promise.all(
      usable.map(async (record) => ({ key: await importVerificationKeyFromCoordinates(record.x, record.y), record })),
    );
  }
}
