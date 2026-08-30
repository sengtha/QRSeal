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
  KeyExpiredError,
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
  /** Human-readable issuer identity. Never used in a trust decision. */
  readonly subject: { readonly name: string; readonly organisationId: string };
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

    if (options.timestamp === undefined || options.timestamp === null) {
      if (options.allowMissingTimestamp !== true) throw new TimestampMissingError();
    } else {
      await TrustAnchor.checkTimestamp(options, statement, digest);
    }

    return new TrustAnchor(statement, digest);
  }

  private static async checkTimestamp(
    options: OpenTrustAnchorOptions,
    statement: TrustListStatement,
    digest: string,
  ): Promise<void> {
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

    return Promise.all(usable.map((r) => importVerificationKeyFromCoordinates(r.x, r.y)));
  }
}
