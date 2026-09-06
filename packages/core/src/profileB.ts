/**
 * Profile B — credential. A standalone signed document attestation.
 *
 *   claims (CBOR) -> COSE_Sign1 (ES256, kid in protected header)
 *                 -> deflate (zlib, RFC 1950) -> base45 (RFC 9285) -> "KH1:"
 *
 * The pipeline is the EU Digital COVID Certificate's, with the prefix and
 * claim set changed. Deflate is applied unconditionally so the pipeline is
 * deterministic in shape, even though at this payload size it may add a few
 * bytes rather than remove them.
 *
 * THE TRANSPLANT ATTACK
 *
 * A valid signature proves a credential was issued. It does not prove that the
 * credential belongs to the sheet of paper it is printed on. Anyone may
 * photograph a genuine degree certificate's QR code and print it onto a forged
 * certificate bearing a different name; the signature still verifies, because
 * nothing about the paper is signed. The only defence is a human or a scanner
 * comparing the signed fields against the visible document — so this module
 * refuses to return an answer that can be read without them. There is no
 * boolean and no `isValid`.
 *
 * Dependency note: this module uses CBOR and DecompressionStream, which is why
 * Profile A must not import it. Profile B verifiers are institutional
 * (desktop, web), not consumer handsets.
 */

import { decodeBase45, encodeBase45 } from './base45.js';
import { decodeCbor, encodeCbor, type CborMap, type CborValue } from './cbor.js';
import { decodeCoseSign1, encodeCoseSign1, verifyCoseSign1 } from './cose.js';
import {
  ClaimMissingError,
  ClaimTypeInvalidError,
  CoseInvalidError,
  InflateFailedError,
  MalformedKidError,
  PrefixInvalidError,
  IssuerKeyMismatchError,
  SignatureInvalidError,
  UrlPayloadRejectedError,
} from './errors.js';
import { bytesToHex, hexToBytes, isUppercaseHex } from './hex.js';
import { KID_BYTES, KID_HEX_LENGTH } from './kid.js';
import type { TrustAnchor, TrustedKeyRecord } from './trustlist.js';

/** The only prefix this profile accepts. */
export const PREFIX = 'KH1:';

export const CLAIM_ISSUER = 1;
export const CLAIM_ISSUED_AT = 6;
export const CLAIM_DOCUMENT_TYPE = 'dt';
export const CLAIM_DOCUMENT_ID = 'di';
export const CLAIM_SUBJECT_NAME = 'sn';
export const CLAIM_ISSUING_ORGANISATION = 'io';
export const CLAIM_ISSUE_DATE = 'idt';
export const CLAIM_DOCUMENT_HASH = 'dh';

/**
 * Claim order as emitted by this implementation.
 *
 * CBOR map order is preserved rather than canonicalised: the signature covers
 * the payload bytes as produced and the verifier never re-encodes them, so no
 * two parties ever have to agree on an ordering.
 */
const CLAIM_ORDER: readonly (number | string)[] = [
  CLAIM_ISSUER,
  CLAIM_ISSUED_AT,
  CLAIM_DOCUMENT_TYPE,
  CLAIM_DOCUMENT_ID,
  CLAIM_SUBJECT_NAME,
  CLAIM_ISSUING_ORGANISATION,
  CLAIM_ISSUE_DATE,
  CLAIM_DOCUMENT_HASH,
];

const URL_CARRIER = /^https?:\/\//i;

/**
 * Reject a scanned string that is an http or https URL.
 *
 * This profile never carries a URL, and a wallet should run this check on
 * every code it scans, not only KH-SQR ones. A URL-bearing QR moves the trust
 * decision into a browser, where the user is asked to judge a domain name — the
 * exact judgement the Cambodian fraud pattern shows people cannot reliably
 * make. Excluding URL carriers is a design constraint, not an oversight.
 */
export function assertNotUrlCarrier(scanned: string): void {
  if (URL_CARRIER.test(scanned.trim())) throw new UrlPayloadRejectedError();
}

/* ------------------------------------------------------------------ *
 * deflate / inflate
 * ------------------------------------------------------------------ */

async function collect(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    total += value.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

/**
 * zlib-wrapped deflate, RFC 1950.
 *
 * `deflate`, not `deflate-raw`: the raw variant omits the zlib header and
 * Adler-32 trailer, producing a different byte stream that other conforming
 * implementations will not inflate.
 */
export async function deflate(input: Uint8Array): Promise<Uint8Array> {
  const stream = new Blob([input as BlobPart]).stream().pipeThrough(new CompressionStream('deflate'));
  return collect(stream as ReadableStream<Uint8Array>);
}

export async function inflate(input: Uint8Array): Promise<Uint8Array> {
  try {
    const stream = new Blob([input as BlobPart]).stream().pipeThrough(new DecompressionStream('deflate'));
    return await collect(stream as ReadableStream<Uint8Array>);
  } catch {
    throw new InflateFailedError('input is not zlib-wrapped deflate (RFC 1950)');
  }
}

/* ------------------------------------------------------------------ *
 * Claims
 * ------------------------------------------------------------------ */

export interface CredentialClaims {
  readonly issuer: string;
  readonly issuedAt: number;
  readonly documentType: string;
  readonly documentId: string;
  readonly subjectName: string;
  readonly issuingOrganisation: string;
  readonly issueDate: string;
  /** Hash of the issued file. SHOULD be present. */
  readonly documentHash?: string;
}

function requireText(claims: CborMap, key: number | string, label: string): string {
  const value = claims.get(key);
  if (value === undefined) throw new ClaimMissingError(`claim ${label} is absent`);
  if (typeof value !== 'string') throw new ClaimTypeInvalidError(`claim ${label} is not a text string`);
  return value;
}

function readClaims(payload: Uint8Array): CredentialClaims {
  const decoded = decodeCbor(payload);
  if (!(decoded instanceof Map)) throw new ClaimTypeInvalidError('claims are not a CBOR map');

  const issuedAt = decoded.get(CLAIM_ISSUED_AT);
  if (issuedAt === undefined) throw new ClaimMissingError('claim 6 (issued at) is absent');
  if (typeof issuedAt !== 'number' || !Number.isSafeInteger(issuedAt) || issuedAt < 0) {
    throw new ClaimTypeInvalidError('claim 6 (issued at) is not a non-negative integer');
  }

  const hash = decoded.get(CLAIM_DOCUMENT_HASH);
  if (hash !== undefined && typeof hash !== 'string') {
    throw new ClaimTypeInvalidError('claim dh is not a text string');
  }

  return {
    issuer: requireText(decoded, CLAIM_ISSUER, '1 (issuer)'),
    issuedAt,
    documentType: requireText(decoded, CLAIM_DOCUMENT_TYPE, 'dt'),
    documentId: requireText(decoded, CLAIM_DOCUMENT_ID, 'di'),
    subjectName: requireText(decoded, CLAIM_SUBJECT_NAME, 'sn'),
    issuingOrganisation: requireText(decoded, CLAIM_ISSUING_ORGANISATION, 'io'),
    issueDate: requireText(decoded, CLAIM_ISSUE_DATE, 'idt'),
    ...(hash === undefined ? {} : { documentHash: hash }),
  };
}

function encodeClaims(claims: CredentialClaims): Uint8Array {
  const map: CborMap = new Map<number | string, CborValue>();
  const source: Record<string, CborValue | undefined> = {
    [String(CLAIM_ISSUER)]: claims.issuer,
    [String(CLAIM_ISSUED_AT)]: claims.issuedAt,
    [CLAIM_DOCUMENT_TYPE]: claims.documentType,
    [CLAIM_DOCUMENT_ID]: claims.documentId,
    [CLAIM_SUBJECT_NAME]: claims.subjectName,
    [CLAIM_ISSUING_ORGANISATION]: claims.issuingOrganisation,
    [CLAIM_ISSUE_DATE]: claims.issueDate,
    [CLAIM_DOCUMENT_HASH]: claims.documentHash,
  };
  for (const key of CLAIM_ORDER) {
    const value = source[String(key)];
    if (value !== undefined) map.set(key, value);
  }
  return encodeCbor(map);
}

/* ------------------------------------------------------------------ *
 * The verification result
 * ------------------------------------------------------------------ */

/** The four signed fields that must be read off the physical document. */
export interface PrintedDocumentFields {
  readonly subjectName: string;
  readonly documentId: string;
  readonly issuingOrganisation: string;
  readonly issueDate: string;
}

export type PrintedField = keyof PrintedDocumentFields;

export interface FieldComparison {
  readonly field: PrintedField;
  readonly signed: string;
  readonly observed: string;
  readonly matches: boolean;
}

export interface TransplantCheck {
  readonly comparisons: readonly FieldComparison[];
  /** Empty only when every signed field matched what the verifier read. */
  readonly mismatches: readonly FieldComparison[];
}

/**
 * The result of verifying a Profile B credential.
 *
 * The signature has verified against a trusted key by the time this exists.
 * That is deliberately not exposed as a boolean or an `isValid` accessor,
 * because on its own it is not the answer to any question a verifier actually
 * has. The answer requires `mustMatchPrintedDocument` to be compared with the
 * document in hand.
 */
export class CredentialAssertion {
  public readonly profile = 'B' as const;
  public readonly kid: string;
  public readonly issuer: string;
  public readonly issuedAt: number;
  public readonly documentType: string;
  public readonly documentHash: string | null;
  /**
   * Fields a verifier MUST compare against the visible document. A signature
   * proves issuance; only this comparison connects the credential to the paper.
   */
  public readonly mustMatchPrintedDocument: PrintedDocumentFields;
  /**
   * Whether this particular credential has been withdrawn by its issuer.
   *
   * Always `'unchecked'`. Verification is offline by construction, so this
   * library cannot know whether a degree was rescinded or a licence
   * suspended after it was signed. A signature is a statement that was true
   * when it was made; it does not become false when the issuer changes their
   * mind, and nothing in the payload can carry news that postdates it.
   *
   * The field exists rather than being omitted so that a caller cannot mistake
   * silence for assurance. An interface MUST NOT present an unchecked
   * credential as current. Key revocation (see `trustlist.ts`) is a different
   * and much blunter thing: it invalidates everything an issuer ever signed,
   * which is right for a compromised key and wrong for one withdrawn diploma.
   */
  public readonly credentialStatus = 'unchecked' as const;

  public constructor(kid: string, claims: CredentialClaims) {
    this.kid = kid;
    this.issuer = claims.issuer;
    this.issuedAt = claims.issuedAt;
    this.documentType = claims.documentType;
    this.documentHash = claims.documentHash ?? null;
    this.mustMatchPrintedDocument = {
      subjectName: claims.subjectName,
      documentId: claims.documentId,
      issuingOrganisation: claims.issuingOrganisation,
      issueDate: claims.issueDate,
    };
  }

  /**
   * Compare the signed fields with what was read off the document.
   *
   * Comparison is on the exact strings, after Unicode NFC normalisation and
   * trimming of surrounding whitespace only. Case is significant: `sn` is
   * specified as the name *as printed*, so a case difference is a real
   * difference an operator should see rather than one this library silently
   * absorbs.
   */
  public compareWithPrintedDocument(observed: PrintedDocumentFields): TransplantCheck {
    const fields: PrintedField[] = ['subjectName', 'documentId', 'issuingOrganisation', 'issueDate'];
    const comparisons = fields.map((field): FieldComparison => {
      const signed = this.mustMatchPrintedDocument[field].normalize('NFC').trim();
      const seen = observed[field].normalize('NFC').trim();
      return { field, signed: this.mustMatchPrintedDocument[field], observed: observed[field], matches: signed === seen };
    });
    return { comparisons, mismatches: comparisons.filter((c) => !c.matches) };
  }
}

/* ------------------------------------------------------------------ *
 * Sign and verify
 * ------------------------------------------------------------------ */

export interface SignProfileBOptions {
  readonly privateKey: CryptoKey;
  /** 16 uppercase hex characters. */
  readonly kid: string;
  readonly claims: CredentialClaims;
}

export async function signProfileB(options: SignProfileBOptions): Promise<string> {
  if (!isUppercaseHex(options.kid, KID_HEX_LENGTH)) throw new MalformedKidError();
  const cose = await encodeCoseSign1({
    privateKey: options.privateKey,
    kid: hexToBytes(options.kid),
    payload: encodeClaims(options.claims),
  });
  return PREFIX + encodeBase45(await deflate(cose));
}

export interface VerifyProfileBOptions {
  /** The scanned string, prefix included. */
  readonly payload: string;
  readonly trustAnchor: TrustAnchor;
  /** Verification time, Unix seconds. */
  readonly now: number;
}

/**
 * Verify a Profile B credential.
 *
 * Returns a `CredentialAssertion`, or throws a `KhSqrError` carrying a stable
 * `reason`. Performs no network access.
 */
export async function verifyProfileB(options: VerifyProfileBOptions): Promise<CredentialAssertion> {
  assertNotUrlCarrier(options.payload);
  if (!options.payload.startsWith(PREFIX)) throw new PrefixInvalidError();

  const compressed = decodeBase45(options.payload.slice(PREFIX.length));
  const cose = decodeCoseSign1(await inflate(compressed));

  if (cose.kid.length !== KID_BYTES) throw new CoseInvalidError('kid is not 8 bytes');
  const kid = bytesToHex(cose.kid);

  const candidates = await options.trustAnchor.resolveRecords(kid, 'B', options.now);
  let signer: TrustedKeyRecord | null = null;
  for (const { key, record } of candidates) {
    if (await verifyCoseSign1(cose, key)) { signer = record; break; }
  }
  if (signer === null) throw new SignatureInvalidError();

  const claims = readClaims(cose.payload);
  // The signature proves which registered key signed. It does not by itself
  // prove the key belongs to the institution the credential names: any
  // enrolled Profile B key could sign a credential in any issuer's name, and
  // a reader would have to notice "signed by X" beside "issued by Y". Binding
  // the issuer claim to the key's registration makes that a rule, not a
  // reading. Checked after the signature, because a mismatch is only
  // meaningful once the signer is known.
  if (claims.issuer !== signer.subject.organisationId) throw new IssuerKeyMismatchError();

  return new CredentialAssertion(kid, claims);
}
