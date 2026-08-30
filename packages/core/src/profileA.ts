/**
 * Profile A — payment. An ECDSA signature bound to an existing EMVCo
 * merchant-presented payload.
 *
 * WHAT THIS PROVES, AND WHAT IT DOES NOT
 *
 * A valid Profile A signature proves that a registered issuer produced this
 * exact payload and that no character of it has changed since. It says nothing
 * whatever about why the payer is scanning, whether the payee deserves the
 * money, or whether the sign above the counter is honest. A genuine, correctly
 * signed code presented under a false pretext verifies perfectly. Cryptography
 * closes forgery; it does not touch deception. Any user interface built on this
 * result must show `payeeDisclosure` to the payer before the transfer, and must
 * not present a verified signature as a reason to trust the transaction.
 *
 * DEPENDENCY DISCIPLINE
 *
 * This module and its entire transitive import graph depend on nothing but Web
 * Crypto — no CBOR, no CompressionStream, no packages — so that a mobile wallet
 * can embed it without a polyfill. Enforced by tools/check-profile-a-isolation.ts.
 */

import {
  AMOUNT_TAG,
  POI_DYNAMIC,
  POI_METHOD_TAG,
  POI_STATIC,
  SIGNATURE_TEMPLATE_TAG,
  appendCrc,
  assertSignatureTemplateIsLast,
  findObject,
  parseDataObjects,
  parseEmvcoPayload,
  serialiseDataObject,
  stripCrc,
  type DataObject,
} from './emvco.js';
import {
  CodeExpiredError,
  DynamicCodeMissingExpiryError,
  ExpiryBeforeIssuanceError,
  ExpiryWindowTooLongError,
  IssuedInFutureError,
  MalformedKidError,
  MalformedPayeeClassError,
  MalformedTimestampError,
  SignatureEncodingInvalidError,
  SignatureInvalidError,
  SignatureSubtagMalformedError,
  SignatureSubtagNotLastError,
  SignatureTemplateMissingError,
  SignatureTemplateNotLastError,
  StaticCodeWithAmountError,
  StaticCodeWithExpiryError,
  UnsupportedAlgorithmError,
  UnsupportedFormatVersionError,
} from './errors.js';
import { asciiToBytes, bytesToHex, hexToBytes, isUppercaseHex } from './hex.js';
import { KID_HEX_LENGTH, RAW_SIGNATURE_LENGTH, looksLikeDer, verifyEs256 } from './kid.js';
import type { TrustAnchor } from './trustlist.js';

/* ------------------------------------------------------------------ *
 * Sub-tags of template 85
 * ------------------------------------------------------------------ */

export const SUBTAG_FORMAT_VERSION = '00';
export const SUBTAG_KID = '01';
export const SUBTAG_ALGORITHM = '02';
export const SUBTAG_ISSUED_AT = '03';
export const SUBTAG_EXPIRES_AT = '04';
export const SUBTAG_PAYEE_CLASS = '05';
export const SUBTAG_SIGNATURE = '99';

export const FORMAT_VERSION = '01';
export const ALGORITHM = 'ES256';
/** 64 raw signature bytes rendered as uppercase hex. */
export const SIGNATURE_HEX_LENGTH = RAW_SIGNATURE_LENGTH * 2;
/** The five characters that terminate the signing input: sub-tag 99's tag and length. */
export const SIGNATURE_HEADER = `${SUBTAG_SIGNATURE}${SIGNATURE_HEX_LENGTH}`;
/** Maximum validity window of a dynamic code. */
export const MAX_DYNAMIC_VALIDITY_SECONDS = 300;
/** Tolerance for a signer's clock running ahead of the verifier's. */
export const DEFAULT_CLOCK_SKEW_SECONDS = 60;

/** Sub-tag 99 declares its length in three digits; 128 exceeds EMVCo's two-digit maximum. */
const TEMPLATE_EXTENDED_LENGTH_TAGS: ReadonlySet<string> = new Set([SUBTAG_SIGNATURE]);

const TEN_DIGITS = /^[0-9]{10}$/;

export type PayeeClass = 'M' | 'I';
export type CodeKind = 'static' | 'dynamic';

/* ------------------------------------------------------------------ *
 * Signing
 * ------------------------------------------------------------------ */

export interface SignProfileAOptions {
  /**
   * An EMVCo payload with no template 85. A trailing CRC, if present, is
   * discarded and recomputed.
   */
  readonly payload: string;
  /** ECDSA P-256 private key. Never held by an edge service; see SPEC.md. */
  readonly privateKey: CryptoKey;
  /** 16 uppercase hex characters identifying the signing key. */
  readonly kid: string;
  readonly issuedAt: number;
  /** Required for dynamic codes, forbidden on static ones. */
  readonly expiresAt?: number;
  readonly payeeClass: PayeeClass;
}

function assertTimestamp(value: number, what: string): string {
  if (!Number.isSafeInteger(value) || value < 0 || value > 9_999_999_999) {
    throw new MalformedTimestampError(`${what} is not representable in ten decimal digits`);
  }
  return String(value).padStart(10, '0');
}

function classifyCode(objects: readonly DataObject[]): CodeKind {
  const poi = findObject(objects, POI_METHOD_TAG);
  // EMVCo treats an absent Point of Initiation Method as static.
  if (poi === undefined || poi.value === POI_STATIC) return 'static';
  if (poi.value === POI_DYNAMIC) return 'dynamic';
  return 'static';
}

/**
 * Build the signing input: the complete payload from position 0 up to and
 * including the five characters `99128`.
 *
 * The signed region is therefore a plain prefix of the final payload. A
 * verifier reconstructs it by taking a substring, never by re-serialising
 * parsed fields, so there is no canonical form to disagree about and no
 * canonicalisation bug to have.
 */
function buildSigningInput(options: SignProfileAOptions): { signingInput: string; kind: CodeKind } {
  const base = stripCrc(options.payload);
  const objects = parseDataObjects(base);
  const kind = classifyCode(objects);

  if (findObject(objects, SIGNATURE_TEMPLATE_TAG) !== undefined) {
    throw new SignatureSubtagMalformedError('payload already carries a template 85');
  }

  if (kind === 'static') {
    if (findObject(objects, AMOUNT_TAG) !== undefined) throw new StaticCodeWithAmountError();
    if (options.expiresAt !== undefined) throw new StaticCodeWithExpiryError();
  } else if (options.expiresAt === undefined) {
    throw new DynamicCodeMissingExpiryError();
  }

  if (!isUppercaseHex(options.kid, KID_HEX_LENGTH)) throw new MalformedKidError();
  if (options.payeeClass !== 'M' && options.payeeClass !== 'I') throw new MalformedPayeeClassError();

  const issuedAt = assertTimestamp(options.issuedAt, 'issuedAt');
  let template =
    serialiseDataObject(SUBTAG_FORMAT_VERSION, FORMAT_VERSION) +
    serialiseDataObject(SUBTAG_KID, options.kid) +
    serialiseDataObject(SUBTAG_ALGORITHM, ALGORITHM) +
    serialiseDataObject(SUBTAG_ISSUED_AT, issuedAt);

  if (options.expiresAt !== undefined) {
    if (options.expiresAt <= options.issuedAt) throw new ExpiryBeforeIssuanceError();
    if (options.expiresAt - options.issuedAt > MAX_DYNAMIC_VALIDITY_SECONDS) throw new ExpiryWindowTooLongError();
    template += serialiseDataObject(SUBTAG_EXPIRES_AT, assertTimestamp(options.expiresAt, 'expiresAt'));
  }

  template += serialiseDataObject(SUBTAG_PAYEE_CLASS, options.payeeClass);

  // The declared length covers the signature that will follow, so it is
  // computed before the signature exists.
  const templateLength = template.length + SIGNATURE_HEADER.length + SIGNATURE_HEX_LENGTH;
  const header = SIGNATURE_TEMPLATE_TAG + String(templateLength).padStart(3, '0');

  return { signingInput: base + header + template + SIGNATURE_HEADER, kind };
}

export interface SignedPayload {
  /** The complete payload, signature and CRC included. */
  readonly payload: string;
  /** The exact string that was signed. */
  readonly signingInput: string;
  /** Raw r||s as 128 uppercase hex characters. */
  readonly signature: string;
  readonly codeKind: CodeKind;
}

/**
 * Sign an EMVCo payload under Profile A.
 *
 * ECDSA is randomised, so signing the same input twice yields different
 * signatures. Both verify. Conformance is tested by verifying this function's
 * own output, not by comparing it to a fixed signature.
 */
export async function signProfileA(options: SignProfileAOptions): Promise<SignedPayload> {
  const { signingInput, kind } = buildSigningInput(options);
  const raw = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    options.privateKey,
    asciiToBytes(signingInput) as BufferSource,
  );
  const signature = bytesToHex(new Uint8Array(raw));
  /* c8 ignore next */
  if (signature.length !== SIGNATURE_HEX_LENGTH) {
    throw new SignatureEncodingInvalidError('Web Crypto returned a signature that is not raw r||s');
  }
  return { payload: appendCrc(signingInput + signature), signingInput, signature, codeKind: kind };
}

/* ------------------------------------------------------------------ *
 * Verification
 * ------------------------------------------------------------------ */

/**
 * Everything a payer must be shown before authorising, extracted from the
 * signed payload.
 *
 * The signature guarantees these values were not altered in transit. It does
 * not guarantee that they describe the person standing in front of the payer,
 * or that the stated reason for the payment is true.
 */
export interface PayeeDisclosure {
  readonly merchantName: string | null;
  readonly merchantCity: string | null;
  readonly countryCode: string | null;
  readonly amount: string | null;
  readonly currencyCode: string | null;
  readonly payeeClass: PayeeClass;
  /** Account identifiers from templates 26-51, in payload order. */
  readonly accounts: readonly { readonly tag: string; readonly value: string }[];
}

export interface PaymentAttestation {
  readonly profile: 'A';
  readonly kid: string;
  readonly algorithm: typeof ALGORITHM;
  readonly formatVersion: string;
  readonly codeKind: CodeKind;
  readonly issuedAt: number;
  readonly expiresAt: number | null;
  /** The signed region: characters [0, signedThrough) of the payload. */
  readonly signedThrough: number;
  /**
   * What the payer must see. Named to be awkward to ignore: a caller that
   * wants a yes/no answer has to walk past this field to get one.
   */
  readonly payeeDisclosure: PayeeDisclosure;
  /** Diagnostics on template 85's length declaration; see SPEC.md. */
  readonly container: {
    readonly declaredTemplateLength: number;
    readonly actualTemplateLength: number;
    readonly declaredLengthConsistent: boolean;
  };
}

export interface VerifyProfileAOptions {
  readonly payload: string;
  readonly trustAnchor: TrustAnchor;
  /** Verification time, Unix seconds. */
  readonly now: number;
  readonly clockSkewSeconds?: number;
}

interface TemplateFields {
  readonly kid: string;
  readonly formatVersion: string;
  readonly issuedAt: number;
  readonly expiresAt: number | null;
  readonly payeeClass: PayeeClass;
  readonly signature: string;
  readonly declaredLength: number;
  readonly actualLength: number;
}

/**
 * Decide whether trailing data inside the length-agnostic template region is a
 * data object appended *after* template 85, or a sub-tag appended after
 * sub-tag 99.
 *
 * Because the fixed-offset rule takes template 85 to run to the CRC, both
 * malformations present identically at first. The declared length — not
 * trusted for locating the signature, but still informative — tells them
 * apart: if the sub-tags tile the declared length exactly and end with the
 * signature, the extra characters lie outside the template.
 */
function trailingDataIsOutsideTemplate(content: string, declaredLength: number): boolean {
  if (declaredLength >= content.length) return false;
  try {
    const inner = parseDataObjects(content.slice(0, declaredLength), {
      extendedLengthTags: TEMPLATE_EXTENDED_LENGTH_TAGS,
    });
    return inner.at(-1)?.tag === SUBTAG_SIGNATURE;
  } catch {
    return false;
  }
}

function readTemplate(template: DataObject, payload: string): TemplateFields {
  const declaredLength = Number.parseInt(payload.slice(template.start + 2, template.start + 5), 10);
  const subtags = parseDataObjects(template.value, { extendedLengthTags: TEMPLATE_EXTENDED_LENGTH_TAGS });

  const last = subtags.at(-1);
  if (last === undefined || last.tag !== SUBTAG_SIGNATURE) {
    if (trailingDataIsOutsideTemplate(template.value, declaredLength)) {
      throw new SignatureTemplateNotLastError();
    }
    throw new SignatureSubtagNotLastError();
  }

  const signature = last.value;
  if (!isUppercaseHex(signature)) throw new SignatureSubtagMalformedError();
  if (signature.length !== SIGNATURE_HEX_LENGTH) {
    // Distinguish the common porting mistake — handing over a DER SEQUENCE —
    // from a value that is merely the wrong size.
    if (looksLikeDer(hexToBytes(signature))) throw new SignatureEncodingInvalidError();
    throw new SignatureSubtagMalformedError();
  }

  const version = findObject(subtags, SUBTAG_FORMAT_VERSION);
  if (version === undefined || version.value !== FORMAT_VERSION) throw new UnsupportedFormatVersionError();

  const algorithm = findObject(subtags, SUBTAG_ALGORITHM);
  if (algorithm === undefined || algorithm.value !== ALGORITHM) throw new UnsupportedAlgorithmError();

  const kid = findObject(subtags, SUBTAG_KID);
  if (kid === undefined || !isUppercaseHex(kid.value, KID_HEX_LENGTH)) throw new MalformedKidError();

  const issuedAt = findObject(subtags, SUBTAG_ISSUED_AT);
  if (issuedAt === undefined || !TEN_DIGITS.test(issuedAt.value)) throw new MalformedTimestampError('sub-tag 03');

  const expiresAt = findObject(subtags, SUBTAG_EXPIRES_AT);
  if (expiresAt !== undefined && !TEN_DIGITS.test(expiresAt.value)) throw new MalformedTimestampError('sub-tag 04');

  const payeeClass = findObject(subtags, SUBTAG_PAYEE_CLASS);
  if (payeeClass === undefined || (payeeClass.value !== 'M' && payeeClass.value !== 'I')) {
    throw new MalformedPayeeClassError();
  }

  return {
    kid: kid.value,
    formatVersion: version.value,
    issuedAt: Number.parseInt(issuedAt.value, 10),
    expiresAt: expiresAt === undefined ? null : Number.parseInt(expiresAt.value, 10),
    payeeClass: payeeClass.value,
    signature,
    declaredLength,
    actualLength: template.value.length,
  };
}

function disclose(objects: readonly DataObject[], payeeClass: PayeeClass): PayeeDisclosure {
  const text = (tag: string): string | null => findObject(objects, tag)?.value ?? null;
  const accounts = objects
    .filter((o) => Number(o.tag) >= 26 && Number(o.tag) <= 51)
    .map((o) => ({ tag: o.tag, value: o.value }));
  return {
    merchantName: text('59'),
    merchantCity: text('60'),
    countryCode: text('58'),
    amount: text(AMOUNT_TAG),
    currencyCode: text('53'),
    payeeClass,
    accounts,
  };
}

/**
 * Verify a Profile A payload.
 *
 * Returns a structured attestation, or throws a `KhSqrError` carrying a stable
 * `reason`. It never returns a boolean: a caller must not be able to reduce
 * this to a tick without reading who is being paid.
 *
 * Order of checks: container and CRC, then structure, then the semantic rules,
 * then the signature, then time. The signature is checked before expiry so
 * that a tampered payload reports tampering rather than staleness.
 *
 * Performs no network access. Everything needed is in `trustAnchor`.
 */
export async function verifyProfileA(options: VerifyProfileAOptions): Promise<PaymentAttestation> {
  const { payload, trustAnchor, now } = options;
  const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  // Template 85's declared length is not trusted; the fixed-offset rule
  // defines the signed region. Tampering with that length still fails, because
  // those characters lie inside the signed prefix.
  const envelope = parseEmvcoPayload(payload, { signatureTemplateLengthAgnostic: true });

  if (findObject(envelope.objects, SIGNATURE_TEMPLATE_TAG) === undefined) {
    throw new SignatureTemplateMissingError();
  }
  const template = assertSignatureTemplateIsLast(envelope.objects);
  const fields = readTemplate(template, payload);

  const signatureStart = template.end - SIGNATURE_HEX_LENGTH;
  const signingInput = payload.slice(0, signatureStart);
  if (!signingInput.endsWith(SIGNATURE_HEADER)) throw new SignatureSubtagNotLastError();

  const kind = classifyCode(envelope.objects);
  if (kind === 'static') {
    if (findObject(envelope.objects, AMOUNT_TAG) !== undefined) throw new StaticCodeWithAmountError();
    if (fields.expiresAt !== null) throw new StaticCodeWithExpiryError();
  } else if (fields.expiresAt === null) {
    throw new DynamicCodeMissingExpiryError();
  }

  if (fields.expiresAt !== null) {
    if (fields.expiresAt <= fields.issuedAt) throw new ExpiryBeforeIssuanceError();
    if (fields.expiresAt - fields.issuedAt > MAX_DYNAMIC_VALIDITY_SECONDS) throw new ExpiryWindowTooLongError();
  }

  const keys = await trustAnchor.resolve(fields.kid, 'A', now);
  const message = asciiToBytes(signingInput);
  const rawSignature = hexToBytes(fields.signature);
  let verified = false;
  for (const key of keys) {
    if (await verifyEs256(key, rawSignature, message)) { verified = true; break; }
  }
  if (!verified) throw new SignatureInvalidError();

  if (fields.issuedAt > now + skew) throw new IssuedInFutureError();
  if (fields.expiresAt !== null && now > fields.expiresAt) throw new CodeExpiredError();

  return {
    profile: 'A',
    kid: fields.kid,
    algorithm: ALGORITHM,
    formatVersion: fields.formatVersion,
    codeKind: kind,
    issuedAt: fields.issuedAt,
    expiresAt: fields.expiresAt,
    signedThrough: signatureStart,
    payeeDisclosure: disclose(envelope.objects, fields.payeeClass),
    container: {
      declaredTemplateLength: fields.declaredLength,
      actualTemplateLength: fields.actualLength,
      declaredLengthConsistent: fields.declaredLength === fields.actualLength,
    },
  };
}
