/**
 * Profile A, encoding version 2 — EMVCo-conformant.
 *
 * WHY THIS EXISTS
 *
 * Version 1 (profileA.ts) declares template `85` with a three-digit length and
 * carries the signature in a sub-tag `99` whose length is also three digits,
 * because 128 hexadecimal characters do not fit in EMVCo's two-digit length
 * field. It also uses sub-tag `00` for a format version where EMVCo requires a
 * Globally Unique Identifier. The consequence is not cosmetic: a strict EMVCo
 * parser reads `85`, takes `20` as the length, consumes twenty characters,
 * misaligns, and loses the CRC. The premise that an unreserved template is
 * transparent to a legacy wallet is therefore false for a template this size.
 *
 * Version 2 fixes that. Every length is two digits with a value of at most 99;
 * every unreserved template carries a GUID at sub-tag `00`; and the signature
 * is split across two templates because 128 characters cannot fit in one.
 *
 * WHAT IS PRESERVED
 *
 * The prefix rule. The signed region is still a plain prefix of the final
 * payload, recovered by substring and never by re-serialising parsed fields,
 * so there is still no canonical form to disagree about. What changes is where
 * the prefix ends: in v1 it ended at the fixed marker `99128`; here it ends
 * where template `86` begins, which a single well-formed TLV walk locates
 * exactly. Because every length in v2 is valid, that walk is the same walk a
 * legacy parser performs.
 *
 * LAYOUT
 *
 *   ...payload fields...
 *   85 LL  00 LL GUID | 01 LL "02" | 02 LL kid | 03 LL "ES256"
 *          | 04 LL issuedAt | 05 LL expiresAt? | 06 LL payeeClass
 *   86 LL  00 LL GUID | 01 64 <signature hex, characters 0..63>
 *   87 LL  00 LL GUID | 01 64 <signature hex, characters 64..127>
 *   63 04  CRC
 *
 * DEPENDENCY DISCIPLINE
 *
 * As with v1: Web Crypto only, no CBOR, no streams, no packages. Enforced by
 * tools/check-profile-a-isolation.ts.
 */

import {
  AMOUNT_TAG,
  POI_METHOD_TAG,
  POI_STATIC,
  POI_DYNAMIC,
  appendCrc,
  findObject,
  parseDataObjects,
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
  SignatureTemplateNotLastError,
  StaticCodeWithAmountError,
  StaticCodeWithExpiryError,
  UnsupportedAlgorithmError,
  UnsupportedFormatVersionError,
} from './errors.js';
import { asciiToBytes, bytesToHex, hexToBytes, isUppercaseHex } from './hex.js';
import { KID_HEX_LENGTH, verifyEs256 } from './kid.js';
import type { TrustAnchor } from './trustlist.js';
import {
  ALGORITHM,
  DEFAULT_CLOCK_SKEW_SECONDS,
  MAX_DYNAMIC_VALIDITY_SECONDS,
  SIGNATURE_HEX_LENGTH,
  type CodeKind,
  type PayeeClass,
  type PayeeDisclosure,
} from './profileA.js';

/** Metadata template. */
export const V2_META_TAG = '85';
/** First half of the signature. */
export const V2_SIG_HI_TAG = '86';
/** Second half of the signature. */
export const V2_SIG_LO_TAG = '87';

/**
 * The Globally Unique Identifier EMVCo requires at sub-tag `00` of an
 * unreserved template.
 *
 * A reverse-domain identifier rather than an ISO 7816 AID, which is the
 * conventional form when a scheme has no registered application identifier.
 *
 * It names the project and the country and asserts no institution. An earlier
 * value was `KH.GOV.NBC.SQR`, which claimed National Bank of Cambodia
 * governance in the wire format for a design the Bank has not endorsed --- a
 * claim the paper's own disclaimer contradicts. A default value must not assert
 * an authority that has not granted it.
 *
 * A national deployment must still settle this value with the scheme operator
 * before issuance; it is part of the wire format and cannot be changed
 * afterwards without a further version. If a central bank adopts the scheme, a
 * GUID naming it is theirs to choose.
 */
export const V2_GUID = 'KH.QRSEAL.SQR';

/** Sub-tags inside template 85. */
export const V2_SUBTAG_GUID = '00';
export const V2_SUBTAG_FORMAT_VERSION = '01';
export const V2_SUBTAG_KID = '02';
export const V2_SUBTAG_ALGORITHM = '03';
export const V2_SUBTAG_ISSUED_AT = '04';
export const V2_SUBTAG_EXPIRES_AT = '05';
export const V2_SUBTAG_PAYEE_CLASS = '06';
/** Sub-tag carrying a signature half inside templates 86 and 87. */
export const V2_SUBTAG_SIGNATURE_PART = '01';

export const V2_FORMAT_VERSION = '02';

/** Half of a 128-character signature. Chosen so each template stays under 99. */
export const V2_SIGNATURE_PART_LENGTH = SIGNATURE_HEX_LENGTH / 2;

/** Every length in v2 is two digits, so no tag is exempt. */
const NO_EXTENDED_LENGTHS: ReadonlySet<string> = new Set();

function assertTimestamp(value: number, what: string): string {
  if (!Number.isSafeInteger(value) || value < 0 || value > 9_999_999_999) {
    throw new MalformedTimestampError(`${what} is not representable in ten decimal digits`);
  }
  return String(value).padStart(10, '0');
}

function classifyCode(objects: readonly DataObject[]): CodeKind {
  const poi = findObject(objects, POI_METHOD_TAG);
  if (poi === undefined || poi.value === POI_STATIC) return 'static';
  if (poi.value === POI_DYNAMIC) return 'dynamic';
  return 'static';
}

/** A signature template: the GUID, then exactly one half of the signature. */
function signatureTemplate(tag: string, half: string): string {
  return serialiseDataObject(
    tag,
    serialiseDataObject(V2_SUBTAG_GUID, V2_GUID) +
      serialiseDataObject(V2_SUBTAG_SIGNATURE_PART, half),
  );
}

export interface SignProfileA2Options {
  /** An EMVCo payload. Any CRC present is discarded and recomputed. */
  readonly payload: string;
  readonly privateKey: CryptoKey;
  readonly kid: string;
  readonly issuedAt: number;
  /** Required for dynamic codes, forbidden on static ones. */
  readonly expiresAt?: number;
  readonly payeeClass: PayeeClass;
}

/**
 * Build the v2 signing input: the payload up to and including template `85`.
 *
 * Unlike v1 this has no trailing marker, because it does not need one. Every
 * length is well formed, so the boundary is the offset at which template `86`
 * starts, and both signer and verifier find it by the same TLV walk.
 */
function buildSigningInput(options: SignProfileA2Options): {
  signingInput: string;
  kind: CodeKind;
} {
  const base = stripCrc(options.payload);
  const objects = parseDataObjects(base, { extendedLengthTags: NO_EXTENDED_LENGTHS });
  const kind = classifyCode(objects);

  for (const tag of [V2_META_TAG, V2_SIG_HI_TAG, V2_SIG_LO_TAG]) {
    if (findObject(objects, tag) !== undefined) {
      throw new SignatureSubtagMalformedError(`payload already carries a template ${tag}`);
    }
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
  let meta =
    serialiseDataObject(V2_SUBTAG_GUID, V2_GUID) +
    serialiseDataObject(V2_SUBTAG_FORMAT_VERSION, V2_FORMAT_VERSION) +
    serialiseDataObject(V2_SUBTAG_KID, options.kid) +
    serialiseDataObject(V2_SUBTAG_ALGORITHM, ALGORITHM) +
    serialiseDataObject(V2_SUBTAG_ISSUED_AT, issuedAt);

  if (options.expiresAt !== undefined) {
    if (options.expiresAt <= options.issuedAt) throw new ExpiryBeforeIssuanceError();
    if (options.expiresAt - options.issuedAt > MAX_DYNAMIC_VALIDITY_SECONDS) {
      throw new ExpiryWindowTooLongError();
    }
    meta += serialiseDataObject(V2_SUBTAG_EXPIRES_AT, assertTimestamp(options.expiresAt, 'expiresAt'));
  }

  meta += serialiseDataObject(V2_SUBTAG_PAYEE_CLASS, options.payeeClass);

  // serialiseDataObject refuses a value over 99 characters, so this line is
  // where the format's size budget is actually enforced.
  return { signingInput: base + serialiseDataObject(V2_META_TAG, meta), kind };
}

export interface SignedPayloadV2 {
  readonly payload: string;
  readonly signingInput: string;
  /** Raw r||s as 128 uppercase hex characters, before splitting. */
  readonly signature: string;
  readonly codeKind: CodeKind;
}

/** Sign an EMVCo payload under Profile A, encoding version 2. */
export async function signProfileA2(options: SignProfileA2Options): Promise<SignedPayloadV2> {
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
  const payload = appendCrc(
    signingInput +
      signatureTemplate(V2_SIG_HI_TAG, signature.slice(0, V2_SIGNATURE_PART_LENGTH)) +
      signatureTemplate(V2_SIG_LO_TAG, signature.slice(V2_SIGNATURE_PART_LENGTH)),
  );
  return { payload, signingInput, signature, codeKind: kind };
}

export interface PaymentAttestationV2 {
  readonly profile: 'A';
  readonly encodingVersion: 2;
  readonly kid: string;
  readonly algorithm: typeof ALGORITHM;
  readonly formatVersion: string;
  readonly codeKind: CodeKind;
  readonly issuedAt: number;
  readonly expiresAt: number | null;
  /** The signed region: characters [0, signedThrough) of the payload. */
  readonly signedThrough: number;
  /**
   * What the payer must see. Named to be awkward to ignore, exactly as in v1.
   */
  readonly payeeDisclosure: PayeeDisclosure;
  /**
   * How lengths are encoded in this payload. Always `'emvco-two-digit'` in v2,
   * which is the entire reason v2 exists.
   *
   * Deliberately a string and not a boolean. Nothing on this result may be a
   * boolean, because a caller must not be able to reduce an attestation to a
   * yes/no without reading who is being paid — a test asserts it, and an
   * earlier draft of this field failed that test.
   */
  readonly lengthEncoding: 'emvco-two-digit';
}

export interface VerifyProfileA2Options {
  readonly payload: string;
  readonly trustAnchor: TrustAnchor;
  readonly now: number;
  readonly clockSkewSeconds?: number;
}

function subtagsOf(template: DataObject): DataObject[] {
  return parseDataObjects(template.value, { extendedLengthTags: NO_EXTENDED_LENGTHS });
}

function requireSubtag(objects: readonly DataObject[], tag: string, what: string): string {
  const found = findObject(objects, tag);
  if (found === undefined) throw new SignatureSubtagMalformedError(`missing ${what}`);
  return found.value;
}

/** Read one half of the signature out of a signature template. */
function signatureHalf(objects: readonly DataObject[], tag: string): string {
  const template = findObject(objects, tag);
  if (template === undefined) throw new SignatureSubtagMalformedError(`missing template ${tag}`);
  const subtags = subtagsOf(template);
  if (requireSubtag(subtags, V2_SUBTAG_GUID, `GUID in template ${tag}`) !== V2_GUID) {
    throw new SignatureSubtagMalformedError(`template ${tag} carries a foreign GUID`);
  }
  const half = requireSubtag(subtags, V2_SUBTAG_SIGNATURE_PART, `signature part in template ${tag}`);
  if (!isUppercaseHex(half, V2_SIGNATURE_PART_LENGTH)) {
    throw new SignatureEncodingInvalidError(
      `template ${tag} does not carry ${V2_SIGNATURE_PART_LENGTH} uppercase hex characters`,
    );
  }
  return half;
}

function discloseFrom(objects: readonly DataObject[], payeeClass: PayeeClass): PayeeDisclosure {
  const text = (tag: string): string | null => findObject(objects, tag)?.value ?? null;
  const accounts = objects
    .filter((o) => Number(o.tag) >= 26 && Number(o.tag) <= 51)
    .map((o) => ({ tag: o.tag, value: o.value }));
  const numeric = text('53');
  const alpha = numeric === null ? null : (CURRENCY_ALPHA.get(numeric) ?? null);
  return {
    merchantName: text('59'),
    merchantCity: text('60'),
    countryCode: text('58'),
    amount: text(AMOUNT_TAG),
    currencyCode: numeric,
    currencyAlpha: alpha,
    payeeClass,
    accounts,
  };
}

/** Same deliberately incomplete table as v1: an unnameable currency stays null. */
const CURRENCY_ALPHA: ReadonlyMap<string, string> = new Map([
  ['116', 'KHR'],
  ['840', 'USD'],
]);

/**
 * Verify a Profile A v2 payload.
 *
 * Returns a structured attestation or throws a `KhSqrError` with a stable
 * `reason`. Never returns a boolean, for the same reason v1 does not.
 */
export async function verifyProfileA2(
  options: VerifyProfileA2Options,
): Promise<PaymentAttestationV2> {
  const { payload, trustAnchor, now } = options;
  const skew = options.clockSkewSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;

  // A strict two-digit walk. If this succeeds, so does a legacy parser's.
  const body = stripCrc(payload);
  const objects = parseDataObjects(body, { extendedLengthTags: NO_EXTENDED_LENGTHS });

  // The tail must be exactly 85, 86, 87 — otherwise an attacker could append
  // data after the signature while leaving the signed prefix intact.
  const tail = objects.slice(-3).map((o) => o.tag);
  if (tail.join(',') !== `${V2_META_TAG},${V2_SIG_HI_TAG},${V2_SIG_LO_TAG}`) {
    throw new SignatureTemplateNotLastError(
      'templates 85, 86 and 87 must be the final three data objects before the CRC',
    );
  }

  const meta = findObject(objects, V2_META_TAG)!;
  const sigHi = findObject(objects, V2_SIG_HI_TAG)!;
  const metaSubtags = subtagsOf(meta);

  if (requireSubtag(metaSubtags, V2_SUBTAG_GUID, 'GUID in template 85') !== V2_GUID) {
    throw new SignatureSubtagMalformedError('template 85 carries a foreign GUID');
  }
  const formatVersion = requireSubtag(metaSubtags, V2_SUBTAG_FORMAT_VERSION, 'format version');
  if (formatVersion !== V2_FORMAT_VERSION) throw new UnsupportedFormatVersionError();

  const algorithm = requireSubtag(metaSubtags, V2_SUBTAG_ALGORITHM, 'algorithm');
  if (algorithm !== ALGORITHM) throw new UnsupportedAlgorithmError();

  const kid = requireSubtag(metaSubtags, V2_SUBTAG_KID, 'key identifier');
  if (!isUppercaseHex(kid, KID_HEX_LENGTH)) throw new MalformedKidError();

  const payeeClass = requireSubtag(metaSubtags, V2_SUBTAG_PAYEE_CLASS, 'payee class');
  if (payeeClass !== 'M' && payeeClass !== 'I') throw new MalformedPayeeClassError();

  const issuedAt = Number.parseInt(
    requireSubtag(metaSubtags, V2_SUBTAG_ISSUED_AT, 'issuance time'),
    10,
  );
  const expiresRaw = findObject(metaSubtags, V2_SUBTAG_EXPIRES_AT)?.value ?? null;
  const expiresAt = expiresRaw === null ? null : Number.parseInt(expiresRaw, 10);

  const kind = classifyCode(objects);
  if (kind === 'static') {
    if (findObject(objects, AMOUNT_TAG) !== undefined) throw new StaticCodeWithAmountError();
    if (expiresAt !== null) throw new StaticCodeWithExpiryError();
  } else if (expiresAt === null) {
    throw new DynamicCodeMissingExpiryError();
  }

  if (expiresAt !== null) {
    if (expiresAt <= issuedAt) throw new ExpiryBeforeIssuanceError();
    if (expiresAt - issuedAt > MAX_DYNAMIC_VALIDITY_SECONDS) throw new ExpiryWindowTooLongError();
  }

  // The signed region is a substring of the received payload, never a
  // re-serialisation of what was parsed.
  const signedThrough = sigHi.start;
  const signingInput = payload.slice(0, signedThrough);

  const signature = signatureHalf(objects, V2_SIG_HI_TAG) + signatureHalf(objects, V2_SIG_LO_TAG);

  const keys = await trustAnchor.resolve(kid, 'A', now);
  const message = asciiToBytes(signingInput);
  const rawSignature = hexToBytes(signature);
  let verified = false;
  for (const key of keys) {
    if (await verifyEs256(key, rawSignature, message)) { verified = true; break; }
  }
  if (!verified) throw new SignatureInvalidError();

  if (issuedAt > now + skew) throw new IssuedInFutureError();
  if (expiresAt !== null && now > expiresAt) throw new CodeExpiredError();

  return {
    profile: 'A',
    encodingVersion: 2,
    kid,
    algorithm: ALGORITHM,
    formatVersion,
    codeKind: kind,
    issuedAt,
    expiresAt,
    signedThrough,
    payeeDisclosure: discloseFrom(objects, payeeClass),
    lengthEncoding: 'emvco-two-digit',
  };
}

/** Tags this encoding occupies, for a caller that needs to reserve them. */
export const V2_TEMPLATE_TAGS: readonly string[] = [V2_META_TAG, V2_SIG_HI_TAG, V2_SIG_LO_TAG];

/**
 * Which Profile A encoding a scanned payload carries, or `null` when it carries
 * no signature template at all.
 *
 * Both encodings are wire formats a verifier must dispatch on, and neither
 * declares itself in a header, so the decision is structural. Version 2 is
 * recognised by a strict two-digit walk — the one a legacy parser performs —
 * that reaches a signature template `86` or `87`, which version 1 never
 * carries. Version 1 is recognised by template `85` under the fixed-offset
 * rule. Anything else is an unsigned EMVCo payload, or not EMVCo at all; the
 * caller decides which by verifying under the profile this function names, or
 * by treating the code as unsigned.
 *
 * The version 2 rule is deliberately looser than `verifyProfileA2`'s: a
 * payload with data appended after template `87` is still routed to version
 * 2, so that the verifier can reject it for that reason
 * (`SIGNATURE_TEMPLATE_NOT_LAST`) rather than a version 1 verifier rejecting
 * it for a less diagnostic one. This is a routing hint and never a verdict.
 */
export function detectProfileAEncoding(payload: string): 2 | 1 | null {
  const body = stripCrc(payload);
  try {
    const objects = parseDataObjects(body, { extendedLengthTags: NO_EXTENDED_LENGTHS });
    if (findObject(objects, V2_SIG_HI_TAG) !== undefined || findObject(objects, V2_SIG_LO_TAG) !== undefined) {
      return 2;
    }
  } catch {
    // Not a valid two-digit walk; fall through to the version 1 rule.
  }
  try {
    // The fixed-offset rule: template 85 runs to the CRC regardless of its
    // declared length, so the walk must not trust that length either. The
    // published v1 reference vector declares 200 for 201 characters and is a
    // valid payload; a length-trusting walk would call it unsigned.
    const objects = parseDataObjects(body, { lengthAgnosticTag: V2_META_TAG, boundary: body.length });
    if (findObject(objects, V2_META_TAG) !== undefined) return 1;
  } catch {
    // Not version 1 either.
  }
  return null;
}
