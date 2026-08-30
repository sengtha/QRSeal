/**
 * One class per normative rejection reason.
 *
 * Every rejection carries a stable, machine-readable `reason` string. These
 * strings are part of the wire contract of the conformance suite: a Kotlin or
 * Swift port proves conformance by producing the same `reason` for the same
 * input, so they must not be renamed once published.
 *
 * Verification never returns a boolean. It either returns a structured result
 * or throws one of these.
 */

export type RejectionReason =
  // --- container / EMVCo ---
  | 'MALFORMED_TLV'
  | 'CRC_MISSING'
  | 'CRC_MALFORMED'
  | 'CRC_MISMATCH'
  | 'SIGNATURE_TEMPLATE_MISSING'
  | 'SIGNATURE_TEMPLATE_NOT_LAST'
  | 'SIGNATURE_SUBTAG_NOT_LAST'
  | 'SIGNATURE_SUBTAG_MALFORMED'
  | 'DUPLICATE_TAG'
  // --- Profile A semantics ---
  | 'UNSUPPORTED_FORMAT_VERSION'
  | 'UNSUPPORTED_ALGORITHM'
  | 'MALFORMED_KID'
  | 'MALFORMED_TIMESTAMP'
  | 'MALFORMED_PAYEE_CLASS'
  | 'STATIC_CODE_WITH_AMOUNT'
  | 'STATIC_CODE_WITH_EXPIRY'
  | 'DYNAMIC_CODE_MISSING_EXPIRY'
  | 'EXPIRY_WINDOW_TOO_LONG'
  | 'EXPIRY_BEFORE_ISSUANCE'
  | 'CODE_EXPIRED'
  | 'ISSUED_IN_FUTURE'
  // --- signature ---
  | 'SIGNATURE_ENCODING_INVALID'
  | 'SIGNATURE_INVALID'
  // --- key / trust ---
  | 'UNKNOWN_KID'
  | 'KEY_REVOKED'
  | 'KEY_NOT_YET_VALID'
  | 'KEY_EXPIRED'
  | 'KEY_PROFILE_MISMATCH'
  | 'KEY_MALFORMED'
  // --- trust list / timestamp ---
  | 'TRUSTLIST_MALFORMED'
  | 'TRUSTLIST_SIGNATURE_INVALID'
  | 'TRUSTLIST_ROLLBACK'
  | 'TRUSTLIST_EXPIRED'
  | 'TRUSTLIST_STALE'
  | 'TIMESTAMP_MALFORMED'
  | 'TIMESTAMP_SIGNATURE_INVALID'
  | 'TIMESTAMP_EXPIRED'
  | 'TIMESTAMP_TARGET_MISMATCH'
  | 'TIMESTAMP_MISSING'
  // --- Profile B pipeline ---
  | 'PREFIX_INVALID'
  | 'BASE45_INVALID'
  | 'INFLATE_FAILED'
  | 'CBOR_INVALID'
  | 'COSE_INVALID'
  | 'URL_PAYLOAD_REJECTED'
  | 'CLAIM_MISSING'
  | 'CLAIM_TYPE_INVALID';

/** Base class for every normative rejection. */
export class KhSqrError extends Error {
  /** Stable machine-readable rejection reason. Never localise, never rename. */
  public readonly reason: RejectionReason;

  public constructor(reason: RejectionReason, message: string) {
    // Messages must never contain payload content; see docs/PRIVACY.md.
    super(`${reason}: ${message}`);
    this.reason = reason;
    this.name = new.target.name;
  }
}

type KhSqrErrorClass = new (message?: string) => KhSqrError;

/**
 * Builds one concrete error class per rejection reason. The class name is set
 * explicitly so it survives minification-free bundling and shows up in stack
 * traces; `instanceof` and `.reason` are both usable by callers.
 */
const define = (name: string, reason: RejectionReason, fallback: string): KhSqrErrorClass => {
  const cls = class extends KhSqrError {
    public constructor(message: string = fallback) {
      super(reason, message);
      this.name = name;
    }
  };
  Object.defineProperty(cls, 'name', { value: name });
  return cls;
};

/* --- container / EMVCo --- */
export const MalformedTlvError = define('MalformedTlvError', 'MALFORMED_TLV', 'payload is not well-formed EMVCo TLV');
export const CrcMissingError = define('CrcMissingError', 'CRC_MISSING', 'payload does not end with a tag 63 CRC object');
export const CrcMalformedError = define('CrcMalformedError', 'CRC_MALFORMED', 'CRC is not four uppercase hex characters');
export const CrcMismatchError = define('CrcMismatchError', 'CRC_MISMATCH', 'computed CRC-16/CCITT-FALSE does not match');
export const SignatureTemplateMissingError = define('SignatureTemplateMissingError', 'SIGNATURE_TEMPLATE_MISSING', 'template 85 is absent');
export const SignatureTemplateNotLastError = define('SignatureTemplateNotLastError', 'SIGNATURE_TEMPLATE_NOT_LAST', 'template 85 is not the last data object before the CRC');
export const SignatureSubtagNotLastError = define('SignatureSubtagNotLastError', 'SIGNATURE_SUBTAG_NOT_LAST', 'sub-tag 99 is not last within template 85');
export const SignatureSubtagMalformedError = define('SignatureSubtagMalformedError', 'SIGNATURE_SUBTAG_MALFORMED', 'sub-tag 99 is not a 128-character uppercase hex value');
export const DuplicateTagError = define('DuplicateTagError', 'DUPLICATE_TAG', 'a data object appears more than once');

/* --- Profile A semantics --- */
export const UnsupportedFormatVersionError = define('UnsupportedFormatVersionError', 'UNSUPPORTED_FORMAT_VERSION', 'sub-tag 00 is not the supported format version');
export const UnsupportedAlgorithmError = define('UnsupportedAlgorithmError', 'UNSUPPORTED_ALGORITHM', 'sub-tag 02 is not ES256');
export const MalformedKidError = define('MalformedKidError', 'MALFORMED_KID', 'sub-tag 01 is not 16 uppercase hex characters');
export const MalformedTimestampError = define('MalformedTimestampError', 'MALFORMED_TIMESTAMP', 'a timestamp sub-tag is not 10 decimal digits');
export const MalformedPayeeClassError = define('MalformedPayeeClassError', 'MALFORMED_PAYEE_CLASS', "sub-tag 05 is neither 'M' nor 'I'");
export const StaticCodeWithAmountError = define('StaticCodeWithAmountError', 'STATIC_CODE_WITH_AMOUNT', 'a static code carries a transaction amount (tag 54)');
export const StaticCodeWithExpiryError = define('StaticCodeWithExpiryError', 'STATIC_CODE_WITH_EXPIRY', 'a static code carries an expiry (sub-tag 04)');
export const DynamicCodeMissingExpiryError = define('DynamicCodeMissingExpiryError', 'DYNAMIC_CODE_MISSING_EXPIRY', 'a dynamic code omits the expiry sub-tag 04');
export const ExpiryWindowTooLongError = define('ExpiryWindowTooLongError', 'EXPIRY_WINDOW_TOO_LONG', 'dynamic code validity exceeds the maximum window');
export const ExpiryBeforeIssuanceError = define('ExpiryBeforeIssuanceError', 'EXPIRY_BEFORE_ISSUANCE', 'expiry precedes issuance');
export const CodeExpiredError = define('CodeExpiredError', 'CODE_EXPIRED', 'the code has expired');
export const IssuedInFutureError = define('IssuedInFutureError', 'ISSUED_IN_FUTURE', 'issued-at is beyond the permitted clock skew');

/* --- signature --- */
export const SignatureEncodingInvalidError = define('SignatureEncodingInvalidError', 'SIGNATURE_ENCODING_INVALID', 'signature is not raw r||s; DER is forbidden');
export const SignatureInvalidError = define('SignatureInvalidError', 'SIGNATURE_INVALID', 'ECDSA verification failed');

/* --- key / trust --- */
export const UnknownKidError = define('UnknownKidError', 'UNKNOWN_KID', 'no trusted key matches the key identifier');
export const KeyRevokedError = define('KeyRevokedError', 'KEY_REVOKED', 'the signing key is revoked');
export const KeyNotYetValidError = define('KeyNotYetValidError', 'KEY_NOT_YET_VALID', 'the signing key is not yet valid');
export const KeyExpiredError = define('KeyExpiredError', 'KEY_EXPIRED', 'the signing key has expired');
export const KeyProfileMismatchError = define('KeyProfileMismatchError', 'KEY_PROFILE_MISMATCH', 'the key is not authorised for this profile');
export const KeyMalformedError = define('KeyMalformedError', 'KEY_MALFORMED', 'the trusted key material is malformed');

/* --- trust list / timestamp --- */
export const TrustlistMalformedError = define('TrustlistMalformedError', 'TRUSTLIST_MALFORMED', 'trust list structure is invalid');
export const TrustlistSignatureInvalidError = define('TrustlistSignatureInvalidError', 'TRUSTLIST_SIGNATURE_INVALID', 'trust list Root signature failed to verify');
export const TrustlistRollbackError = define('TrustlistRollbackError', 'TRUSTLIST_ROLLBACK', 'offered trust list version is lower than the version held');
export const TrustlistExpiredError = define('TrustlistExpiredError', 'TRUSTLIST_EXPIRED', 'trust list expiry has passed');
export const TrustlistStaleError = define('TrustlistStaleError', 'TRUSTLIST_STALE', 'trust list cache age exceeds the maximum');
export const TimestampMalformedError = define('TimestampMalformedError', 'TIMESTAMP_MALFORMED', 'timestamp statement structure is invalid');
export const TimestampSignatureInvalidError = define('TimestampSignatureInvalidError', 'TIMESTAMP_SIGNATURE_INVALID', 'timestamp statement signature failed to verify');
export const TimestampExpiredError = define('TimestampExpiredError', 'TIMESTAMP_EXPIRED', 'timestamp statement validity has passed');
export const TimestampTargetMismatchError = define('TimestampTargetMismatchError', 'TIMESTAMP_TARGET_MISMATCH', 'timestamp statement does not attest the trust list held');
export const TimestampMissingError = define('TimestampMissingError', 'TIMESTAMP_MISSING', 'no timestamp statement supplied');

/* --- Profile B pipeline --- */
export const PrefixInvalidError = define('PrefixInvalidError', 'PREFIX_INVALID', 'payload does not carry the KH1: prefix');
export const Base45InvalidError = define('Base45InvalidError', 'BASE45_INVALID', 'payload is not valid RFC 9285 base45');
export const InflateFailedError = define('InflateFailedError', 'INFLATE_FAILED', 'zlib inflate failed');
export const CborInvalidError = define('CborInvalidError', 'CBOR_INVALID', 'CBOR is malformed or uses an unsupported construct');
export const CoseInvalidError = define('CoseInvalidError', 'COSE_INVALID', 'COSE_Sign1 structure is invalid');
export const UrlPayloadRejectedError = define('UrlPayloadRejectedError', 'URL_PAYLOAD_REJECTED', 'payload is an http/https URL, which this profile forbids');
export const ClaimMissingError = define('ClaimMissingError', 'CLAIM_MISSING', 'a mandatory claim is absent');
export const ClaimTypeInvalidError = define('ClaimTypeInvalidError', 'CLAIM_TYPE_INVALID', 'a claim has the wrong CBOR type');
