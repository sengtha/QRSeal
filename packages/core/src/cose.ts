/**
 * COSE_Sign1 over ES256 (RFC 9052).
 *
 * Only the single-signer, ES256, empty-external-aad case is implemented, which
 * is all Profile B uses. Everything else is rejected rather than ignored.
 *
 * Dependency note: Profile A must NOT reach this module.
 */

import {
  decodeCbor,
  encodeCbor,
  isCborTagged,
  type CborMap,
  type CborValue,
} from './cbor.js';
import { CoseInvalidError } from './errors.js';
import { RAW_SIGNATURE_LENGTH, looksLikeDer, verifyEs256 } from './kid.js';

/** CBOR tag 18, COSE_Sign1. */
export const COSE_SIGN1_TAG = 18;
/** COSE header parameter 1: algorithm. */
export const HEADER_ALG = 1;
/** COSE header parameter 4: key identifier. */
export const HEADER_KID = 4;
/** COSE algorithm -7: ECDSA with SHA-256. */
export const ALG_ES256 = -7;

const CONTEXT = 'Signature1';

export interface CoseSign1 {
  /** The protected header exactly as it appeared, as signed. */
  readonly protectedBytes: Uint8Array;
  readonly protectedHeader: CborMap;
  readonly unprotectedHeader: CborMap;
  readonly payload: Uint8Array;
  readonly signature: Uint8Array;
  /** Key identifier from the protected header, 8 bytes. */
  readonly kid: Uint8Array;
}

/**
 * Build the Sig_structure whose encoding is what actually gets signed:
 * ["Signature1", protected, external_aad, payload].
 *
 * The protected header is carried through as the original bytes, never
 * re-encoded from the parsed map — the same discipline as Profile A's prefix
 * rule, for the same reason.
 */
export function buildSigStructure(protectedBytes: Uint8Array, payload: Uint8Array): Uint8Array {
  return encodeCbor([CONTEXT, protectedBytes, new Uint8Array(0), payload]);
}

function asMap(value: CborValue, what: string): CborMap {
  if (!(value instanceof Map)) throw new CoseInvalidError(`${what} is not a CBOR map`);
  return value;
}

/** Decode a tagged or untagged COSE_Sign1 structure. */
export function decodeCoseSign1(data: Uint8Array): CoseSign1 {
  const top = decodeCbor(data);
  let body: CborValue = top;
  if (isCborTagged(top)) {
    if (top.tag !== COSE_SIGN1_TAG) throw new CoseInvalidError('CBOR tag is not 18 (COSE_Sign1)');
    body = top.value;
  }
  if (!Array.isArray(body) || body.length !== 4) throw new CoseInvalidError('COSE_Sign1 is not a four-element array');

  const [protectedValue, unprotectedValue, payloadValue, signatureValue] = body;
  if (!(protectedValue instanceof Uint8Array)) throw new CoseInvalidError('protected header is not a byte string');
  if (!(payloadValue instanceof Uint8Array)) throw new CoseInvalidError('a detached payload is not supported');
  if (!(signatureValue instanceof Uint8Array)) throw new CoseInvalidError('signature is not a byte string');

  const protectedHeader = protectedValue.length === 0
    ? (new Map() as CborMap)
    : asMap(decodeCbor(protectedValue), 'protected header');
  const unprotectedHeader = asMap(unprotectedValue as CborValue, 'unprotected header');

  const alg = protectedHeader.get(HEADER_ALG);
  if (alg !== ALG_ES256) throw new CoseInvalidError('protected header does not select ES256');
  if (unprotectedHeader.has(HEADER_ALG)) {
    throw new CoseInvalidError('algorithm must be in the protected header only');
  }

  // The kid must be protected. An unprotected kid can be swapped in transit to
  // steer a verifier at a different trust-list entry.
  const kid = protectedHeader.get(HEADER_KID);
  if (!(kid instanceof Uint8Array)) throw new CoseInvalidError('protected header carries no byte-string kid');

  if (looksLikeDer(signatureValue)) throw new CoseInvalidError('signature is DER-encoded; raw r||s is required');
  if (signatureValue.length !== RAW_SIGNATURE_LENGTH) {
    throw new CoseInvalidError('signature is not 64 bytes of raw r||s');
  }

  return {
    protectedBytes: protectedValue,
    protectedHeader,
    unprotectedHeader,
    payload: payloadValue,
    signature: signatureValue,
    kid,
  };
}

/** Verify a decoded COSE_Sign1 against a candidate key. */
export async function verifyCoseSign1(message: CoseSign1, key: CryptoKey): Promise<boolean> {
  return verifyEs256(key, message.signature, buildSigStructure(message.protectedBytes, message.payload));
}

export interface EncodeCoseSign1Options {
  readonly privateKey: CryptoKey;
  /** 8-byte key identifier. */
  readonly kid: Uint8Array;
  readonly payload: Uint8Array;
}

/** Produce a tagged COSE_Sign1 over ES256. */
export async function encodeCoseSign1(options: EncodeCoseSign1Options): Promise<Uint8Array> {
  const header: CborMap = new Map<number | string, CborValue>([
    [HEADER_ALG, ALG_ES256],
    [HEADER_KID, options.kid],
  ]);
  const protectedBytes = encodeCbor(header);
  const raw = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    options.privateKey,
    buildSigStructure(protectedBytes, options.payload) as BufferSource,
  );
  const signature = new Uint8Array(raw);
  return encodeCbor({
    tag: COSE_SIGN1_TAG,
    value: [protectedBytes, new Map() as CborMap, options.payload, signature],
  });
}
