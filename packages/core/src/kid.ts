/**
 * Key identifier derivation and P-256 key import.
 *
 * kid = the first 8 bytes of SHA-256 over the uncompressed point
 * (0x04 || X || Y), rendered as 16 uppercase hex characters in Profile A and
 * carried as an 8-byte byte string in Profile B.
 *
 * Truncation to 8 bytes is a size choice, not a security claim: the kid is a
 * lookup hint into the trust list, never an authenticator. A verifier that
 * finds two trust-list entries sharing a kid must try both and accept only if
 * a signature verifies; it must never treat kid equality as identity.
 *
 * Dependency note: Web Crypto only.
 */

import { KeyMalformedError } from './errors.js';
import { bytesToHex, hexToBytes, isUppercaseHex } from './hex.js';

export const KID_BYTES = 8;
export const KID_HEX_LENGTH = KID_BYTES * 2;

/** The uncompressed-point encoding of a P-256 public key: 0x04 || X || Y. */
export const UNCOMPRESSED_POINT_LENGTH = 65;

const P256: EcKeyImportParams = { name: 'ECDSA', namedCurve: 'P-256' };
const ES256_VERIFY: EcdsaParams = { name: 'ECDSA', hash: 'SHA-256' };

/** Raw ECDSA P-256 signature length: r||s, 32 bytes each. */
export const RAW_SIGNATURE_LENGTH = 64;

export function assertUncompressedPoint(point: Uint8Array): void {
  if (point.length !== UNCOMPRESSED_POINT_LENGTH || point[0] !== 0x04) {
    throw new KeyMalformedError('public key is not a 65-byte uncompressed P-256 point');
  }
}

/** Derive the key identifier from an uncompressed P-256 point. */
export async function deriveKid(uncompressedPoint: Uint8Array): Promise<string> {
  assertUncompressedPoint(uncompressedPoint);
  const digest = await crypto.subtle.digest('SHA-256', uncompressedPoint as BufferSource);
  return bytesToHex(new Uint8Array(digest).subarray(0, KID_BYTES));
}

/** Derive the key identifier from 64 uppercase hex characters of X and Y. */
export async function deriveKidFromCoordinates(xHex: string, yHex: string): Promise<string> {
  if (!isUppercaseHex(xHex, 64) || !isUppercaseHex(yHex, 64)) {
    throw new KeyMalformedError('coordinates must each be 64 uppercase hex characters');
  }
  return deriveKid(hexToBytes(`04${xHex}${yHex}`));
}

/** Import a P-256 verification key from its uncompressed point. */
export async function importVerificationKey(uncompressedPoint: Uint8Array): Promise<CryptoKey> {
  assertUncompressedPoint(uncompressedPoint);
  try {
    return await crypto.subtle.importKey('raw', uncompressedPoint as BufferSource, P256, false, ['verify']);
  } catch {
    throw new KeyMalformedError('public key point could not be imported');
  }
}

/** Import a P-256 verification key from 64 uppercase hex characters of X and Y. */
export async function importVerificationKeyFromCoordinates(xHex: string, yHex: string): Promise<CryptoKey> {
  if (!isUppercaseHex(xHex, 64) || !isUppercaseHex(yHex, 64)) {
    throw new KeyMalformedError('coordinates must each be 64 uppercase hex characters');
  }
  return importVerificationKey(hexToBytes(`04${xHex}${yHex}`));
}

/**
 * Verify an ES256 signature given as raw r||s.
 *
 * `crypto.subtle.verify` for ECDSA takes IEEE P1363 raw r||s, which is exactly
 * what the wire format carries. There is no DER conversion step anywhere in
 * this library, and therefore no DER length-parsing bug to have.
 */
export async function verifyEs256(
  key: CryptoKey,
  rawSignature: Uint8Array,
  message: Uint8Array,
): Promise<boolean> {
  if (rawSignature.length !== RAW_SIGNATURE_LENGTH) return false;
  return crypto.subtle.verify(ES256_VERIFY, key, rawSignature as BufferSource, message as BufferSource);
}

/**
 * Detect a DER-encoded ECDSA signature offered where raw r||s is required.
 *
 * DER signatures begin with SEQUENCE (0x30) and declare a length. Recognising
 * them lets the verifier return a specific rejection reason rather than a
 * generic length failure, which matters for a conformance suite that asserts
 * on reasons.
 */
export function looksLikeDer(signature: Uint8Array): boolean {
  if (signature.length < 8 || signature[0] !== 0x30) return false;
  const declared = signature[1];
  return declared !== undefined && declared === signature.length - 2;
}
