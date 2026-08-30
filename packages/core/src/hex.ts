/**
 * Uppercase-hex helpers.
 *
 * Profile A carries every binary field as uppercase hexadecimal, not base64,
 * because QR alphanumeric mode admits only digits, uppercase letters and nine
 * punctuation marks. A single lowercase character forces the encoder into byte
 * mode and enlarges the symbol.
 *
 * Dependency note: this module must remain free of CBOR and stream APIs so
 * that Profile A's import graph stays Web-Crypto-only.
 */

const HEX_UPPER = /^[0-9A-F]*$/;

export function isUppercaseHex(value: string, length?: number): boolean {
  if (length !== undefined && value.length !== length) return false;
  if (value.length % 2 !== 0) return false;
  return HEX_UPPER.test(value);
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new RangeError('hex string has odd length');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new RangeError('hex string contains a non-hex character');
    out[i] = byte;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).toUpperCase().padStart(2, '0');
  return out;
}

/** ASCII-only encode. Profile A payloads are ASCII by construction. */
export function asciiToBytes(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code > 0x7f) throw new RangeError('input is not ASCII');
    out[i] = code;
  }
  return out;
}

/**
 * Length-independent comparison of two equal-length strings.
 *
 * Used for CRC and digest comparison. Neither is secret, but a constant-time
 * habit costs nothing here and removes a class of future mistake.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
