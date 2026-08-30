/**
 * Base45 as specified in RFC 9285.
 *
 * Chosen for the same reason the EU Digital COVID Certificate chose it: its
 * alphabet is exactly the QR alphanumeric character set, so a base45 payload
 * encodes in alphanumeric mode rather than byte mode and the symbol stays
 * smaller despite base45's worse expansion ratio.
 */

import { Base45InvalidError } from './errors.js';

/** RFC 9285 table 1. Order is normative. */
export const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:';

const DECODE_TABLE: ReadonlyMap<string, number> = new Map(
  [...ALPHABET].map((char, index) => [char, index] as const),
);

export function encodeBase45(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 1 < bytes.length; i += 2) {
    let value = (bytes[i] as number) * 256 + (bytes[i + 1] as number);
    const e = Math.floor(value / (45 * 45));
    value -= e * 45 * 45;
    const d = Math.floor(value / 45);
    const c = value - d * 45;
    out += (ALPHABET[c] as string) + (ALPHABET[d] as string) + (ALPHABET[e] as string);
  }
  if (i < bytes.length) {
    const value = bytes[i] as number;
    const d = Math.floor(value / 45);
    out += (ALPHABET[value - d * 45] as string) + (ALPHABET[d] as string);
  }
  return out;
}

export function decodeBase45(text: string): Uint8Array {
  const remainder = text.length % 3;
  if (remainder === 1) throw new Base45InvalidError('length modulo 3 is 1, which encodes no whole byte');

  const values = new Array<number>(text.length);
  for (let i = 0; i < text.length; i += 1) {
    const value = DECODE_TABLE.get(text[i] as string);
    if (value === undefined) throw new Base45InvalidError('input contains a character outside the base45 alphabet');
    values[i] = value;
  }

  const out = new Uint8Array(Math.floor(text.length / 3) * 2 + (remainder === 2 ? 1 : 0));
  let o = 0;
  let i = 0;
  for (; i + 2 < values.length; i += 3) {
    const n = (values[i] as number) + (values[i + 1] as number) * 45 + (values[i + 2] as number) * 45 * 45;
    // RFC 9285 section 4: a triple must encode a value representable in 16 bits.
    if (n > 0xffff) throw new Base45InvalidError('a character triple encodes a value above 0xFFFF');
    out[o++] = n >>> 8;
    out[o++] = n & 0xff;
  }
  if (remainder === 2) {
    const n = (values[i] as number) + (values[i + 1] as number) * 45;
    if (n > 0xff) throw new Base45InvalidError('the final character pair encodes a value above 0xFF');
    out[o++] = n;
  }
  return out;
}
