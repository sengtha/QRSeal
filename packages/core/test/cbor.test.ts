/**
 * The CBOR codec is hand-written to keep the audit surface small, so it is
 * differentially fuzzed against a reference implementation rather than trusted.
 */

import { decode as referenceDecode, encode as referenceEncode } from 'cbor2';
import { describe, expect, it } from 'vitest';

import { decodeCbor, encodeCbor, type CborValue } from '../src/cbor.js';
import { CborInvalidError } from '../src/errors.js';

/** Deterministic xorshift, so a failure is reproducible from its seed. */
function rng(seed: number): () => number {
  let state = seed | 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 0x1_0000_0000;
  };
}

function randomValue(next: () => number, depth: number): CborValue {
  const choice = Math.floor(next() * (depth > 2 ? 4 : 6));
  switch (choice) {
    case 0: return Math.floor(next() * 2 ** 32) - 2 ** 31;
    case 1: return Array.from({ length: Math.floor(next() * 12) }, () =>
      String.fromCharCode(32 + Math.floor(next() * 90))).join('');
    case 2: return Uint8Array.from({ length: Math.floor(next() * 20) }, () => Math.floor(next() * 256));
    case 3: return Math.floor(next() * Number.MAX_SAFE_INTEGER);
    case 4: return Array.from({ length: Math.floor(next() * 4) }, () => randomValue(next, depth + 1));
    default: {
      const map = new Map<number | string, CborValue>();
      const size = Math.floor(next() * 5);
      for (let i = 0; i < size; i += 1) {
        map.set(next() < 0.5 ? i : `k${i}`, randomValue(next, depth + 1));
      }
      return map;
    }
  }
}

/** cbor2 returns plain objects for text-keyed maps; normalise for comparison. */
function normalise(value: unknown): unknown {
  if (value instanceof Uint8Array) return ['bytes', [...value]];
  if (Array.isArray(value)) return value.map(normalise);
  if (value instanceof Map) {
    return ['map', [...value.entries()].map(([k, v]) => [k, normalise(v)]).sort((a, b) => String(a[0]).localeCompare(String(b[0])))];
  }
  if (typeof value === 'object' && value !== null) {
    return ['map', Object.entries(value).map(([k, v]) => [k, normalise(v)]).sort((a, b) => String(a[0]).localeCompare(String(b[0])))];
  }
  if (typeof value === 'bigint') return Number(value);
  return value;
}

describe('CBOR codec', () => {
  it('encodes what the reference implementation decodes, over 500 random values', () => {
    const next = rng(0x5eed);
    for (let i = 0; i < 500; i += 1) {
      const value = randomValue(next, 0);
      const ours = encodeCbor(value);
      expect(normalise(referenceDecode(ours)), `seed case ${i}`).toEqual(normalise(value));
    }
  });

  it('decodes what the reference implementation encodes, over 500 random values', () => {
    const next = rng(0xd1ce);
    for (let i = 0; i < 500; i += 1) {
      const value = randomValue(next, 0);
      const theirs = referenceEncode(value);
      expect(normalise(decodeCbor(theirs)), `seed case ${i}`).toEqual(normalise(value));
    }
  });

  it('round-trips through itself', () => {
    const next = rng(0xfeed);
    for (let i = 0; i < 500; i += 1) {
      const value = randomValue(next, 0);
      expect(normalise(decodeCbor(encodeCbor(value)))).toEqual(normalise(value));
    }
  });

  describe('strictness', () => {
    it('rejects indefinite-length items', () => {
      expect(() => decodeCbor(Uint8Array.from([0x5f, 0x41, 0x61, 0xff]))).toThrow(CborInvalidError);
    });

    it('rejects non-minimal integer encodings', () => {
      expect(() => decodeCbor(Uint8Array.from([0x18, 0x01]))).toThrow(CborInvalidError);
      expect(() => decodeCbor(Uint8Array.from([0x19, 0x00, 0x01]))).toThrow(CborInvalidError);
    });

    it('rejects floating point and simple values', () => {
      expect(() => decodeCbor(Uint8Array.from([0xfb, 0, 0, 0, 0, 0, 0, 0, 0]))).toThrow(CborInvalidError);
      expect(() => decodeCbor(Uint8Array.from([0xf6]))).toThrow(CborInvalidError);
    });

    it('rejects trailing bytes after the top-level item', () => {
      expect(() => decodeCbor(Uint8Array.from([0x01, 0x01]))).toThrow(CborInvalidError);
    });

    it('rejects duplicate map keys', () => {
      expect(() => decodeCbor(Uint8Array.from([0xa2, 0x01, 0x01, 0x01, 0x02]))).toThrow(CborInvalidError);
    });

    it('rejects truncated input', () => {
      expect(() => decodeCbor(Uint8Array.from([0x42, 0x01]))).toThrow(CborInvalidError);
    });

    it('rejects text that is not well-formed UTF-8', () => {
      expect(() => decodeCbor(Uint8Array.from([0x62, 0xc3, 0x28]))).toThrow(CborInvalidError);
    });
  });
});
