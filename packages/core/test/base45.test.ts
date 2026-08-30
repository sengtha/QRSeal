import { describe, expect, it } from 'vitest';

import { decodeBase45, encodeBase45 } from '../src/base45.js';
import { Base45InvalidError } from '../src/errors.js';

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

describe('base45 (RFC 9285)', () => {
  // The four examples given in RFC 9285 sections 4.3 and 4.4.
  it.each([
    ['AB', 'BB8'],
    ['Hello!!', '%69 VD92EX0'],
    ['base-45', 'UJCLQE7W581'],
    ['ietf!', 'QED8WEX0'],
  ])('encodes %o as %o', (plain, encoded) => {
    expect(encodeBase45(utf8(plain))).toBe(encoded);
    expect(new TextDecoder().decode(decodeBase45(encoded))).toBe(plain);
  });

  it('round-trips every byte length up to 64', () => {
    for (let length = 0; length <= 64; length += 1) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff);
      expect(decodeBase45(encodeBase45(bytes))).toEqual(bytes);
    }
  });

  it('rejects a length that encodes no whole byte', () => {
    expect(() => decodeBase45('AAAA')).toThrow(Base45InvalidError);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => decodeBase45('ab8')).toThrow(Base45InvalidError);
  });

  it('rejects a triple encoding a value above 0xFFFF', () => {
    // 'GGW' decodes to 16 + 16*45 + 32*2025 = 65536.
    expect(() => decodeBase45('GGW')).toThrow(Base45InvalidError);
  });

  it('rejects a final pair encoding a value above 0xFF', () => {
    expect(() => decodeBase45('BB8:8')).toThrow(Base45InvalidError);
  });
});
