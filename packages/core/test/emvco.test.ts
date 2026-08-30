import { describe, expect, it } from 'vitest';

import {
  CrcMismatchError,
  DuplicateTagError,
  MalformedTlvError,
} from '../src/errors.js';
import {
  appendCrc,
  crc16CcittFalse,
  parseDataObjects,
  parseEmvcoPayload,
  serialiseDataObject,
  stripCrc,
} from '../src/emvco.js';

describe('CRC-16/CCITT-FALSE', () => {
  // The check value every CRC catalogue publishes for this parameterisation.
  it('produces 29B1 for "123456789"', () => {
    expect(crc16CcittFalse('123456789')).toBe('29B1');
  });

  it('produces FFFF for the empty string', () => {
    expect(crc16CcittFalse('')).toBe('FFFF');
  });

  it('reproduces the published reference payload CRC', () => {
    const upToCrcHeader =
      '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM ' +
      'PENH85200000201011627403764C95F4F5B0205ES25603101756512000041017565120600501M991288D060DF7D9848BAA71' +
      '69DF7946242B491306E1EEBD17AC8367F0D5DA1693990D1CEB7A018D96CBAFEC1744F8A4A2B9B83374297CAF8F8C68E5DDAE' +
      'C3BB8F08DC6304';
    expect(crc16CcittFalse(upToCrcHeader)).toBe('CB0C');
  });
});

describe('TLV', () => {
  it('parses a flat payload', () => {
    const objects = parseDataObjects('000201010211');
    expect(objects.map((o) => [o.tag, o.value])).toEqual([['00', '01'], ['01', '11']]);
  });

  it('rejects a duplicate tag at the same level', () => {
    expect(() => parseDataObjects('000201000201')).toThrow(DuplicateTagError);
  });

  it('rejects a length running past the end', () => {
    expect(() => parseDataObjects('0099AB')).toThrow(MalformedTlvError);
  });

  it('rejects a trailing fragment too short to be a data object', () => {
    expect(() => parseDataObjects('00020112')).toThrow(MalformedTlvError);
  });

  it('refuses to serialise a value above the two-digit length maximum', () => {
    expect(() => serialiseDataObject('59', 'x'.repeat(100))).toThrow(RangeError);
  });

  it('appends and strips a CRC symmetrically', () => {
    const base = '00020101021130310011abaakhppxxx0112855012345678';
    const withCrc = appendCrc(base);
    expect(withCrc).toHaveLength(base.length + 8);
    expect(stripCrc(withCrc)).toBe(base);
    expect(() => parseEmvcoPayload(withCrc)).not.toThrow();
  });

  it('detects a corrupted CRC', () => {
    const withCrc = appendCrc('00020101021130310011abaakhppxxx0112855012345678');
    const broken = withCrc.slice(0, -1) + (withCrc.endsWith('0') ? '1' : '0');
    expect(() => parseEmvcoPayload(broken)).toThrow(CrcMismatchError);
  });
});
