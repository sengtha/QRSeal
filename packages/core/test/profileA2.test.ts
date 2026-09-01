/**
 * Profile A v2 exists to make one claim true that v1 could not make: a strict
 * EMVCo parser can walk the payload. These tests assert that claim directly by
 * parsing with a two-digit-only walker, rather than trusting the encoder.
 */

import { describe, expect, it } from 'vitest';

import { keyPairFromScalar } from '../../../tools/keys.ts';
import { appendCrc, parseDataObjects, stripCrc, crc16CcittFalse } from '../src/emvco.js';
import {
  V2_FORMAT_VERSION,
  V2_GUID,
  V2_META_TAG,
  V2_SIGNATURE_PART_LENGTH,
  V2_SIG_HI_TAG,
  V2_SIG_LO_TAG,
  signProfileA2,
  verifyProfileA2,
} from '../src/profileA2.js';
import { anchorFor, suite } from './support/anchors.js';

const STATIC_BASE =
  '00020101021130310011abaakhppxxx01128550123456785204581253031165802KH5908SOK DARA6010PHNOM PENH';
const DYNAMIC_BASE =
  '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM PENH';

const published = suite.cases.find((c) => c.id === 'A-accept-published-reference')!;

async function signer() {
  return keyPairFromScalar(suite.keys['issuer']!.scalar);
}

async function signDynamic() {
  const key = await signer();
  return signProfileA2({
    payload: DYNAMIC_BASE,
    privateKey: key.privateKey,
    kid: key.kid,
    issuedAt: suite.time.issuedAt,
    expiresAt: suite.time.expiresAt,
    payeeClass: 'M',
  });
}

const verifyOptions = async () => ({
  trustAnchor: await anchorFor(published.state),
  now: suite.time.nowValid,
});

describe('v2 is walkable by a strict EMVCo parser', () => {
  it('uses two-digit lengths everywhere, so a legacy walk tiles the payload', async () => {
    const signed = await signDynamic();

    // The whole point: parse with no extended-length exemptions at all. This is
    // what a wallet implementing EMVCo 1.1 and nothing else would do.
    const objects = parseDataObjects(stripCrc(signed.payload), {
      extendedLengthTags: new Set(),
    });

    expect(objects.every((o) => o.lengthDigits === 2)).toBe(true);
    expect(objects.every((o) => o.value.length <= 99)).toBe(true);
    // Tiling exactly is what parseDataObjects enforces; assert the tail so a
    // silent re-ordering cannot pass.
    expect(objects.slice(-3).map((o) => o.tag)).toEqual([V2_META_TAG, V2_SIG_HI_TAG, V2_SIG_LO_TAG]);
  });

  it('keeps the CRC reachable, which is what v1 loses', async () => {
    const signed = await signDynamic();
    const body = signed.payload.slice(0, -4);
    expect(signed.payload.slice(-4)).toBe(crc16CcittFalse(body));

    // A legacy parser that misaligns cannot find tag 63 at the end. Here it can.
    const withCrc = parseDataObjects(signed.payload, { extendedLengthTags: new Set() });
    expect(withCrc.at(-1)!.tag).toBe('63');
    expect(withCrc.at(-1)!.value).toHaveLength(4);
  });

  it('carries a GUID at sub-tag 00 of every unreserved template', async () => {
    const signed = await signDynamic();
    const objects = parseDataObjects(stripCrc(signed.payload), { extendedLengthTags: new Set() });
    for (const tag of [V2_META_TAG, V2_SIG_HI_TAG, V2_SIG_LO_TAG]) {
      const template = objects.find((o) => o.tag === tag)!;
      const subtags = parseDataObjects(template.value, { extendedLengthTags: new Set() });
      expect(subtags[0]!.tag).toBe('00');
      expect(subtags[0]!.value).toBe(V2_GUID);
    }
  });
});

describe('v2 signing and verification', () => {
  it('round-trips a dynamic code and reports the encoding version', async () => {
    const signed = await signDynamic();
    const result = await verifyProfileA2({ payload: signed.payload, ...(await verifyOptions()) });
    expect(result.encodingVersion).toBe(2);
    expect(result.formatVersion).toBe(V2_FORMAT_VERSION);
    expect(result.codeKind).toBe('dynamic');
    expect(result.lengthEncoding).toBe('emvco-two-digit');
  });

  it('round-trips a static code', async () => {
    const key = await signer();
    const signed = await signProfileA2({
      payload: STATIC_BASE,
      privateKey: key.privateKey,
      kid: key.kid,
      issuedAt: suite.time.issuedAt,
      payeeClass: 'M',
    });
    const result = await verifyProfileA2({ payload: signed.payload, ...(await verifyOptions()) });
    expect(result.codeKind).toBe('static');
    expect(result.expiresAt).toBeNull();
  });

  it('recovers the signed region by substring, not by re-serialising', async () => {
    const signed = await signDynamic();
    const result = await verifyProfileA2({ payload: signed.payload, ...(await verifyOptions()) });
    expect(signed.payload.slice(0, result.signedThrough)).toBe(signed.signingInput);
    // The prefix ends where template 86 begins, and template 85 is inside it.
    expect(signed.signingInput.includes(`${V2_META_TAG}`)).toBe(true);
    expect(signed.signingInput.includes(V2_SIG_HI_TAG + '8')).toBe(false);
  });

  it('splits the signature into two halves that recombine exactly', async () => {
    const signed = await signDynamic();
    expect(signed.signature).toHaveLength(V2_SIGNATURE_PART_LENGTH * 2);
    const objects = parseDataObjects(stripCrc(signed.payload), { extendedLengthTags: new Set() });
    const half = (tag: string) => {
      const t = objects.find((o) => o.tag === tag)!;
      return parseDataObjects(t.value, { extendedLengthTags: new Set() }).find((o) => o.tag === '01')!.value;
    };
    expect(half(V2_SIG_HI_TAG) + half(V2_SIG_LO_TAG)).toBe(signed.signature);
    expect(half(V2_SIG_HI_TAG)).toHaveLength(V2_SIGNATURE_PART_LENGTH);
  });

  it('surfaces the payee rather than returning a verdict', async () => {
    const signed = await signDynamic();
    const result = await verifyProfileA2({ payload: signed.payload, ...(await verifyOptions()) });
    expect(result.payeeDisclosure.merchantName).toBe('SOK DARA');
    expect(result.payeeDisclosure.currencyAlpha).toBe('KHR');
    for (const [key, value] of Object.entries(result)) {
      expect(typeof value, `${key} must not be a boolean`).not.toBe('boolean');
    }
  });
});

describe('v2 rejects what v1 rejects', () => {
  const tamper = async (mutate: (payload: string) => string) => {
    const signed = await signDynamic();
    return appendCrc(mutate(stripCrc(signed.payload)));
  };

  it('rejects a mutation inside the signed region', async () => {
    const payload = await tamper((b) => b.replace('SOK DARA', 'SOK DARB'));
    await expect(verifyProfileA2({ payload, ...(await verifyOptions()) })).rejects.toThrow();
  });

  it('rejects a mutation inside the signature', async () => {
    const signed = await signDynamic();
    const body = stripCrc(signed.payload);
    const flipped = body.slice(0, -1) + (body.endsWith('0') ? '1' : '0');
    const payload = appendCrc(flipped);
    await expect(verifyProfileA2({ payload, ...(await verifyOptions()) })).rejects.toThrow();
  });

  it('rejects data appended after the signature templates', async () => {
    // The tail-order rule is what stops an attacker extending the payload
    // while leaving the signed prefix byte-identical.
    const payload = await tamper((b) => b + '6204ABCD');
    await expect(verifyProfileA2({ payload, ...(await verifyOptions()) })).rejects.toThrow(
      /final three data objects/,
    );
  });

  it('rejects a foreign GUID', async () => {
    const payload = await tamper((b) => b.replace(V2_GUID, 'XX.XXX.XXX.XXX'));
    await expect(verifyProfileA2({ payload, ...(await verifyOptions()) })).rejects.toThrow(/GUID/);
  });

  it('refuses to sign a static code carrying an amount', async () => {
    const key = await signer();
    await expect(
      signProfileA2({
        payload: STATIC_BASE.replace('5802KH', '540525005802KH'),
        privateKey: key.privateKey,
        kid: key.kid,
        issuedAt: suite.time.issuedAt,
        payeeClass: 'M',
      }),
    ).rejects.toThrow();
  });

  it('refuses to sign a dynamic code with no expiry', async () => {
    const key = await signer();
    await expect(
      signProfileA2({
        payload: DYNAMIC_BASE,
        privateKey: key.privateKey,
        kid: key.kid,
        issuedAt: suite.time.issuedAt,
        payeeClass: 'M',
      }),
    ).rejects.toThrow();
  });
});
