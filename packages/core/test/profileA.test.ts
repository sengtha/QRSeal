import { describe, expect, it } from 'vitest';

import { keyPairFromScalar } from '../../../tools/keys.ts';
import { SIGNATURE_HEADER, signProfileA, verifyProfileA } from '../src/profileA.js';
import { anchorFor, suite } from './support/anchors.js';

const PUBLISHED_SIGNING_INPUT =
  '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM ' +
  'PENH85200000201011627403764C95F4F5B0205ES25603101756512000041017565120600501M99128';

const published = suite.cases.find((c) => c.id === 'A-accept-published-reference')!;
const DYNAMIC_BASE =
  '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM PENH';

describe('Profile A signing input', () => {
  it('is 181 characters and ends with the five characters 99128', () => {
    expect(PUBLISHED_SIGNING_INPUT).toHaveLength(181);
    expect(PUBLISHED_SIGNING_INPUT.endsWith(SIGNATURE_HEADER)).toBe(true);
  });

  it('is a plain prefix of the complete payload', () => {
    expect(published.input['payload'] as string).toMatch(
      new RegExp(`^${PUBLISHED_SIGNING_INPUT.replace(/[$()*+.?[\\\]^{|}]/g, '\\$&')}`),
    );
  });

  it('is recovered by substring, never by re-serialising parsed fields', async () => {
    const result = await verifyProfileA({
      payload: published.input['payload'] as string,
      trustAnchor: await anchorFor(published.state),
      now: published.state.now,
    });
    const payload = published.input['payload'] as string;
    expect(payload.slice(0, result.signedThrough)).toBe(PUBLISHED_SIGNING_INPUT);
  });
});

describe('Profile A verification result', () => {
  it('discloses the payee rather than returning a verdict', async () => {
    const result = await verifyProfileA({
      payload: published.input['payload'] as string,
      trustAnchor: await anchorFor(published.state),
      now: published.state.now,
    });
    expect(result.payeeDisclosure).toEqual({
      merchantName: 'SOK DARA',
      merchantCity: 'PHNOM PENH',
      countryCode: 'KH',
      amount: '25000',
      currencyCode: '116',
      currencyAlpha: 'KHR',
      payeeClass: 'M',
      accounts: [{ tag: '30', value: '0011abaakhppxxx0112855012345678' }],
    });
    expect((result as unknown as Record<string, unknown>)['isValid']).toBeUndefined();
  });

  it('reports the published payload as having an inconsistent declared template length', async () => {
    const result = await verifyProfileA({
      payload: published.input['payload'] as string,
      trustAnchor: await anchorFor(published.state),
      now: published.state.now,
    });
    expect(result.container).toEqual({
      declaredTemplateLength: 200,
      actualTemplateLength: 201,
      declaredLengthConsistent: false,
    });
  });

  it('emits a self-consistent declared length when signing', async () => {
    const key = await keyPairFromScalar(suite.keys['issuer']!.scalar);
    const signed = await signProfileA({
      payload: DYNAMIC_BASE,
      privateKey: key.privateKey,
      kid: key.kid,
      issuedAt: suite.time.issuedAt,
      expiresAt: suite.time.expiresAt,
      payeeClass: 'M',
    });
    const result = await verifyProfileA({
      payload: signed.payload,
      trustAnchor: await anchorFor(published.state),
      now: suite.time.nowValid,
    });
    expect(result.container.declaredLengthConsistent).toBe(true);
    expect(result.container.declaredTemplateLength).toBe(201);
  });
});

describe('Profile A signatures are randomised', () => {
  it('produces different signatures over the same input, both of which verify', async () => {
    const key = await keyPairFromScalar(suite.keys['issuer']!.scalar);
    const options = {
      payload: DYNAMIC_BASE,
      privateKey: key.privateKey,
      kid: key.kid,
      issuedAt: suite.time.issuedAt,
      expiresAt: suite.time.expiresAt,
      payeeClass: 'M' as const,
    };
    const first = await signProfileA(options);
    const second = await signProfileA(options);
    expect(first.signingInput).toBe(second.signingInput);
    expect(first.signature).not.toBe(second.signature);

    const trustAnchor = await anchorFor(published.state);
    for (const signed of [first, second]) {
      await expect(
        verifyProfileA({ payload: signed.payload, trustAnchor, now: suite.time.nowValid }),
      ).resolves.toBeDefined();
    }
  });
});

describe('currency disclosure', () => {
  const signWithCurrency = async (numeric: string) => {
    // DYNAMIC_BASE carries 5303116. Swap the value in place; the length byte is
    // unchanged because every ISO 4217 numeric code is three digits.
    const base = DYNAMIC_BASE.replace('5303116', `5303${numeric}`);
    expect(base).toContain(`5303${numeric}`);
    const key = await keyPairFromScalar(suite.keys['issuer']!.scalar);
    const signed = await signProfileA({
      payload: base,
      privateKey: key.privateKey,
      kid: key.kid,
      issuedAt: suite.time.issuedAt,
      expiresAt: suite.time.expiresAt,
      payeeClass: 'M' as const,
    });
    return verifyProfileA({
      payload: signed.payload,
      trustAnchor: await anchorFor(published.state),
      now: suite.time.nowValid,
    });
  };

  it('resolves the ISO 4217 numeric code to an alphabetic one', async () => {
    // A payer shown "116" learns nothing, and an amount shown without a
    // currency in a dual-currency economy is worse than nothing: the two live
    // codes differ by roughly four thousand times.
    const khr = await signWithCurrency('116');
    expect(khr.payeeDisclosure.currencyCode).toBe('116');
    expect(khr.payeeDisclosure.currencyAlpha).toBe('KHR');

    const usd = await signWithCurrency('840');
    expect(usd.payeeDisclosure.currencyCode).toBe('840');
    expect(usd.payeeDisclosure.currencyAlpha).toBe('USD');
  });

  it('reports null rather than guessing for a currency it cannot name', async () => {
    // An incomplete mapping must fail closed: a verifier that cannot name the
    // currency has to say so, not imply the local one. 978 is EUR, which this
    // scheme does not carry.
    const eur = await signWithCurrency('978');
    expect(eur.payeeDisclosure.currencyCode).toBe('978');
    expect(eur.payeeDisclosure.currencyAlpha).toBeNull();
  });
});
