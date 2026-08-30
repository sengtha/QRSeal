import { describe, expect, it } from 'vitest';

import {
  MAX_TRUSTLIST_CACHE_AGE_SECONDS,
  TrustAnchor,
  TrustlistRollbackError,
  TrustlistStaleError,
} from '../src/index.js';
import { anchorFor, suite } from './support/anchors.js';

const base = { trustList: 'current', timestamp: 'farFuture' as string | null, now: suite.time.nowValid };

describe('trust list version monotonicity', () => {
  it('accepts a list at the version held', async () => {
    await expect(anchorFor({ ...base, heldVersion: 7 })).resolves.toBeInstanceOf(TrustAnchor);
  });

  it('accepts a list above the version held', async () => {
    await expect(anchorFor({ ...base, heldVersion: 6 })).resolves.toBeInstanceOf(TrustAnchor);
  });

  it('rejects a list below the version held', async () => {
    await expect(
      anchorFor({ trustList: 'rolledBack', timestamp: 'rolledBack', now: suite.time.nowValid, heldVersion: 7 }),
    ).rejects.toThrow(TrustlistRollbackError);
  });
});

describe('cache staleness', () => {
  const fetchedAt = suite.time.issuedAt;

  it('accepts a cache exactly at the 30-day limit', async () => {
    await expect(
      anchorFor({ ...base, now: fetchedAt + MAX_TRUSTLIST_CACHE_AGE_SECONDS, fetchedAt }),
    ).resolves.toBeInstanceOf(TrustAnchor);
  });

  it('rejects a cache one second past the limit', async () => {
    await expect(
      anchorFor({ ...base, now: fetchedAt + MAX_TRUSTLIST_CACHE_AGE_SECONDS + 1, fetchedAt }),
    ).rejects.toThrow(TrustlistStaleError);
  });
});

describe('key resolution', () => {
  it('distinguishes a revoked key from an unknown one', async () => {
    const anchor = await anchorFor(base);
    const revokedKid = suite.keys['revokedIssuer']!.kid;
    await expect(anchor.resolve(revokedKid, 'A', suite.time.nowValid)).rejects.toThrow(/KEY_REVOKED/);
    await expect(anchor.resolve('0000000000000000', 'A', suite.time.nowValid)).rejects.toThrow(/UNKNOWN_KID/);
  });

  it('returns every usable candidate for a key identifier', async () => {
    const anchor = await anchorFor(base);
    const keys = await anchor.resolve(suite.keys['issuer']!.kid, 'A', suite.time.nowValid);
    expect(keys.length).toBeGreaterThanOrEqual(1);
  });
});
