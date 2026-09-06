import { describe, expect, it } from 'vitest';

import {
  MAX_TRUSTLIST_CACHE_AGE_SECONDS,
  RevocationsMalformedError,
  RevocationsRollbackError,
  RevocationsSignatureInvalidError,
  RevocationsStaleError,
  TrustAnchor,
  TrustlistRollbackError,
  TrustlistStaleError,
  revocationEntryId,
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

describe('revocation lists', () => {
  const withList = { ...base, revocations: 'current' };
  const issuer = 'kh.gov.mptc.moeys';
  const listed = async () => revocationEntryId(issuer, 'RUPP-2026-000099');
  const unlisted = async () => revocationEntryId(issuer, 'RUPP-2026-004821');

  it('reports a listed credential as revoked and an unlisted one as clear', async () => {
    const anchor = await anchorFor(withList);
    expect(anchor.revocationStatus(issuer, await listed())).toMatchObject({ state: 'revoked', reason: 'withdrawn', listVersion: 1 });
    expect(anchor.revocationStatus(issuer, await unlisted())).toMatchObject({ state: 'clear', listVersion: 1 });
  });

  it('reports withheld when the timestamp declares a list the anchor was not given', async () => {
    const anchor = await anchorFor(base);
    expect(anchor.revocationStatus(issuer, await unlisted())).toMatchObject({ state: 'withheld', declaredVersion: 1 });
  });

  it('reports unchecked for an issuer no list is declared for', async () => {
    const anchor = await anchorFor(withList);
    expect(anchor.revocationStatus('kh.edu.someone-else', await unlisted())).toEqual({ state: 'unchecked' });
  });

  it('binds the entry identifier to the issuer', async () => {
    expect(await revocationEntryId(issuer, 'X')).not.toBe(await revocationEntryId('kh.edu.other', 'X'));
    expect(await revocationEntryId(issuer, 'X')).toMatch(/^[0-9A-F]{64}$/);
  });

  it('refuses a list signed by a key not registered to its issuer', async () => {
    await expect(anchorFor({ ...base, revocations: 'forged' })).rejects.toThrow(RevocationsSignatureInvalidError);
  });

  it('refuses a list below the version already held', async () => {
    await expect(
      TrustAnchor.open({
        trustList: suite.trustLists['current'],
        timestamp: suite.timestamps['farFuture'],
        rootKeys: suite.pinned.rootKeys,
        timestampKeys: suite.pinned.timestampKeys,
        now: suite.time.nowValid,
        revocations: suite.revocations['current'],
        heldRevocationVersions: { [issuer]: 2 },
      }),
    ).rejects.toThrow(RevocationsRollbackError);
  });

  it('refuses a list older than the cache limit, under a freshly fetched trust list', async () => {
    const now = suite.time.issuedAt + MAX_TRUSTLIST_CACHE_AGE_SECONDS + 1;
    await expect(anchorFor({ ...withList, now, fetchedAt: now })).rejects.toThrow(RevocationsStaleError);
  });

  it('refuses two lists for the same issuer', async () => {
    const list = suite.revocations['current']![0];
    await expect(anchorFor({ ...base, revocations: 'current' }).then(() =>
      TrustAnchor.open({
        trustList: suite.trustLists['current'],
        timestamp: suite.timestamps['farFuture'],
        rootKeys: suite.pinned.rootKeys,
        timestampKeys: suite.pinned.timestampKeys,
        now: suite.time.nowValid,
        revocations: [list, list],
      }),
    )).rejects.toThrow(RevocationsMalformedError);
  });
});
