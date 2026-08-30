import { applyD1Migrations, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import worker, {
  DEFAULT_RESTRICTED_TTL_SECONDS,
  INSTITUTION_ANOMALY_THRESHOLD,
  type Env,
} from '../src/index.js';
import { shardFor, type StatusReading } from '../src/shard.js';

const typed = env as unknown as Env & { TEST_MIGRATIONS: D1Migration[] };

const ALICE = 'AA'.repeat(32); // officer, ABAAKHPP
const BORA = 'BB'.repeat(32); // officer, ABAAKHPP
const SUPERVISOR = 'CC'.repeat(32); // supervisor, ABAAKHPP
const OTHER_BANK = 'DD'.repeat(32); // officer, ACLBKHPP
const READER = 'EE'.repeat(32); // reader, NBC

const ACCOUNT = 'KH-855012345678';

interface CallOptions {
  readonly method?: string;
  readonly body?: unknown;
  readonly fingerprint?: string;
}

async function call(path: string, options: CallOptions = {}): Promise<Response> {
  const init: RequestInit & { cf?: unknown } = { method: options.method ?? 'GET' };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
    init.headers = { 'content-type': 'application/json' };
  }
  if (options.fingerprint !== undefined) {
    init.cf = {
      tlsClientAuth: { certVerified: 'SUCCESS', certFingerprintSHA256: options.fingerprint, certSubjectDN: 'CN=o' },
    };
  }
  const request = new Request(`https://risklist.example.kh${path}`, init as RequestInit);
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, typed, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

const statusOf = async (account = ACCOUNT, who = READER): Promise<StatusReading> =>
  (await call(`/accounts/${account}/status`, { fingerprint: who })).json<StatusReading>();

beforeAll(async () => {
  await applyD1Migrations(typed.DB, typed.TEST_MIGRATIONS);
});

beforeEach(async () => {
  await typed.DB.exec('DELETE FROM officers');
  await typed.DB.exec('DELETE FROM proposals');
  await typed.DB.exec('DELETE FROM write_rate');
  await typed.DB.batch([
    typed.DB.prepare("INSERT INTO officers VALUES (?, 'ABAAKHPP', 'alice', 'officer', 1, 1756512000)").bind(ALICE),
    typed.DB.prepare("INSERT INTO officers VALUES (?, 'ABAAKHPP', 'bora', 'officer', 1, 1756512000)").bind(BORA),
    typed.DB.prepare("INSERT INTO officers VALUES (?, 'ABAAKHPP', 'chan', 'supervisor', 1, 1756512000)").bind(SUPERVISOR),
    typed.DB.prepare("INSERT INTO officers VALUES (?, 'ACLBKHPP', 'dara', 'officer', 1, 1756512000)").bind(OTHER_BANK),
    typed.DB.prepare("INSERT INTO officers VALUES (?, 'NBC', 'reader', 'reader', 1, 1756512000)").bind(READER),
  ]);
});

describe('service posture', () => {
  it('states that it does not use KV and does not sweep', async () => {
    const body = await (await call('/health')).json<{ consistency: string; expiry: string }>();
    expect(body.consistency).toMatch(/not KV/);
    expect(body.expiry).toMatch(/no sweep/);
  });
});

describe('sharding', () => {
  it('spreads accounts across shards rather than following bank numbering', async () => {
    const shards = new Set<string>();
    for (let i = 0; i < 200; i += 1) shards.add(await shardFor(`KH-85501234${String(i).padStart(4, '0')}`));
    expect(shards.size).toBeGreaterThan(80);
  });

  it('is stable for the same account', async () => {
    expect(await shardFor(ACCOUNT)).toBe(await shardFor(ACCOUNT));
  });
});

describe('restriction: one officer, immediate', () => {
  it('takes effect at once and is visible to the next read', async () => {
    const response = await call('/listings', {
      method: 'POST',
      body: { account: ACCOUNT, status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: ALICE,
    });
    expect(response.status).toBe(201);
    const body = await response.json<{ applied: boolean; requiresSecondOfficer: boolean }>();
    expect(body).toMatchObject({ applied: true, requiresSecondOfficer: false });

    const status = await statusOf();
    expect(status.status).toBe('restricted');
    expect(status.reasonCode).toBe('MULE_SUSPECTED');
    expect(status.institution).toBe('ABAAKHPP');
  });

  it('carries a default deadline of 72 hours', async () => {
    await call('/listings', {
      method: 'POST',
      body: { account: ACCOUNT, status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: ALICE,
    });
    const status = await statusOf();
    const ttl = (status.expiresAt as number) - (status.listedAt as number);
    expect(ttl).toBe(DEFAULT_RESTRICTED_TTL_SECONDS);
  });

  it('refuses a ttl beyond the maximum rather than truncating it', async () => {
    const response = await call('/listings', {
      method: 'POST',
      body: { account: ACCOUNT, status: 'restricted', reasonCode: 'MULE_SUSPECTED', ttlSeconds: 400 * 86400 },
      fingerprint: ALICE,
    });
    expect(response.status).toBe(400);
    expect((await response.json<{ code: string }>()).code).toBe('TTL_TOO_LONG');
  });
});

describe('expiry is evaluated at read time', () => {
  it('reports a lapsed restriction as clear, and says what lapsed', async () => {
    const account = 'KH-EXPIRY-CASE';
    await call('/listings', {
      method: 'POST',
      body: { account, status: 'restricted', reasonCode: 'MULE_SUSPECTED', ttlSeconds: 60 },
      fingerprint: ALICE,
    });
    expect((await statusOf(account)).status).toBe('restricted');

    // Move the stored deadline into the past. No sweep runs; the next read
    // simply compares the deadline against the clock.
    await typed.DB.prepare('UPDATE account_status SET expires_at = 1 WHERE account = ?').bind(account).run();
    const shard = typed.SHARDS.get(typed.SHARDS.idFromName(await shardFor(account)));
    await shard.applyStatus(
      {
        account,
        status: 'restricted',
        reasonCode: 'MULE_SUSPECTED',
        listedBy: 'alice',
        institution: 'ABAAKHPP',
        listedAt: 1,
        expiresAt: 2,
      },
      3,
    );

    const status = await statusOf(account);
    expect(status.status).toBe('clear');
    expect(status.lapsedFrom).toBe('restricted');
  });
});

describe('blocking: two officers', () => {
  async function proposeBlock(who = ALICE): Promise<string> {
    const response = await call('/listings', {
      method: 'POST',
      body: { account: ACCOUNT, status: 'blocked', reasonCode: 'CONFIRMED_FRAUD' },
      fingerprint: who,
    });
    expect(response.status).toBe(202);
    return (await response.json<{ proposalId: string }>()).proposalId;
  }

  it('does not take effect on one signature', async () => {
    await proposeBlock();
    expect((await statusOf()).status).not.toBe('blocked');
  });

  it('refuses approval by the proposing officer', async () => {
    const id = await proposeBlock();
    const response = await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: ALICE });
    expect(response.status).toBe(409);
    expect((await response.json<{ code: string }>()).code).toBe('SECOND_OFFICER_REQUIRED');
  });

  it('refuses approval from another institution', async () => {
    const id = await proposeBlock();
    expect((await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: OTHER_BANK })).status).toBe(403);
  });

  it('applies on a second officer and records both names', async () => {
    const id = await proposeBlock();
    const response = await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: BORA });
    expect(response.status).toBe(200);
    expect((await statusOf()).status).toBe('blocked');

    const { results } = await typed.DB.prepare(
      "SELECT actor, action FROM audit_log WHERE subject = ? ORDER BY seq ASC",
    )
      .bind(ACCOUNT)
      .all<{ actor: string; action: string }>();
    const actions = results.map((r) => `${r.actor}:${r.action}`);
    expect(actions).toContain('alice:proposal.list.blocked');
    expect(actions).toContain('bora:status.blocked');
  });

  it('refuses to approve twice', async () => {
    const id = await proposeBlock();
    expect((await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: BORA })).status).toBe(200);
    expect((await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: SUPERVISOR })).status).toBe(409);
  });
});

describe('removal: two officers, in both directions', () => {
  it('needs a second officer to clear a listing', async () => {
    const account = 'KH-REMOVAL-CASE';
    await call('/listings', {
      method: 'POST',
      body: { account, status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: ALICE,
    });
    const proposal = await call('/removals', {
      method: 'POST',
      body: { account, reasonCode: 'INVESTIGATION_CLOSED' },
      fingerprint: ALICE,
    });
    expect(proposal.status).toBe(202);
    const id = (await proposal.json<{ proposalId: string }>()).proposalId;

    expect((await statusOf(account)).status).toBe('restricted');
    expect((await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: ALICE })).status).toBe(409);
    expect((await call(`/proposals/${id}/approve`, { method: 'POST', fingerprint: BORA })).status).toBe(200);
    expect((await statusOf(account)).status).toBe('clear');
  });
});

describe('authorisation', () => {
  it('lets a reader read but not write', async () => {
    expect((await call(`/accounts/${ACCOUNT}/status`, { fingerprint: READER })).status).toBe(200);
    const response = await call('/listings', {
      method: 'POST',
      body: { account: ACCOUNT, status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: READER,
    });
    expect(response.status).toBe(403);
  });

  it('requires a certificate at all', async () => {
    expect((await call(`/accounts/${ACCOUNT}/status`)).status).toBe(401);
  });

  it('restricts the audit export to a supervisor', async () => {
    expect((await call('/audit/export', { fingerprint: ALICE })).status).toBe(403);
    expect((await call('/audit/export', { fingerprint: SUPERVISOR })).status).toBe(200);
  });
});

describe('rate limiting', () => {
  it('refuses and flags an institution listing implausibly many accounts', async () => {
    const windowStart = Math.floor(Date.now() / 1000 / 3600) * 3600;
    await typed.DB.prepare('INSERT INTO write_rate VALUES (?, ?, ?, ?)')
      .bind('institution', 'ABAAKHPP', windowStart, INSTITUTION_ANOMALY_THRESHOLD - 1)
      .run();

    const response = await call('/listings', {
      method: 'POST',
      body: { account: 'KH-FLOOD-0001', status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: ALICE,
    });
    expect(response.status).toBe(429);
    expect((await response.json<{ code: string }>()).code).toBe('INSTITUTION_VOLUME_ANOMALY');

    const flagged = await typed.DB.prepare(
      "SELECT action FROM audit_log WHERE action = 'ratelimit.anomaly' ORDER BY seq DESC LIMIT 1",
    ).first<{ action: string }>();
    expect(flagged?.action).toBe('ratelimit.anomaly');
  });
});

describe('delta feed', () => {
  it('returns changes after a cursor and reports when it is caught up', async () => {
    const before = await (await call('/delta?since=0&limit=1000', { fingerprint: READER })).json<{ cursor: number }>();
    await call('/listings', {
      method: 'POST',
      body: { account: 'KH-DELTA-0001', status: 'restricted', reasonCode: 'MULE_SUSPECTED' },
      fingerprint: ALICE,
    });
    const after = await (
      await call(`/delta?since=${before.cursor}&limit=1000`, { fingerprint: READER })
    ).json<{ changes: { account: string }[]; complete: boolean }>();
    expect(after.changes.map((c) => c.account)).toContain('KH-DELTA-0001');
    expect(after.complete).toBe(true);
  });
});

describe('append-only history', () => {
  it('refuses UPDATE and DELETE on the change feed and the audit log', async () => {
    await expect(typed.DB.prepare("UPDATE status_changes SET status = 'clear'").run()).rejects.toThrow(/append-only/);
    await expect(typed.DB.prepare('DELETE FROM status_changes').run()).rejects.toThrow(/append-only/);
    await expect(typed.DB.prepare('DELETE FROM audit_log').run()).rejects.toThrow(/append-only/);
  });
});
