import { applyD1Migrations, createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { CHAIN_GENESIS, chainHash, verifyChain, type AuditRow } from '../src/audit.js';
import worker, { type Env } from '../src/index.js';

const typed = env as unknown as Env & { TEST_MIGRATIONS: D1Migration[] };

const SUBMITTER = 'AA'.repeat(32);
const CEREMONY = 'BB'.repeat(32);
const STRANGER = 'CC'.repeat(32);

const CSR_PEM = '-----BEGIN CERTIFICATE REQUEST-----\nMIIBTTCB9AIBADAT\n-----END CERTIFICATE REQUEST-----\n';
const CERT_PEM = '-----BEGIN CERTIFICATE-----\nMIIBTTCB9AIBADAT\n-----END CERTIFICATE-----\n';

interface CallOptions {
  readonly method?: string;
  readonly body?: unknown;
  readonly fingerprint?: string;
  readonly certVerified?: string;
}

async function call(path: string, options: CallOptions = {}): Promise<Response> {
  const init: RequestInit & { cf?: unknown } = { method: options.method ?? 'GET' };
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body);
    init.headers = { 'content-type': 'application/json' };
  }
  if (options.fingerprint !== undefined) {
    init.cf = {
      tlsClientAuth: {
        certVerified: options.certVerified ?? 'SUCCESS',
        certFingerprintSHA256: options.fingerprint,
        certSubjectDN: 'CN=officer',
      },
    };
  }
  const request = new Request(`https://registry.example.kh${path}`, init as RequestInit);
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, typed, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

beforeAll(async () => {
  await applyD1Migrations(typed.DB, typed.TEST_MIGRATIONS);
});

beforeEach(async () => {
  await typed.DB.exec('DELETE FROM csr_queue');
  await typed.DB.exec('DELETE FROM officers');
  await typed.DB.batch([
    typed.DB.prepare(
      "INSERT INTO officers VALUES (?, 'ABAAKHPP', 'sok.dara', 'submitter', 1, 1756512000)",
    ).bind(SUBMITTER),
    typed.DB.prepare(
      "INSERT INTO officers VALUES (?, 'NBC', 'chan.sopheak', 'ceremony', 1, 1756512000)",
    ).bind(CEREMONY),
  ]);
});

describe('authentication', () => {
  it('refuses a request with no client certificate', async () => {
    expect((await call('/csr', { method: 'POST', body: {} })).status).toBe(401);
  });

  it('refuses a certificate that did not verify', async () => {
    const response = await call('/csr', {
      method: 'POST',
      body: {},
      fingerprint: SUBMITTER,
      certVerified: 'FAILED',
    });
    expect(response.status).toBe(401);
  });

  it('refuses an unenrolled certificate', async () => {
    expect((await call('/queue', { fingerprint: STRANGER })).status).toBe(403);
  });

  it('refuses a submitter acting in a ceremony role', async () => {
    expect((await call('/queue', { fingerprint: SUBMITTER })).status).toBe(403);
  });
});

describe('CSR intake', () => {
  it('queues a well-formed CSR and returns its digest', async () => {
    const response = await call('/csr', {
      method: 'POST',
      body: { csrPem: CSR_PEM, profiles: 'A' },
      fingerprint: SUBMITTER,
    });
    expect(response.status).toBe(201);
    const body = await response.json<{ id: string; status: string; csrSha256: string }>();
    expect(body.status).toBe('queued');
    expect(body.csrSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is idempotent for the same CSR', async () => {
    const body = { csrPem: CSR_PEM, profiles: 'A' };
    const first = await (await call('/csr', { method: 'POST', body, fingerprint: SUBMITTER })).json<{ id: string }>();
    const second = await call('/csr', { method: 'POST', body, fingerprint: SUBMITTER });
    expect(second.status).toBe(200);
    expect(await second.json<{ id: string; duplicate: boolean }>()).toEqual({
      id: first.id,
      status: 'queued',
      duplicate: true,
    });
  });

  it('rejects something that is not a CSR', async () => {
    const response = await call('/csr', {
      method: 'POST',
      body: { csrPem: 'not a pem', profiles: 'A' },
      fingerprint: SUBMITTER,
    });
    expect(response.status).toBe(400);
  });

  it('rejects a malformed profile list', async () => {
    const response = await call('/csr', {
      method: 'POST',
      body: { csrPem: CSR_PEM, profiles: 'A,C' },
      fingerprint: SUBMITTER,
    });
    expect(response.status).toBe(400);
  });
});

describe('ceremony decisions', () => {
  async function queueOne(): Promise<string> {
    const response = await call('/csr', {
      method: 'POST',
      body: { csrPem: CSR_PEM, profiles: 'A,B' },
      fingerprint: SUBMITTER,
    });
    return (await response.json<{ id: string }>()).id;
  }

  it('publishes a certificate produced offline', async () => {
    const id = await queueOne();
    const response = await call(`/csr/${id}/decision`, {
      method: 'POST',
      body: { decision: 'issued', certificatePem: CERT_PEM, kid: '27403764C95F4F5B' },
      fingerprint: CEREMONY,
    });
    expect(response.status).toBe(200);
    const body = await response.json<{ certificateKey: string }>();
    expect(body.certificateKey).toBe('certificates/ABAAKHPP/27403764C95F4F5B.pem');
    expect(await (await typed.ARTIFACTS.get(body.certificateKey))?.text()).toBe(CERT_PEM);
  });

  it('refuses to decide the same request twice', async () => {
    const id = await queueOne();
    const decision = {
      method: 'POST',
      body: { decision: 'rejected', note: 'key too short' },
      fingerprint: CEREMONY,
    };
    expect((await call(`/csr/${id}/decision`, decision)).status).toBe(200);
    expect((await call(`/csr/${id}/decision`, decision)).status).toBe(409);
  });

  it('does not let a submitter decide', async () => {
    const id = await queueOne();
    const response = await call(`/csr/${id}/decision`, {
      method: 'POST',
      body: { decision: 'issued', certificatePem: CERT_PEM, kid: '27403764C95F4F5B' },
      fingerprint: SUBMITTER,
    });
    expect(response.status).toBe(403);
  });

  it('hides another institution\'s request from a submitter', async () => {
    const id = await queueOne();
    await typed.DB.prepare("UPDATE csr_queue SET institution_id = 'OTHER' WHERE id = ?").bind(id).run();
    expect((await call(`/csr/${id}`, { fingerprint: SUBMITTER })).status).toBe(404);
    expect((await call(`/csr/${id}`, { fingerprint: CEREMONY })).status).toBe(200);
  });
});

describe('audit log', () => {
  it('names the officer as well as the institution', async () => {
    await call('/csr', { method: 'POST', body: { csrPem: CSR_PEM, profiles: 'A' }, fingerprint: SUBMITTER });
    const row = await typed.DB.prepare('SELECT actor, institution_id, action FROM audit_log ORDER BY seq DESC LIMIT 1')
      .first<{ actor: string; institution_id: string; action: string }>();
    expect(row).toEqual({ actor: 'sok.dara', institution_id: 'ABAAKHPP', action: 'csr.submitted' });
  });

  it('rejects UPDATE and DELETE at the database level', async () => {
    await call('/csr', { method: 'POST', body: { csrPem: CSR_PEM, profiles: 'A' }, fingerprint: SUBMITTER });
    await expect(typed.DB.prepare("UPDATE audit_log SET actor = 'someone else'").run()).rejects.toThrow(
      /append-only/,
    );
    await expect(typed.DB.prepare('DELETE FROM audit_log').run()).rejects.toThrow(/append-only/);
  });

  it('exports a chain that verifies', async () => {
    const id = await (async () => {
      const r = await call('/csr', { method: 'POST', body: { csrPem: CSR_PEM, profiles: 'A' }, fingerprint: SUBMITTER });
      return (await r.json<{ id: string }>()).id;
    })();
    await call(`/csr/${id}/decision`, {
      method: 'POST',
      body: { decision: 'issued', certificatePem: CERT_PEM, kid: '27403764C95F4F5B' },
      fingerprint: CEREMONY,
    });

    const response = await call('/audit/export', { fingerprint: CEREMONY });
    expect(response.headers.get('x-kh-sqr-chain-valid')).toBe('true');
    const rows = (await response.text())
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as AuditRow);
    // The audit log is append-only, so it carries every entry this file has
    // written, not only this test's two.
    expect(rows.length).toBeGreaterThanOrEqual(2);
    expect(rows[0]?.prevHash).toBe(CHAIN_GENESIS);
    expect(rows.slice(-2).map((r) => r.action)).toEqual(['csr.submitted', 'csr.issued']);
    await expect(verifyChain(rows)).resolves.toEqual({ ok: true, brokenAt: null });
  });

  it('detects an altered entry in an export', async () => {
    await call('/csr', { method: 'POST', body: { csrPem: CSR_PEM, profiles: 'A' }, fingerprint: SUBMITTER });
    const response = await call('/audit/export', { fingerprint: CEREMONY });
    const rows = (await response.text())
      .split('\n')
      .filter((line) => line.length > 0)
      .map((line) => JSON.parse(line) as AuditRow);
    const tampered: AuditRow[] = [{ ...(rows[0] as AuditRow), actor: 'someone else' }];
    await expect(verifyChain(tampered)).resolves.toEqual({ ok: false, brokenAt: rows[0]?.seq ?? 1 });
  });

  it('binds each entry to its predecessor', async () => {
    const entry = {
      at: 1_756_512_000,
      actor: 'a',
      institutionId: 'i',
      action: 'x',
      subject: 's',
      detail: '{}',
    };
    const first = await chainHash(CHAIN_GENESIS, entry, 1);
    const second = await chainHash('f'.repeat(64), entry, 1);
    expect(first).not.toBe(second);
  });
});

describe('service posture', () => {
  it('reports that it cannot issue', async () => {
    const body = await (await call('/health')).json<{ canIssue: boolean; holdsSigningKey: boolean }>();
    expect(body).toMatchObject({ canIssue: false, holdsSigningKey: false });
  });
});
