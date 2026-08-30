/**
 * registry-api — certificate signing request intake for the offline ceremony.
 *
 * WHAT THIS SERVICE CANNOT DO
 *
 * It cannot issue a certificate. It accepts a CSR, stores it, and queues it;
 * later, a ceremony officer uploads the certificate that the offline Root
 * produced. No private key is reachable from here, so compromising this
 * service yields the ability to enqueue junk and to read the queue — not the
 * ability to mint an issuer. That is the entire point of putting the portal
 * online and the Root offline, and it is why there is no secret binding in
 * wrangler.toml and a CI check that fails if one appears.
 *
 * Every state change is written to an append-only, hash-chained audit log,
 * naming the officer as well as the institution.
 */

import { append, verifyChain, type AuditRow } from './audit.js';
import { AuthError, authenticate, type Officer } from './mtls.js';

export interface Env {
  readonly DB: D1Database;
  readonly ARTIFACTS: R2Bucket;
}

/** A submitted CSR above this size is not a CSR. */
const MAX_CSR_BYTES = 8 * 1024;
const CSR_PEM = /^-----BEGIN CERTIFICATE REQUEST-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE REQUEST-----\r?\n?$/;
const CERT_PEM = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/;
const KID = /^[0-9A-F]{16}$/;
const PROFILES = /^[AB](,[AB])*$/;

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...init.headers },
  });
}

class RequestError extends Error {
  public readonly status: number;

  public constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'RequestError';
  }
}

const hex = (buffer: ArrayBuffer): string =>
  [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function readJson(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get('content-type')?.includes('application/json') !== true) {
    throw new RequestError(415, 'content-type must be application/json');
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new RequestError(400, 'body is not valid JSON');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new RequestError(400, 'body must be a JSON object');
  }
  return body as Record<string, unknown>;
}

function requireString(body: Record<string, unknown>, field: string, pattern?: RegExp): string {
  const value = body[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new RequestError(400, `field ${field} is required`);
  }
  if (pattern !== undefined && !pattern.test(value)) {
    throw new RequestError(400, `field ${field} is malformed`);
  }
  return value;
}

/* ------------------------------------------------------------------ *
 * Handlers
 * ------------------------------------------------------------------ */

/**
 * Accept a CSR and queue it.
 *
 * The CSR is stored verbatim in R2 and identified by its own digest, so
 * resubmitting the same request is idempotent rather than producing a second
 * queue entry for a ceremony officer to disambiguate.
 */
async function submitCsr(request: Request, env: Env, officer: Officer, now: number): Promise<Response> {
  const body = await readJson(request);
  const csr = requireString(body, 'csrPem', CSR_PEM);
  if (csr.length > MAX_CSR_BYTES) throw new RequestError(413, 'CSR is too large');
  const profiles = requireString(body, 'profiles', PROFILES);

  const digest = hex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(csr)));

  const existing = await env.DB.prepare('SELECT id, status FROM csr_queue WHERE csr_sha256 = ?')
    .bind(digest)
    .first<{ id: string; status: string }>();
  if (existing !== null) {
    return json({ id: existing.id, status: existing.status, duplicate: true }, { status: 200 });
  }

  const id = crypto.randomUUID();
  const key = `csr/${officer.institutionId}/${id}.pem`;
  await env.ARTIFACTS.put(key, csr);

  await env.DB.prepare(
    'INSERT INTO csr_queue (id, institution_id, submitted_by, submitted_at, csr_sha256, csr_key, profiles, status) ' +
      "VALUES (?, ?, ?, ?, ?, ?, ?, 'queued')",
  )
    .bind(id, officer.institutionId, officer.officerId, now, digest, key, profiles)
    .run();

  await append(env.DB, {
    at: now,
    actor: officer.officerId,
    institutionId: officer.institutionId,
    action: 'csr.submitted',
    subject: id,
    detail: JSON.stringify({ csrSha256: digest, profiles }),
  });

  return json({ id, status: 'queued', csrSha256: digest }, { status: 201 });
}

/**
 * Record the outcome of an offline ceremony.
 *
 * The certificate arrives as an artifact produced elsewhere. This service
 * stores and publishes it; it does not and cannot create it.
 */
async function recordDecision(
  request: Request,
  env: Env,
  officer: Officer,
  id: string,
  now: number,
): Promise<Response> {
  const body = await readJson(request);
  const decision = requireString(body, 'decision');
  if (decision !== 'issued' && decision !== 'rejected') {
    throw new RequestError(400, "decision must be 'issued' or 'rejected'");
  }

  const row = await env.DB.prepare('SELECT id, institution_id, status FROM csr_queue WHERE id = ?')
    .bind(id)
    .first<{ id: string; institution_id: string; status: string }>();
  if (row === null) throw new RequestError(404, 'no such request');
  if (row.status !== 'queued') throw new RequestError(409, `request is already ${row.status}`);

  let certificateKey: string | null = null;
  let kid: string | null = null;

  if (decision === 'issued') {
    const certificate = requireString(body, 'certificatePem', CERT_PEM);
    kid = requireString(body, 'kid', KID);
    certificateKey = `certificates/${row.institution_id}/${kid}.pem`;
    await env.ARTIFACTS.put(certificateKey, certificate);
  }

  const note = typeof body['note'] === 'string' ? body['note'] : '';

  await env.DB.prepare(
    'UPDATE csr_queue SET status = ?, decided_at = ?, decided_by = ?, decision_note = ?, certificate_key = ?, kid = ? ' +
      "WHERE id = ? AND status = 'queued'",
  )
    .bind(decision, now, officer.officerId, note, certificateKey, kid, id)
    .run();

  await append(env.DB, {
    at: now,
    actor: officer.officerId,
    institutionId: row.institution_id,
    action: `csr.${decision}`,
    subject: id,
    detail: JSON.stringify({ kid, certificateKey, note }),
  });

  return json({ id, status: decision, kid, certificateKey });
}

async function readQueue(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(
    "SELECT id, institution_id, submitted_by, submitted_at, csr_sha256, csr_key, profiles FROM csr_queue " +
      "WHERE status = 'queued' ORDER BY submitted_at ASC LIMIT 200",
  ).all();
  return json({ queued: results });
}

async function exportAudit(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(
    'SELECT seq, at, actor, institution_id, action, subject, detail, prev_hash, entry_hash FROM audit_log ORDER BY seq ASC',
  ).all<{
    seq: number;
    at: number;
    actor: string;
    institution_id: string;
    action: string;
    subject: string;
    detail: string;
    prev_hash: string;
    entry_hash: string;
  }>();

  const rows: AuditRow[] = results.map((r) => ({
    seq: r.seq,
    at: r.at,
    actor: r.actor,
    institutionId: r.institution_id,
    action: r.action,
    subject: r.subject,
    detail: r.detail,
    prevHash: r.prev_hash,
    entryHash: r.entry_hash,
  }));

  const chain = await verifyChain(rows);
  // Newline-delimited JSON so the export can be appended to and hashed
  // incrementally, and published to a transparency log later unchanged.
  const body = rows.map((row) => JSON.stringify(row)).join('\n');
  return new Response(body, {
    headers: {
      'content-type': 'application/x-ndjson; charset=utf-8',
      'cache-control': 'no-store',
      'x-kh-sqr-chain-valid': String(chain.ok),
      'x-kh-sqr-chain-length': String(rows.length),
      ...(chain.brokenAt === null ? {} : { 'x-kh-sqr-chain-broken-at': String(chain.brokenAt) }),
    },
  });
}

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const now = Math.floor(Date.now() / 1000);

    if (path === '/health') {
      return json({ service: 'kh-sqr-registry-api', holdsSigningKey: false, canIssue: false });
    }

    try {
      if (path === '/csr' && request.method === 'POST') {
        return await submitCsr(request, env, await authenticate(request, env.DB, 'submitter'), now);
      }

      if (path === '/queue' && request.method === 'GET') {
        await authenticate(request, env.DB, 'ceremony');
        return await readQueue(env);
      }

      const decision = /^\/csr\/([0-9a-f-]{36})\/decision$/.exec(path);
      if (decision !== null && request.method === 'POST') {
        const officer = await authenticate(request, env.DB, 'ceremony');
        return await recordDecision(request, env, officer, decision[1] as string, now);
      }

      const status = /^\/csr\/([0-9a-f-]{36})$/.exec(path);
      if (status !== null && request.method === 'GET') {
        const officer = await authenticate(request, env.DB, ['submitter', 'ceremony']);
        const row = await env.DB.prepare(
          'SELECT id, institution_id, status, submitted_at, decided_at, kid FROM csr_queue WHERE id = ?',
        )
          .bind(status[1])
          .first<{ id: string; institution_id: string }>();
        if (row === null) throw new RequestError(404, 'no such request');
        // A submitter sees only their own institution's requests.
        if (officer.role === 'submitter' && row.institution_id !== officer.institutionId) {
          throw new RequestError(404, 'no such request');
        }
        return json(row);
      }

      if (path === '/audit/export' && request.method === 'GET') {
        await authenticate(request, env.DB, 'ceremony');
        return await exportAudit(env);
      }

      return json({ error: 'no such resource' }, { status: 404 });
    } catch (error) {
      if (error instanceof AuthError) return json({ error: error.message }, { status: error.status });
      if (error instanceof RequestError) return json({ error: error.message }, { status: error.status });
      // Never echo an unexpected error to the caller: it may quote request
      // content, and this service handles material that must not be logged.
      return json({ error: 'internal error' }, { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
