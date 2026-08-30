/**
 * risklist-api — the Annex C account risk list.
 *
 * This is the institutional layer, and it is where the fraud this project
 * cannot solve with cryptography is actually fought. A signature proves a code
 * is genuine; it says nothing about whether the account behind it is a mule
 * opened last Tuesday. Only an institution seeing the account's behaviour can
 * know that, and only if it can say so to every other institution fast enough
 * to matter. Time-to-list is the operative metric.
 *
 * Design commitments, each of which is a rule about failure:
 *
 *   - A status expires by a stored deadline evaluated at read time, never by a
 *     sweep. A missed cron must not silently extend a restriction.
 *   - Blocking, and any manual removal, needs two officers. A single
 *     compromised or coerced account cannot both freeze and unfreeze money.
 *   - Every write records institution AND officer, append-only. Corrections
 *     are new rows.
 *   - Writes are rate limited per institution and per officer, and an
 *     institution listing implausibly many accounts is refused and flagged
 *     rather than believed. An institution listing thousands of accounts in an
 *     hour is compromised or misconfigured; neither is a reason to act on it.
 *
 * A hold is not a sanction. `restricted` is a prudential pause an institution
 * takes on its own account of a suspicion, expiring by default; `blocked` is a
 * standing assertion and is treated accordingly. Conflating them would let an
 * operational reflex acquire the force of a penalty.
 */

import { append, verifyChain, type AuditRow } from './audit.js';
import { AuthError, authenticate, type Officer } from './mtls.js';
import { AccountShard, shardFor, type RiskStatus, type StatusReading } from './shard.js';

export { AccountShard };

export interface Env {
  readonly DB: D1Database;
  readonly SHARDS: DurableObjectNamespace<AccountShard>;
}

/** A prudential hold expires in three days unless renewed. */
export const DEFAULT_RESTRICTED_TTL_SECONDS = 72 * 60 * 60;
/** A standing block still expires, so that nobody is listed forever by inattention. */
export const DEFAULT_BLOCKED_TTL_SECONDS = 30 * 24 * 60 * 60;
export const MAX_TTL_SECONDS = 90 * 24 * 60 * 60;

export const RATE_WINDOW_SECONDS = 3600;
export const OFFICER_WRITES_PER_WINDOW = 120;
export const INSTITUTION_WRITES_PER_WINDOW = 600;
/**
 * Sustained volume at or above this level in one window is treated as a defect
 * rather than a signal: the attempt is refused and an incident is recorded.
 *
 * Refused attempts still count, so an institution that keeps hammering after
 * being throttled crosses this line and is flagged, which is the behaviour
 * that distinguishes a busy afternoon from a compromised or misconfigured
 * integration listing thousands of accounts.
 */
export const INSTITUTION_ANOMALY_THRESHOLD = 1200;

const ACCOUNT = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;
const REASON_CODE = /^[A-Z][A-Z0-9_]{2,31}$/;
const LISTABLE: readonly RiskStatus[] = ['restricted', 'blocked'];

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...init.headers },
  });
}

class RequestError extends Error {
  public readonly status: number;
  public readonly code: string;

  public constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.name = 'RequestError';
  }
}

async function readJson(request: Request): Promise<Record<string, unknown>> {
  if (request.headers.get('content-type')?.includes('application/json') !== true) {
    throw new RequestError(415, 'UNSUPPORTED_MEDIA_TYPE', 'content-type must be application/json');
  }
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    throw new RequestError(400, 'MALFORMED_BODY', 'body is not valid JSON');
  }
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new RequestError(400, 'MALFORMED_BODY', 'body must be a JSON object');
  }
  return body as Record<string, unknown>;
}

function field(body: Record<string, unknown>, name: string, pattern: RegExp): string {
  const value = body[name];
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new RequestError(400, 'MALFORMED_FIELD', `field ${name} is missing or malformed`);
  }
  return value;
}

/* ------------------------------------------------------------------ *
 * Rate limiting
 * ------------------------------------------------------------------ */

async function bump(db: D1Database, scope: string, identifier: string, windowStart: number): Promise<number> {
  const row = await db
    .prepare(
      'INSERT INTO write_rate (scope, identifier, window_start, count) VALUES (?, ?, ?, 1) ' +
        'ON CONFLICT(scope, identifier, window_start) DO UPDATE SET count = count + 1 RETURNING count',
    )
    .bind(scope, identifier, windowStart)
    .first<{ count: number }>();
  return row?.count ?? 1;
}

/**
 * Count this write against both limits and refuse if either is exceeded.
 *
 * The anomaly threshold is checked first so that an institution flooding the
 * list is recorded as an incident rather than merely throttled.
 */
async function enforceRateLimits(db: D1Database, officer: Officer, now: number): Promise<void> {
  const windowStart = Math.floor(now / RATE_WINDOW_SECONDS) * RATE_WINDOW_SECONDS;
  const byInstitution = await bump(db, 'institution', officer.institutionId, windowStart);
  const byOfficer = await bump(db, 'officer', `${officer.institutionId}/${officer.officerId}`, windowStart);

  if (byInstitution === INSTITUTION_ANOMALY_THRESHOLD) {
    await append(db, {
      at: now,
      actor: officer.officerId,
      institutionId: officer.institutionId,
      action: 'ratelimit.anomaly',
      subject: officer.institutionId,
      detail: JSON.stringify({ windowStart, writes: byInstitution, threshold: INSTITUTION_ANOMALY_THRESHOLD }),
    });
  }

  // Most specific reason first: an anomaly is a different operational event
  // from ordinary throttling and must not be reported as one.
  if (byInstitution >= INSTITUTION_ANOMALY_THRESHOLD) {
    throw new RequestError(
      429,
      'INSTITUTION_VOLUME_ANOMALY',
      'write volume for this institution is implausible; it has been flagged for review',
    );
  }
  if (byOfficer > OFFICER_WRITES_PER_WINDOW) {
    throw new RequestError(429, 'OFFICER_RATE_LIMIT', 'officer write rate exceeded');
  }
  if (byInstitution > INSTITUTION_WRITES_PER_WINDOW) {
    throw new RequestError(429, 'INSTITUTION_RATE_LIMIT', 'institution write rate exceeded');
  }
}

/* ------------------------------------------------------------------ *
 * Status reads and writes
 * ------------------------------------------------------------------ */

async function shardStub(env: Env, account: string): Promise<DurableObjectStub<AccountShard>> {
  const shard = await shardFor(account);
  return env.SHARDS.get(env.SHARDS.idFromName(shard));
}

async function readStatus(env: Env, account: string, now: number): Promise<StatusReading> {
  return (await shardStub(env, account)).readStatus(account, now);
}

interface ApplyInput {
  readonly account: string;
  readonly status: RiskStatus;
  readonly reasonCode: string;
  readonly ttlSeconds: number | null;
  readonly officer: Officer;
  readonly now: number;
  readonly approvedBy?: string;
}

async function applyStatus(env: Env, input: ApplyInput): Promise<StatusReading> {
  const stub = await shardStub(env, input.account);
  await stub.applyStatus(
    {
      account: input.account,
      status: input.status,
      reasonCode: input.reasonCode,
      listedBy: input.officer.officerId,
      institution: input.officer.institutionId,
      listedAt: input.now,
      expiresAt: input.ttlSeconds === null ? null : input.now + input.ttlSeconds,
    },
    input.now,
  );

  await append(env.DB, {
    at: input.now,
    actor: input.officer.officerId,
    institutionId: input.officer.institutionId,
    action: `status.${input.status}`,
    subject: input.account,
    detail: JSON.stringify({
      reasonCode: input.reasonCode,
      expiresAt: input.ttlSeconds === null ? null : input.now + input.ttlSeconds,
      approvedBy: input.approvedBy ?? null,
    }),
  });

  return readStatus(env, input.account, input.now);
}

/**
 * Propose a listing.
 *
 * A restriction takes effect at once: it is a reversible, expiring hold, and
 * delaying it for a second signature would cost exactly the minutes that
 * matter. A block waits for a second officer, because it is a standing
 * assertion about someone's access to their own money.
 */
async function propose(request: Request, env: Env, officer: Officer, now: number): Promise<Response> {
  const body = await readJson(request);
  const account = field(body, 'account', ACCOUNT);
  const reasonCode = field(body, 'reasonCode', REASON_CODE);
  const status = body['status'];
  if (typeof status !== 'string' || !LISTABLE.includes(status as RiskStatus)) {
    throw new RequestError(400, 'MALFORMED_FIELD', "status must be 'restricted' or 'blocked'");
  }

  const requested = body['ttlSeconds'];
  const fallback = status === 'blocked' ? DEFAULT_BLOCKED_TTL_SECONDS : DEFAULT_RESTRICTED_TTL_SECONDS;
  let ttl = fallback;
  if (requested !== undefined) {
    if (typeof requested !== 'number' || !Number.isSafeInteger(requested) || requested <= 0) {
      throw new RequestError(400, 'MALFORMED_FIELD', 'ttlSeconds must be a positive integer');
    }
    if (requested > MAX_TTL_SECONDS) {
      throw new RequestError(400, 'TTL_TOO_LONG', 'ttlSeconds exceeds the maximum; renew instead');
    }
    ttl = requested;
  }

  await enforceRateLimits(env.DB, officer, now);

  if (status === 'restricted') {
    const reading = await applyStatus(env, {
      account,
      status: 'restricted',
      reasonCode,
      ttlSeconds: ttl,
      officer,
      now,
    });
    return json({ applied: true, requiresSecondOfficer: false, status: reading }, { status: 201 });
  }

  const id = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO proposals (id, account, kind, status, reason_code, ttl_seconds, institution, proposed_by, proposed_at, state) " +
      "VALUES (?, ?, 'list', 'blocked', ?, ?, ?, ?, ?, 'pending')",
  )
    .bind(id, account, reasonCode, ttl, officer.institutionId, officer.officerId, now)
    .run();

  await append(env.DB, {
    at: now,
    actor: officer.officerId,
    institutionId: officer.institutionId,
    action: 'proposal.list.blocked',
    subject: account,
    detail: JSON.stringify({ proposalId: id, reasonCode, ttlSeconds: ttl }),
  });

  return json({ applied: false, requiresSecondOfficer: true, proposalId: id }, { status: 202 });
}

/** Propose removal. Always needs two officers, in both directions. */
async function proposeRemoval(request: Request, env: Env, officer: Officer, now: number): Promise<Response> {
  const body = await readJson(request);
  const account = field(body, 'account', ACCOUNT);
  const reasonCode = field(body, 'reasonCode', REASON_CODE);

  await enforceRateLimits(env.DB, officer, now);

  const id = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO proposals (id, account, kind, status, reason_code, ttl_seconds, institution, proposed_by, proposed_at, state) " +
      "VALUES (?, ?, 'remove', 'clear', ?, NULL, ?, ?, ?, 'pending')",
  )
    .bind(id, account, reasonCode, officer.institutionId, officer.officerId, now)
    .run();

  await append(env.DB, {
    at: now,
    actor: officer.officerId,
    institutionId: officer.institutionId,
    action: 'proposal.remove',
    subject: account,
    detail: JSON.stringify({ proposalId: id, reasonCode }),
  });

  return json({ applied: false, requiresSecondOfficer: true, proposalId: id }, { status: 202 });
}

/**
 * Approve a pending proposal.
 *
 * The approver must be a different person. Two certificates issued to the same
 * officer are still one officer, which is why the comparison is on officer
 * identity rather than on the certificate fingerprint.
 */
async function approve(env: Env, officer: Officer, id: string, now: number): Promise<Response> {
  const row = await env.DB.prepare(
    'SELECT id, account, kind, status, reason_code, ttl_seconds, institution, proposed_by, state FROM proposals WHERE id = ?',
  )
    .bind(id)
    .first<{
      id: string;
      account: string;
      kind: 'list' | 'remove';
      status: RiskStatus;
      reason_code: string;
      ttl_seconds: number | null;
      institution: string;
      proposed_by: string;
      state: string;
    }>();

  if (row === null) throw new RequestError(404, 'NO_SUCH_PROPOSAL', 'no such proposal');
  if (row.state !== 'pending') throw new RequestError(409, 'ALREADY_DECIDED', `proposal is already ${row.state}`);
  if (row.institution !== officer.institutionId) {
    throw new RequestError(403, 'WRONG_INSTITUTION', 'a proposal may only be approved within its institution');
  }
  if (row.proposed_by === officer.officerId) {
    throw new RequestError(409, 'SECOND_OFFICER_REQUIRED', 'a proposal must be approved by a different officer');
  }

  await enforceRateLimits(env.DB, officer, now);

  await env.DB.prepare("UPDATE proposals SET state = 'applied', approved_by = ?, approved_at = ? WHERE id = ? AND state = 'pending'")
    .bind(officer.officerId, now, id)
    .run();

  const reading = await applyStatus(env, {
    account: row.account,
    status: row.kind === 'remove' ? 'clear' : row.status,
    reasonCode: row.reason_code,
    ttlSeconds: row.kind === 'remove' ? null : row.ttl_seconds,
    officer,
    now,
    approvedBy: officer.officerId,
  });

  return json({ applied: true, proposalId: id, approvedBy: officer.officerId, status: reading });
}

async function delta(env: Env, url: URL): Promise<Response> {
  const since = Number(url.searchParams.get('since') ?? '0');
  const limit = Math.min(Number(url.searchParams.get('limit') ?? '500'), 1000);
  if (!Number.isSafeInteger(since) || since < 0 || !Number.isSafeInteger(limit) || limit < 1) {
    throw new RequestError(400, 'MALFORMED_FIELD', 'since and limit must be non-negative integers');
  }

  const { results } = await env.DB.prepare(
    'SELECT seq, at, account, status, reason_code, expires_at, institution FROM status_changes ' +
      'WHERE seq > ? ORDER BY seq ASC LIMIT ?',
  )
    .bind(since, limit)
    .all<{ seq: number }>();

  const cursor = results.at(-1)?.seq ?? since;
  return json({ since, cursor, complete: results.length < limit, changes: results });
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
  return new Response(rows.map((row) => JSON.stringify(row)).join('\n'), {
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
      return json({
        service: 'kh-sqr-risklist-api',
        holdsSigningKey: false,
        consistency: 'durable-object per shard; not KV',
        expiry: 'stored deadline evaluated at read time; no sweep job',
      });
    }

    try {
      const status = /^\/accounts\/([A-Za-z0-9][A-Za-z0-9._-]{2,63})\/status$/.exec(path);
      if (status !== null && request.method === 'GET') {
        await authenticate(request, env.DB, ['reader', 'officer', 'supervisor']);
        return json(await readStatus(env, status[1] as string, now));
      }

      if (path === '/listings' && request.method === 'POST') {
        const officer = await authenticate(request, env.DB, ['officer', 'supervisor']);
        return await propose(request, env, officer, now);
      }

      if (path === '/removals' && request.method === 'POST') {
        const officer = await authenticate(request, env.DB, ['officer', 'supervisor']);
        return await proposeRemoval(request, env, officer, now);
      }

      const approval = /^\/proposals\/([0-9a-f-]{36})\/approve$/.exec(path);
      if (approval !== null && request.method === 'POST') {
        const officer = await authenticate(request, env.DB, ['officer', 'supervisor']);
        return await approve(env, officer, approval[1] as string, now);
      }

      if (path === '/delta' && request.method === 'GET') {
        await authenticate(request, env.DB, ['reader', 'officer', 'supervisor']);
        return await delta(env, url);
      }

      if (path === '/audit/export' && request.method === 'GET') {
        await authenticate(request, env.DB, 'supervisor');
        return await exportAudit(env);
      }

      return json({ error: 'no such resource' }, { status: 404 });
    } catch (error) {
      if (error instanceof AuthError) return json({ error: error.message }, { status: error.status });
      if (error instanceof RequestError) {
        return json({ error: error.message, code: error.code }, { status: error.status });
      }
      // Account identifiers must not leak into an error body or a log line.
      return json({ error: 'internal error' }, { status: 500 });
    }
  },
} satisfies ExportedHandler<Env>;
