/**
 * One Durable Object per shard of the account space.
 *
 * WHY NOT KV
 *
 * The read this service exists to answer is "may this transfer proceed right
 * now". KV is eventually consistent, so for some seconds after an institution
 * lists a mule account, the account still reads clear — which is exactly the
 * interval the account is drained in. A Durable Object serialises reads and
 * writes for the accounts it owns, so a write that has returned is visible to
 * every subsequent read. D1 remains the authority and the record of history;
 * the object is the consistency point, and rehydrates from D1 if evicted.
 *
 * WHY EXPIRY IS EVALUATED HERE, AT READ TIME
 *
 * A restriction carries a stored deadline and is compared against the clock
 * when someone asks. There is no sweep job. A cron that failed to run would
 * silently extend a restriction on a real person's account, and neither they
 * nor the institution would see anything wrong; a deadline that has simply
 * passed cannot fail in that direction.
 */

import { DurableObject } from 'cloudflare:workers';

export type RiskStatus = 'clear' | 'restricted' | 'blocked';

export interface StatusRecord {
  readonly account: string;
  readonly status: RiskStatus;
  readonly reasonCode: string;
  readonly listedBy: string;
  readonly institution: string;
  readonly listedAt: number;
  /** Deadline after which the status no longer applies. Null only for 'clear'. */
  readonly expiresAt: number | null;
  readonly version: number;
}

export interface StatusReading {
  readonly account: string;
  /** The status in force at `now`, after applying the stored deadline. */
  readonly status: RiskStatus;
  readonly reasonCode: string | null;
  readonly expiresAt: number | null;
  readonly listedAt: number | null;
  readonly institution: string | null;
  readonly version: number;
  /**
   * Set when a stored status has lapsed. Readers should treat the account as
   * clear, but an operator looking at the same response can see that the
   * listing expired rather than never existing.
   */
  readonly lapsedFrom: RiskStatus | null;
  /** Which layer answered. Present so a caller can tell a cold read from a warm one. */
  readonly source: 'object' | 'database';
}

export interface ShardEnv {
  readonly DB: D1Database;
}

const CLEAR = (account: string, source: 'object' | 'database'): StatusReading => ({
  account,
  status: 'clear',
  reasonCode: null,
  expiresAt: null,
  listedAt: null,
  institution: null,
  version: 0,
  lapsedFrom: null,
  source,
});

interface StatusRow {
  account: string;
  status: RiskStatus;
  reason_code: string;
  listed_by: string;
  institution: string;
  listed_at: number;
  expires_at: number | null;
  version: number;
}

const toRecord = (row: StatusRow): StatusRecord => ({
  account: row.account,
  status: row.status,
  reasonCode: row.reason_code,
  listedBy: row.listed_by,
  institution: row.institution,
  listedAt: row.listed_at,
  expiresAt: row.expires_at,
  version: row.version,
});

export class AccountShard extends DurableObject<ShardEnv> {
  /**
   * Read the status in force for an account.
   *
   * Fails closed on nothing: an account with no listing is clear, which is the
   * correct default for a risk list. The fail-closed behaviour in this system
   * lives in the verifier's trust-list rules, not here.
   */
  public async readStatus(account: string, now: number): Promise<StatusReading> {
    let record = await this.ctx.storage.get<StatusRecord>(account);
    let source: 'object' | 'database' = 'object';

    if (record === undefined) {
      // Cold object, or one evicted since the last write. D1 is the authority.
      const row = await this.env.DB.prepare(
        'SELECT account, status, reason_code, listed_by, institution, listed_at, expires_at, version ' +
          'FROM account_status WHERE account = ?',
      )
        .bind(account)
        .first<StatusRow>();
      source = 'database';
      if (row === null) return CLEAR(account, source);
      record = toRecord(row);
      await this.ctx.storage.put(account, record);
    }

    if (record.status === 'clear') return { ...CLEAR(account, source), version: record.version };

    if (record.expiresAt !== null && now > record.expiresAt) {
      return {
        ...CLEAR(account, source),
        version: record.version,
        lapsedFrom: record.status,
        expiresAt: record.expiresAt,
      };
    }

    return {
      account,
      status: record.status,
      reasonCode: record.reasonCode,
      expiresAt: record.expiresAt,
      listedAt: record.listedAt,
      institution: record.institution,
      version: record.version,
      lapsedFrom: null,
      source,
    };
  }

  /**
   * Apply a status change.
   *
   * Runs inside the object's single-threaded context, so the D1 write and the
   * cached copy cannot interleave with a concurrent read of the same account.
   * The version counter is taken from the object's own view, which is the
   * reason writes are routed through here rather than made directly against
   * D1 by each caller.
   */
  public async applyStatus(
    input: Omit<StatusRecord, 'version'>,
    now: number,
  ): Promise<{ record: StatusRecord; changeSeq: number }> {
    const current = await this.readStatus(input.account, now);
    const record: StatusRecord = { ...input, version: current.version + 1 };

    await this.env.DB.prepare(
      'INSERT INTO account_status (account, status, reason_code, listed_by, institution, listed_at, expires_at, version) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(account) DO UPDATE SET status = excluded.status, reason_code = excluded.reason_code, ' +
        'listed_by = excluded.listed_by, institution = excluded.institution, listed_at = excluded.listed_at, ' +
        'expires_at = excluded.expires_at, version = excluded.version',
    )
      .bind(
        record.account,
        record.status,
        record.reasonCode,
        record.listedBy,
        record.institution,
        record.listedAt,
        record.expiresAt,
        record.version,
      )
      .run();

    const change = await this.env.DB.prepare(
      'INSERT INTO status_changes (at, account, status, reason_code, expires_at, institution) ' +
        'VALUES (?, ?, ?, ?, ?, ?) RETURNING seq',
    )
      .bind(now, record.account, record.status, record.reasonCode, record.expiresAt, record.institution)
      .first<{ seq: number }>();

    await this.ctx.storage.put(record.account, record);
    return { record, changeSeq: change?.seq ?? 0 };
  }
}

/**
 * Map an account identifier to its shard.
 *
 * 256 shards keyed by the first byte of SHA-256 over the identifier. Hashing
 * rather than prefixing spreads accounts evenly regardless of how a bank
 * numbers them, so one institution's numbering scheme cannot concentrate on a
 * single object.
 */
export async function shardFor(account: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(account));
  return (new Uint8Array(digest)[0] as number).toString(16).padStart(2, '0');
}
