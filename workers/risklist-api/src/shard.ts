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

/** Why a stored status is no longer in force. */
export type LapseReason = 'expired' | 'appeal_unanswered';

export interface StatusRecord {
  readonly account: string;
  readonly status: RiskStatus;
  readonly reasonCode: string;
  readonly listedBy: string;
  readonly institution: string;
  readonly listedAt: number;
  /** Deadline after which the status no longer applies. Null only for 'clear'. */
  readonly expiresAt: number | null;
  /**
   * Deadline by which the listing institution must answer a contest of this
   * listing. Null when no appeal is open. Evaluated at read time exactly like
   * the expiry, so an unanswered appeal cannot quietly sustain a listing.
   */
  readonly appealDeadline: number | null;
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
  /** Why it lapsed: the listing's own deadline passed, or an appeal went unanswered. */
  readonly lapsedBecause: LapseReason | null;
  /** The open appeal deadline, if any. */
  readonly appealDeadline: number | null;
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
  lapsedBecause: null,
  appealDeadline: null,
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
  appeal_deadline: number | null;
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
  appealDeadline: row.appeal_deadline,
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
        'SELECT account, status, reason_code, listed_by, institution, listed_at, expires_at, ' +
          'appeal_deadline, version FROM account_status WHERE account = ?',
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
        lapsedBecause: 'expired',
        expiresAt: record.expiresAt,
      };
    }

    // An appeal the listing institution did not answer in time lapses the
    // listing. Silence favours the account holder, who is the party unable to
    // act on their own behalf.
    if (record.appealDeadline !== null && now > record.appealDeadline) {
      return {
        ...CLEAR(account, source),
        version: record.version,
        lapsedFrom: record.status,
        lapsedBecause: 'appeal_unanswered',
        expiresAt: record.expiresAt,
        appealDeadline: record.appealDeadline,
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
      lapsedBecause: null,
      appealDeadline: record.appealDeadline,
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
    input: Omit<StatusRecord, 'version' | 'appealDeadline'> & { readonly appealDeadline?: number | null },
    now: number,
  ): Promise<{ record: StatusRecord; changeSeq: number }> {
    const current = await this.readStatus(input.account, now);
    // A new listing decision supersedes any appeal deadline attached to the
    // previous one: the contest was about the listing being replaced.
    const record: StatusRecord = {
      ...input,
      appealDeadline: input.appealDeadline ?? null,
      version: current.version + 1,
    };

    await this.env.DB.prepare(
      'INSERT INTO account_status (account, status, reason_code, listed_by, institution, listed_at, ' +
        'expires_at, appeal_deadline, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ' +
        'ON CONFLICT(account) DO UPDATE SET status = excluded.status, reason_code = excluded.reason_code, ' +
        'listed_by = excluded.listed_by, institution = excluded.institution, listed_at = excluded.listed_at, ' +
        'expires_at = excluded.expires_at, appeal_deadline = excluded.appeal_deadline, version = excluded.version',
    )
      .bind(
        record.account,
        record.status,
        record.reasonCode,
        record.listedBy,
        record.institution,
        record.listedAt,
        record.expiresAt,
        record.appealDeadline,
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

  /**
   * Attach or remove an appeal deadline without otherwise altering the listing.
   *
   * Raising an appeal does not by itself change an account's status: an
   * institution must not be able to clear its own suspicion, nor another's, by
   * asserting a contest. What the appeal does is start a clock that the listing
   * institution must beat.
   */
  public async setAppealDeadline(
    account: string,
    deadline: number | null,
    now: number,
  ): Promise<StatusReading> {
    const stored = await this.ctx.storage.get<StatusRecord>(account);
    await this.env.DB.prepare('UPDATE account_status SET appeal_deadline = ? WHERE account = ?')
      .bind(deadline, account)
      .run();
    if (stored !== undefined) {
      await this.ctx.storage.put(account, { ...stored, appealDeadline: deadline });
    }
    return this.readStatus(account, now);
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
