/**
 * Append-only, hash-chained audit log.
 *
 * Each entry commits to its predecessor, so the log can be exported as a file
 * whose integrity is checkable without trusting the database it came from, and
 * published to a tamper-evident log later without redesigning anything. The
 * chain does not prevent an operator with database access from truncating the
 * log; it prevents them from altering its interior without that being visible.
 */

export interface AuditEntry {
  readonly at: number;
  readonly actor: string;
  readonly institutionId: string;
  readonly action: string;
  readonly subject: string;
  readonly detail: string;
}

/** The genesis predecessor for the first entry. */
export const CHAIN_GENESIS = '0'.repeat(64);

const encoder = new TextEncoder();

function hex(bytes: ArrayBuffer): string {
  return [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * The exact string each entry hash covers.
 *
 * Every variable field is JSON-escaped before being joined, so no two distinct
 * entries can produce the same preimage. Without that, a writer could split a
 * value across field boundaries and forge a chain link that verifies.
 */
export function chainPreimage(previousHash: string, entry: AuditEntry, seq: number): string {
  return [
    previousHash,
    String(seq),
    String(entry.at),
    JSON.stringify(entry.actor),
    JSON.stringify(entry.institutionId),
    JSON.stringify(entry.action),
    JSON.stringify(entry.subject),
    JSON.stringify(entry.detail),
  ].join('');
}

export async function chainHash(previousHash: string, entry: AuditEntry, seq: number): Promise<string> {
  return hex(await crypto.subtle.digest('SHA-256', encoder.encode(chainPreimage(previousHash, entry, seq))));
}

/**
 * Append one entry.
 *
 * The read of the previous hash and the insert are not one transaction, so two
 * concurrent appends could read the same predecessor. An export verifier
 * detects that as a fork rather than accepting it silently, and the write rate
 * here is a handful of events per day.
 */
export async function append(db: D1Database, entry: AuditEntry): Promise<{ seq: number; entryHash: string }> {
  const previous = await db
    .prepare('SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1')
    .first<{ seq: number; entry_hash: string }>();

  const seq = (previous?.seq ?? 0) + 1;
  const previousHash = previous?.entry_hash ?? CHAIN_GENESIS;
  const entryHash = await chainHash(previousHash, entry, seq);

  await db
    .prepare(
      'INSERT INTO audit_log (seq, at, actor, institution_id, action, subject, detail, prev_hash, entry_hash) ' +
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    )
    .bind(
      seq,
      entry.at,
      entry.actor,
      entry.institutionId,
      entry.action,
      entry.subject,
      entry.detail,
      previousHash,
      entryHash,
    )
    .run();

  return { seq, entryHash };
}

export interface AuditRow extends AuditEntry {
  readonly seq: number;
  readonly prevHash: string;
  readonly entryHash: string;
}

/** Recompute the chain over an export and report the first inconsistency. */
export async function verifyChain(rows: readonly AuditRow[]): Promise<{ ok: boolean; brokenAt: number | null }> {
  let expected = CHAIN_GENESIS;
  for (const row of rows) {
    if (row.prevHash !== expected) return { ok: false, brokenAt: row.seq };
    const computed = await chainHash(expected, row, row.seq);
    if (computed !== row.entryHash) return { ok: false, brokenAt: row.seq };
    expected = row.entryHash;
  }
  return { ok: true, brokenAt: null };
}
