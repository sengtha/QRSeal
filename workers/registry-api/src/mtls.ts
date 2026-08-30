/**
 * Caller identification from Cloudflare API Shield mutual TLS.
 *
 * The client certificate identifies a person, not an institution. An audit
 * entry that says only "Acleda Bank listed this account" is not an audit
 * entry — someone specific must be nameable afterwards. The certificate
 * fingerprint is the join key into the officers table, rather than the subject
 * DN, because a DN is a string an issuing CA can reuse and a parser can
 * disagree about.
 */

export type Role = 'submitter' | 'ceremony';

export interface Officer {
  readonly fingerprint: string;
  readonly institutionId: string;
  readonly officerId: string;
  readonly role: Role;
}

export class AuthError extends Error {
  public readonly status: number;

  public constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = 'AuthError';
  }
}

interface TlsClientAuth {
  readonly certVerified?: string;
  readonly certFingerprintSHA256?: string;
  readonly certSubjectDN?: string;
  readonly certRevoked?: string;
}

/**
 * Resolve the calling officer, or throw.
 *
 * Cloudflare terminates the mutual TLS handshake and reports the outcome in
 * `request.cf.tlsClientAuth`. A certificate that did not verify, or that is
 * revoked, is treated as no certificate at all.
 */
export async function authenticate(
  request: Request,
  db: D1Database,
  required: Role | readonly Role[],
): Promise<Officer> {
  const auth = (request as unknown as { cf?: { tlsClientAuth?: TlsClientAuth } }).cf?.tlsClientAuth;
  if (auth === undefined) throw new AuthError(401, 'a client certificate is required');
  if (auth.certVerified !== 'SUCCESS') throw new AuthError(401, 'client certificate did not verify');
  if (auth.certRevoked === '1') throw new AuthError(401, 'client certificate is revoked');

  const fingerprint = auth.certFingerprintSHA256;
  if (fingerprint === undefined || fingerprint.length === 0) {
    throw new AuthError(401, 'client certificate carries no fingerprint');
  }

  const row = await db
    .prepare('SELECT fingerprint, institution_id, officer_id, role, active FROM officers WHERE fingerprint = ?')
    .bind(fingerprint.toUpperCase())
    .first<{ fingerprint: string; institution_id: string; officer_id: string; role: Role; active: number }>();

  if (row === null) throw new AuthError(403, 'certificate is not enrolled');
  if (row.active !== 1) throw new AuthError(403, 'enrolment is not active');

  const allowed = typeof required === 'string' ? [required] : required;
  if (!allowed.includes(row.role)) throw new AuthError(403, `role ${row.role} may not perform this action`);

  return {
    fingerprint: row.fingerprint,
    institutionId: row.institution_id,
    officerId: row.officer_id,
    role: row.role,
  };
}
