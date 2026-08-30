-- Registry queue and audit log.
--
-- The audit log is append-only. SQLite has no GRANT, so the prohibition is
-- enforced by triggers that abort any UPDATE or DELETE. Corrections are new
-- rows, never edits: an audit trail that can be rewritten is not one.

CREATE TABLE officers (
  fingerprint     TEXT PRIMARY KEY,   -- SHA-256 of the mTLS client certificate
  institution_id  TEXT NOT NULL,
  officer_id      TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('submitter', 'ceremony')),
  active          INTEGER NOT NULL DEFAULT 1,
  enrolled_at     INTEGER NOT NULL
);

CREATE TABLE csr_queue (
  id               TEXT PRIMARY KEY,
  institution_id   TEXT NOT NULL,
  submitted_by     TEXT NOT NULL,
  submitted_at     INTEGER NOT NULL,
  csr_sha256       TEXT NOT NULL UNIQUE,
  csr_key          TEXT NOT NULL,     -- R2 object key of the stored CSR
  profiles         TEXT NOT NULL,     -- comma-separated: A, B
  status           TEXT NOT NULL CHECK (status IN ('queued', 'issued', 'rejected')),
  decided_at       INTEGER,
  decided_by       TEXT,
  decision_note    TEXT,
  certificate_key  TEXT,              -- R2 object key of the issued certificate
  kid              TEXT
);

CREATE INDEX csr_queue_status ON csr_queue (status, submitted_at);

CREATE TABLE audit_log (
  seq             INTEGER PRIMARY KEY AUTOINCREMENT,
  at              INTEGER NOT NULL,
  actor           TEXT NOT NULL,
  institution_id  TEXT NOT NULL,
  action          TEXT NOT NULL,
  subject         TEXT NOT NULL,
  detail          TEXT NOT NULL,
  prev_hash       TEXT NOT NULL,
  entry_hash      TEXT NOT NULL
);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
