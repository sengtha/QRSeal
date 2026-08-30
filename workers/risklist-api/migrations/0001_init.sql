-- Annex C account risk list.
--
-- Two rules shape this schema:
--
--   1. A status expires by a stored deadline evaluated when it is read. There
--      is no sweep job, because a missed sweep would silently extend a
--      restriction on someone's account, and the person affected would have no
--      way to tell that had happened.
--
--   2. The audit log is append-only, enforced by triggers, since SQLite has no
--      GRANT. Corrections are new rows. Every write names the officer as well
--      as the institution.

CREATE TABLE officers (
  fingerprint     TEXT PRIMARY KEY,
  institution_id  TEXT NOT NULL,
  officer_id      TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('officer', 'supervisor', 'reader')),
  active          INTEGER NOT NULL DEFAULT 1,
  enrolled_at     INTEGER NOT NULL
);

-- Current status per account. `expires_at` NULL means no deadline, which is
-- only permitted for 'clear'.
CREATE TABLE account_status (
  account       TEXT PRIMARY KEY,
  status        TEXT NOT NULL CHECK (status IN ('clear', 'restricted', 'blocked')),
  reason_code   TEXT NOT NULL,
  listed_by     TEXT NOT NULL,
  institution   TEXT NOT NULL,
  listed_at     INTEGER NOT NULL,
  expires_at    INTEGER,
  version       INTEGER NOT NULL
);

-- Proposals. A 'blocked' listing and any manual removal need a second officer.
CREATE TABLE proposals (
  id             TEXT PRIMARY KEY,
  account        TEXT NOT NULL,
  kind           TEXT NOT NULL CHECK (kind IN ('list', 'remove')),
  status         TEXT NOT NULL CHECK (status IN ('clear', 'restricted', 'blocked')),
  reason_code    TEXT NOT NULL,
  ttl_seconds    INTEGER,
  institution    TEXT NOT NULL,
  proposed_by    TEXT NOT NULL,
  proposed_at    INTEGER NOT NULL,
  state          TEXT NOT NULL CHECK (state IN ('pending', 'applied', 'withdrawn')),
  approved_by    TEXT,
  approved_at    INTEGER
);

CREATE INDEX proposals_pending ON proposals (state, proposed_at);

-- Append-only feed readers poll. Sequence numbers are dense and monotonic.
CREATE TABLE status_changes (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  at           INTEGER NOT NULL,
  account      TEXT NOT NULL,
  status       TEXT NOT NULL,
  reason_code  TEXT NOT NULL,
  expires_at   INTEGER,
  institution  TEXT NOT NULL
);

CREATE TRIGGER status_changes_no_update BEFORE UPDATE ON status_changes
BEGIN SELECT RAISE(ABORT, 'status_changes is append-only'); END;

CREATE TRIGGER status_changes_no_delete BEFORE DELETE ON status_changes
BEGIN SELECT RAISE(ABORT, 'status_changes is append-only'); END;

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

-- Fixed-window write counters, per institution and per officer.
CREATE TABLE write_rate (
  scope         TEXT NOT NULL,
  identifier    TEXT NOT NULL,
  window_start  INTEGER NOT NULL,
  count         INTEGER NOT NULL,
  PRIMARY KEY (scope, identifier, window_start)
);
