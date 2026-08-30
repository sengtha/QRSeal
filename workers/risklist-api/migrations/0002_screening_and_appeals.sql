-- Transaction-time screening, and the right to contest a listing.
--
-- Two additions, each shaped by a rule about which way the system should fail.
--
--   1. Screening is the checkpoint the list exists for. Only decisions with a
--      consequence are recorded. Recording every cleared payment would build a
--      national log of who paid whom, which is not this system's business and
--      is not needed: whether an account was listed at a given moment is
--      already reconstructable from the append-only status_changes feed.
--
--   2. An appeal starts a clock against the institution that made the listing.
--      If that institution does not answer within the deadline, the listing
--      lapses on its own. Silence must favour the account holder, because the
--      account holder is the party who cannot act. This is the same failure
--      direction as read-time expiry: a process that stops running must not
--      silently keep someone's money frozen.

-- The deadline lives on the status row so that the shard object can evaluate
-- it at read time, alongside the expiry, with no sweep job.
ALTER TABLE account_status ADD COLUMN appeal_deadline INTEGER;

CREATE TABLE appeals (
  id                     TEXT PRIMARY KEY,
  account                TEXT NOT NULL,
  -- The account-holding institution raises the appeal for its customer. The
  -- customer never talks to this service, and cannot query it: an open lookup
  -- would tell a mule operator whether their account had been detected yet.
  raised_by_institution  TEXT NOT NULL,
  raised_by_officer      TEXT NOT NULL,
  raised_at              INTEGER NOT NULL,
  grounds_code           TEXT NOT NULL,
  -- The institution that made the listing, and therefore owes the answer.
  answering_institution  TEXT NOT NULL,
  deadline               INTEGER NOT NULL,
  state                  TEXT NOT NULL CHECK (state IN ('open', 'upheld', 'withdrawn')),
  resolved_at            INTEGER,
  resolved_by            TEXT,
  resolution_code        TEXT
);

CREATE INDEX appeals_open ON appeals (state, deadline);
CREATE INDEX appeals_account ON appeals (account, raised_at);

-- Screening decisions that had a consequence: warn, hold or block. Append-only.
CREATE TABLE screenings (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  at            INTEGER NOT NULL,
  account       TEXT NOT NULL,
  decision      TEXT NOT NULL CHECK (decision IN ('warn', 'hold', 'block')),
  status        TEXT NOT NULL,
  reason_code   TEXT NOT NULL,
  -- The institution that asked. The payer is deliberately not recorded.
  asked_by      TEXT NOT NULL,
  reference     TEXT NOT NULL UNIQUE
);

CREATE INDEX screenings_account ON screenings (account, at);

CREATE TRIGGER screenings_no_update BEFORE UPDATE ON screenings
BEGIN SELECT RAISE(ABORT, 'screenings is append-only'); END;

CREATE TRIGGER screenings_no_delete BEFORE DELETE ON screenings
BEGIN SELECT RAISE(ABORT, 'screenings is append-only'); END;
