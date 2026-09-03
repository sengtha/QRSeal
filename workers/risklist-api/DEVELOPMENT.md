# `risklist-api` — developer guide

The Annex C account risk list: authenticated institutional writes, strongly
consistent status reads, transaction-time screening, a delta feed, and the right
to contest a listing.

**Serves two solutions: S3** (screening at the moment of payment) and **S4**
(the right to contest a listing). They live in one service because they act on
the same listing and must share one consistency point — split them and a screen
could read a status an appeal had already lapsed. To stand one up, see
[`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md).

This is the largest of the three services and the one that acts on the fraud the
cryptography cannot reach — see
[README §3 P4](../../README.md#p4--authorised-push-payment-fraud--not-addressed-at-all)
and [§4.4](../../README.md#44-screen-at-the-moment-of-payment--built).
This file is about working on it.

---

## What this service is for

A signature proves a code is genuine. It says nothing about whether the account
behind it is a mule opened last Tuesday. Only an institution watching that
account's behaviour can know, and only if it can tell every other institution
fast enough to matter.

**Time-to-list is the operative metric.** Detection accuracy matters less than
dissemination latency, because an accurate signal delivered after the money has
moved changes nothing. Almost every design decision below follows from that one
sentence, or from its counterweight: this service can freeze a real person's
money, so every mechanism that makes listing fast has a matching one that makes
being wrongly listed survivable.

---

## Five rules, each about failure

These are the load-bearing commitments. Changing any of them is a design
decision, not a refactor.

**1. State lives in a Durable Object per shard, never in KV.**
The read this service answers is "may this transfer proceed *right now*". KV is
eventually consistent, so for some seconds after an institution lists a mule
account, that account still reads clear — which is precisely the interval it is
drained in. `AccountShard` serialises reads and writes for the accounts it owns,
so a write that has returned is visible to every subsequent read. D1 stays the
authority and the history; the object is the consistency point, and rehydrates
from D1 if evicted (`source: 'object' | 'database'` in the reading tells you
which answered).

**2. Expiry is evaluated at read time. There is no sweep job.**
A cron that failed to run would silently extend a restriction on someone's
account, and neither they nor the listing institution would see anything wrong.
A deadline that has simply passed cannot fail in that direction.

**3. Blocking, and any discretionary removal, needs two officers.**
A single compromised or coerced account must not be able to both freeze and
unfreeze money.

**4. Every write names the institution *and* the officer, append-only.**
Corrections are new rows.

**5. An institution listing implausibly many accounts is refused and flagged,
not believed.**
Thousands of listings in an hour means compromised or misconfigured. Neither is
a reason to act on the assertions.

### A hold is not a sanction

`restricted` is a prudential pause an institution takes on its own account of a
suspicion, and it expires. `blocked` is a standing assertion, and is treated
accordingly. Conflating them would let an operational reflex acquire the force
of a penalty — so they differ in who may impose them, for how long, and how fast
a contest must be answered.

| | `restricted` | `blocked` |
|---|---|---|
| To impose | one officer, immediate | **two officers** |
| Default lifetime | 72 h | 30 d |
| Appeal must be answered within | 24 h | 72 h |
| Screening decision | `hold` | `block` |

`MAX_TTL_SECONDS` is 90 days in both cases; a longer request is refused with
`TTL_TOO_LONG` and the guidance to renew instead. A listing nobody re-affirms
should lapse.

**Removal by a non-listing institution takes two officers — but answering a
contest takes one, either way.** An earlier version had this wrong: a restriction
took one officer to impose and two to lift, which made an error more expensive to
correct than to make. Upholding must also not be harder than ignoring, or the
incentive runs the wrong way.

---

## Setup

```sh
pnpm install
```

Node ≥ 20.

---

## Test loop

**This is the development loop.** See [Running locally](#running-locally) for why.

```sh
pnpm --filter @kh-sqr/risklist-api test          # 37 tests
pnpm --filter @kh-sqr/risklist-api test -- --watch
```

Tests run in `workerd` with real D1 and Durable Object bindings under Miniflare.
Migrations are read at config time and applied in `beforeAll`.

**Authenticating a test request** — the suite injects what Cloudflare puts on the
request after terminating mutual TLS, and enrols the fingerprint:

```ts
init.cf = { tlsClientAuth: { certVerified: 'SUCCESS', certFingerprintSHA256: ALICE, … } };
```

| Constant | Institution | Role |
|---|---|---|
| `ALICE` | `ABAAKHPP` | officer |
| `BORA` | `ABAAKHPP` | officer — the *second* officer for two-officer flows |
| `SUPERVISOR` | `ABAAKHPP` | supervisor |
| `OTHER_BANK` | `ACLBKHPP` | officer — for cross-institution refusals |
| `READER` | `NBC` | reader |

### Two gotchas that will cost you an hour each

**Account state is not reset between tests.** `beforeEach` clears `officers`,
`proposals`, `appeals` and `write_rate` — but **not** `account_status`, and not
the Durable Object storage behind it. A test that needs a clean account must use
a distinct account identifier. That is why the suite has `KH-FLOOD-0001`,
`KH-DELTA-0001`, `KH-SCREEN-RECORD` and `KH-SCREEN-CLEAR` rather than reusing one
constant. Follow the convention; do not try to clear the shard.

**Rate-limit counters are per fixed window.** `write_rate` is keyed by
`(scope, identifier, window_start)` with `RATE_WINDOW_SECONDS = 3600`. A test
that performs many writes will exhaust `OFFICER_WRITES_PER_WINDOW` (120) and start
getting 429s that look like unrelated failures. `beforeEach` clears the table for
exactly this reason — if you add a suite that writes in bulk, either spread the
work across officers or clear it yourself.

---

## Running locally

```sh
pnpm --filter @kh-sqr/risklist-api migrate:local
pnpm --filter @kh-sqr/risklist-api dev
```

**Only `/health` is reachable.** `wrangler dev` cannot terminate mutual TLS, so
every other route answers `{"error":"client certificate did not verify"}`.
`src/mtls.ts` treats anything short of `certVerified === 'SUCCESS'` as no
certificate at all, which is correct.

**Do not add a development bypass to `mtls.ts`.** An `if (env.DEV)` branch in the
authentication path of a service that can freeze bank accounts is one
misconfigured deploy away from a very bad afternoon. The test harness gives you
any officer, role, institution and certificate state you need, including revoked
and unenrolled.

`/health` is worth reading — it states the service's posture as checkable claims.
A test asserts the first two still match `/not KV/` and `/no sweep/`; the third is
not asserted, so if you change the appeals rule, change this string by hand:

```json
{ "consistency": "durable-object per shard; not KV",
  "expiry": "stored deadline evaluated at read time; no sweep job",
  "appeals": "an unanswered contest lapses the listing; silence favours the account holder" }
```

---

## Routes

All routes except `/health` require a verified, enrolled, active client
certificate. Roles: `reader`, `officer`, `supervisor`.

| Route | Role | Purpose |
|---|---|---|
| `GET /health` | — | posture |
| `GET /accounts/{account}/status` | any | status in force now |
| `POST /screen` | any | the payment-time checkpoint |
| `POST /listings` | officer+ | list an account |
| `POST /removals` | officer+ | propose removal (always two officers) |
| `POST /proposals/{uuid}/approve` | officer+ | second signature |
| `POST /appeals` | officer+ | contest a listing |
| `GET /appeals` | officer+ | contests this institution owes an answer to |
| `POST /appeals/{uuid}/resolve` | officer+ | answer one |
| `GET /delta?since=&limit=` | any | append-only change feed |
| `GET /audit/export` | **supervisor** | hash-chained log as NDJSON |

### `POST /screen` — the reason the list exists

```json
{ "account": "KH-855012345678", "amount": 250.0, "currency": "USD" }
```

→ `{"decision": "allow" | "warn" | "hold" | "block", "guidance", "screeningRef", … }`

A register nobody consults before releasing money is a record of the fraud, not
a control on it.

Three things about this endpoint are deliberate and easy to undo by accident:

- **The payer is never identified.** There is no payer field in the request
  shape, and there should not be one.
- **Only decisions with a consequence are recorded.** Logging every cleared
  payment would build a national record of who paid whom. Whether an account was
  listed at a given moment is already reconstructable from `/delta`.
- **`listedByInstitution` is for institutional routing and must never be shown
  to the payer.** It tells a mule operator which institution detected them.

`LOW_VALUE_SCREENING_THRESHOLD` is `{ KHR: 0, USD: 0 }` — every payment to a
restricted account is held. It is a **policy parameter, not a technical
constant**: the safe value is the default, and a regulator who wants less
friction on small payments must choose the number and own it.

**Screening in the payment path must fail open.** Everything else in this system
fails closed; this cannot. A verifier that refuses to verify is safe, but a
screening call that refuses to answer during an availability incident is a
national payment outage. An unreachable service means `unscreened`, and
`unscreened` is not `clear` — the caller must distinguish them.

### `POST /listings`

```json
{ "account": "KH-855012345678", "status": "restricted",
  "reasonCode": "MULE_SUSPECTED", "ttlSeconds": 259200 }
```

- `restricted` → `201 {"applied": true, "requiresSecondOfficer": false, "status": …}`,
  in force immediately. Waiting for a second signature would cost exactly the
  minutes that matter.
- `blocked` → `202 {"applied": false, "requiresSecondOfficer": true, "proposalId": …}`.

### `POST /proposals/{uuid}/approve`

The approver must be a **different officer** (`SECOND_OFFICER_REQUIRED`) in the
**same institution** (`WRONG_INSTITUTION`). The comparison is on `officer_id`,
not on certificate fingerprint: two certificates issued to the same person are
still one person.

### Appeals

Three constraints shape the design, and each is a refusal:

1. **The customer cannot query or appeal to this service.** An open lookup would
   tell a mule operator whether their account had been detected. The
   account-holding institution raises the appeal on the customer's behalf.
2. **Raising an appeal does not change the status.** An institution must not be
   able to clear a suspicion — its own or anyone else's — by asserting a contest.
   It starts a clock the listing institution must beat.
3. **An unanswered appeal lapses the listing.** Silence favours the account
   holder, because the account holder is the party who cannot act. Same failure
   direction as read-time expiry.

Only the listing institution may answer (`NOT_THE_LISTING_INSTITUTION`), and
answering `upheld` after the deadline fails with `APPEAL_LAPSED` — a listing that
has lapsed cannot be reinstated by answering late.

A reading carries `lapsedFrom` and `lapsedBecause: 'expired' | 'appeal_unanswered'`,
so an operator can tell a listing that expired from one that never existed, and
tell which of the two clocks fired.

### `GET /delta`

```
/delta?since=0&limit=500   →   { since, cursor, complete, changes: [...] }
```

Poll with the returned `cursor`. `complete` is false while more rows remain.
`status_changes` is append-only, enforced by triggers, and `seq` is dense and
monotonic — a consumer that has seen `seq` N has seen everything up to N.

---

## Sharding

```ts
shardFor(account) // first byte of SHA-256(account), hex → 256 shards
```

Hashed rather than prefixed, so one institution's account-numbering scheme cannot
concentrate on a single object. A test asserts 200 sequential identifiers spread
across more than 80 shards.

**Do not change the shard function without a migration plan.** Accounts would
move to different objects while their state stayed in the old ones, and reads
would silently fall back to D1 and re-cache in the wrong place.

---

## Enrolling an officer

No enrolment route, deliberately: a service that can enrol its own operators can
grant itself authority.

```sh
npx wrangler d1 execute kh-sqr-risklist --local --command \
  "INSERT INTO officers VALUES ('<SHA256-FINGERPRINT-UPPERCASE>','ABAAKHPP','sok.dara','officer',1,unixepoch())"
```

Uppercase the fingerprint — `mtls.ts` upper-cases the incoming value, so a
lowercase row never matches. Revoke with `active = 0`; never delete, or old audit
entries become unattributable.

---

## The append-only tables

`audit_log`, `status_changes` and `screenings` all carry `BEFORE UPDATE` and
`BEFORE DELETE` triggers that `RAISE(ABORT, '… is append-only')`, because SQLite
has no `GRANT`. Tests assert every one of them.

The hash chain in `src/audit.ts` is shared with `registry-api` and works
identically — including the rule that a new `AuditEntry` field must be added to
`chainPreimage` in the same commit, or it is unauthenticated and nothing will
tell you. See [`registry-api/DEVELOPMENT.md`](../registry-api/DEVELOPMENT.md#the-audit-log)
for the full account and its two honest limits.

This is not defensive engineering against a hypothetical insider. It is why a
listing made for a reason other than the stated one leaves a record its author
cannot quietly revise.

---

## Rate limiting and the anomaly threshold

| Constant | Value | Meaning |
|---|---|---|
| `RATE_WINDOW_SECONDS` | 3600 | fixed window |
| `OFFICER_WRITES_PER_WINDOW` | 120 | per officer |
| `INSTITUTION_WRITES_PER_WINDOW` | 600 | per institution |
| `INSTITUTION_ANOMALY_THRESHOLD` | 1200 | refused **and recorded as an incident** |

The anomaly threshold is checked *before* the ordinary limits, so a flooding
institution is recorded as an incident rather than merely throttled. **Refused
attempts still count** — an integration that keeps hammering after being
throttled crosses the line and is flagged, which is exactly what distinguishes a
busy afternoon from a compromised or misconfigured caller.

---

## Bindings and migrations

```toml
[[d1_databases]]            binding    = "DB"      database_name = "kh-sqr-risklist"
[[durable_objects.bindings]] name      = "SHARDS"  class_name    = "AccountShard"
[[migrations]] tag = "v1"  new_sqlite_classes = ["AccountShard"]
```

```sh
pnpm --filter @kh-sqr/risklist-api migrate:local
npx wrangler d1 migrations apply kh-sqr-risklist --remote
```

Two different things are called "migrations" here and they are unrelated: the
`[[migrations]]` block in `wrangler.toml` is the Durable Object class migration,
and `migrations/*.sql` are the D1 schema migrations. Adding a new DO class needs
a new `[[migrations]]` tag; adding a table needs a new `.sql` file.

---

## Deploying

```sh
pnpm --filter @kh-sqr/risklist-api deploy
```

Replace `REPLACE_WITH_D1_DATABASE_ID`, apply migrations, and configure
**Cloudflare API Shield mutual TLS** in front of the route. Without it every
request fails closed with 401.

One certificate per *person*, not per institution. An audit entry that says only
"Acleda Bank listed this account" is not an audit entry.

---

## Before you push

```sh
pnpm --filter @kh-sqr/risklist-api test
pnpm check:no-signing-keys
pnpm typecheck && pnpm lint
```

`pnpm check:all` does **not** run Worker tests. Run `pnpm test:workers` too.
