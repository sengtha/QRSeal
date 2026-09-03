# `registry-api` — developer guide

Accepts issuer certificate signing requests, queues them for the offline Root
ceremony, and publishes the certificates that ceremony produced.

**Serves solution S0** (QRSeal signing) together with `trustlist-edge`: this
half enrols the issuers whose keys that list carries. To stand one up, see
[`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md).

For *why* this service exists, see
[README §6.1](../../README.md#61-the-three-workers-and-what-each-one-is-unable-to-do).
This file is about working on it.

---

## The invariant

**This service must not be able to issue a certificate.**

It accepts a CSR, stores it, and queues it. Later, a ceremony officer uploads a
certificate that the offline Root produced somewhere else. No private key is
reachable from here.

That is the entire reason the portal is online and the Root is not. Compromise
yields the ability to enqueue rubbish and read the queue. It does not yield an
issuer.

Enforced, not merely intended:

- `wrangler.toml` has **no secret binding**, and none may be added.
- `pnpm check:no-signing-keys` fails the build on `crypto.subtle.sign`,
  `generateKey`, `deriveKey`, `unwrapKey`, an `importKey` with the `'sign'`
  usage, a PKCS#8 blob, an inline PEM private key, or a JWK private scalar —
  in source *or* configuration. The check is verified to fail on a deliberately
  introduced violation, not merely to pass.
- `/health` answers `{"holdsSigningKey": false, "canIssue": false}`.

If a change needs any of that relaxed, the change is wrong.

---

## Setup

From the repository root:

```sh
pnpm install
```

Node ≥ 20.

---

## Test loop

**This is the development loop.** Read the next section before reaching for
`wrangler dev`.

```sh
pnpm --filter @kh-sqr/registry-api test         # 18 tests
pnpm --filter @kh-sqr/registry-api test -- --watch
```

Tests run in `workerd` via `@cloudflare/vitest-pool-workers`, against real D1
and R2 bindings in Miniflare. `vitest.config.ts` reads the migrations at config
time and hands them to the test as a `TEST_MIGRATIONS` binding; the suite applies
them in `beforeAll`:

```ts
await applyD1Migrations(typed.DB, typed.TEST_MIGRATIONS);
```

**Authenticating a test request.** There is no login. The suite injects what
Cloudflare would put on the request after terminating mutual TLS:

```ts
init.cf = {
  tlsClientAuth: {
    certVerified: 'SUCCESS',
    certFingerprintSHA256: SUBMITTER,   // 'AA'.repeat(32)
    certSubjectDN: 'CN=officer',
  },
};
```

and `beforeEach` enrols that fingerprint in the `officers` table:

```sql
INSERT INTO officers VALUES (?, 'ABAAKHPP', 'sok.dara', 'submitter', 1, 1756512000)
```

The fingerprint is the join key, **not the subject DN**. A DN is a string an
issuing CA can reuse and two parsers can disagree about; a fingerprint is not.
If you add a role or an actor, add the fingerprint constant and the `officers`
row together — a request with an unenrolled certificate gets 403
`certificate is not enrolled`, which reads like a routing bug and is not one.

---

## Running locally

```sh
pnpm --filter @kh-sqr/registry-api migrate:local
pnpm --filter @kh-sqr/registry-api dev
```

**Only `/health` is reachable this way.** `wrangler dev` cannot terminate mutual
TLS, so every authenticated route answers:

```console
$ curl -s -X POST localhost:8787/csr -H 'content-type: application/json' -d '{"csrPem":"x","profiles":"A"}'
{"error":"client certificate did not verify"}
```

Miniflare does populate `request.cf.tlsClientAuth`, but with `certVerified`
absent, and `src/mtls.ts` treats anything short of `SUCCESS` as no certificate at
all. That is correct behaviour, and it means `wrangler dev` is good for checking
routing, 404s and `/health`, and useless for everything else.

**Do not add a development bypass to `mtls.ts`.** An `if (env.DEV)` branch in the
authentication path is one misconfigured deploy away from an unauthenticated
national registry. Write a test instead — the harness above gives you any
officer, role and certificate state you want, including the failure cases.

---

## Routes

All routes except `/health` require a verified, enrolled, active client
certificate. Roles are `submitter` and `ceremony`.

| Route | Role | Notes |
|---|---|---|
| `GET /health` | — | posture only |
| `POST /csr` | `submitter` | queue a CSR |
| `GET /queue` | `ceremony` | oldest 200 queued requests |
| `GET /csr/{uuid}` | either | a submitter sees only their own institution |
| `POST /csr/{uuid}/decision` | `ceremony` | record the ceremony outcome |
| `GET /audit/export` | `ceremony` | the hash-chained log as NDJSON |

### `POST /csr`

```json
{ "csrPem": "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----\n",
  "profiles": "A,B" }
```

≤ 8 KiB; `profiles` matches `^[AB](,[AB])*$`. The CSR is stored in R2 at
`csr/{institution}/{uuid}.pem` and keyed in D1 by its own SHA-256.

**Resubmission is idempotent.** An identical CSR returns `200` with
`{"duplicate": true}` and the original id, rather than a second queue entry.
That is not a convenience: a ceremony officer facing two identical entries has
to decide which one is real, and there is no correct answer.

→ `201 {"id","status":"queued","csrSha256"}`

### `POST /csr/{uuid}/decision`

```json
{ "decision": "issued",
  "certificatePem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n",
  "kid": "0123456789ABCDEF",
  "note": "ceremony 2026-09-02" }
```

`decision` is `issued` or `rejected`; `kid` is 16 uppercase hex characters. On
`issued` the certificate is stored at `certificates/{institution}/{kid}.pem`.

The `UPDATE` carries `AND status = 'queued'`, and a request that is already
decided gets `409`. **This route records an outcome. It does not produce one** —
the certificate arrives as an artefact made elsewhere.

### `GET /audit/export`

NDJSON, one entry per line, `seq` ascending, plus:

| Header | Meaning |
|---|---|
| `x-kh-sqr-chain-valid` | the chain recomputed cleanly |
| `x-kh-sqr-chain-length` | entries exported |
| `x-kh-sqr-chain-broken-at` | first inconsistent `seq` (absent when valid) |

Newline-delimited so the export can be appended to and hashed incrementally, and
published to a transparency log later without reformatting.

---

## Enrolling an officer

There is **no enrolment route**, deliberately: a service that can enrol its own
operators can grant itself authority. Officers are inserted out of band.

```sh
npx wrangler d1 execute kh-sqr-registry --local --command \
  "INSERT INTO officers VALUES ('<SHA256-FINGERPRINT-UPPERCASE>','ABAAKHPP','sok.dara','submitter',1,unixepoch())"
```

Drop `--local` for the deployed database. The fingerprint must be uppercase —
`mtls.ts` upper-cases the incoming value before the lookup, and a lowercase row
will simply never match.

Revoke by setting `active = 0`. Do not delete the row: the audit log names
`officer_id`, and deleting the officer makes an old entry unattributable.

---

## The audit log

`src/audit.ts` plus the triggers in `migrations/0001_init.sql`. Every state
change appends an entry naming **the institution and the officer**; an entry
naming only an institution is not an audit entry.

Append-only is enforced by SQLite triggers, because SQLite has no `GRANT`:

```sql
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
```

Corrections are new rows. Tests assert both triggers fire.

**The hash chain's preimage is JSON-escaped field by field** before joining
(`chainPreimage`). Without that a writer could split a value across a field
boundary and forge a link that verifies. If you add a field to `AuditEntry`, add
it to `chainPreimage` in the same commit — otherwise the new field is
unauthenticated and every existing entry still verifies, so nothing will tell
you.

Two honest limits, stated in the source and repeated here so they are not
rediscovered as bugs:

- The chain does not stop an operator with database access from **truncating**
  the log. It stops them altering its interior invisibly.
- `append()` reads the previous hash and inserts in two statements, not one
  transaction. Two concurrent appends could read the same predecessor. The
  export verifier reports that as a fork rather than accepting it silently, and
  the write rate here is a handful of events per day.

---

## Bindings and migrations

```toml
[[d1_databases]] binding = "DB"        database_name = "kh-sqr-registry"
[[r2_buckets]]   binding = "ARTIFACTS" bucket_name   = "kh-sqr-registry-artifacts"
```

```sh
pnpm --filter @kh-sqr/registry-api migrate:local          # local
npx wrangler d1 migrations apply kh-sqr-registry --remote  # deployed
```

New migrations go in `migrations/` as `NNNN_name.sql`. `vitest.config.ts` picks
them up automatically — no test wiring needed.

---

## Deploying

```sh
pnpm --filter @kh-sqr/registry-api deploy
```

Replace `REPLACE_WITH_D1_DATABASE_ID` first, create the R2 bucket, apply
migrations, and configure **Cloudflare API Shield mutual TLS** in front of the
route. Without that last step the service is not merely insecure — every request
fails closed with 401, because `certVerified` is never `SUCCESS`.

Each officer holds their own client certificate. One certificate per institution
would make the audit log say "Acleda Bank issued this", which is not an audit
entry; someone specific has to be nameable afterwards.

---

## Before you push

```sh
pnpm --filter @kh-sqr/registry-api test
pnpm check:no-signing-keys
pnpm typecheck && pnpm lint
```

`pnpm check:all` does **not** run Worker tests. Run `pnpm test:workers` too.
