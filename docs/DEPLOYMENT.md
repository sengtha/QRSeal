# Deployment and setup

How to stand up the three QRSeal Workers from nothing, in the order the
dependencies actually require.

**This is a reference implementation.** It has not been independently audited
and is not represented as fit for production deployment. Two of its own
specification's preconditions are unmet — see
[What this deployment does not satisfy](#what-this-deployment-does-not-satisfy)
before deploying anything anyone relies on.

For working *on* a Worker rather than deploying it, each has its own guide:
[`trustlist-edge`](../workers/trustlist-edge/DEVELOPMENT.md),
[`registry-api`](../workers/registry-api/DEVELOPMENT.md),
[`risklist-api`](../workers/risklist-api/DEVELOPMENT.md).

---

## Which Worker serves which solution

QRSeal is the specification (KH-SQR) plus seven numbered proposals (S0–S6).
**Only three of the seven have running code, and the three Workers are it.**

| Solution | Worker | What the Worker does |
|---|---|---|
| **S0** — QRSeal signing<br/>*solves P1, P2, P7* | `registry-api` | Queues issuer CSRs for the offline ceremony and publishes the certificates it produced. **Cannot issue one.** |
| | `trustlist-edge` | Serves the trust list, timestamp statement and application trust list that a verifier needs. **Read-only.** |
| **S3** — Screening at the moment of payment | `risklist-api` | `POST /screen` → `allow` / `warn` / `hold` / `block` before funds are released |
| **S4** — The right to contest a listing | `risklist-api` | `POST /appeals`, the answering deadline, and the lapse when nobody answers |

**The other four have no Worker, and that is not an omission:**

| Solution | Why no code |
|---|---|
| **S1** — Mandatory incident reporting | A reporting obligation between institutions and regulators. Nothing to deploy; it needs an instrument, not a service. |
| **S2** — Categorical URL prohibition | A rule applied at issuance and in the wallet. The prohibition is normative (SPEC §8); enforcement is the wallet's. |
| **S5** — Liability allocation | Policy. Who bears an unrecovered loss is not a thing software decides. |
| **S6** — Exit controls on cash-out | Proposed, not designed. Thresholds, risk classes and the cost to legitimate small traders are unspecified — see the paper's Limitations. |

So the deployment surface is smaller than the proposal set, deliberately.
`risklist-api` carries two solutions because screening and appeals act on the
same listing and must share one consistency point; splitting them would let a
screen read a status an appeal had already lapsed.

### One naming collision to know about

In README §5's diagrams, `REG` is `registry-api` under S0 but "NBC / regulator"
under S5. Same node label, different meaning, different diagram.

---

## Which of these can be exposed publicly

Only one, and the difference is structural rather than a matter of caution.

| Worker | Public? | Why |
|---|---|---|
| `trustlist-edge` | **Yes** | No authentication by design — the trust list is *meant* to be fetchable by anyone. Read-only: every mutating method is refused before routing. Holds no key. Full compromise yields withholding, which the verifier already treats as hostile. |
| `registry-api` | **No** | Every route but `/health` requires a client certificate. Without API Shield mTLS configured, `cf.tlsClientAuth` is absent and everything returns 401. Safe, but a public tester reaches exactly one endpoint. |
| `risklist-api` | **Never** | Same gate, plus one officer can restrict a real account for 72 hours. Public write access means strangers freezing account identifiers. |

Exposing the two authenticated services is not blocked by caution but by
arithmetic: to let someone use them you must issue them a client certificate,
which is onboarding, not public testing.

### If you publish `trustlist-edge` as a demo

Three things to get right, because this project is about people trusting
artefacts that do not deserve it.

1. **Label it.** A demo list is signed by the repository's published test Root
   key, whose private half is public and protects nothing. Say so at the
   hostname, or you have built the exact artefact this paper warns about: a
   thing that verifies and should not be believed.
2. **Set `MIRROR_HINTS` to hosts you actually operate.** It is echoed verbatim
   at `/health` and in `x-kh-sqr-mirrors` on every response, so it tells the
   world where to fetch an authoritative list. Never name an institution that
   has not agreed to operate a mirror.
3. **`workers_dev = false` is deliberate** — these should answer at an
   operational hostname, not a `workers.dev` subdomain nobody watches. Flipping
   it to `true` for a throwaway demo is reasonable; leaving it flipped for
   anything else is not.

### The better public test needs no server at all

Verification performs no network access — a test poisons every network global
and verifies both reference payloads anyway. So the whole Profile A story is
testable by anyone, offline, with no attack surface:

```sh
kh-sqr run-vectors --file vectors/vectors.json   # 50 cases, 38 negative
kh-sqr verify --payload @payload.txt --trustlist @trustlist-v1.json \
  --root-keys @root-keys.json --timestamp @timestamp-1.json
```

Profile A reaches seven modules and depends on nothing beyond Web Crypto, so
the same verification runs unmodified in a browser. That is what the sandbox
PWA under `demo/pwa/` is: it generates its own scheme in the browser, issues
and verifies both profiles, and runs offline. It is served by a fourth,
assets-only Worker, `workers/demo-pwa`, which holds nothing and exposes
nothing writable — see [`demo/README.md`](../demo/README.md) and
[`workers/demo-pwa/DEVELOPMENT.md`](../workers/demo-pwa/DEVELOPMENT.md).
Because its keys are generated on the device, it does not even need the
published test Root, and nothing it verifies can be mistaken for a real
attestation by anyone who reads its footer.

---

## Before you start

You need, and this repository does not provide:

- A **Cloudflare account** with Workers, D1, R2, KV and Durable Objects.
- **Cloudflare API Shield mutual TLS** on the routes for `registry-api` and
  `risklist-api`. Without it every authenticated route fails closed with 401,
  because `certVerified` is never `SUCCESS`. This is not optional configuration;
  it *is* the authentication.
- An **offline, air-gapped machine** for the Root ceremony.
- A **client certificate per officer** — per person, not per institution. An
  audit entry naming only "Acleda Bank" is not an audit entry.

Local prerequisites: Node ≥ 20, `pnpm`, and a `wrangler login`.

```sh
pnpm install
pnpm build
pnpm check:all          # typecheck, lint, tests, vectors, isolation, key check
pnpm test:workers       # 64 Worker tests — check:all does NOT include these
```

---

## Step 0 — The Root ceremony, offline

**Do this first.** Nothing verifies until a signed trust list exists, and no
Worker can produce one: the edge holds no private key of any kind, and
`pnpm check:no-signing-keys` fails the build if one appears.

On the air-gapped machine, with the CLI from `packages/cli`:

```sh
# 1. Generate the Root key pair with your HSM or offline tooling.
#    This repository deliberately provides no key-generation command.

# 2. Derive the key identifier for each issuer's public key.
kh-sqr kid --public-key issuer-acleda.pub.pem

# 3. Assemble keys.json — one TrustedKeyRecord per issuer:
#    { "kid", "x", "y", "profiles", "status", "notBefore", "notAfter",
#      "subject": { "name", "organisationId" }, "acquirers": [ ... ] }
#    organisationId is what the issuer's Profile B credentials must name;
#    acquirers lists the merchant-account identifiers its Profile A codes may
#    pay into (exact values, or "@bank" suffixes). Both are trust decisions.
#    x and y are 64 uppercase hex characters each.

# 4. Sign the trust list with the Root key.
kh-sqr build-trustlist --keys @keys.json --version 1 \
  --expires 1790000000 --key root.pkcs8.pem --kid <ROOT_KID> > trustlist-v1.json

# 5. Sign a timestamp statement over it. This is the freshness signal;
#    it is valid for seven days and must be reissued before it expires.
#    Pass every issuer's current revocation list (SPEC §4.5), and the
#    statement declares each by version and digest; a verifier then refuses a
#    credential whose declared list it does not hold, rather than passing it.
kh-sqr build-timestamp --trustlist @trustlist-v1.json \
  --revocations @revocations-moeys-v3.json \
  --key timestamp.pkcs8.pem --kid <TS_KID> > timestamp-1.json
```

An issuer produces its revocation list with its own current key, not in this
ceremony (`kh-sqr build-revocations`, [`docs/INTEGRATION.md`](INTEGRATION.md)
§2.6), and hands the signed file to whoever runs the timestamp signer.

The timestamp signer is a **separate key from the Root**, held outside
Cloudflare. Reissuing the timestamp is a recurring operational duty, not a
one-off: a verifier that cannot obtain a fresh statement stops verifying rather
than falling back on what it holds.

Carry `trustlist-v1.json` and `timestamp-1.json` off the air-gapped machine.

---

## Step 1 — `trustlist-edge`

Deploy this **before** the other two: a verifier is useless without it, and it
has no dependency on them.

```sh
npx wrangler r2 bucket create kh-sqr-artifacts
npx wrangler kv namespace create POINTER          # note the id it prints
```

Put the KV id into `workers/trustlist-edge/wrangler.toml`, replacing
`REPLACE_WITH_KV_NAMESPACE_ID`. Set `MIRROR_HINTS` to the real mirror URLs.

```sh
pnpm --filter @kh-sqr/trustlist-edge deploy
```

### Publishing artefacts, and why the order matters

There is deliberately **no publication route** — this Worker never writes. An
out-of-band job uploads to R2 and then updates the KV pointer:

```sh
npx wrangler r2 object put kh-sqr-artifacts/trustlist/v1.json --file=trustlist-v1.json --remote
npx wrangler r2 object put kh-sqr-artifacts/timestamp/1.json  --file=timestamp-1.json  --remote
npx wrangler r2 object put kh-sqr-artifacts/applications/v1.json --file=applications-v1.json --remote

# The pointer LAST. It is the commit.
npx wrangler kv key put --binding=POINTER --remote current \
  '{"version":1,"trustListKey":"trustlist/v1.json","timestampKey":"timestamp/1.json","applicationsKey":"applications/v1.json","updatedAt":1790000000}'
```

Writing the pointer before its objects exist produces a window in which
`/trustlist/current` returns 404 while `/health` reports a version. Nothing in
the Worker enforces the ordering, because the Worker never writes — the
publication job owns it.

Until a pointer exists, `/trustlist/current` returns **503 `no trust list has
been published`**. That is correct, not a fault.

Check:

```sh
curl -s https://<host>/health | jq
# holdsSigningKey: false, readOnly: true, currentVersion: 1
```

---

## Step 2 — `registry-api`

```sh
npx wrangler d1 create kh-sqr-registry              # note the database_id
npx wrangler r2 bucket create kh-sqr-registry-artifacts
```

Replace `REPLACE_WITH_D1_DATABASE_ID` in `workers/registry-api/wrangler.toml`,
then:

```sh
npx wrangler d1 migrations apply kh-sqr-registry --remote
pnpm --filter @kh-sqr/registry-api deploy
```

Configure API Shield mTLS on the route. Then enrol officers — there is **no
enrolment route**, deliberately, because a service that can enrol its own
operators can grant itself authority:

```sh
npx wrangler d1 execute kh-sqr-registry --remote --command \
  "INSERT INTO officers VALUES ('<SHA256-FINGERPRINT-UPPERCASE>','ABAAKHPP','sok.dara','submitter',1,unixepoch())"
```

Roles are `submitter` (may `POST /csr`) and `ceremony` (may read the queue and
record decisions). **The fingerprint must be uppercase** — the lookup
upper-cases the incoming value, so a lowercase row never matches. Revoke with
`active = 0`; never delete, or old audit entries become unattributable.

---

## Step 3 — `risklist-api`

```sh
npx wrangler d1 create kh-sqr-risklist              # note the database_id
```

Replace `REPLACE_WITH_D1_DATABASE_ID` in `workers/risklist-api/wrangler.toml`.
The `[[migrations]]` block already declares the `AccountShard` Durable Object;
that is a *different* thing from the D1 schema migrations in `migrations/`.

```sh
npx wrangler d1 migrations apply kh-sqr-risklist --remote   # 0001 and 0002
pnpm --filter @kh-sqr/risklist-api deploy
```

Configure API Shield mTLS, then enrol officers as above. Roles here are
`reader` (status and screening), `officer` (may list and propose) and
`supervisor` (adds `/audit/export`).

### Two policy decisions to make before anyone depends on it

**`LOW_VALUE_SCREENING_THRESHOLD` is `{ KHR: 0, USD: 0 }`** — every payment to a
restricted account is held. The safe value is the default. A regulator who wants
less friction on small payments must choose the number and own it; it is a
policy parameter, not a technical constant.

**Screening must fail open in the caller.** Everything else in this system fails
closed, and this cannot: a screening call that refuses to answer during an
availability incident is a national payment outage. An unreachable service means
`unscreened`, and **`unscreened` is not `clear`** — the calling PSP must
distinguish them. Nothing in this Worker can enforce that; it is a contract on
the caller.

---

## Smoke test

```sh
# S0 — the trust list a verifier will actually fetch
curl -s https://<trustlist-host>/trustlist/current | jq .signature.kid

# Verify a reference payload against it, offline
kh-sqr verify --payload @payload.txt --trustlist @trustlist-v1.json \
  --root-keys @root-keys.json --timestamp @timestamp-1.json

# The whole conformance suite against this implementation
kh-sqr run-vectors --file vectors/vectors.json      # 50 cases, 38 negative

# S3/S4 — posture only; every other route needs a client certificate
curl -s https://<risklist-host>/health | jq
```

---

## What this deployment does not satisfy

Stated here rather than discovered later. All four are recorded in the paper's
Limitations and in README §10.

1. **Mirror independence is unmet.** The specification requires publication at
   three mirrors under distinct operational control. This is one provider, one
   account, one governance failure. `/health` says so in its own response, and a
   test asserts it keeps saying so. It is a primary, not a conforming mirror set.

2. **The scheme GUID must be settled before issuance.** The default is
   `KH.QRSEAL.SQR` — it names the project and the country and asserts no
   institution, deliberately. It is part of the wire format and cannot be changed
   afterwards without a further encoding version (SPEC §2.9 clause 3).

3. **Template identifiers `85`, `86` and `87` must be confirmed unused** against
   the national scheme's own merchant-presented guideline and against every
   scheme it is linked to for cross-border acceptance (SPEC §2.9 clause 3a).
   We have checked JPQR, which allocates only `80` and nothing in `81`–`99`.
   **Cambodia's own guideline is unchecked.** EMVCo reserves `80`–`99` without
   allocating within it, so two schemes may independently pick the same
   identifier for different content.

4. **Coverage is a precondition and is unaddressed.** A signature asks a verifier
   to act on an *absence*, and below saturation an unsigned code means an
   unenrolled merchant far more often than a forgery. A partial deployment is not
   a proportionate fraction of the value. There is no enrolment model here, no
   cost estimate, and no answer for what a verifier should display while coverage
   is partial — which is the interval of maximum exposure.

---

## Invariants that must survive any deployment change

Enforced by CI, not by review. `pnpm check:no-signing-keys` runs over Worker
source *and* configuration and fails on a signing key, a key generation or
derivation call, a PKCS#8 blob, an inline PEM private key, or a JWK private
scalar. It is verified to fail on a deliberately introduced violation.

- **No Worker holds a private key.** The Root signs offline; issuer keys live in
  each institution's HSM; the timestamp signer sits outside Cloudflare.
- **No secret binding in any `wrangler.toml`.** None may be added.
- **`workers_dev = false`** on all three: these should answer at the operational
  hostname, not at a `workers.dev` subdomain nobody is watching.
- **The audit log is append-only**, enforced by SQLite triggers rather than
  convention, in both write services. Corrections are new rows.
