# `trustlist-edge` — developer guide

Serves the trust list, the timestamp statement and the application trust list.
Read-only, and keyless by construction.

**Serves solution S0** (QRSeal signing) together with `registry-api`: this half
distributes what the offline ceremony produced, so a verifier has something to
verify against. To stand one up, see
[`docs/DEPLOYMENT.md`](../../docs/DEPLOYMENT.md) — deploy this Worker first, as
the other two do not depend on it and a verifier is useless without it.

For *why* this service exists and where it sits in the architecture, see
[README §6.1](../../README.md#61-the-three-workers-and-what-each-one-is-unable-to-do).
This file is about working on it.

---

## The invariant

**This Worker must never be able to produce a signed artefact, and must never
be able to mutate one.**

Everything it serves is signed elsewhere: the trust list in an offline Root
ceremony, the timestamp statement by a separate signer outside Cloudflare. This
service is a cache with opinions about caching.

That buys a specific property. An attacker who owns this Worker, its R2 bucket
and its KV namespace can *withhold* or *delay* artefacts — and the verifier in
`packages/core/src/trustlist.ts` already treats withholding as hostile through
its staleness and rollback rules. They cannot issue, alter or backdate one.

Two mechanical consequences you will meet immediately:

- `wrangler.toml` has **no secret binding**, and none may be added.
  `pnpm check:no-signing-keys` fails the build if one appears.
- Any method other than `GET`/`HEAD` is refused **before routing** (`src/index.ts`,
  first statement in `fetch`). There is no mutating route to find, and a test
  asserts every mutating method returns 405.

If a change you are making seems to need either of those relaxed, the change is
wrong. Publication happens out of band — see [Publishing](#publishing) below.

---

## Setup

From the repository root:

```sh
pnpm install
```

Node ≥ 20. Everything else comes from the workspace.

---

## Test loop

This is the primary development loop, and unlike the other two Workers it is
not the *only* one — see [Running locally](#running-locally).

```sh
pnpm --filter @kh-sqr/trustlist-edge test        # 9 tests
pnpm --filter @kh-sqr/trustlist-edge test -- --watch
```

Tests run in `workerd` through `@cloudflare/vitest-pool-workers`, so R2 and KV
are the real bindings against Miniflare rather than mocks. `test/index.test.ts`
seeds the pointer and three artefacts in `beforeEach`:

```ts
await typed.POINTER.put('current', JSON.stringify(POINTER));
await typed.ARTIFACTS.put(POINTER.trustListKey, …);
```

**What the tests are actually holding down.** Four of the nine are not testing
behaviour so much as pinning promises the README and the paper make:

| Test | What breaks if you delete it |
|---|---|
| refuses every mutating method | the read-only claim becomes convention rather than code |
| reports `holdsSigningKey: false` | `/health` stops being an assertion anyone can check |
| does not claim mirror independence | the deployment starts overstating its own conformance |
| serves a versioned object as immutable | the cache story silently inverts |

Treat a failure in those four as a design question, not a test to update.

---

## Running locally

```sh
pnpm --filter @kh-sqr/trustlist-edge dev
```

`wrangler dev` is genuinely useful here, because this service has no
authentication — every route is reachable with `curl`. But it starts empty, so
`/trustlist/current` returns **503 `no trust list has been published`** until
you seed local storage:

```sh
cd workers/trustlist-edge

# One artefact, and a pointer naming it.
echo '{"statement":"{}","signature":{}}' > /tmp/tl.json
npx wrangler r2 object put kh-sqr-artifacts/trustlist/v7.json --file=/tmp/tl.json --local
npx wrangler kv key put --binding=POINTER --local current \
  '{"version":7,"trustListKey":"trustlist/v7.json","timestampKey":"timestamp/1756512000.json","applicationsKey":"applications/v3.json","updatedAt":1756512000}'
```

The `--local` state lives under `.wrangler/state/`. Delete that directory to
start clean.

Then:

```sh
curl -s localhost:8787/health | jq
curl -si localhost:8787/trustlist/current | head -20
curl -si -X POST localhost:8787/trustlist/current    # 405, before routing
```

---

## Routes

| Route | Cache-Control | Notes |
|---|---|---|
| `GET /`, `GET /health` | `no-store` | posture, current version, mirror hints |
| `GET /trustlist/v/{n}` | `max-age=31536000, immutable` | a versioned object never changes |
| `GET /trustlist/current` | `max-age=300, must-revalidate` | adds `x-kh-sqr-version` and `link rel="canonical"` |
| `GET /.well-known/kh-sqr/trustlist` | as above | alias |
| `GET /timestamp/current` | `max-age=60, must-revalidate` | |
| `GET /.well-known/kh-sqr/timestamp` | as above | alias |
| `GET /applications/current` | `max-age=300, must-revalidate` | |

`HEAD` works on all of them. `If-None-Match` against the R2 `httpEtag` returns
304 with the headers intact.

**The three cache lifetimes are not arbitrary, and each encodes a threat.**

- *Immutable* for versioned objects: the content is bound to the version, so
  the only correct revalidation frequency is never.
- *300s, must-revalidate* for `current`: the alias moves when a new list is
  published, and revalidation must stay cheap enough to happen often.
- *60s, must-revalidate* for the timestamp: the timestamp statement **is** the
  freshness signal. Caching it for long would recreate exactly the freeze the
  statement exists to detect. If you find yourself raising this number for
  performance, you are trading away the property the endpoint is for.

---

## Bindings

```toml
[[r2_buckets]]     binding = "ARTIFACTS"  bucket_name = "kh-sqr-artifacts"
[[kv_namespaces]]  binding = "POINTER"    id = "REPLACE_WITH_KV_NAMESPACE_ID"
[vars]             MIRROR_HINTS = "https://…,https://…"
```

**KV is correct here, and it is wrong in `risklist-api`.** The difference is
worth internalising, because it is the same decision reached two ways. Here the
pointer is a cache hint over immutable, independently-signed content: a stale
read serves an older *validly signed* list, which the verifier's staleness rules
already handle. In `risklist-api` an eventually consistent read means a
just-listed mule account still reads clear, during the seconds it is being
drained. Same primitive, opposite consequence.

`MIRROR_HINTS` is a comma-separated list echoed in the `x-kh-sqr-mirrors`
header and at `/health`. It is a **hint**, not a conformance claim — see below.

---

## Mirror independence, and why `/health` admits to failing it

The specification requires publication at three mirrors under distinct
operational control. This deployment is one provider, one account, one
governance failure. `/health` says so:

```json
{ "mirrorIndependence": "not satisfied by this deployment; see README.md" }
```

A test asserts that string still matches `/not satisfied/`. Do not "fix" that
test by changing the string. It becomes true when there is a second and third
publication path under different operational control — at which point the string
changes because the fact changed. Until then this is a primary, not a
conforming mirror set.

---

## Publishing

There is deliberately no publication route. New artefacts arrive by an out-of-band
job that writes to R2 and then updates the KV pointer:

1. Upload the versioned object (`trustlist/v{n}.json`).
2. Upload the timestamp statement and application list.
3. **Last**, write the pointer naming all three.

Order matters. The pointer is the commit: writing it before its objects exist
produces a window in which `/trustlist/current` 404s while `/health` claims a
version. Nothing in this Worker enforces the ordering, because this Worker never
writes — so the publication job owns it.

---

## Deploying

```sh
pnpm --filter @kh-sqr/trustlist-edge deploy
```

Before the first deploy, replace `REPLACE_WITH_KV_NAMESPACE_ID` in
`wrangler.toml` and create the R2 bucket. `workers_dev = false` is set
deliberately: this service should be reachable at the operational hostname and
not at a `workers.dev` subdomain that nobody is watching.

---

## Before you push

```sh
pnpm --filter @kh-sqr/trustlist-edge test
pnpm check:no-signing-keys
pnpm typecheck && pnpm lint
```

`pnpm check:all` runs the repository-wide checks but **does not** run the Worker
tests. Run `pnpm test:workers` too.
