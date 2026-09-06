# AGENTS.md — a guide for AI coding agents working with KH-SQR

You are helping a developer use or extend this repository. This file tells
you what the system is, how to build things on it correctly, and the rules
you must not break. It is written plainly on purpose. When this file and
`SPEC.md` disagree, `SPEC.md` wins.

## 1. What this is, in five sentences

KH-SQR is a proposed way to put a digital signature inside a QR code, so that
a scanner can tell whether a bank, a university or a licensing body really
produced the code. It has two profiles: **Profile A** signs a KHQR/EMVCo
payment code, and **Profile B** signs a document credential such as a degree
or a licence. Verification is **offline**: the app holds a signed list of
issuer keys and checks the code on the device, with no server call. The
signature proves *who made the code*. It never proves that paying is safe or
that the paper in your hand is the one the code was issued for.

Things it is **not**: it is not a standard, it is not adopted by any
authority, and it is not a fraud detector. The repository names *roles*
(Root, scheme operator, timestamp signer, issuer) and never says which
institution should hold them. Keep it that way in anything you write.

## 2. Map of the repository

```
SPEC.md                 the normative specification; wins over everything else
docs/INTEGRATION.md     the long developer guide; this file is the short one
docs/DEPLOYMENT.md      how to run the Root ceremony and the Workers
docs/USE-CASES.md       which real cases fit and which do not
packages/core/          the library. TypeScript, Web Crypto only, runs in Node and browsers
packages/cli/           kid, sign-a, sign-b, verify, build-trustlist, build-timestamp,
                        build-revocations, run-vectors
vectors/vectors.json    the conformance suite: 50 cases, 38 of them rejections
workers/trustlist-edge  serves trust list, timestamp, revocation lists (read-only, keyless)
workers/registry-api    takes key enrolment requests; cannot issue anything
workers/risklist-api    account risk list, screening, appeals (Annex C)
demo/                   an offline PWA that issues and verifies; the built copy is demo/pwa/
tools/                  generators and checks; vectors and the demo are built from here
paper/                  the preprint (LaTeX)
```

## 3. Commands

```sh
pnpm install
pnpm build                 # packages/core and packages/cli → dist/
pnpm test                  # unit tests plus every vector
pnpm check:all             # typecheck, lint, test, build, vectors:check, two guards
pnpm test:workers          # the three Workers, in workerd
pnpm vectors:generate      # regenerate vectors/vectors.json (after changing the generator)
pnpm demo:build            # rebuild demo/pwa/ from demo/src/ and the library
pnpm demo:check            # drive the built demo in headless Chromium
```

Run the CLI as `node packages/cli/dist/index.js <command>`. The core package is
not on npm; a developer consumes it by building this monorepo or copying
`packages/core` into their own build.

## 4. Building a verifier (a wallet, a scanner, an HR tool)

This is what most developers want. The whole job is eight steps.

1. **Pin two keys in the app binary**: the Root public key and the timestamp
   signer public key, as `{ kid, x, y }`. Everything else is fetched and
   checked against these.
2. **Fetch four things in the background**, never at scan time: the trust
   list, the timestamp statement, the revocation lists, and the application
   trust list. The edge service serves them at `/trustlist/current`,
   `/timestamp/current`, `/revocations/current`, `/applications/current`.
3. **Persist** the trust list, timestamp, revocation lists, the time you
   fetched them, and the list version you hold. Refresh daily.
4. **Open a trust anchor** from what you hold. If `TrustAnchor.open` throws,
   you cannot verify anything right now; say so, and never fall back on an
   older state.
5. **On every scan, refuse URLs first** with `assertNotUrlCarrier`, even for
   codes you do not think are yours.
6. **Route**: a `KH1:` prefix is Profile B; otherwise
   `detectProfileAEncoding` returns `2`, `1` or `null` (null means an
   ordinary unsigned code).
7. **Verify** with `verifyProfileA2`, `verifyProfileA` or `verifyProfileB`.
   Each throws a `KhSqrError` with a stable `reason` string on rejection.
8. **Display what the rules require** (section 6 below) and nothing that the
   rules forbid.

Minimal code:

```ts
import {
  TrustAnchor, KhSqrError, assertNotUrlCarrier, detectProfileAEncoding,
  verifyProfileA, verifyProfileA2, verifyProfileB,
} from '@kh-sqr/core';

const anchor = await TrustAnchor.open({
  trustList, timestamp, revocations,          // fetched earlier, persisted
  rootKeys: ROOT_KEYS, timestampKeys: TIMESTAMP_KEYS,
  heldVersion, fetchedAt, now: Math.floor(Date.now() / 1000),
});

async function scan(text: string) {
  const now = Math.floor(Date.now() / 1000);
  assertNotUrlCarrier(text);                                    // throws URL_PAYLOAD_REJECTED
  try {
    if (text.startsWith('KH1:')) return await verifyProfileB({ payload: text, trustAnchor: anchor, now });
    const enc = detectProfileAEncoding(text);
    if (enc === null) return { unsigned: true };               // ordinary KHQR, not a forgery
    return enc === 2
      ? await verifyProfileA2({ payload: text, trustAnchor: anchor, now })
      : await verifyProfileA({ payload: text, trustAnchor: anchor, now });
  } catch (e) {
    if (e instanceof KhSqrError) return { rejected: e.reason }; // stable string, never rename it
    throw e;
  }
}
```

The full pipeline with an outcome type is in `docs/INTEGRATION.md` §1.4, and
`demo/src/app.ts` is a complete working verifier you can copy from.

## 5. Building an issuer (a bank, a university, a licensing body)

1. Generate a P-256 key pair in an HSM. The private key never leaves it. The
   CLI accepts a PEM only so that developers can test.
2. Get the key identifier: `kid --public-key issuer.pub.pem`.
3. Enrol the public key with the scheme operator. The trust-list record you
   end up with carries your `organisationId` (what your credentials must name
   as issuer) and, for payment keys, the `acquirers` you may sign for.
4. **Payment code** (Profile A, encoding 2): `signProfileA2({ payload,
   privateKey, kid, issuedAt, expiresAt, payeeClass })`. A static printed code
   has no amount and no expiry. A dynamic code has an amount and expires
   within 300 seconds. A printed bill with an amount cannot be signed; that is
   a rule, not a bug.
5. **Credential** (Profile B): `signProfileB({ privateKey, kid, claims })`
   with `issuer` equal to your registered `organisationId`, plus
   `documentType`, `documentId`, `subjectName` exactly as printed,
   `issuingOrganisation`, `issueDate`, `issuedAt`, and optionally the
   SHA-256 of the issued file.
6. **Withdrawing one credential**: publish a revocation list with
   `build-revocations`, signed by your current key, with a version number
   that always goes up. Re-sign it at least every 30 days even if nothing
   changed. Hand it to the scheme operator, whose timestamp statement declares
   it. Verifiers that lack a declared list refuse your credentials rather than
   pass them, so publish before the declaration goes out.
7. **Long-lived credentials**: a credential can be verified only while its
   signing key is valid on the trust list. For degrees, use one key per
   graduating cohort with a long validity, and destroy the private key after
   the cohort is signed (SPEC §3.1a).

## 6. Rules a verifier interface must follow

These come from SPEC §8 and the result types are built so that you cannot
easily skip them. Do not write code that works around them.

- **No tick, no boolean, no "verified merchant" badge.** The library returns
  an attestation with fields, not `true`. A valid signature means "a
  registered key made these bytes". It does not mean the payment is safe.
- **Show the amount and its currency together**, as the alphabetic code
  (`payeeDisclosure.currencyAlpha`), never the numeric code and never a bare
  symbol. Riel and dollars differ by a factor of four thousand.
- **For a credential, show the four printed fields** from
  `mustMatchPrintedDocument` and let the reader compare them with the paper.
  A genuine code photographed from a real degree verifies on a forged one.
- **Report standing honestly.** `credentialStatus` is `clear` (checked against
  the issuer's revocation list, whose version and date are in
  `revocationList`) or `unchecked` (the issuer publishes no list). Never show
  `unchecked` as current.
- **Unsigned, rejected and unavailable are three different outcomes.** During
  rollout an unsigned code is a merchant not yet enrolled, not a forgery. A
  rejection is a refusal. "Unavailable" means your own trust state is the
  problem, and the code is not to blame.
- **Never log payload contents.** Log the reason and a timestamp.
- **Never fetch during verification.** Refresh in the background.

## 7. Rejection reasons, grouped by what to do

| Group | Reasons | Action |
|---|---|---|
| Your trust state | `TRUSTLIST_*`, `TIMESTAMP_*`, `REVOCATIONS_MALFORMED/SIGNATURE_INVALID/STALE/ROLLBACK` | refresh and retry once; then "verification unavailable" |
| A declared list you lack | `REVOCATIONS_MISSING` | fetch `/revocations/current`, retry |
| The key | `UNKNOWN_KID`, `KEY_REVOKED`, `KEY_EXPIRED`, `KEY_NOT_YET_VALID`, `KEY_PROFILE_MISMATCH`, `ISSUER_KEY_MISMATCH`, `ACQUIRER_KEY_MISMATCH` | refuse; `UNKNOWN_KID` may be a new issuer, so refresh once first |
| Tampered, forged or foreign | `CRC_*`, `MALFORMED_TLV`, `SIGNATURE_*`, `STATIC_CODE_WITH_AMOUNT`, `EXPIRY_WINDOW_TOO_LONG`, … | refuse and say the code did not verify |
| Time | `CODE_EXPIRED`, `ISSUED_IN_FUTURE` | ask for a fresh code; mention the clock if it recurs |
| Profile B decoding | `PREFIX_INVALID`, `BASE45_INVALID`, `INFLATE_FAILED`, `CBOR_INVALID`, `COSE_INVALID`, `CLAIM_*`, `URL_PAYLOAD_REJECTED` | refuse |
| Withdrawn by the issuer | `CREDENTIAL_REVOKED` | refuse, and say the issuer withdrew it |

Reason strings are part of the conformance contract. Localise the message,
never the reason.

## 8. Porting to another language

Everything you need is `vectors/vectors.json`. Build a trust anchor from each
case's `state`, verify `input.payload`, and match `expect` and `reason`
exactly. You need P-256 ECDSA with SHA-256 and raw `r||s` signatures,
SHA-256, CRC-16/CCITT-FALSE, base45, zlib inflate, and a small strict CBOR
decoder. `docs/INTEGRATION.md` §3 lists the traps each negative case exists
to catch, and `SPEC.md` §2.8 gives the verification order that must be kept.

## 9. Hard rules for agents

Do not do any of these, even if asked casually. Stop and explain instead.

- Do not add a boolean `isValid`, a tick, or any wrapper that reduces a
  result to yes/no. A test fails the build if the types grow one.
- Do not make verification perform network access. A test poisons every
  network global and must keep passing.
- Do not rename, remove or renumber a rejection reason once published.
- Do not commit a private key, a PEM, a scalar, or a real payment payload.
  `pnpm check:no-signing-keys` guards the Workers; you guard the rest.
- Do not commit real people's data. Test names and document numbers in the
  vectors are fictional and must stay so.
- Do not name a ministry, a central bank or a company as the operator of any
  role, in code, docs or the paper. Roles only.
- Do not describe KH-SQR as a standard, as adopted, or as endorsed.
- Do not edit `vectors/vectors.json` or `demo/pwa/` by hand. Change
  `tools/generate-vectors.ts` or `demo/src/` and regenerate.
- Do not present a per-credential revocation check as instantaneous. Offline
  verifiers can be up to seven days behind the issuer.

## 10. Working on this repository itself

- Chain checks with `set -o pipefail` so a piped `tail` cannot hide a failing
  test. Commit only after `pnpm check:all` and, when the demo or a Worker
  changed, `pnpm demo:check` and `pnpm test:workers`.
- Changing the library usually means changing four places: `packages/core`,
  the generator and vectors, the CLI, and the docs (`SPEC.md`,
  `docs/INTEGRATION.md`, the counts in `README.md`). The demo picks up the
  library on `pnpm demo:build`.
- Vector counts appear in `README.md`, `docs/INTEGRATION.md`,
  `docs/DEPLOYMENT.md`, `demo/README.md`, `demo/e2e/pwa.mjs` and the paper.
  Update all of them when the suite changes.
- The paper builds with `make -C paper all` and must report zero unresolved
  references.
- Every rejection reason has one error class in `packages/core/src/errors.ts`
  and appears in at least one vector.
