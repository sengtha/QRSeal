# Integrating KH-SQR

A guide for developers, in four parts:

1. [**Wallet or verifier integration**](#1-wallet-or-verifier-integration) —
   you scan codes and must decide what to show.
2. [**Issuer integration**](#2-issuer-integration) — you produce codes and
   hold a signing key.
3. [**Porting to another language**](#3-porting-to-another-language) — you are
   writing a Kotlin, Swift, Go or Rust implementation and want to prove it
   conforms.
4. [**API reference**](#4-api-reference) for `@kh-sqr/core` and the CLI.

`SPEC.md` is normative and wins over anything here. This document tells you
how to use the reference implementation and what the specification's rules
mean at the point where you call a function. Where a rule is a MUST, the
section number in the specification is given so you can read the reason.

**Status, stated first.** The `@kh-sqr/core` package is not published to a
registry; you consume it by building this monorepo (§4.1). The implementation
has one author, no external audit, and a conformance suite that has not yet
been run against an independent port (README §10). Two things cannot be
expressed at all, and both are rules rather than gaps you can work around: a
printed bill carrying an amount (§2.4), and a credential whose life exceeds its
signing key's (§2.5). Read those two sections before you design around them.

---

## 1. Wallet or verifier integration

### 1.1 What you embed

Profile A verification depends on Web Crypto and nothing else: no CBOR, no
streams, no polyfill. A build check (`pnpm check:profile-a-isolation`) fails
if that ever changes. Profile B additionally needs `DecompressionStream`
(`'deflate'`) for the zlib layer. Your runtime therefore needs:

| Profile | Requires |
|---|---|
| A (payment) | `crypto.subtle` with ECDSA P-256 / SHA-256 verify |
| B (credential) | the above, plus `DecompressionStream` |

Node 20+, every current browser, and Cloudflare Workers satisfy both. A
React Native or Flutter shell needs a Web Crypto bridge; a native app should
port rather than bridge (§3).

### 1.2 Pin two keys before you fetch anything

The trust list is signed by an offline Root; the timestamp statement is
signed by a separate online signer. Both public keys are **pinned in your
application and never fetched**. Ship them as constants:

```ts
import type { PinnedKey } from '@kh-sqr/core';

// From the scheme operator, out of band. Never from the trust-list service.
export const ROOT_KEYS: readonly PinnedKey[] = [
  { kid: 'ED305634665F665A', x: '32D6…3437', y: 'A397…469A' },
];
export const TIMESTAMP_KEYS: readonly PinnedKey[] = [
  { kid: '64D797C34895E71C', x: '7855…4DA8', y: 'D8AE…B1FF' },
];
```

The values above are the **published test keys** from `vectors/vectors.json`.
They protect nothing. A deployment pins the keys produced by its own Root
ceremony (`docs/DEPLOYMENT.md`, step 0). Ship more than one Root key when a
rotation is planned, so that the next list still opens.

### 1.3 Fetch, persist, refresh

The edge service is read-only and serves three JSON artefacts:

| Route | What | Refresh |
|---|---|---|
| `GET /trustlist/current` | signed trust list; header `x-kh-sqr-version` | daily |
| `GET /timestamp/current` | signed statement naming the current list version and digest; valid 7 days | daily, and always before the timestamp expires |
| `GET /applications/current` | application trust list (verifier authenticity) | daily |

Alias paths under `/.well-known/kh-sqr/` serve the first two. `HEAD` and
`If-None-Match` work. Each artefact has the shape:

```json
{ "statement": "<opaque JSON string>", "signature": { "alg": "ES256", "kid": "…", "value": "<128 hex>" } }
```

Treat `statement` as an opaque string. The signature covers its exact bytes,
and the library parses that same string; you never re-serialise it.

**Persist four things** between runs, in application storage that survives
restarts:

| Field | Why |
|---|---|
| the trust-list artefact | verification is offline; this is what you verify against |
| the timestamp artefact | freeze protection; without a fresh one the verifier stops |
| `fetchedAt` (Unix seconds) | cache age is measured from here; the limit is 30 days |
| `heldVersion` | rollback protection: a list numbered below this is refused |

A fetch loop that respects the rules:

```ts
import { TrustAnchor } from '@kh-sqr/core';

interface TrustState {
  trustList: unknown; timestamp: unknown; fetchedAt: number; heldVersion: number | undefined;
}

async function refreshTrust(origin: string, held: TrustState | null, now: number): Promise<TrustState> {
  const [trustList, timestamp] = await Promise.all([
    fetch(`${origin}/trustlist/current`).then((r) => r.json()),
    fetch(`${origin}/timestamp/current`).then((r) => r.json()),
  ]);
  // Open before persisting. A list that does not open is not held.
  const anchor = await TrustAnchor.open({
    trustList, timestamp, rootKeys: ROOT_KEYS, timestampKeys: TIMESTAMP_KEYS,
    heldVersion: held?.heldVersion, fetchedAt: now, now,
  });
  return { trustList, timestamp, fetchedAt: now, heldVersion: anchor.version };
}

async function openHeld(held: TrustState, now: number): Promise<TrustAnchor> {
  return TrustAnchor.open({
    trustList: held.trustList, timestamp: held.timestamp,
    rootKeys: ROOT_KEYS, timestampKeys: TIMESTAMP_KEYS,
    heldVersion: held.heldVersion, fetchedAt: held.fetchedAt, now,
  });
}
```

`TrustAnchor.open` performs every list-level check: Root signature, version
monotonicity, list expiry, cache age, timestamp signature, timestamp expiry,
and that the timestamp names this exact list version and digest. If it
returns, the anchor is usable. If it throws, the reason tells you which rule
failed (§1.7).

**Refresh from the background, never from the payment path.** Verification
takes an anchor you already hold and performs no network access (SPEC §6). A
verifier that fetched at scan time could be stalled or steered by whoever
controls the network at the stall.

**When you cannot refresh.** The held state keeps working until one of two
clocks runs out: the timestamp statement expires seven days after issuance,
and the cached list is refused thirty days after `fetchedAt`. After that,
`open` throws `TIMESTAMP_EXPIRED` or `TRUSTLIST_STALE` and you can no longer
verify anything. That is deliberate: the alternative is a verifier pinned by a
hostile network to a list in which a revoked key is still good. Your interface
then treats every code as unsigned (§1.6) and says, in its own diagnostics,
that verification is unavailable. It does not show a tick, and it does not
show a warning against the code, because the fault is yours and not the
code's.

### 1.4 The scan pipeline

Every scanned string goes through the same five steps, in this order, whether
or not you expect it to be KH-SQR:

1. **Refuse URL carriers.** `assertNotUrlCarrier` throws
   `URL_PAYLOAD_REJECTED` for any `http` or `https` string. Run it on *every*
   scan, not only on codes you think are yours (SPEC §3.2). A payment
   application that opens a browser has moved the trust decision to a domain
   name.
2. **Route.** `KH1:` prefix → Profile B. Otherwise
   `detectProfileAEncoding` says `2`, `1`, or `null`.
3. **Verify** under the profile and encoding named.
4. **Classify the outcome** as verified, unsigned, or rejected. These are
   three different things (§1.6).
5. **Display** what the specification obliges you to (§1.5).

```ts
import {
  KhSqrError, TrustAnchor, assertNotUrlCarrier, detectProfileAEncoding,
  verifyProfileA, verifyProfileA2, verifyProfileB,
} from '@kh-sqr/core';
import type {
  CredentialAssertion, PaymentAttestation, PaymentAttestationV2, RejectionReason,
} from '@kh-sqr/core';

export type ScanOutcome =
  | { kind: 'payment'; attestation: PaymentAttestation | PaymentAttestationV2 }
  | { kind: 'credential'; assertion: CredentialAssertion }
  | { kind: 'unsigned-payment'; payload: string }
  | { kind: 'rejected'; profile: 'A' | 'B'; reason: RejectionReason }
  | { kind: 'refused-url' };

export async function classifyScan(scanned: string, anchor: TrustAnchor, now: number): Promise<ScanOutcome> {
  try {
    assertNotUrlCarrier(scanned);
  } catch {
    return { kind: 'refused-url' };
  }

  if (scanned.startsWith('KH1:')) {
    try {
      return { kind: 'credential', assertion: await verifyProfileB({ payload: scanned, trustAnchor: anchor, now }) };
    } catch (error) {
      if (error instanceof KhSqrError) return { kind: 'rejected', profile: 'B', reason: error.reason };
      throw error;
    }
  }

  const encoding = detectProfileAEncoding(scanned);
  if (encoding === null) return { kind: 'unsigned-payment', payload: scanned };

  try {
    const attestation = encoding === 2
      ? await verifyProfileA2({ payload: scanned, trustAnchor: anchor, now })
      : await verifyProfileA({ payload: scanned, trustAnchor: anchor, now });
    return { kind: 'payment', attestation };
  } catch (error) {
    if (error instanceof KhSqrError) return { kind: 'rejected', profile: 'A', reason: error.reason };
    throw error;
  }
}
```

`now` is Unix seconds from the device clock. Dynamic codes expire within 300
seconds of issuance, and issuance more than 60 seconds in the future is
refused (`clockSkewSeconds` adjusts that), so a device with a badly wrong
clock will reject genuine codes with `CODE_EXPIRED` or `ISSUED_IN_FUTURE`.
Say so in the diagnostic rather than blaming the merchant.

Both encodings must be verified for years to come: version 1 is frozen for
new issuance but printed stickers carrying it stay in circulation (SPEC §2.9,
*Migration*).

### 1.5 What you must display, and what you must not

The result of a successful Profile A verification carries a
`payeeDisclosure`. The name is awkward on purpose: a caller who wants a yes/no
answer has to walk past it. The specification's interface obligations (§8)
are:

| Rule | Level |
|---|---|
| Never present a valid signature as an assurance that the payment is safe | MUST |
| Show the amount **and its currency together** before authorisation, whenever the payload carries an amount | MUST |
| Show the currency as the alphabetic code (`currencyAlpha`) or an unambiguous name; never the numeric code from tag 53; never a bare symbol where it is ambiguous | MUST |
| Where `currencyAlpha` is `null`, say the currency is unrecognised; never imply the local one | MUST |
| Make merchant name, city, country, payee class and account identifiers available; show them before authorisation | SHOULD |
| Never log payload contents | MUST |

Why the currency rules are MUST and the rest SHOULD: a genuine code whose
amount is authentic and whose currency the payer misreads is the one case in
which a valid signature actively assists the attacker. In Cambodia the two
live currencies differ by a factor of about four thousand, and a tuk-tuk fare
of 7,200 has already been collected once as dollars instead of riel.

```ts
import type { PayeeDisclosure } from '@kh-sqr/core';

function renderBeforeAuthorising(p: PayeeDisclosure): string[] {
  const lines: string[] = [];
  lines.push(`Pay to: ${p.merchantName ?? '(no name in code)'}${p.merchantCity ? ', ' + p.merchantCity : ''}`);
  lines.push(`Payee class: ${p.payeeClass === 'M' ? 'merchant' : 'individual'}`);

  if (p.amount !== null) {
    // The amount and the currency are one string. Never split them across the screen.
    const currency = p.currencyAlpha ?? 'UNRECOGNISED CURRENCY';
    lines.push(`Amount: ${p.amount} ${currency}`);
    if (p.currencyAlpha === null) lines.push('This code names a currency this app does not recognise.');
  } else {
    lines.push('Amount: you enter it. Check the currency you are paying in.');
  }
  return lines;
}
```

Three things not to build:

- **A tick.** Not green, not any colour. The library will not give you a
  boolean, and the result types are tested to have none. A tick teaches the
  payer that the system has checked on their behalf, which is exactly the
  belief a genuine code with a false story depends on.
- **A "verified merchant" badge** derived from the signature. The signature
  says a registered issuer produced these bytes. Registration is not
  legitimacy.
- **A warning against unsigned codes** before your deployment has reached
  coverage (§1.6).

### 1.6 Unsigned, rejected, and unavailable are three different things

| Outcome | What it means | What to do |
|---|---|---|
| `unsigned-payment` | An ordinary EMVCo code with no signature template | During rollout this is a merchant not yet enrolled, not a forgery. Show the payee fields you can read from the plain EMVCo payload, with the same amount-and-currency rule. **No visible difference** from a signed code until the scheme reaches its coverage gate (`docs/ADOPTION.md`, phase 3). |
| `rejected` | A code that *claims* a signature and fails | Refuse, and say why in terms the payer can act on (§1.7). A rejection is a tampered, forged, expired or foreign code, or your own stale trust state. It is never "probably fine". |
| verification unavailable | `TrustAnchor.open` threw | Treat every code as unsigned and say verification is unavailable. The fault is your trust state, not the code. |

The middle row is where wallets get this wrong. A code carrying template `85`
that does not verify is a strong signal, because an honest issuer's code
verifies. Do not fall back to treating it as unsigned.

### 1.7 Rejection reasons, grouped by what to do

Every rejection is a `KhSqrError` with a stable `reason`. Never localise or
rename the reason; localise the message you show. The groups below cover all
of them.

**Your trust state is the problem.** Refresh (§1.3) and retry once; if it
persists, verification is unavailable.

`TRUSTLIST_MALFORMED` `TRUSTLIST_SIGNATURE_INVALID` `TRUSTLIST_ROLLBACK`
`TRUSTLIST_EXPIRED` `TRUSTLIST_STALE` `TIMESTAMP_MALFORMED`
`TIMESTAMP_SIGNATURE_INVALID` `TIMESTAMP_EXPIRED` `TIMESTAMP_TARGET_MISMATCH`
`TIMESTAMP_MISSING`

**The key is the problem.** Refuse. `UNKNOWN_KID` on a list older than a day
may be a newly enrolled issuer, so refresh and retry once before refusing.

`UNKNOWN_KID` `KEY_REVOKED` `KEY_EXPIRED` `KEY_NOT_YET_VALID`
`KEY_PROFILE_MISMATCH` `KEY_MALFORMED` `ISSUER_KEY_MISMATCH` (a registered key
signed a credential in another institution's name) `ACQUIRER_KEY_MISMATCH` (a
registered key signed a payment code paying into an account it is not
registered for)

**The code is tampered, forged, or foreign.** Refuse. Tell the payer the code
did not verify and not to pay it. These are the reasons the negative test
vectors exist for.

`CRC_MISSING` `CRC_MALFORMED` `CRC_MISMATCH` `MALFORMED_TLV` `DUPLICATE_TAG`
`SIGNATURE_TEMPLATE_MISSING` `SIGNATURE_TEMPLATE_NOT_LAST`
`SIGNATURE_SUBTAG_NOT_LAST` `SIGNATURE_SUBTAG_MALFORMED`
`SIGNATURE_ENCODING_INVALID` `SIGNATURE_INVALID` `UNSUPPORTED_FORMAT_VERSION`
`UNSUPPORTED_ALGORITHM` `MALFORMED_KID` `MALFORMED_TIMESTAMP`
`MALFORMED_PAYEE_CLASS` `STATIC_CODE_WITH_AMOUNT` `STATIC_CODE_WITH_EXPIRY`
`DYNAMIC_CODE_MISSING_EXPIRY` `EXPIRY_WINDOW_TOO_LONG` `EXPIRY_BEFORE_ISSUANCE`

**Time.** A dynamic code has expired, or the device clock is wrong. Ask the
merchant to show a fresh code; mention the clock if it recurs.

`CODE_EXPIRED` `ISSUED_IN_FUTURE`

**Profile B only.** Not a credential, or not one of ours. Refuse.

`PREFIX_INVALID` `BASE45_INVALID` `INFLATE_FAILED` `CBOR_INVALID` `COSE_INVALID`
`CLAIM_MISSING` `CLAIM_TYPE_INVALID` `URL_PAYLOAD_REJECTED`

The library's own messages never contain payload content, and yours must not
either (SPEC §8, last clause). Log the reason and a timestamp; never the code.

### 1.8 Verifying a credential (Profile B)

A valid signature proves the credential was issued. It does not prove it
belongs to the paper it is printed on: a genuine code photographed from a real
degree and printed onto a forged one verifies perfectly. The only defence is
comparing the signed fields with the visible document, and the API is shaped
so that a caller cannot skip it. `CredentialAssertion` has no `isValid` and
no boolean; it has `mustMatchPrintedDocument`.

```ts
import type { CredentialAssertion, PrintedDocumentFields } from '@kh-sqr/core';

function presentCredential(a: CredentialAssertion, readFromPaper: PrintedDocumentFields) {
  const check = a.compareWithPrintedDocument(readFromPaper);

  for (const c of check.comparisons) {
    // Show both strings side by side. The operator decides; the app does not.
    console.log(`${c.field}: signed "${c.signed}" / on paper "${c.observed}" ${c.matches ? '' : '<-- DIFFERS'}`);
  }
  if (check.mismatches.length > 0) {
    // A mismatch means the code was not issued for this document.
  }

  // Always 'unchecked'. Verification is offline; the library cannot know
  // whether this diploma was withdrawn last week.
  console.log(`Standing: ${a.credentialStatus === 'unchecked' ? 'signature valid, standing unknown' : a.credentialStatus}`);
}
```

Comparison is on exact strings after Unicode NFC normalisation and trimming.
Case is significant, because the subject name is specified as the name *as
printed*. Where the operator reads the paper by eye, show both strings; where
you OCR the paper, expect to show both strings anyway.

`credentialStatus` is always `'unchecked'` and an interface MUST NOT present
an unchecked credential as current (SPEC §8, clause 6). If your deployment
also has a lookup service for the issuer's record, consult it and report
three states: current, withdrawn, or *signature valid, standing unknown*.

**The horizon gate.** A credential is verifiable only while its signing key
is within its validity window on the trust list, and only while a trust list
at most 30 days old can be obtained. A degree checked in forty years is
rejected as `KEY_EXPIRED`. Until the specification defines archival
verification, Profile B is restricted, as a rule, to documents whose life is
shorter than the key's (SPEC §3.1a). Do not deploy it for degrees or land
titles on the assumption that this will be sorted out later.

### 1.9 Screening at the moment of payment (sending institution, not wallet)

Screening is a call the **payer's institution** makes before releasing funds,
against the shared risk list. A wallet does not call it directly: the service
requires a per-officer client certificate, and an open lookup would tell a
mule operator whether they had been detected yet. What the wallet contributes
is the verified payee account: because it came from a payload whose signature
verified, the account screened is the account that will be paid.

```ts
// Inside the sending institution's authorisation path. mTLS identifies the caller.
const response = await fetchWithTimeout(`${RISKLIST}/screen`, {
  method: 'POST',
  body: JSON.stringify({ account: payeeAccountId, amount: 25000, currency: 'KHR' }),
  timeoutMs: 800,
});
```

Response:

```json
{
  "decision": "allow" | "warn" | "hold" | "block",
  "guidance": "…",
  "screeningRef": "uuid or null",
  "account": "…", "status": "clear" | "restricted" | "blocked",
  "reasonCode": "…", "expiresAt": 0, "lapsedFrom": null, "lapsedBecause": null,
  "listedByInstitution": "…"
}
```

The mapping from status to action is normative (SPEC Annex C.2): `clear`
executes, `restricted` holds or routes to review and expires within 72 hours,
`blocked` refuses. `warn` is the low-value carve-out and is off by default.
`listedByInstitution` is for routing between institutions and **must never be
shown to the payer**.

**Fail open, and record it.** If the call times out, the payment proceeds and
you record the decision as `unscreened`, never as `clear`. The distinction is
what lets you reconcile afterwards against listings made in the interval. Do
not fail closed: an unreachable register that stopped payments would hand
anyone who can degrade it the ability to stop the country paying.

**Keep a local replica.** `GET /delta?since=<cursor>&limit=500` returns
status changes in sequence; persist the cursor and poll. A replica of age τ
is a list whose time-to-list is longer by τ for every account listed in that
interval, so the number to report during an outage is the replica's age, not
the outage's duration.

---

## 2. Issuer integration

An issuer is a bank, payment institution, ministry, university or other body
that signs codes. It holds a key; nothing online in this system does.

### 2.1 Keys and the key identifier

- ECDSA P-256. The private key lives in your HSM or, at minimum, a hardware
  key store, and is exported to nothing. The signing commands accept a
  PKCS#8 PEM only so that a developer can test.
- The key identifier is the first 8 bytes of SHA-256 over the uncompressed
  public point, as 16 uppercase hex characters. It is a lookup hint, not an
  authenticator: a verifier that meets two list entries with the same
  identifier tries both.

```bash
node packages/cli/dist/index.js kid --public-key issuer.pub.pem
# 27403764C95F4F5B
```

```ts
import { deriveKidFromCoordinates } from '@kh-sqr/core';
const kid = await deriveKidFromCoordinates(xHex, yHex);
```

### 2.2 Enrolment

1. Generate the key pair inside your HSM and produce a certificate signing
   request.
2. Submit it to the registry with `POST /csr`, body
   `{ "csrPem": "<PEM>", "profiles": "A" | "B" | "A,B" }`, over mutual TLS
   with an officer certificate. The response is a queue id. The registry
   **cannot issue**: it holds no key, and its only outputs are a queue and an
   audit log.
3. The offline ceremony authority signs a new trust list that includes your
   key, with a `notBefore`, `notAfter`, the profiles you are authorised for,
   the `organisationId` your Profile B credentials must name, and the
   `acquirers` your Profile A codes may pay into — the exact value your
   scheme puts at sub-tag 00 of the merchant-account template, or an `@bank`
   suffix where that value is a per-merchant `merchant@bank` identifier — and
   publishes it through the edge service.
4. Poll `GET /csr/{id}` for `issued`, then confirm your key appears in
   `GET /trustlist/current`. Only then sign anything a payer will see.

Your key is scoped to profiles: a key enrolled for `A` cannot sign a
credential (`KEY_PROFILE_MISMATCH`). Ask for both only if you issue both.

### 2.3 Signing payment codes (Profile A, encoding version 2)

New issuance uses encoding version 2. Version 1 is frozen: verifiers must
still read it, but you should not produce it.

The input is an ordinary EMVCo merchant-presented payload — the same string
your scheme already produces — with three constraints:

- **Tag 01 decides static versus dynamic.** `010211` or absent is static;
  `010212` is dynamic. The library reads it; you do not tell it.
- **A static code MUST NOT carry tag 54 (amount)** and MUST NOT be given an
  expiry. `STATIC_CODE_WITH_AMOUNT` / `STATIC_CODE_WITH_EXPIRY`.
- **A dynamic code MUST carry an expiry** at most 300 seconds after issuance.
  `DYNAMIC_CODE_MISSING_EXPIRY` / `EXPIRY_WINDOW_TOO_LONG`.
- **Every merchant-account template must name an identifier your key is
  registered for**, at sub-tag 00. Signing does not check this; every
  verifier does, and rejects with `ACQUIRER_KEY_MISMATCH`. Your key cannot
  vouch for another institution's accounts, which is the point.

A trailing CRC on the input is discarded and recomputed. The payload must not
already contain templates 85, 86 or 87.

```ts
import { signProfileA2 } from '@kh-sqr/core';

// For development only. In production the key never leaves the HSM; you
// call its signing interface and adapt the raw r||s output.
async function loadPrivateKey(pkcs8Der: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey('pkcs8', pkcs8Der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

// A printed sticker: signed once at enrolment, no amount, no expiry.
const sticker = await signProfileA2({
  payload: '00020101021130310011abaakhppxxx01128550123456785204581253031165802KH5908SOK DARA6010PHNOM PENH',
  privateKey, kid: '27403764C95F4F5B',
  issuedAt: Math.floor(Date.now() / 1000),
  payeeClass: 'M',
});
renderQr(sticker.payload);   // sticker.codeKind === 'static'

// A per-transaction code on the merchant's screen: amount, currency, 60-second life.
const issuedAt = Math.floor(Date.now() / 1000);
const dynamic = await signProfileA2({
  payload: '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM PENH',
  privateKey, kid: '27403764C95F4F5B',
  issuedAt, expiresAt: issuedAt + 60,
  payeeClass: 'M',
});
renderQr(dynamic.payload);   // dynamic.codeKind === 'dynamic'
```

`payeeClass` is `'M'` for a merchant and `'I'` for an individual, and it is
inside the signed region, so a payer can be told which kind of account they
are paying.

Render the payload in QR **alphanumeric mode where the payload allows it**.
Everything the signature adds is uppercase hex and uppercase identifiers; a
lowercase acquirer id in the base payload forces byte mode for that segment
(README §9). Expect symbol version 11 at error-correction level M for a
dynamic code, version 5 unsigned.

Same call from the command line. `sign-a` produces encoding version 2 unless
you pass `--encoding 1`:

```bash
node packages/cli/dist/index.js sign-a --payload '@base.txt' --key issuer.key.pem \
  --kid 27403764C95F4F5B --payee-class M --expires-at $(( $(date +%s) + 60 ))
```

**What you cannot sign.** A printed bill or notice that carries an amount.
It needs an amount and a life measured in weeks, and the rules above give you
one or the other. Attempting it produces `STATIC_CODE_WITH_AMOUNT` or
`EXPIRY_WINDOW_TOO_LONG`, by design. What a bill issuer can do today is sign
the payee and leave the amount for the payer to enter; that authenticates who
is paid and leaves the amount unauthenticated. A third code kind is a
specification change, not a setting (`docs/USE-CASES.md`, case A6).

### 2.4 Issuing credentials (Profile B)

```ts
import { signProfileB } from '@kh-sqr/core';

const code = await signProfileB({
  privateKey, kid: '27403764C95F4F5B',
  claims: {
    issuer: 'KH.EDU.RUPP',
    issuedAt: Math.floor(Date.now() / 1000),
    documentType: 'degree',
    documentId: 'RUPP-2026-004821',
    subjectName: 'CHAY SOPHEA',          // exactly as printed on the document
    issuingOrganisation: 'Royal University of Phnom Penh',
    issueDate: '2026-07-15',
    documentHash: sha256HexOfIssuedPdf,  // SHOULD; lets a verifier bind the file too
  },
});
// 'KH1:6BFOXN%TSMAHN-H3Q8DJO…' — base45, uppercase, alphanumeric QR mode
```

`issuer` must equal the `organisationId` your key is registered under on the
trust list, or every verifier rejects the credential with
`ISSUER_KEY_MISMATCH`. That binding is what stops another enrolled key from
issuing in your name. `subjectName`, `documentId`, `issuingOrganisation` and
`issueDate` are the four fields a verifier compares with the paper, on exact
strings. Whatever
you print is what you sign. Deflate is not canonical, so signing the same
claims twice produces different strings that both verify; do not store the
code as if it were a digest.

**The horizon gate applies to you first.** Do not issue a Profile B credential
for a document that must verify after your key's `notAfter`. Today that
excludes degrees and land titles. A short-lived permit, a licence with an
annual renewal, or an official notice is inside the profile; a document that
outlives the key is outside it as a rule (SPEC §3.1a). Where you already run
a lookup service, the honest pattern is both: keep the lookup for revocation
and correction, and emit the signed credential beside it for offline
verification within the key's life.

### 2.5 Rotation and revocation

Revocation is per **key**, and it invalidates everything the key ever
signed. That is right for a compromised key and wrong for one withdrawn
document, which is why Profile B has no per-credential revocation. Plan for
it: sign long-lived static stickers under a key with a long `notAfter`, and
rotate the key that signs dynamic codes freely, because nothing signed under
it outlives five minutes.

---

## 3. Porting to another language

The conformance suite exists so that a port proves itself without reading
this TypeScript. As of this writing no independent port has run it, so the
first one will also be the first test of the suite's language neutrality.
Report what you find.

### 3.1 The suite

`vectors/vectors.json` has these top-level members:

| Member | Content |
|---|---|
| `keys` | test key pairs by name, with `scalar` (private), `x`, `y`, `kid`, `pem` |
| `pinned` | `rootKeys` and `timestampKeys`, the `PinnedKey` records a verifier ships |
| `trustLists` | signed trust-list artefacts by state name: `current`, `rolledBack`, `expired`, `forgedRootSignature` |
| `timestamps` | signed timestamp artefacts by state name: `current`, `expired`, `rolledBack`, `expiredList`, `farFuture` |
| `time` | the reference clock the vectors were generated against |
| `cases` | 47 cases, 35 of them rejections |

Each case:

```json
{
  "id": "A-reject-template-not-last",
  "profile": "A", "type": "verify",
  "description": "A data object appended after template 85, outside the signed prefix.",
  "input": { "payload": "0002010102…" },
  "state": { "trustList": "current", "timestamp": "current", "now": 1756512030 },
  "expect": "reject",
  "reason": "SIGNATURE_TEMPLATE_NOT_LAST"
}
```

To run a `verify` case: build a trust anchor from `state` (the named trust
list and timestamp, the pinned keys, `now`, and `heldVersion` / `fetchedAt`
when present), then verify `input.payload` under `profile` and, for Profile
A, `input.encodingVersion` (2, or absent for 1). The outcome must match
`expect`, and a rejection must carry exactly `reason`. An accepting case may
carry `accepted`, a few fields the result must contain.

A `roundtrip` case gives you a base payload and a private scalar: sign, then
verify your own output. ECDSA is randomised and deflate is not canonical, so
your bytes will differ from ours and must still verify.

### 3.2 Primitives you need

| Primitive | Where |
|---|---|
| ECDSA P-256 with SHA-256, **raw `r‖s` signatures**, 64 bytes | both profiles, trust list, timestamp |
| SHA-256 | key identifiers, timestamp digest |
| CRC-16/CCITT-FALSE | EMVCo tag 63 |
| CBOR decoder (maps, text, integers, byte strings, arrays) | Profile B |
| COSE_Sign1 structure with `kid` in the protected header | Profile B |
| zlib inflate (RFC 1950, not raw deflate) | Profile B |
| base45 (RFC 9285) | Profile B |

If your platform's ECDSA emits DER, convert to raw before comparing and
refuse DER on input (`A-reject-der-signature`). Web Crypto emits raw.

### 3.3 Verification order

The reported reason must be the most diagnostic one, so the order is
normative (SPEC §2.8):

1. Container: CRC present, well-formed, matching.
2. Structure: signature template present and last; sub-tag present, last,
   128 uppercase hex characters. Version 2: the last three objects are
   exactly `85`, `86`, `87`, each carrying the scheme GUID at sub-tag `00`.
3. Semantics: format version, algorithm, key identifier shape, timestamps,
   payee class, static/dynamic rules.
4. Trust: resolve the key identifier against the validated list; try every
   candidate with that identifier.
5. Signature, over a **substring** of the received payload. Version 1: up to
   and including the five characters `99128`. Version 2: up to the first
   character of template `86`. Never re-serialise parsed fields.
6. Acquirer binding: every merchant-account template (26–51) names, at
   sub-tag 00, an identifier the signing key's record lists in `acquirers`,
   exactly or by a registered `@bank` suffix.
7. Time: issuance skew, then expiry. Signature before expiry is deliberate: a
   tampered payload should report tampering, not staleness.

### 3.4 The traps the negative cases exist for

| Case | The mistake it catches |
|---|---|
| `A-reject-template-not-last`, `A-reject-subtag-not-last`, `A2-reject-appended-after-signature` | Accepting data appended after the signed prefix. The CRC was recomputed; the ordering rule is the defence, not the CRC. |
| `A-reject-mutation-outside-signed-region` | Skipping the CRC check. It catches corruption before any cryptography runs. |
| `A-reject-der-signature` | Accepting DER. Variable length breaks the fixed-offset rule. |
| `A2-reject-foreign-guid` | Accepting any GUID at sub-tag 00 rather than this scheme's. |
| `A2-reject-acquirer-key-mismatch`, `A2-accept-bank-suffix-binding` | Skipping the acquirer binding, or implementing only the exact form of it. A compromised issuer key could then sign codes paying into any account anywhere. |
| `A-reject-static-with-amount`, `A-reject-expiry-window-too-long`, `A-reject-dynamic-without-expiry` | Signing what the code kind forbids. |
| `A-reject-trustlist-rollback` | Not persisting the held version. |
| `A-reject-trustlist-stale`, `A-reject-timestamp-missing`, `A-reject-timestamp-expired`, `A-reject-timestamp-digest-mismatch` | Verifying without freeze protection. A verifier pinned to an old list keeps trusting a revoked key. |
| `A-reject-revoked-key` vs `A-reject-unknown-kid` | Collapsing the two. An operator needs to tell withdrawn from never-existed. |
| `B-reject-https-payload` | Not running the URL check. |
| `B-reject-issuer-key-mismatch` | Accepting a valid signature without checking that the issuer claim matches the signing key's registered organisation. Any enrolled key could then issue in any name. |
| `B-reject-deflate-raw` | Using raw deflate instead of zlib-wrapped. |
| `B-reject-base45-alphabet` | Accepting characters outside the base45 alphabet. |

### 3.5 Two properties to carry across

- **No network during verification.** The suite cannot test it; a test in
  this repository poisons every network global and verifies both reference
  payloads. Write the same test.
- **No boolean on the result.** `PaymentAttestation` and
  `CredentialAssertion` have no `isValid` and no boolean member, and a test
  fails the build if one is added. The reason is in §1.5 and §1.8: the only
  remaining defence is a comparison a programmer must not be able to skip.

---

## 4. API reference

### 4.1 Getting the package

```bash
pnpm install
pnpm build          # packages/core/dist and packages/cli/dist
pnpm test           # 47 vectors plus unit tests
```

Consume it as a workspace dependency, or bundle it: `tools/build-demo.ts`
uses esbuild to produce a single IIFE exposing `KHSQR`, which is how the
browser demo embeds it. The package is ESM, `sideEffects: false`, and exports
`.` and `./profileA` (the latter for a wallet that wants Profile A alone).

### 4.2 Verification

| Export | Signature | Notes |
|---|---|---|
| `TrustAnchor.open(opts)` | `→ Promise<TrustAnchor>` | `trustList`, `timestamp`, `rootKeys`, `timestampKeys`, `now`; optional `heldVersion`, `fetchedAt`, `allowMissingTimestamp` (testing only) |
| `anchor.version` `.issuedAt` `.expires` `.digest` | | persist `version` as the next `heldVersion` |
| `anchor.resolve(kid, profile, now)` | `→ Promise<CryptoKey[]>` | every usable candidate; throws the most specific key reason |
| `assertNotUrlCarrier(s)` | `→ void` | throws `URL_PAYLOAD_REJECTED`; run on every scan |
| `detectProfileAEncoding(payload)` | `→ 2 \| 1 \| null` | routing hint, not a verdict |
| `verifyProfileA({payload, trustAnchor, now, clockSkewSeconds?})` | `→ Promise<PaymentAttestation>` | encoding 1 |
| `verifyProfileA2({payload, trustAnchor, now, clockSkewSeconds?})` | `→ Promise<PaymentAttestationV2>` | encoding 2 |
| `verifyProfileB({payload, trustAnchor, now})` | `→ Promise<CredentialAssertion>` | |
| `KhSqrError` | `.reason: RejectionReason`, `.message` | base class of every rejection; one subclass per reason |

`PaymentAttestation` and `PaymentAttestationV2` carry `kid`, `codeKind`,
`issuedAt`, `expiresAt`, `signedThrough`, and `payeeDisclosure`
(`merchantName`, `merchantCity`, `countryCode`, `amount`, `currencyCode`,
`currencyAlpha`, `payeeClass`, `accounts[]`). V2 adds
`encodingVersion: 2` and `lengthEncoding: 'emvco-two-digit'`.

`CredentialAssertion` carries `kid`, `issuer`, `issuedAt`, `documentType`,
`documentHash`, `mustMatchPrintedDocument`, `credentialStatus: 'unchecked'`,
and `compareWithPrintedDocument(fields) → TransplantCheck`.

### 4.3 Signing

| Export | Notes |
|---|---|
| `signProfileA2({payload, privateKey, kid, issuedAt, expiresAt?, payeeClass})` | `→ { payload, signingInput, signature, codeKind }` |
| `signProfileA(...)` | same shape; encoding 1, frozen for new issuance |
| `signProfileB({privateKey, kid, claims})` | `→ string` beginning `KH1:` |
| `deriveKid(point)` / `deriveKidFromCoordinates(x, y)` | key identifier |

### 4.4 Lower-level helpers

`parseDataObjects`, `findObject`, `appendCrc`, `stripCrc`, `crc16CcittFalse`
(EMVCo); `encodeBase45` / `decodeBase45`; `encodeCbor` / `decodeCbor`;
`deflate` / `inflate`; `hexToBytes` / `bytesToHex`. Useful for a wallet
that wants to show the plain EMVCo fields of an unsigned code with the same
parser it uses for signed ones.

### 4.5 Command line

```
kid              --public-key <spki.pem>
sign-a           --payload <text|@file> --key <pkcs8.pem> --kid <hex> --payee-class M|I [--issued-at <s>] [--expires-at <s>] [--encoding 1|2]
sign-b           --claims <json|@file> --key <pkcs8.pem> --kid <hex>
verify           --payload <text|@file> --trustlist @f --root-keys @f --timestamp @f --timestamp-keys @f [--now <s>] [--held-version <n>] [--fetched-at <s>]
run-vectors      --file vectors/vectors.json
build-trustlist  --keys @f --version <n> --key <root.pem> --kid <hex> [--validity-seconds <s>]
build-timestamp  --trustlist @f --key <ts.pem> --kid <hex> [--validity-seconds <s>]
```

`verify` exits 0 with the attestation as JSON, or 1 with
`{ "accepted": false, "reason": "…" }`. It dispatches on the `KH1:` prefix
and on `detectProfileAEncoding`, so it reads both payment encodings. Run it
without `--timestamp` and it warns that freeze protection is off.

### 4.6 Related documents

- `SPEC.md` — normative.
- `docs/USE-CASES.md` — every deployment shape for both profiles, including
  the two that are not supported.
- `docs/DEPLOYMENT.md` and `workers/*/DEVELOPMENT.md` — running the three
  services.
- `docs/EXPOSURE.md` — what a signature fixes and what it does not, by attack.
- `demo/README.md` — the sandbox PWA, which embeds this library, issues and
  verifies both profiles on the device, and is a working example of §1 and §2
  of this guide (`demo/src/app.ts`).
