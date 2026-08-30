# KH-SQR

A reference implementation of signed QR codes for Cambodia: a payment profile
that binds an ECDSA signature to an existing KHQR/EMVCo payload, and a
credential profile for signed documents. TypeScript, Web Crypto only,
Cloudflare Workers for the services.

---

## Read this before the usage section

**This addresses forgery. It does not prevent authorised push payment fraud,
and nothing built on it should suggest that it does.**

Cambodian QR fraud takes two forms, and they are not variants of one problem:

1. **Forgery** — an overlay sticker, a printed code, a URL-bearing QR
   impersonating a payment or an official document check. Cryptography closes
   this completely.

2. **Deception** — a *genuine* KHQR, correctly signed, paid to a correctly
   registered account, presented under a false pretext: "scan to receive your
   refund", "scan to release your parcel". This is authorised push payment
   fraud, it is currently the dominant vector, and **a correct implementation of
   this specification verifies such a code and must.** Every byte is authentic.
   The lie is in the reason the payer was given for scanning, which is not a
   property of any byte.

The gap is structural, not a gap in the design. A control enforced at one layer
does not govern meaning created at the layer above it. Signing the code secures
the *instrument*; it cannot secure the *transaction*, because the deception
happens one layer up, in the person.

So: a verified signature is not a reason to pay. The API is built to make that
hard to forget — verification never returns a boolean, and the Profile B result
has no `isValid` accessor precisely so a caller cannot reach a verdict without
handling the fields that would catch a transplanted code.

---

## What is here

```
packages/core/         isomorphic library. Web Crypto only. What a wallet embeds.
  src/base45.ts        RFC 9285
  src/cbor.ts          minimal strict encoder/decoder, fixed claim shapes only
  src/cose.ts          COSE_Sign1 over ES256
  src/emvco.ts         TLV parse/serialise, CRC-16/CCITT-FALSE
  src/kid.ts           key identifier derivation
  src/profileA.ts      payment: sign, verify
  src/profileB.ts      credential: sign, verify
  src/trustlist.ts     list validation, timestamp statement, rollback + staleness
  src/errors.ts        one class per normative rejection reason
packages/cli/          sign, verify, build-trustlist, build-timestamp, run-vectors
workers/
  trustlist-edge/      serves trust list + timestamp statement (read-only)
  registry-api/        CSR intake, queued for the offline ceremony
  risklist-api/        Annex C: authenticated institutional writes
vectors/vectors.json   language-neutral conformance suite
docs/                  measurements and operational notes
paper/                 the preprint
```

`SPEC.md` is the normative specification.

## Usage

```bash
pnpm install
pnpm build
```

Verify the published reference payload:

```bash
node packages/cli/dist/index.js verify \
  --payload @payload.txt \
  --trustlist @trustlist.json --root-keys @root-keys.json \
  --timestamp @timestamp.json --timestamp-keys @timestamp-keys.json
```

It exits 0 and prints the attestation, or exits 1 and prints a stable machine
readable rejection reason. Signing:

```bash
node packages/cli/dist/index.js sign-a \
  --payload '000201010212…6010PHNOM PENH' \
  --key issuer.key.pem --kid 27403764C95F4F5B \
  --payee-class M --expires-at $(( $(date +%s) + 60 ))
```

In code:

```ts
import { TrustAnchor, verifyProfileA } from '@kh-sqr/core';

const anchor = await TrustAnchor.open({
  trustList, timestamp, rootKeys, timestampKeys,
  heldVersion, fetchedAt, now,
});

// Throws a KhSqrError carrying a stable `reason` on any rejection.
const attestation = await verifyProfileA({ payload, trustAnchor: anchor, now });

// Show this to the payer. The signature says these values were not altered.
// It does not say the person in front of them is who they think.
showBeforeAuthorising(attestation.payeeDisclosure);
```

Run the conformance suite against your own port:

```bash
node packages/cli/dist/index.js run-vectors --file vectors/vectors.json
```

## Design decisions worth knowing

**The signing input is a prefix.** Profile A signs the payload from position 0
up to and including the five characters `99128`. A verifier recovers it with a
substring, never by re-serialising parsed fields. There is no canonical form to
disagree about and therefore no canonicalisation bug to have.

**Raw `r‖s`, never DER.** `crypto.subtle.sign` returns IEEE P1363 raw `r‖s`,
which is exactly what the wire format carries, so there is no conversion step
anywhere and no DER length-parsing bug to have. DER is rejected with its own
reason.

**Uppercase hex, never base64.** QR alphanumeric mode admits only uppercase
letters, digits and nine punctuation marks. One lowercase character forces a
byte-mode segment.

**Profile A depends on nothing but Web Crypto.** No CBOR, no streams, no
packages, so a mobile wallet can embed it with no polyfill. Its import graph
reaches six modules and CI fails if it reaches a seventh kind. Profile B may use
CBOR and `DecompressionStream`, because Profile B verifiers are institutional.

**CBOR is hand-written and strict.** A general CBOR library is a large audit
surface on a security-critical path for no benefit at this payload complexity.
It is differentially fuzzed against a reference implementation in CI, and
rejects indefinite lengths, non-minimal integers, floats, duplicate keys and
trailing bytes.

**No signing key exists at the edge.** The Workers serve signed artifacts and
verify signatures. The Root signs offline in a ceremony, issuer keys live in
each institution's HSM, and the timestamp statement is produced outside
Cloudflare and uploaded. This is not caution, it is the specification:
certificate issuance must be impossible through compromise of the online portal.
CI fails if a signing key appears in any Worker configuration or source.

**The risk list does not use KV.** KV is eventually consistent, which leaves a
window in which a just-listed account still reads clear — which is the window a
mule account is drained in. A Durable Object per shard serialises reads and
writes; D1 remains the authority.

**Risk-list statuses expire at read time.** A stored deadline compared against
the clock when someone asks, never a cron sweep. A missed sweep would silently
extend a restriction on a real person's account, and neither they nor the
institution would see anything wrong.

**URL carriers are rejected — and that check is the weaker half of the rule.**
A code scanned by the handset's native camera never reaches any verifier, which
is how a great many codes are scanned. The software check binds implementations;
it cannot bind an attacker's printer. The half that does the work is a
categorical prohibition on URL-bearing QR codes across the regulated perimeter,
which empties the legitimate set so that "a QR code never opens a website"
becomes true rather than aspirational. `SPEC.md` §3.2 and the paper §7.1.

## Measured QR symbol sizes

Error-correction level M. Generated by `pnpm measure:qr`, not transcribed;
`docs/qr-measurements.json` carries the machine-readable form.

| Payload | Chars | Version | Modules | Encoding mode |
|---|---|---|---|---|
| Unsigned KHQR baseline | 111 | 5 | 37 × 37 | numeric + byte + alphanumeric |
| Profile A signed | 317 | 10 | 57 × 57 | numeric + byte + alphanumeric |
| Profile B credential | 381 | 12 | 65 × 65 | alphanumeric |
| Unsigned baseline, uppercase acquirer id | 111 | 5 | 37 × 37 | numeric + alphanumeric |
| Profile A signed, uppercase acquirer id | 317 | 10 | 57 × 57 | numeric + alphanumeric |

Signing takes a merchant code from version 5 to version 10: a 54 per cent
increase in linear dimension, and 2.4 times the module count. At a fixed module
size the sticker gets larger; at a fixed sticker size the modules get smaller
and scan less reliably on a cheap handset in poor light. This is the practical
cost of the scheme and it falls on merchants, who must reprint.

The measurement also records the encoding mode, which surfaces something the
version alone hides: the reference payload's acquirer identifier
(`abaakhppxxx`) is lowercase, forcing a byte-mode segment. Making it uppercase
keeps the symbol alphanumeric throughout without changing the version at these
lengths — worth doing, but not where the size cost lives.

## Two things this deployment does not conform to

**Mirror independence.** `SPEC.md` §4.4 requires publication at three mirrors
under *distinct operational control*. Cloudflare's anycast network provides
availability, not operational independence: three URLs on one provider are one
account and one governance failure. `trustlist-edge` is the **primary**, and at
least two mirrors elsewhere — NBC's own infrastructure and a second provider —
are required before the clause is met. **This repository does not claim
conformance to §4.4 from a single-provider deployment**, and the service's own
health endpoint says so.

**Legacy transparency.** `SPEC.md` §2.4 records two deviations from the EMVCo
merchant-presented QR specification. Template `85` carries 201 characters while
EMVCo length fields hold at most 99, so KH-SQR declares three-digit lengths for
template `85` and sub-tag `99`; and EMVCo requires an unreserved template to
carry a Globally Unique Identifier at sub-tag `00`, where KH-SQR puts a format
version. A strict legacy EMVCo parser will therefore *fail* on a signed payload
rather than ignoring the template. The premise that a signature in the
unreserved 80–99 range is transparent to existing applications does not hold
here. Deployment must upgrade parsers, not merely signers.

## Reproducing the reference vectors

Every key in the suite comes from a published scalar or a published label, so
the whole file regenerates from this repository alone:

```bash
pnpm build && pnpm vectors:generate
```

The published issuer scalar
`1F2E…E2F1` is deliberately public and protects nothing.
Its key identifier is `27403764C95F4F5B`.

Because ECDSA is randomised, regeneration produces different signatures each
time; `pnpm vectors:check` compares the case inventory rather than bytes. The
published Profile B payload was produced by a different deflate implementation
and is a `verify` case: conformance requires that it decodes and verifies, not
that your encoder reproduces it.

## Development

```bash
pnpm check:all      # typecheck, lint, tests, vectors, both architectural guards
pnpm test           # core: 97 tests including the 41-case conformance suite
pnpm --filter @kh-sqr/risklist-api test   # workers run in workerd, not a shim
```

The conformance suite is 40 cases, 31 of them negative. Negative cases are the
point: an implementation that accepts a well-formed payload has demonstrated
very little; one that rejects each malformation for the right stated reason has
demonstrated most of the specification.

## Licence

MIT. See `LICENSE`.

## Citation

The accompanying preprint is in `paper/`. The paper cites a specific tagged
commit of this repository; see `paper/main.tex` for the pinned reference.
