# KH-SQR — specification

Version 1.0. Normative keywords (MUST, MUST NOT, SHOULD, MAY) are used as in
BCP 14.

This document specifies two profiles for signing QR codes, a trust hierarchy,
and the rules a conforming verifier follows. It specifies what those mechanisms
achieve and, equally normatively, what they do not.

## 0. Scope, and the limit of scope

KH-SQR addresses **forgery**: an attacker producing a code that a verifier
accepts as coming from a registered issuer when it does not. Within its threat
model it closes that problem.

KH-SQR does not address **deception**: a genuine code, correctly signed by a
registered issuer, paid to a correctly registered account, presented under a
false pretext. A conforming implementation verifies such a code and must; the
payload is authentic. The fraud is in the reason the payer was given for
scanning it, which is not a property of any byte in the payload.

An implementation MUST NOT present a successful verification as an assurance
about the transaction. Section 8 states the interface obligations that follow.

## 1. Cryptographic primitives

| Purpose | Algorithm |
|---|---|
| Signature | ECDSA on P-256 with SHA-256 (COSE `ES256`, -7) |
| Signature encoding | IEEE P1363 raw `r‖s`, 64 bytes |
| Digest | SHA-256 |
| Compression (Profile B) | DEFLATE with zlib wrapper, RFC 1950 |
| Binary-to-text (Profile B) | base45, RFC 9285 |

DER-encoded signatures MUST NOT be used or accepted. DER is variable-length,
which would defeat the fixed-offset rule in §2.3; a verifier that encounters one
MUST reject with `SIGNATURE_ENCODING_INVALID`.

`crypto.subtle.sign('ECDSA', …)` returns raw `r‖s` and `crypto.subtle.verify`
consumes it, so a Web Crypto implementation performs no signature format
conversion at any point. Implementations on platforms whose ECDSA API is
DER-native MUST convert at the boundary and MUST reject any `r` or `s` that is
not exactly 32 bytes after conversion.

## 2. Profile A — payment

Profile A adds a signature to an existing EMVCo merchant-presented payload
using template `85`, from the unreserved range 80–99.

### 2.1 Template 85

| Sub-tag | Field | Length | Value |
|---|---|---|---|
| `00` | Format version | 02 | `01` |
| `01` | Key identifier | 16 | uppercase hex |
| `02` | Algorithm | 05 | `ES256` |
| `03` | Issued at | 10 | Unix seconds, zero-padded |
| `04` | Expires at | 10 | Unix seconds; dynamic codes only |
| `05` | Payee class | 01 | `M` merchant, `I` individual |
| `99` | Signature | 128 | raw `r‖s`, uppercase hex |

Sub-tags `00`, `01`, `02`, `03`, `05` and `99` are mandatory. Sub-tag `04` is
mandatory on dynamic codes and MUST NOT appear on static ones.

### 2.2 Ordering

- Template `85` MUST be the last data object before the CRC (tag `63`).
- Sub-tag `99` MUST be the last sub-tag within template `85`.

Both rules exist so that the signed region is a prefix. A verifier that omitted
the first would accept a payload with data objects appended after the signature,
outside the signed region.

### 2.3 Signing input — the fixed-offset rule

The signing input is the ASCII octets of the payload from position 0 up to **and
including** the five characters `99128` — sub-tag `99`'s tag and its length
declaration — excluding the 128 signature characters and the CRC that follows.

The signed region is therefore a plain prefix of the final payload.

A verifier MUST recover it by taking the substring `payload[0 … s)`, where `s`
is the index of the first signature character, and MUST NOT reconstruct it by
re-serialising parsed fields. There is consequently no canonical form for two
implementations to disagree about, and no canonicalisation step in which to have
a bug. A verifier MUST check that the recovered prefix ends with `99128`.

Equivalently: the signature is the 128 characters immediately preceding the
eight-character CRC object, and `99128` is the five characters immediately
preceding those.

### 2.4 Two deviations from EMVCo, and what they cost

Template `85` departs from the EMVCo merchant-presented QR specification in two
ways. Both are recorded here rather than in a footnote, because together they
retire the claim that a signature in the unreserved template range is
transparent to existing applications.

**(a) Three-digit lengths.** EMVCo length fields are exactly two decimal
digits, ranging `01` to `99`, so the maximum value length is 99 characters.
Template `85` and sub-tag `99` both exceed that: the signature alone is 128
characters. KH-SQR therefore declares the length of template `85` and of
sub-tag `99` in **three** decimal digits.

**(b) Sub-tag `00` is not a Globally Unique Identifier.** EMVCo requires that
an Unreserved Template with an ID in `80`–`99` contain the primitive data
object *Globally Unique Identifier* at ID `00`, which sets the context for the
remainder of the template. KH-SQR uses sub-tag `00` for the format version
instead, so template `85` does not identify its own namespace in the way EMVCo
prescribes. In practice this means a conforming EMVCo parser that reached
template `85` would not be able to establish what the template is, even if the
length encoding permitted it to parse the template at all.

A future revision SHOULD place a globally unique identifier
(for example `KH.GOV.NBC.SQR`) at sub-tag `00` and move the format version to a
free sub-tag. That is a wire-format change and is out of scope for version 1.0,
whose published reference vectors this document preserves.

**These deviations have a cost that must be stated rather than glossed.** A
strict legacy EMVCo parser reads tag `85`,
interprets `20` as its length, consumes 20 characters, and then misparses
everything that follows — it will not find tag `63` and will reject the payload.
The claim that a signature in the unreserved template range is transparent to
existing applications is **not** satisfied by a template this large. Deployment
must assume conforming KH-SQR parsers, not tolerant legacy ones. This is
discussed further in §9.

Because the declared length is not trustworthy for locating the signature — and
is not needed for it, given §2.3 — a verifier:

- MUST determine the extent of template `85` from its position (the content runs
  from the end of its five-character header to the start of the trailing
  `6304` object), not from its declared length;
- MUST NOT reject a payload solely because template `85`'s declared length
  disagrees with its actual content length;
- SHOULD report the discrepancy as a diagnostic.

A signer MUST emit a declared length equal to the actual content length.

Tampering with the declared length is not a malleability risk: those characters
lie inside the signed prefix, so any change to them invalidates the signature.

**Erratum.** The published 317-character reference payload declares template
`85`'s length as `200` while its content is 201 characters, because its
generator counted sub-tag `99`'s length declaration as two characters and then
emitted three. The payload is retained unchanged as a normative *verification*
vector — the signature over it is valid, and a conforming verifier accepts it
under the rules above. Conforming signers emit `201`. The conformance suite
carries both as separate cases.

### 2.5 Semantic rules

- A static code (Point of Initiation Method `01` absent or `11`) MUST NOT carry
  a transaction amount (tag `54`) and MUST NOT carry sub-tag `04`.
- A dynamic code (`01` = `12`) MUST carry sub-tag `04`, with
  `expires − issued ≤ 300` seconds.
- A verifier MUST reject a code whose issuance time is more than a small
  tolerance (RECOMMENDED: 60 seconds) ahead of its own clock.
- Expiry is exclusive: a code is valid at `now == expires` and invalid at
  `now == expires + 1`.

### 2.6 CRC

CRC-16/CCITT-FALSE: polynomial `0x1021`, initial value `0xFFFF`, no input or
output reflection, no final XOR. Four uppercase hex characters, computed over
everything up to and including `6304`.

The CRC is not a security control — it is trivially recomputable by an
attacker — but it does cover the region *outside* the signed prefix, so a
mutation of the signature characters themselves is caught by it.

### 2.7 Character set

All KH-SQR fields use uppercase hexadecimal, never base64. QR alphanumeric mode
admits only digits, uppercase letters, space and eight further punctuation
marks; a single lowercase character forces a byte-mode segment, which costs
roughly 45 per cent more capacity for that segment.

Note that this is a property of the fields KH-SQR adds. The surrounding EMVCo
payload may contain lowercase — the reference payload's acquirer identifier
does — and an issuer who wants a fully alphanumeric symbol must address that
separately. See the measurements in `README.md`.

### 2.8 Verification order

A conforming verifier performs checks in this order, so that the reported
rejection reason is the most diagnostic one available:

1. Container: CRC present, well-formed, and matching.
2. Structure: template `85` present and last; sub-tag `99` present, last, and
   128 uppercase hex characters.
3. Semantics: format version, algorithm, key identifier shape, timestamps,
   payee class, static/dynamic rules.
4. Trust: resolve the key identifier against a validated trust list (§4).
5. Signature.
6. Time: issuance skew, then expiry.

Signature before expiry is deliberate: a payload that has been tampered with
should report tampering, not staleness.

## 3. Profile B — credential

```
claims (CBOR) → COSE_Sign1 (ES256, kid in protected header)
              → deflate (zlib, RFC 1950) → base45 (RFC 9285) → prefix "KH1:"
```

The pipeline is the EU Digital COVID Certificate's, with a different prefix and
claim set. Deflate is applied unconditionally, for determinism of shape, even
where it adds bytes at this size.

`deflate-raw` MUST NOT be used: it omits the zlib header and Adler-32 trailer
and produces a byte stream other implementations will not inflate.

### 3.1 Claims

| Key | Field | Type | Requirement |
|---|---|---|---|
| `1` | Issuer | tstr | MUST |
| `6` | Issued at | uint | MUST |
| `dt` | Document type | tstr | MUST |
| `di` | Document identifier | tstr | MUST |
| `sn` | Subject name, as printed | tstr | MUST |
| `io` | Issuing organisation | tstr | MUST |
| `idt` | Issue date | tstr | MUST |
| `dh` | Hash of the issued file | tstr | SHOULD |

The key identifier MUST appear in the COSE **protected** header as an 8-byte
byte string. A kid in the unprotected header can be replaced in transit to steer
a verifier at a different trust-list entry, and MUST be rejected.

### 3.2 The payload MUST NOT be a URL

A Profile B payload MUST NOT be an `http` or `https` URL, and a verifier MUST
reject one with `URL_PAYLOAD_REJECTED`.

This is a design constraint, not an omission. A URL-bearing QR relocates the
trust decision into a browser and asks the user to judge a domain name — the
judgement the fraud pattern this design responds to shows people do not reliably
make. An implementation SHOULD apply this check to every code it scans, not only
to KH-SQR ones.

**This clause is only half of the rule, and it is the weaker half.** A code
scanned by the handset's native camera application never reaches this check, and
that is how a great many codes are scanned. The check binds implementations; it
cannot bind an attacker's printer.

The other half is not technical and is stated here because a reader of this
document should not have to infer it:

> No licensed bank, payment institution, government body or telecommunications
> operator should issue, publish or display a QR code whose payload is an
> `http` or `https` URL.

Enforced across the regulated perimeter, that prohibition empties the set of
legitimate URL-bearing payment and official codes, which is what makes the
corresponding public rule — *a QR code never opens a website; if a website
opens, do not pay and do not enter your PIN, password, one-time code or personal
details* — true rather than aspirational. The rule is deliberately categorical:
a scoped version would require a person to classify a code before scanning it,
and a QR code's class is not knowable until after it has been scanned. See the
accompanying paper, §7.1.

### 3.3 The transplant attack, and the required API shape

A valid Profile B signature proves the credential was issued. It does not prove
the credential belongs to the document it is printed on. A genuine QR code
photographed from a real degree certificate and printed onto a forged one
verifies perfectly, because nothing about the paper is signed.

The only defence is comparison of the signed fields with the visible document.
Therefore:

- Verification MUST return a structure carrying `sn`, `di`, `io` and `idt` in a
  form the caller must handle.
- Verification MUST NOT return a boolean.
- An implementation MUST NOT expose an `isValid`, `valid` or equivalent
  convenience accessor that lets a caller reach a verdict without those fields.

The reference implementation returns a `CredentialAssertion` whose comparison
fields are named `mustMatchPrintedDocument`, with a
`compareWithPrintedDocument()` method returning per-field results. A test pins
the absence of any boolean member.

### 3.4 CBOR profile

A conforming decoder MUST accept only: unsigned and negative integers, byte
strings, text strings, arrays, maps, and CBOR tag 18. It MUST reject
indefinite-length items, non-minimal integer encodings, floating-point and
simple values, duplicate map keys, map keys that are not integers or text
strings, trailing bytes after the top-level item, and text that is not
well-formed UTF-8.

Every accepted construct is a construct an attacker may use to make two parsers
disagree about the same bytes.

Map key order is preserved as produced and is not canonicalised. The signature
covers the payload bytes as produced and a verifier never re-encodes them, so no
two parties ever need to agree on an ordering.

## 4. Key identifiers and the trust list

### 4.1 Key identifier

`kid` = the first 8 bytes of SHA-256 over the uncompressed point
`0x04 ‖ X ‖ Y`. Rendered as 16 uppercase hex characters in Profile A; carried as
an 8-byte byte string in Profile B.

The `kid` is a lookup hint, never an authenticator. A verifier that finds more
than one trust-list entry with the same `kid` MUST try each and accept only on a
signature that verifies. It MUST NOT treat `kid` equality as identity.

### 4.2 Trust list

The trust list is a signed artifact:

```json
{
  "statement": "<the exact JSON text that is signed>",
  "signature": { "alg": "ES256", "kid": "…", "value": "<128 hex>" }
}
```

The signature covers the UTF-8 bytes of the `statement` string exactly as they
appear, and the verifier parses that same string. As in §2.3, there is no
canonicalisation step.

The statement is `{ "type": "kh-sqr/trustlist/1", "version", "issuedAt",
"expires", "keys": [ … ] }`. Each key record carries `kid`, `x`, `y`,
`profiles`, `status` (`active` | `revoked`), `notBefore`, `notAfter` and
`subject`.

The Root public key MUST be pinned in the verifier and MUST NOT be fetched.

A verifier MUST reject a trust list whose:

- Root signature does not verify — `TRUSTLIST_SIGNATURE_INVALID`;
- `version` is lower than the version it already holds — `TRUSTLIST_ROLLBACK`;
- `expires` has passed — `TRUSTLIST_EXPIRED`;
- cache age exceeds **30 days** — `TRUSTLIST_STALE`.

### 4.3 Timestamp statement — freeze protection

An attacker who can withhold updates — a hostile network, a captive portal, a
compromised mirror — can pin a verifier to an old but still-unexpired trust list,
so that a key revoked yesterday keeps verifying. The defence is TUF's timestamp
role.

The timestamp statement is a **separate signed object**, not a field on the
list:

```json
{ "type": "kh-sqr/timestamp/1", "trustListVersion": 7,
  "trustListDigest": "<SHA-256 of the trust list statement, 64 hex>",
  "issuedAt": …, "expires": … }
```

Validity is 7 days. It is signed by a key distinct from the Root, because the
timestamp signer is online and short-lived while the Root is offline.

A verifier MUST reject when the freshest timestamp statement it holds has
expired (`TIMESTAMP_EXPIRED`), when none is available (`TIMESTAMP_MISSING`), or
when the statement does not attest the version and digest of the list it holds
(`TIMESTAMP_TARGET_MISMATCH`). It MUST fail closed: stop verifying rather than
fall back on what it holds.

### 4.4 Publication

The trust list, the timestamp statement, and the application trust list MUST be
published at **three mirrors under distinct operational control**.

A deployment on a single provider does not satisfy this, regardless of that
provider's internal redundancy. Anycast delivers availability, not operational
independence: one provider, one account, one governance failure. See
`README.md` for the status of the reference deployment, which does not conform
to this clause and does not claim to.

## 5. Rejection reasons

Every rejection carries a stable, machine-readable reason. These strings are
part of the conformance contract: a port proves conformance by producing the
same reason for the same input, and they MUST NOT be renamed once published. The
full list is in `packages/core/src/errors.ts`, and every reason the suite
exercises appears in `vectors/vectors.json`.

## 6. Verification is offline

Verification MUST NOT perform network access. Everything needed is supplied by
the caller: the trust list, the timestamp statement, the pinned keys, and the
time.

A verifier that fetches during verification can be stalled or steered by
whoever controls the network at the moment of payment, who at a market stall is
not a trustworthy party.

## 7. Key custody

- The Root key is generated and used **offline**, in a ceremony. It MUST NOT
  exist on any network-reachable machine.
- Issuer keys live in each institution's HSM.
- The timestamp statement is produced by a signer outside the serving
  infrastructure and uploaded.
- No online service holds a private key of any kind. Certificate issuance MUST
  be impossible through compromise of the online portal.

The reference deployment enforces this by construction — the Workers have no key
custody story at all — and by a CI check that fails if a signing key appears in
any Worker configuration or source.

## 8. Interface obligations

These are normative, and they are the clauses most likely to be quietly
dropped.

1. An implementation MUST NOT present a valid signature as an assurance that a
   payment is safe to make.
2. A Profile A verifier MUST make the payee disclosure — merchant name, city,
   country, amount, currency, payee class, account identifiers — available to
   the interface, and an interface intended for a payer SHOULD display it before
   authorisation.
3. A Profile B verifier MUST require the caller to handle the printed-document
   comparison fields (§3.3).
4. An implementation MUST NOT log payload contents.

## 9. What this specification does not achieve

Stated here because an implementer who reads only the normative text should
still encounter it.

- **URL-bearing codes scanned outside a conforming verifier.** §3.2's check
  runs only where this specification runs. A code scanned by the handset's
  native camera application reaches no verifier at all. This is unreachable in
  software and is addressed by the institutional prohibition in §3.2.
- **Authorised push payment fraud.** A genuine code presented under a false
  pretext. Unreachable from the code layer: every byte is authentic. Addressed,
  partially and after the fact, by the institutional layer (Annex C) and by
  liability allocation, neither of which is cryptography.
- **Registration abuse.** A fraudster who registers a merchant account with
  genuine documents receives a genuine key and signs genuine codes. The
  signature then attests a real identity that is real and fraudulent.
- **Counterfeit verifiers.** A fake wallet application that displays a tick for
  anything. The application trust list helps a diligent user and does nothing
  for one who installed the application from a link.
- **Foreign and platform codes.** Codes from systems outside the trust
  hierarchy cannot be verified, and a verifier that shows "unverified" for the
  majority of what people scan trains them to ignore the indicator.
- **Legacy transparency.** As §2.4 records, template `85` is not transparent to
  a strict EMVCo parser: its length encoding is not EMVCo's, and it does not
  carry the Globally Unique Identifier EMVCo requires of an unreserved
  template. A deployment must upgrade parsers, not merely signers.

## 10. Conformance

An implementation conforms if it produces the stated outcome for every case in
`vectors/vectors.json`, and for each rejection reports the stated reason where
one is given. Cases are typed:

- `verify` — the recorded payload must produce the stated outcome.
- `roundtrip` — the implementation signs, then verifies its own output. ECDSA is
  randomised, so a fresh signature differs from any fixed vector and must still
  verify; and deflate is not canonical, so a Profile B encoder is not required
  to reproduce the published bytes.
