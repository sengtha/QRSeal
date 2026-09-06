# KH-SQR — specification

Version 1.0. Normative keywords (MUST, MUST NOT, SHOULD, MAY) are used as in
BCP 14.

This document specifies two profiles for signing QR codes, a trust hierarchy,
and the rules a conforming verifier follows. It specifies what those mechanisms
achieve and, equally normatively, what they do not.

**KH-SQR is one half of a project called QRSeal.** This document is the half an
implementer conforms to. The other half is a set of institutional proposals,
numbered S0–S6 in the project's README and paper, which act on the fraud this
specification cannot reach; they are deliberately not specified here, because
they are reference designs rather than normative requirements.

**Neither name designates a standard.** KH-SQR is proposed by this project, not
adopted by anyone. It is not issued by, endorsed by, or agreed with the National
Bank of Cambodia or any other authority, and no identifier defined in this
document should be read as claiming otherwise.

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

### 2.4 Encoding version 1: two deviations from EMVCo, and what they cost

> **Status.** Encoding version 1 is **frozen and deprecated for new issuance.**
> It is retained because its reference vectors are published and cited, and
> because deployed verifiers must keep reading codes already in circulation.
> New issuance SHOULD use encoding version 2 (§2.9), which does not deviate
> from EMVCo. A verifier MUST support version 1 for as long as version 1 codes
> may be presented to it, and MUST dispatch on the encoding rather than
> attempting to read one with the other's rules.

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

Both are fixed in encoding version 2 (§2.9), which places a globally unique
identifier at sub-tag `00`, moves the format version to a free sub-tag, and
keeps every length inside EMVCo's two digits by splitting the signature across
templates. §2.9 is the recommended encoding; this section describes what
version 1 does and why a verifier must still tolerate it.

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
- Every merchant-account template in the payload MUST name an identifier the
  signing key is registered for (§2.10).

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
6. Acquirer binding (§2.10): every merchant-account identifier in the payload
   is one the signing key is registered for.
7. Time: issuance skew, then expiry.

Signature before expiry is deliberate: a payload that has been tampered with
should report tampering, not staleness. Binding after signature is likewise
deliberate: it is only meaningful once the signer is known.

### 2.10 Acquirer binding — a key signs only for its own accounts

A signature proves which registered key signed. It does not by itself prove
that the key was entitled to vouch for the account the code pays into: without
a further rule, any key enrolled for Profile A — or any compromised one —
could sign codes paying into any account at any institution, and the
signature would lend them a scheme's authority.

Each Profile A key record therefore carries `acquirers`, a list of
merchant-account identifiers the key may sign for. A verifier MUST, after the
signature verifies, examine every Merchant Account Information template
(IDs `26`–`51`) in the payload and MUST reject the payload with
`ACQUIRER_KEY_MISMATCH` if:

- there is no such template; or
- any such template has no sub-tag `00`, or does not parse as sub-objects; or
- any such template's sub-tag `00` is bound to none of the key's `acquirers`.

An entry binds a sub-tag `00` value either **exactly**, or, where the entry
begins with `@`, as a **suffix** the value must end with (and be longer than).
The suffix form exists for schemes whose sub-tag `00` is an account-style
identifier of the form `merchant@bank`, where the bank part is what the key
should be bound to and the merchant part varies per code. A scheme whose
sub-tag `00` is a fixed acquirer identifier registers it exactly. A key that
signs for several identifiers — an institution's own scheme identifier and a
proprietary template it also emits — registers each.

The rule confines a compromised or rogue issuer key to codes paying into the
institution it was registered for. It does not make those codes honest: a
registered institution's own key signing for its own fraudulent customer is
registration abuse (§9), and is not reached here.

### 2.9 Encoding version 2 — EMVCo-conformant

Version 2 encodes the same claims as version 1 without deviating from EMVCo.
It exists because §2.4's deviations are not cosmetic: they cost the payload its
readability by a conforming parser, which was the property the unreserved-
template design was chosen for in the first place.

**Layout.**

```
  ...payload data objects...
  85 LL   00 LL GUID          Globally Unique Identifier
          01 LL "02"          encoding version
          02 LL kid           16 uppercase hex
          03 LL "ES256"
          04 LL issuedAt      10 digits
          05 LL expiresAt     10 digits, dynamic codes only
          06 LL payeeClass    "M" or "I"
  86 LL   00 LL GUID
          01 64 <signature characters 0..63>
  87 LL   00 LL GUID
          01 64 <signature characters 64..127>
  63 04   CRC
```

**Rules.**

1. Every length field MUST be exactly two decimal digits with a value of at
   most 99. There is no extended-length form in version 2.
2. Templates `85`, `86` and `87` MUST each carry the scheme's Globally Unique
   Identifier at sub-tag `00`. A verifier MUST reject a payload whose GUID is
   not this scheme's; the presence of *a* GUID is not sufficient.
3. The GUID for this scheme is `KH.QRSEAL.SQR`. It is part of the wire format.
   A national deployment MUST settle this value with the scheme operator before
   issuance, because changing it later is a further version.

   The default names the project and the country and asserts no institution.
   An earlier draft used `KH.GOV.NBC.SQR`, which claimed National Bank of
   Cambodia governance in the wire format for a design the Bank has not
   endorsed. **A default value MUST NOT assert an authority that has not
   granted it**, because the payload is the one place the claim travels without
   the document that disclaims it. If a central bank adopts this scheme, a GUID
   naming it is theirs to choose.
3a. **The template identifiers `85`, `86` and `87` MUST be confirmed unused
   before issuance** — against the national scheme's own merchant-presented
   guideline, and against the guideline of every scheme it is linked to for
   cross-border acceptance. EMVCo reserves `80`–`99` for unreserved templates
   but does not allocate within that range, so two schemes may independently
   choose the same identifier for different content. A collision would not be
   caught by any check in this specification: a foreign parser would read our
   template as theirs, or the reverse, and both would be conformant. We have
   **not** performed this check. It is a deployment precondition, not an
   implementation detail, and it became more pressing once KHQR and JPQR were
   linked for cross-border acceptance.
4. The signature MUST be split at exactly 64 characters: the first half in
   template `86`, the second in `87`, both at sub-tag `01`, both 64 uppercase
   hexadecimal characters.
5. Templates `85`, `86` and `87` MUST be the final three data objects before
   the CRC, in that order. This is what prevents an attacker appending data
   while leaving the signed prefix byte-identical, and a verifier MUST reject a
   payload whose tail is anything else.
6. The signing input is the payload from position 0 to the first character of
   template `86`. A verifier MUST recover it by substring from the received
   payload, never by re-serialising parsed objects — the §2.3 rule, unchanged.
7. All semantic rules in §2.5 apply unaltered.

**What version 2 buys.** A strict EMVCo 1.1 parser walks the payload, tiles it
exactly, reaches tag `63`, and validates the CRC. It will not understand
templates `85`–`87`, which is correct and expected: they are unreserved, it
ignores them, and the payment fields it does understand are intact. That is the
legacy transparency version 1 claimed and did not have.

**What it costs, measured.** The reference dynamic payload grows from 317 to
378 characters, and the QR symbol from version 10 to version 11 — 57×57 to
61×61 modules at error-correction level M. `tools/measure-qr.ts` reports both
encodings side by side. The cost is the three repeated GUIDs and the second
template header; it is the price of being readable by a parser that was never
told about this scheme.

**Migration.** Signers and verifiers are separate populations and move at
different speeds. The order that works is: verifiers accept both encodings;
then issuance switches to version 2; then version 1 issuance stops; and version
1 verification is retired only when no version 1 code can still be presented,
which for a printed static sticker is a matter of years, not weeks. §9's
statement that a deployment must upgrade parsers rather than only signers
remains true, and version 2 is what makes the upgraded parser an *EMVCo* parser
rather than a scheme-specific one.

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

**Issuer binding.** Claim `1` (Issuer) MUST equal the `subject.organisationId`
of the trust-list record whose key verified the signature, and a verifier MUST
reject a credential where it does not with `ISSUER_KEY_MISMATCH`. The check is
made after the signature verifies, because a mismatch is only meaningful once
the signer is known. Without this rule the signature proves only *which
registered key* signed; any key enrolled for Profile B could then issue a
credential in any institution's name, and the sole defence would be a reader
noticing that "signed by" and "issued by" differ, which is the kind of check
this specification exists to take away from readers. An issuer that operates
several keys registers each under the same `organisationId`.

### 3.1a Horizon — a hard gate on what Profile B may carry

A verifier resolves a key only while the trust list says it is valid (§4.2,
`KEY_EXPIRED`) and stops verifying once its list is older than 30 days (§4.2,
`TRUSTLIST_STALE`). Neither rule is written for a document that outlives its
issuing key, and this specification does not yet say how a verifier decades
after issuance obtains the issuer's key, establishes that it was the issuer's,
or shows that the signature predated the key's expiry.

Until it does, **an issuer MUST NOT issue a Profile B credential for a document
whose intended verification life exceeds the `notAfter` of the signing key.**
This is a rule, not advice. A degree, a land title and a civil-status record
are outside the profile as it stands; a receipt, a permit, a ticket or a
short-lived licence are inside it. An issuer that needs the former today should
keep its lookup reference, or emit a signed credential beside it that is
understood to expire with its key (paper §4.3). The archival mechanism that
would lift this gate is a specification change and is recorded as open in §9.

**Cohort keys narrow the gap without lifting the gate.** Nothing above caps a
key's `notAfter`, and nothing ties an institution to one key: the trust list
may carry any number of records under one `organisationId`, each credential
names the key that signed it, and keys are added and revoked independently. An
issuer of long-lived documents SHOULD therefore:

1. use one key per cohort — a graduating year, a faculty, a batch — so that
   revocation, which is per key, removes one cohort and not the institution's
   history;
2. register each cohort key with a `notAfter` as long as the documents must
   verify, and **destroy the private key** once the cohort is signed. After
   destruction nothing remains to compromise, so a long public validity
   carries no forgery risk, and the question whether a signature predated the
   key's expiry does not arise;
3. treat a compromise before destruction as the loss of that cohort, and
   reissue it under a fresh key.

The gate is then satisfied as written. What remains is organisational, and an
issuer MUST accept it knowingly: the trust list must keep carrying the public
record, and keep being republished and stamped within the freshness limits of
§4, for as long as the documents matter — a static signed file, mirrored,
rather than a per-query service, but a commitment across decades all the same.
Two limits stay open: cryptographic agility, since a signature made today must
still be trusted when read decades later and this specification does not yet
say how a scheme migrates algorithms; and the absence of any archival
mechanism for a verifier that cannot obtain a fresh list at all.

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
`subject`, and, for a key enrolled for Profile A, `acquirers`. Within
`subject`, `name` is for people and is never used in a trust decision;
`organisationId` is the issuer identifier that a Profile B credential's issuer
claim MUST equal (§3.1). `acquirers` lists the merchant-account identifiers a
Profile A key may sign for (§2.10). Both are part of the trust decision, and
the ceremony authority MUST assign them deliberately: a Profile A key with no
`acquirers` can sign nothing that verifies.

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
- A cohort key for long-lived credentials (§3.1a) is used for one cohort and
  then destroyed; only its public record persists, on the trust list, for the
  documents' life. Destruction is part of the issuing ceremony, not an
  afterthought.
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
3. Where the payload carries an amount (tag `54`), an interface intended for a
   payer MUST display that amount **and its currency together** before
   authorisation. This is a MUST where clause 2 is a SHOULD, and §8.1 says why.
4. The currency MUST be displayed as the ISO 4217 alphabetic code
   (`payeeDisclosure.currencyAlpha`) or an unambiguous localised name. An
   implementation MUST NOT display the ISO 4217 numeric code from tag `53` to a
   human, and MUST NOT display a currency symbol alone where that symbol is
   ambiguous in the deployment's locale. Where `currencyAlpha` is `null` — the
   numeric code is outside the mapping — the interface MUST indicate that the
   currency is unrecognised and MUST NOT imply the local one.
5. A Profile B verifier MUST require the caller to handle the printed-document
   comparison fields (§3.3).
6. A Profile B result MUST carry a per-credential status field, and offline
   verification MUST report it as `unchecked`. An implementation MUST NOT omit
   the field, and MUST NOT present an `unchecked` credential as current. This
   specification defines no per-credential revocation mechanism: the trust list
   revokes *keys*, which invalidates everything an issuer ever signed and is
   the wrong granularity for a single withdrawn document. A deployment needing
   revocation must consult the issuer's own record, and must report
   *signature valid, standing unknown* when it cannot.
6. An implementation MUST NOT log payload contents.

### 8.1 Why clauses 3 and 4 are MUST

A code whose payee is the intended payee and whose amount is authentic, but
whose currency the payer misreads, is the one case in which a valid signature
actively assists the attacker. The signature attests the very field carrying the
deception, and an interface that reduces verification to a tick presents the
wrong number as confirmed.

This is not hypothetical. In October 2025 a Cambodian tuk-tuk driver was
arrested after presenting passengers with codes that charged an agreed fare in
US dollars rather than in riel. Cambodia circulates both currencies at a rate
around four thousand riel to the dollar, so one three-character field carried
the entire loss.

Two properties of this specification make these clauses necessary rather than
merely prudent. The amount and currency sit *inside* the signed prefix, so a
conforming verifier confirms them. And every other field in the disclosure is
correct — the payee really is the person the payer means to pay, the merchant
name matches, `payeeClass` is right — so nothing else gives the payer a reason
to look. Only showing the currency does.

Clause 4 exists separately from clause 3 because showing a currency badly is a
way of not showing it. Tag `53` holds `116`, not `KHR`; a payer shown `116`
learns nothing, and a payer shown `$` in Cambodia learns something false.

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
- **Currency and amount deception.** §8 clauses 3 and 4 reduce this; they do not
  remove it. They oblige an interface to show the currency. They cannot oblige a
  payer to read it, and a payer who has already agreed a price out loud has
  formed the expectation that the display would have to overturn.
- **Counterfeit verifiers.** A fake wallet application that displays a tick for
  anything. The application trust list helps a diligent user and does nothing
  for one who installed the application from a link.
- **Foreign and platform codes.** Codes from systems outside the trust
  hierarchy cannot be verified, and a verifier that shows "unverified" for the
  majority of what people scan trains them to ignore the indicator.
- **A printed bill carrying an amount.** §2.5 forbids an amount on a static
  code and bounds a dynamic code's life at 300 s (`STATIC_CODE_WITH_AMOUNT`,
  `EXPIRY_WINDOW_TOO_LONG`). A payable notice that needs both an amount and a
  life of weeks is therefore not expressible. The issuers affected — utilities,
  tax and fee collection — are national in scale. Closing this is a third code
  kind with its own replay and reprint semantics, not a setting, and it has not
  been designed.
- **Credentials that outlive their key.** §3.1a gates Profile B to documents
  shorter-lived than the signing key, because the archival verification path —
  how a verifier decades out obtains and trusts the issuer's key and dates the
  signature against it — is unspecified. Until it is specified, long-lived
  documents are outside the profile.
- **Legacy transparency, in encoding version 1.** As §2.4 records, template
  `85` is not transparent to a strict EMVCo parser under version 1: its length
  encoding is not EMVCo's, and it does not carry the Globally Unique Identifier
  EMVCo requires of an unreserved template. **Encoding version 2 (§2.9) removes
  both deviations**, and a strict parser walks a version 2 payload and reaches
  its CRC. The limitation persists only for as long as version 1 codes remain
  in circulation, which for printed static codes is years.

## 10. Conformance

An implementation conforms if it produces the stated outcome for every case in
`vectors/vectors.json`, and for each rejection reports the stated reason where
one is given. Cases are typed:

- `verify` — the recorded payload must produce the stated outcome.
- `roundtrip` — the implementation signs, then verifies its own output. ECDSA is
  randomised, so a fresh signature differs from any fixed vector and must still
  verify; and deflate is not canonical, so a Profile B encoder is not required
  to reproduce the published bytes.

## Annex C — account risk list, screening and appeal

Annex C is the institutional layer. It is not cryptography and it is the part
that reaches authorised push payment fraud, which §0 and §9 record as
unreachable from the code.

### C.1 Statuses

| Status | Meaning | Approval | Default lifetime |
|---|---|---|---|
| `clear` | No listing in force | — | — |
| `restricted` | A prudential hold: one institution's operational judgement about its own exposure | One officer, immediate | 72 hours |
| `blocked` | A standing assertion about the account | Two distinct officers | 30 days |

A hold is not a sanction. A status that never expires is a penalty imposed
without process; the expiry is what keeps a hold a hold. Every status MUST carry
a deadline, and that deadline MUST be evaluated when the status is read. There
MUST NOT be a sweep job: a missed sweep would silently extend a restriction on a
real person's account, and neither they nor the institution would observe
anything wrong.

### C.2 Screening

A payer's institution MUST screen the payee account before executing a push
payment, and MUST apply this mapping:

| Status | Action |
|---|---|
| `clear` | Execute |
| `restricted` | Hold: delay, require additional confirmation, or route to manual review |
| `blocked` | Refuse |

The mapping is normative rather than advisory because a scheme in which one
institution holds where another releases is not a scheme.

A low-value carve-out MAY allow a payment to a `restricted` account below a
configured threshold to proceed with a prominent warning. The threshold MUST
default to zero in every currency, so that the safe behaviour is what an
unconfigured deployment does.

Reads MUST be strongly consistent. An eventually consistent store leaves a
window in which a just-listed account still reads clear, and that window is when
the account is drained.

**Recording.** A screening decision of `warn`, `hold` or `block` MUST be
recorded. A decision of `allow` MUST NOT be recorded individually, and the payer
MUST NOT be identified to the service. Whether an account was listed at a given
moment is reconstructable from the append-only change feed; recording every
cleared payment would build a national record of who paid whom, which is outside
this system's purpose.

### C.3 Attribution and audit

Every write MUST record the institution **and** the individual officer, by
per-officer mutual TLS credentials. An entry naming only an institution is not
an audit entry.

The audit log MUST be append-only, enforced by the storage layer rather than by
convention, and hash-chained so that an export's interior integrity is checkable
without trusting the database it came from. Corrections are new rows.

Writes MUST be rate limited per institution and per officer. Sustained volume
above a threshold MUST be refused **and** recorded as an incident: an institution
listing thousands of accounts in an hour is compromised or misconfigured, and
neither condition is a reason to act on its assertions.

### C.4 The right to contest a listing

An account holder MUST be able to contest a listing, through their
account-holding institution.

- The affected customer MUST NOT be able to query this service directly. An open
  lookup would tell a mule operator whether their account had been detected.
- Raising a contest MUST NOT by itself change the status. No institution may
  clear a suspicion by asserting that it is disputed.
- **An unanswered contest MUST lapse the listing.** Raising it starts a deadline
  against the listing institution — RECOMMENDED: 24 hours for `restricted`, 72
  hours for `blocked`, in both cases shorter than the listing's own lifetime.
  The deadline MUST be evaluated at read time, like the expiry. Silence must
  favour the account holder, who is the party unable to act.
- Answering takes **one** officer, whether the answer upholds or withdraws.
  Upholding must not be more onerous than ignoring. Withdrawal by the listing
  institution must not be more onerous than the listing was: a restriction takes
  one officer to impose, so requiring two to retract would make an error more
  expensive to correct than to make. The two-officer requirement remains on a
  discretionary removal by an institution that did not make the listing.

The listing institution's identity is disclosed to the account-holding
institution, not to the customer, so that the contest is possible without
defeating the tipping-off constraints anti-money-laundering regimes impose. This
leaves the affected person able to contest a listing without learning who made
it or on what evidence, which is unsatisfactory and is recorded here as an open
problem.

### C.5 What Annex C does not achieve

- It stops payments only to accounts **already listed**. Victims during the
  interval before anyone lists an account are not protected. Time-to-list, not
  detection accuracy, is the operative metric.
- It sees the first hop only. Cash-out and onward layering are invisible to it.
- It sits in the payment path, so an implementation that is not fast will be
  routed around.
