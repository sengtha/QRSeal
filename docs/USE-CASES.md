# Use cases: what P1 and P2 look like in practice

Every deployment shape QRSeal's two profiles cover, what happens step by step,
which Worker is involved, and — for two cases — why the design does not cover it.

Every character count, symbol version and rejection code below was produced by
running the library, not estimated. The two unsupported cases were confirmed by
attempting to sign them.

- **P1** — overlay forgery: a sticker carrying the attacker's code pasted over a
  merchant's. Answered by **Profile A**.
- **P2** — forged official codes: a printed code on a fake notice or certificate,
  claiming to prove the document genuine. Answered by **Profile B**.

---

## What cross-verification actually requires

A code signed in bank A's app verifies in bank B's app. That is the point of a
trust list rather than bilateral agreements — but it takes **four** things, and
only two of them are Workers.

| | What it does | When |
|---|---|---|
| **Offline Root ceremony** | Produces the Root-signed trust list carrying every enrolled issuer's public key | Not a Worker. Air-gapped, periodic |
| **`registry-api`** | Gets bank A's key *into* the ceremony's input — CSR intake, queue, published certificate | Issuance path |
| **`trustlist-edge`** | Gets the list *out* to bank B — read-only distribution | Fetch path |
| **Root key pinned in bank B's app** | The anchor everything else chains to | Not a Worker. Baked into the app build, out of band |

Trust is not bilateral. Bank B never agrees anything with bank A: it pins the
Root, fetches one list, and can then verify codes from every enrolled issuer.
The `kid` in the payload selects the key; a key not on the list gives
`UNKNOWN_KID`.

**Neither Worker is in the moment-of-payment path.** Bank B's app verifies
offline, against a trust list it fetched earlier — at most 30 days old — and a
timestamp statement valid for seven days. If both Workers vanish, existing
verifiers keep working until those windows lapse, and then stop rather than
fall back on stale material. That is deliberate: §4 of the paper argues a
verifier that fetched *during* verification could be stalled or steered by
whoever controls the network, who at a market stall is not a trustworthy party.

So: both Workers are required to **establish and maintain** cross-verification.
Neither is required to **perform** it.

### Both profiles, one registry, one list

The same two Workers serve P1 and P2. There is no separate credential registry
and no second trust list. `registry-api` accepts a `profiles` field on the CSR
matching `^[AB](,[AB])*$`, each trust-list record carries the profiles its key
is authorised for, and the resolver enforces it:

```ts
if (!record.profiles.includes(profile)) { sawWrongProfile = true; continue; }
// ... throw new KeyProfileMismatchError()   →  KEY_PROFILE_MISMATCH
```

That scoping is a control rather than a convention. A university key enrolled
for `B` alone cannot sign a payment code; a bank key for `A` alone cannot sign a
diploma. The check happens at verification and has its own reason code.

### Where the shared mechanism stops: archival verification

For verification *today*, P1 and P2 are identical — same ceremony, same
registry, same list, same distribution. For a credential at its stated horizon
they are not, and the difference is easy to miss.

A verifier needs a trust list at most 30 days old and a timestamp statement
valid for seven days. In 2050 there may be no `trustlist-edge`, no ceremony and
no scheme. The paper's answer for that horizon is different in kind — *the
relying party needs the issuer's archived public key and nothing else* — and
that is not the trust-list mechanism. It is an assertion about what a verifier
could do in principle with an archived key, and **the specification does not
say how a 2050 verifier obtains that key, establishes it was the issuer's, or
determines that the signature was made while it was valid.** The last of those
is the `KEY_EXPIRED` question below.

So the accurate statement is:

- **P1 and P2, contemporary cross-verification:** both Workers, one list, one
  mechanism. Identical.
- **P2 at archival horizons:** neither Worker, and no specified mechanism.

There is also a cadence difference worth planning for. A payment app refreshes
its trust list invisibly, because it is used daily. An HR system that checks two
diplomas a year will find its list stale every time and must fetch on demand —
so "offline verification" means offline *at the moment of checking*, not offline
*ever*. A credential verifier that is genuinely disconnected — a border post, a
rural registry — needs its list refreshed on a schedule someone owns.

---

## The one rule that generates every P1 case

`SPEC.md` §2.5:

- A **static** code (Point of Initiation `01` absent or `11`) MUST NOT carry an
  amount (tag `54`).
- A **dynamic** code (`01` = `12`) MUST carry an expiry, with
  `expires − issued ≤ 300` seconds.

So: **no amount, lives forever. Amount, lives five minutes.** Every case below
is a consequence of that, including the two that fall outside it.

---

## P1 · A1 — Market stall, tuk-tuk, roadside vendor

**The artefact.** One printed sticker. No device, no power, no connectivity.

**Signing happens once, at enrolment.** The bank signs the merchant's static
payload and prints the sticker. It is never re-signed for a transaction.

| | |
|---|---|
| Signed payload | **355 characters** |
| QR symbol | **version 11, 61 × 61** at error-correction M |
| Unsigned equivalent | 93 characters, version 5, 37 × 37 |

**Every scan, forever.** This is the property that makes signatures the right
instrument here and one-time tokens the wrong one: a token is consumed, a
printed sticker is not. A signature attests *provenance*, not novelty, so it is
re-verifiable on the ten-thousandth scan of the same sticker.

**What the customer's app does.** Fetches the trust list from `trustlist-edge`
periodically — at most 30 days old — plus a fresh timestamp statement. At the
moment of payment it verifies **offline**, with no network call.

**Overlay attack:** the attacker's sticker is either unsigned, or signed by a key
not on the trust list. Rejected — `UNKNOWN_KID`. They cannot alter the genuine
one by a character without breaking the signature.

**What forces a reprint.** Not transactions. Two other things:

- **Key expiry.** `trustlist.ts` checks the key window against *now*, not
  against when the code was signed. When the issuer key passes `notAfter`, every
  sticker signed under it fails with `KEY_EXPIRED`. Schedulable — rotate on a
  long cycle, reprint on a known date.
- **Key revocation.** Checked first and absolute: every code that key ever
  signed stops verifying immediately, including physical stock already on ten
  thousand counters. There is no way to revoke one sticker.

---

## P1 · A2 — Shop counter, standee, printed menu

Identical to A1 in every technical respect. Larger paper, same 355 characters,
same version 11 symbol, same reprint triggers. Listed separately only because
the *inspection* advice differs: a merchant with a fixed counter can check the
code daily, which is the merchant-directed remedy Japan's guideline recommends
and §7.3 of the paper endorses.

---

## P1 · A3 — Restaurant, POS terminal, till with a screen

**The artefact.** A code rendered on a screen for one transaction, carrying the
amount.

| | |
|---|---|
| Signed payload | **378 characters** |
| QR symbol | **version 11, 61 × 61** |
| Lifetime | ≤ 300 seconds, enforced at signing |

**Signing happens per transaction**, in the merchant's app or the acquirer's
backend — wherever the issuer key lives. Not on the customer's device, and not
in any Worker.

**This is the strongest case in the system**, and the reason is not
cryptographic: there is no printed artefact to cover. The overlay attack has
nothing to attach itself to, there is nothing to inspect periodically, and no
spot-check to remember. The signature then closes the residual case of a
screen-photographed code replayed after expiry.

**The cost is a device**, and §7.3 is careful about who pays it.

---

## P1 · A4 — Merchant phone app, amount typed in

Mechanically A3. The distinction worth drawing is *where the key is*: on a
handset rather than in a till or a backend. A phone can be lost or rooted, which
is a key-custody question rather than a protocol one, and the answer is
revocation — with the consequence noted in A1.

---

## P1 · A5 — Person-to-person, receiving money

Same as A1 or A3 depending on medium, with one field different: `payeeClass` is
`'I'` rather than `'M'`. A verifier surfaces it, and an interface should show
it, because *paying an individual* and *paying a registered business* are
different acts and the payer is entitled to know which one they are performing.

It changes nothing cryptographically. It is a disclosure, not a control.

---

## P1 · A6 — A printed bill carrying an amount · **NOT SUPPORTED**

**The artefact.** An electricity bill, a water bill, an invoice: printed,
delivered, carrying the amount owed, paid days later. The paper already cites
exactly this — the national utility promoting a QR printed on its bills for
customers to scan and pay.

**It cannot be signed.** Confirmed by attempting all three encodings:

```
printed bill, STATIC + amount, no expiry     ->  STATIC_CODE_WITH_AMOUNT
printed bill, DYNAMIC + amount, 30-day life  ->  EXPIRY_WINDOW_TOO_LONG
printed bill, DYNAMIC + amount, 24-hour life ->  EXPIRY_WINDOW_TOO_LONG
counter code, DYNAMIC + amount, 300 seconds  ->  signs (378 chars, dynamic)
stall sticker, STATIC, no amount             ->  signs (355 chars, static)
```

Static forbids an amount; dynamic caps life at five minutes. A bill needs both
an amount and a life measured in weeks, and falls between them.

**This is a real gap, not a configuration mistake.** Both rules are there for
good reasons — an amount on an indefinitely-reusable code is a replay waiting to
happen, and a five-minute window is what makes a dynamic code
non-reusable — but their conjunction excludes a common and entirely legitimate
artefact.

**What a deployment can do today:** print an unsigned code for the bill and sign
nothing, or print a *static* signed code identifying the payee only and have the
customer enter the amount. The second keeps the payee authentic and loses the
amount's integrity, which is the half that matters for P9 currency
substitution.

**What the specification would need:** a third code kind — an amount plus a
long, explicit validity window — with a replay story that does not depend on
freshness. That is a specification change, not a parameter change, and this
document does not propose one.

---

## P1 · Worked example — the National University of Management

A single institution, spanning three of the cases above and running into the
fourth. Every figure below was produced by signing a payload built from NUM's
details; the account identifier is the published test one, not a real account.

NUM appears in **both profiles**: it takes payments (A) and it issues diplomas
(B). Those should be **two keys, not one**. The scheme permits a single key
enrolled for `"A,B"`, but separating them separates custody and rotation — the
finance office holds the payment key, the registrar holds the credential key,
and compromising one does not invalidate the other's artefacts. Given that
revocation is per key and absolute, that separation is worth the second
enrolment.

### First question: who signs NUM's payment codes?

This is the P1 counterpart of the credential-issuance question, and the answer
is usually *not the merchant*.

**Model 1 — the acquiring bank signs.** NUM is a merchant like any other. Its
bank holds the Profile A key, signs NUM's payload at enrolment, and hands over
the printed artefact. NUM does nothing cryptographic and holds no key. This is
what a canteen stall must do, and what most merchants would do.

**Model 2 — NUM signs its own.** NUM enrols its own key through `registry-api`
with `profiles: "A"` and signs at its own cashier desks. Worth it only if NUM
issues many per-transaction codes and does not want a live dependency on the
bank at each one. It also means NUM now holds a payment-signing key, with
everything that implies.

The choice does not change what a payer's app does. Either way the `kid` in the
payload resolves against the same trust list.

### The three artefacts

**Canteen stall — printed sticker, no amount**

```
static · 367 characters · QR version 11, 61 × 61
```

Signed once at enrolment, printed once, verifies on every scan for the life of
the key. A stall has no device and needs none.

**Cashier desk — screen, tuition of 1,200,000 KHR**

```
dynamic · 392 characters · QR version 12, 65 × 65 · valid 300 seconds
```

Signed per transaction. The amount and currency are inside the signature, so a
student's app shows `1,200,000 KHR` as attested rather than as typed — which is
the P9 currency-substitution defence, and the reason the amount belongs in the
signed region rather than in the cashier's spoken instruction.

Note the cost: the amount and the longer merchant name push this to **version
12, 65 × 65**, one version above the reference payload in Table 1.

**Fee notice posted to a student — printed, carrying the amount**

```
as static  ->  STATIC_CODE_WITH_AMOUNT
as dynamic, 14-day life  ->  EXPIRY_WINDOW_TOO_LONG
```

**Cannot be signed.** NUM prints a fee notice with 1,200,000 KHR on it and gives
the student two weeks to pay. That is the A6 gap, in NUM's own numbers: static
forbids the amount, dynamic caps life at five minutes.

What NUM can do today is print the *canteen-style* code — payee authenticated,
no amount — and have the student key in 1,200,000 themselves. The payee is then
genuine and the number is not attested, which is the half that matters if
someone substitutes a currency or a digit.

### What the overlay attack looks like here

Someone pastes their own sticker over the canteen's. Under QRSeal the student's
app resolves the `kid` on the attacker's code against the trust list and finds
nothing: **`UNKNOWN_KID`**. The attacker cannot instead alter NUM's genuine
sticker, because a single changed character breaks the signature —
`SIGNATURE_INVALID`.

What it does *not* stop: someone messaging students "pay your fees here" with a
genuine code for their own account. That code verifies. It is
[P4](../README.md#p4--authorised-push-payment-fraud--not-addressed-at-all), it is
what the ministry-impersonation incident in the paper's §3 actually was, and no
signature reaches it.

### What NUM has to run

| Model 1 — bank signs | Model 2 — NUM signs |
|---|---|
| Nothing. Enrol as a merchant, receive printed codes | Generate and protect a Profile A key |
| | Run signing at each cashier desk |
| | Re-enrol and reprint on key rotation |
| Bank's key rotates → bank reissues NUM's codes | NUM's key compromised → every NUM code invalid at once |

For the canteen stall, Model 1 is obviously right. For a university cashier
running hundreds of per-transaction codes a day, Model 2 may be — and that is
the same devolution-of-key-custody question that Profile B raises for the
registrar, arriving from the payments side.

---

## P2 · The asymmetry that shapes every credential case

The display rule that answers P1 **does not transfer**. A screen cannot be
attached to a diploma or a land title. A printed credential carries its own
proof, possibly for decades. So every P2 case is printed, static, and long-lived
— there is no dynamic option and no screen option.

Reference credential: **381 characters, version 12, 65 × 65**.

Verification returns `mustMatchPrintedDocument` — subject name, document id,
issuing organisation, issue date — and offers no boolean. A caller cannot reach
a verdict without performing the comparison.

---

## P2 · The issuance flow, next to the lookup flow

The two models put the same university in very different positions. This is the
part that matters operationally, more than any cryptographic difference.

### The lookup flow

1. The platform operator holds the authoritative record for every certificate.
2. The university **submits each graduate's data** to the platform.
3. The platform returns a code; the university prints it on the certificate.
4. Anyone verifies by visiting the platform in a browser.

Every certificate passes through the centre. The centre can therefore revoke
one, correct one, and see them all.

### The QRSeal flow

**Once per university — enrolment, not per certificate:**

1. The university generates a key pair **on its own hardware**. The private key
   never leaves, and is never transmitted anywhere.
2. It submits a certificate signing request to `registry-api`:
   `POST /csr` with `csrPem` and `profiles: "B"`. **That is the entire payload** —
   a public key and which profiles it may sign for.
3. The offline Root ceremony issues the certificate; the university's public key
   joins the trust list.
4. `trustlist-edge` publishes the list.

**Per certificate — entirely inside the university:**

5. The university assembles the claims: subject name, document identifier,
   issuing organisation, issue date.
6. It signs locally — `kh-sqr sign-b --claims @claims.json --key <its own key>`.
7. It prints the resulting code on the certificate.

**No graduate data leaves the university. Ever.** `registry-api` has three
tables — `officers`, `csr_queue`, `audit_log` — and none of them holds a
credential. The registry enrols *keys*, not certificates. It could not produce a
list of who graduated if compelled to, because it has never been told.

**Verification (§ below):** anyone with the trust list, offline.

### What actually changed

| | Lookup | QRSeal |
|---|---|---|
| Who holds graduate data | the platform operator | **the university only** |
| Who signs | the platform, implicitly, by holding the record | **the university, with its own key** |
| Central interaction per certificate | one submission each | **none** |
| What the centre needs from a university | every record | one public key, once |
| What a university needs from the centre | the platform, permanently | the trust list |
| Centre can revoke one certificate | **yes** | no |
| Centre can correct one certificate | **yes** | no |
| Centre sees who verified whom | yes | **nothing to see** |

### The trade, stated plainly

QRSeal moves the work *and the risk* from the centre to the issuer.

The university gains autonomy and data sovereignty: it is not dependent on a
central service at issuance time, and no graduate record is centralised. What it
takes on is real:

- It must generate and protect a signing key, ideally in an HSM.
- It must run signing software as part of its graduation process.
- If its key is compromised, **every diploma it has ever signed** is invalidated
  at once, because revocation is per key and not per credential.
- It cannot withdraw a single rescinded degree — `credentialStatus` is always
  `unchecked`.

Under the lookup model the platform operator carries all four, and the
university types data into a form.

For a large university with an IT department, that is a good trade. For a small
provincial institution it may not be one, and a national deployment would have
to answer whether every issuer can hold a key properly — or whether some should
sign through a shared service, which reintroduces exactly the central dependency
the design removes. This paper does not answer that question.

---

## P2 · Who can be the verifier

**Anyone.** That is the architectural answer, and it is the sharpest difference
between carrying a credential and carrying a reference to one.

The trust list is public and verification is offline, so there is no gatekeeper
and no permission to obtain. A relying party needs the issuer's public key and
the document in hand:

- an employer checking a job applicant's degree
- a foreign university checking a Cambodian transcript
- a bank checking a land title before lending against it
- a notary, a registry clerk, a border officer
- the holder themselves, confirming their own document still verifies

### Against the reference model

Cambodia operates `verify.gov.kh`, which places QR codes on diplomas, medical
licences, certificates of incorporation, land titles and civil status documents.
The code on an issued degree carries a URL — no signature, nothing checkable
offline. The two models put the verifier in different places:

| | Reference (lookup) | Credential (Profile B) |
|---|---|---|
| What the code carries | a URL and a key | the signed credential itself |
| To verify | ask the platform's server | check a signature against a public list |
| Who can verify | the platform. Everyone else is its **client** | **anyone** holding the trust list |
| Needs network | yes, at the moment of checking | no |
| Works in 2050 | only while that service answers at that name | yes, with the archived public key |
| Who learns you checked | the platform | **nobody** |

That last row is worth dwelling on, because it is a cost of the lookup model
that is easy to miss. Every verification is a request, and a request is a
record: that this employer checked this candidate's degree on this date, that
this bank checked this land title the week before a loan. Offline verification
generates no such record, because there is no request. The paper names this
*reader privacy* alongside archival longevity and offline operation.

**The paper does not propose replacing the platform.** A service already holding
the authoritative record could emit a signed credential *alongside* its lookup
code at no cost to the lookup path — gaining longevity, offline operation and
reader privacy, and able to report three states rather than two: current,
withdrawn, or *signature valid, standing unknown*.

### The catch, and it is the same property

If anyone can verify, anyone can also *claim* to verify. That is **P6**, the
counterfeit verifier: an application that displays a satisfying tick for
anything at all. `trustlist-edge` serves an application trust list for this, and
the paper is blunt that it is weak — it helps a person who checks what they
installed, and does nothing for a person who installed from a link in a message.
Schechter et al. found that 23 of 25 participants entered passwords after their
own chosen site-authentication image was removed: people do not reliably notice
a missing positive indicator.

So the practical recommendation is about *where* the verifier lives rather than
who is permitted to build one. Put verification inside an application the
relying party already has a reason to trust — the bank's app for a land title,
a ministry's own app, an HR system, a registry's terminal. A standalone
"document checker" app is exactly the shape a counterfeit imitates most easily,
and it asks the user to make a trust decision about the checker before they can
make one about the document.

---

## P2 · B1 — University degree certificate

**Issued once, printed once, must verify for forty years.**

The signature proves the university issued *a* credential with these fields. The
`mustMatchPrintedDocument` comparison is what connects it to the paper in the
holder's hand — and that comparison is the entire defence against **P7**, the
transplanted credential: a genuine QR photographed off a real certificate and
printed onto a forged one verifies perfectly, because nothing about the paper is
signed.

**Two limits, both structural:**

- **`credentialStatus` is always `'unchecked'`.** Verification is offline, so
  the library cannot know whether a degree was rescinded after signing. A
  withdrawn diploma still verifies. `SPEC.md` §8 requires an interface report
  this as `unchecked` rather than presenting the credential as current.
- **Key expiry defeats the forty years.** `profileB.ts` resolves keys through
  the same `resolve(kid, profile, now)` as Profile A, so a diploma fails with
  `KEY_EXPIRED` the moment the issuing university's key passes `notAfter`. See
  [the open question](#p2--the-unresolved-question) below.

---

## P2 · B2 — Land title, property deed

B1 with a longer horizon — the paper says a century — and a higher loss on
failure. Everything in B1 applies more sharply, and the key-expiry question
becomes the dominant one: no key custody arrangement is credible over a hundred
years, and no title can be reissued because a key rotated.

---

## P2 · B3 — Licence, permit, short-lived official document

A business licence valid one year, a permit valid thirty days. **The most
comfortable P2 case**, because the credential's own life is shorter than any
plausible key lifetime, so the expiry problem does not arise.

`credentialStatus: 'unchecked'` still bites — a suspended licence verifies — and
here it bites harder than for a diploma, because suspension is an ordinary
administrative event rather than a rarity.

---

## P2 · B4 — Official notice or letter

The case P2 is named for: a printed code on a notice, attesting that the notice
is genuine. Directly relevant to the ministry-impersonation incident in the
paper's §3 — though note what a signature would and would not have done there.

It would have let a recipient check that a letter claiming to come from a
ministry actually did. It would **not** have helped in the incident as it
happened, because that letter carried no code at all: it carried a *payment*
code, in a different profile, belonging to someone else. A reader who expects
official letters to be signed and receives one that is not has to notice an
absence — which is the coverage problem in §7.3, and the reason B4 is worth
little until signed notices are the norm.

---

## P2 · The unresolved question

**Both profiles share one key resolver**, and it checks the key window against
`now`:

```ts
if (now > record.notAfter) { sawExpired = true; continue; }   // trustlist.ts
```

For Profile A this is right: payment codes are short-lived or reprintable. For
Profile B it contradicts the requirement the paper itself states — a degree must
verify in forty years, a land title in a hundred.

Two obvious fixes each break something:

| Fix | What it costs |
|---|---|
| Validate against the credential's `issuedAt` instead of `now` | A compromised key's historical credentials stay valid forever — defeating revocation for exactly the artefacts that cannot be recalled |
| Give credential keys hundred-year lifetimes | A key that cannot be rotated, protecting documents that cannot be reissued |

The standard resolution is a notarisation proving the signature existed while
the key was valid. QRSeal has timestamp machinery, but it attests *trust-list
freshness*, not signing time — adjacent, and not doing this job.

`SPEC.md` names `notAfter` as a trust-list field and says nothing about this
interaction. It is an open design question, and choosing between the two
resolutions is a policy decision about whether revocation or longevity wins.

---

## Summary

| Case | Medium | Amount | Signed | Symbol |
|---|---|---|---|---|
| A1 stall sticker | printed | no | once, at enrolment | v11, 61 × 61 |
| A2 counter standee | printed | no | once, at enrolment | v11, 61 × 61 |
| A3 POS / till | screen | yes | per transaction | v11, 61 × 61 |
| A4 merchant phone | screen | yes | per transaction | v11, 61 × 61 |
| A5 person-to-person | either | either | as A1 or A3 | as A1 or A3 |
| **A6 printed bill** | printed | yes | **cannot be signed** | — |
| B1 degree | printed | — | once, ~40 years | v12, 65 × 65 |
| B2 land title | printed | — | once, ~100 years | v12, 65 × 65 |
| B3 licence / permit | printed | — | once, months to a year | v12, 65 × 65 |
| B4 official notice | printed | — | once | v12, 65 × 65 |

**And in none of these cases does verification tell anyone the payment is one
they should make.** Every case above closes forgery of the artefact. The
attack that forgery's closure leaves standing — a genuine code presented with a
lie — passes through all of them untouched, which is what [README §3](../README.md#3-what-kh-sqr-cannot-solve)
and the paper's §3 are about.
