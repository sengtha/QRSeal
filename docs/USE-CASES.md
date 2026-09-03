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
dominant Cambodian attack — a genuine code presented with a lie — passes through
all of them untouched, which is what [README §3](../README.md#3-what-qrseal-cannot-solve)
and the paper's §3 are about.
