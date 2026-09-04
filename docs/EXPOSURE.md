# What is exposed today, and what a signature changes

Two tables. The first says which attacks each **deployment pattern in common use**
is open to. The second says which of those KH-SQR closes, which it does not, and
what has to carry the rest.

**This document names patterns, not products.** No national scheme, platform or
operator is identified anywhere in it. That is deliberate and it is not
politeness: the exposure follows from the *shape* of a deployment — what the
payload carries and what the verifier can check — so naming an operator would
attach a structural finding to an institution that happens to have chosen a
common design. Every pattern below is in use in more than one country.

Problem numbering (P1–P9) follows [README §1](../README.md#1-the-problems-that-exist-now).

---

## The deployment patterns

| | Pattern | What the scanned code carries |
|---|---|---|
| **D1** | Printed payment code, fixed, no amount | Payee account and name, unsigned |
| **D2** | Payment code rendered per transaction on a screen | Payee, amount, unsigned |
| **D3** | Printed notice or bill carrying a payment code with an amount | Payee and amount, unsigned, printed days before payment |
| **D4** | Document credential carried as a **lookup reference** | A URL and a capability key. Nothing about the document itself |
| **D5** | Document credential with a **visual seal or badge only** | Nothing machine-checkable |

---

## Table 1 · What each pattern is exposed to

`Yes` = the attack works as designed against this pattern.
`Partly` = it works in some variants or with extra steps.
`—` = not applicable to this pattern.

| | | D1 | D2 | D3 | D4 | D5 |
|---|---|---|---|---|---|---|
| **P1** | Overlay forgery | **Yes** | — | **Yes** | — | — |
| **P2** | Forged official code | — | — | **Yes** | **Partly** | **Yes** |
| **P3** | URL-bearing code (quishing) | — | — | — | **Yes** | — |
| **P4** | Genuine code, false pretext | **Yes** | **Yes** | **Yes** | — | — |
| **P5** | Registration abuse | **Yes** | **Yes** | **Yes** | — | — |
| **P6** | Counterfeit verifier | **Partly** | **Partly** | **Partly** | **Yes** | **Yes** |
| **P7** | Transplanted credential | — | — | — | **Yes** | **Yes** |
| **P8** | Mule cash-out | **Yes** | **Yes** | **Yes** | — | — |
| **P9** | Currency substitution | **Yes** | **Yes** | **Yes** | — | — |

### The rows that need a sentence

**P1 does not touch D2.** A code rendered for one transaction cannot be covered
by one printed in advance. This is the single strongest argument for screens,
and it costs a device.

**P2 against D4 is *partly*, not *yes*, and the reason matters.** A lookup
platform can confirm that a record exists. But the printed code itself is
unsigned, so a forged notice can carry *any* code alongside a convincing badge,
and the reader who does not scan — or who scans and lands somewhere that looks
right — is not protected by a record they never reached.

**P3 against D4 is structural.** A lookup reference *is* a URL-bearing code.
The pattern cannot avoid this problem; it is made of it.

**P6 against D1–D3 is *partly*** because a counterfeit wallet can display a
satisfying result, but a payer using their real bank's app is not exposed.
Against D4 and D5 it is `Yes`: verification by browser or by eye is exactly what
a counterfeit imitates most cheaply.

**P9 applies wherever a currency code travels unauthenticated and unshown.** Two
codes differing in three characters can carry a factor of several thousand in a
dual-currency economy, and neither the payer nor the verifier is told which one
was presented.

**One exposure has no P-number.** D4 makes verification a *request*, so the
platform learns who checked which document and when — an employer checking a
candidate, a lender checking a title before a loan. It also makes the
credential's lifetime the service's lifetime. Neither is an attack; both are
costs the pattern carries permanently.

---

## Table 2 · What KH-SQR changes

`Fixed` = closed at the code layer, within the standard cryptographic threat
model. `Partly` = improved, with the residue named. `No` = untouched, and
something else must carry it.

| | | KH-SQR | What actually carries it |
|---|---|---|---|
| **P1** | Overlay forgery | **Fixed** | An attacker without a registered key cannot produce a code that verifies, and cannot alter a genuine one by one character |
| **P2** | Forged official code | **Fixed** | Signed by a registered issuer against a Root-anchored trust list; unsigned or altered fails |
| **P7** | Transplanted credential | **Partly** | Verification returns the fields that must match the paper and refuses to return a verdict, so the comparison cannot be skipped — but a person must still make it |
| **P9** | Currency substitution | **Partly** | Amount and currency move inside the signature, and displaying both is a MUST. Does not help if the payer does not read them |
| **P3** | URL-bearing code | **Partly** | The library rejects `http`/`https` payloads and exposes that check for *every* scanned code. Does nothing for a code opened by the handset's native camera — **S2**, a categorical prohibition, is the rest |
| **P6** | Counterfeit verifier | **Partly, weakly** | An application trust list helps someone who checks what they installed, and nothing for someone who installed from a link in a message |
| **P4** | Genuine code, false pretext | **No** | **S3** screening at the moment of payment reaches the repeat-payee subset only. The rest is **S1** incident data and **S5** liability |
| **P5** | Registration abuse | **No** | Onboarding quality, then cross-institution detection — **S3** and time-to-list |
| **P8** | Mule cash-out | **No** | **S6** exit controls on convertibility. Not a code-layer problem at any point |

**The two `Fixed` rows are the whole of what cryptography buys**, and P4 — the
one marked `No` — is the attack toward which effort migrates once they are
closed, and the one every documented Cambodian case falls into. Whether it
already dominates losses is unmeasured (see the last section). That ordering is
the argument, not a disclaimer attached to it.

---

## Table 3 · Which pattern to replace, and with what

| Current | Replace with | Why |
|---|---|---|
| **D1** printed payment code | **KH-SQR Profile A, static** — sign once at enrolment, print once | Closes P1 outright. Keeps the printed sticker, so the stall with no device is not excluded |
| **D2** per-transaction screen | **KH-SQR Profile A, dynamic** | P1 was already closed by the medium. The signature adds authenticated amount and currency (P9) and closes replay of a photographed screen |
| **D3** printed bill with an amount | **Nothing yet — see below** | Not expressible in KH-SQR today |
| **D4** lookup reference | **Both.** Keep the lookup; emit a signed credential beside it | The lookup keeps per-credential revocation and correction, which a signature cannot do. The signature adds offline verification, archival life and reader privacy. Neither replaces the other |
| **D5** visual seal only | **KH-SQR Profile B** | There is nothing to preserve. A badge is reproducible by anyone with a printer |

**D4 is the row to read twice.** The honest recommendation is not replacement.
A lookup platform can revoke one rescinded degree and correct one wrong date;
KH-SQR can do neither, because revocation is per key and invalidates everything
that key ever signed. Emitting a signed credential *alongside* the lookup code
costs the platform nothing in its own path and lets a verifier report three
states rather than two: current, withdrawn, or **signature valid, standing
unknown**.

---

## Where KH-SQR does not fit at all

Two cases, both confirmed by attempting them rather than reasoned about.

**A printed bill or notice carrying an amount (D3).** Not expressible. A static
code may not carry an amount; a dynamic code may not live longer than five
minutes. A bill needs an amount and a life measured in weeks.

```
printed bill, static + amount        ->  STATIC_CODE_WITH_AMOUNT
printed bill, dynamic, 14-day life   ->  EXPIRY_WINDOW_TOO_LONG
```

Today the payee can be signed and the amount left for the payer to key in —
which authenticates who is paid and leaves unauthenticated the number that P9 is
about. A third code kind would be a specification change, not a setting.

**A credential at its stated horizon.** A verifier needs a trust list at most 30
days old. A degree must verify in forty years, when no such list may be
published. The specification does not say how a verifier at that distance
obtains the issuer's key, establishes it was the issuer's, or shows the
signature predated the key's expiry — and today the key-window check would
reject it outright.

Both are recorded in [`USE-CASES.md`](USE-CASES.md) with the reproduction.

---

## What this table cannot tell you

How much of each attack happens. There is no published Cambodian incident data
broken down by mechanism, so nothing here is weighted by frequency or loss.
`Yes` in Table 1 means *the attack works*, never *this is where the money goes*.
Establishing the second is **S1**, and it is the proposal the project ranks
first for exactly this reason.
