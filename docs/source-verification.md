# Source verification record

Every external claim in `paper/main.tex`, its primary source, and how it was
checked. Claims not listed here are supported by an artefact in this
repository rather than by a citation; those are in the second table.

Two of these checks corrected the working notes this project started from, and
both corrections are reflected in the paper.

## External claims

| Claim in the paper | Primary source | Status |
|---|---|---|
| EMVCo length fields are two decimal digits, `01`–`99`, max value 99 characters | EMVCo MPM v1.1, payload data-object format | **Verified.** Specification text confirms `ID` two digits `00`–`99`, `Length` two digits `01`–`99`, value 1–99 characters. Corroborated by two national specifications derived from it (HKMA, Cambodia/KHQR). |
| IDs `80`–`99` are unreserved templates, and each must carry a Globally Unique Identifier at sub-tag `00` | EMVCo MPM v1.1, Unreserved Templates | **Verified, and it corrected the design.** The requirement for a GUID at `00` was not in the original design notes, which used `00` for a format version. Recorded as a deviation in `SPEC.md` §2.4(b) and paper §5.4. |
| EU DCC pipeline: CBOR → COSE_Sign1 → zlib (RFC 1950) → base45 → `HC1:` prefix | Commission Implementing Decision (EU) 2021/1073 | **Verified.** Confirms zlib per RFC 1950, base45, and the `HC1:` context identifier. |
| EU DCC recommends error-correction level Q | Commission Implementing Decision (EU) 2021/1073 | **Verified.** Noted in the paper, since our measurements use level M and are therefore not directly comparable. |
| TUF's timestamp role defends against freeze attacks; version monotonicity against rollback | The Update Framework Specification | **Verified.** `timestamp.json` has a short shelf life specifically to prevent indefinite freeze attacks; a new timestamp with a lower version number must be discarded and reported as a potential rollback. The timestamp key is explicitly an online key, which is why our design keeps it separate from the offline Root. |
| Web Crypto ECDSA signatures are P1363 raw `r‖s`, not DER | W3C Web Cryptography API | **Verified.** Also confirmed empirically: `tools/` and the test suite verify the published 64-byte signature directly with no conversion step. |
| UK APP mandatory reimbursement in force 7 October 2024, maximum £85,000, cost shared equally between sending and receiving PSPs | UK Payment Systems Regulator final policy | **Verified.** In force 7 October 2024 for in-scope Faster Payments and CHAPS payments; £85,000 maximum; cost split equally between sending and receiving firms. |
| Schechter et al., site-authentication images: 23 of 25 participants entered passwords when the image was removed | Schechter, Dhamija, Ozment & Fischhoff, *The Emperor's New Security Indicators*, IEEE S&P 2007 | **Verified, with a correction.** The figure is 23 of the **25 participants who used their own accounts** (92%), not 23 of 25 participants overall — the study had 67 participants in total across role-playing and own-account groups. The paper states the qualifier, because dropping it overstates the result. |
| Bakong 2024: 608.32 million transactions; ~4.5 million KHQR-registered accounts, +36.4% on 2023 | National Bank of Cambodia, *Annual Report 2024* | **Partially verified.** The figures are consistently reported and attributed to the NBC Annual Report 2024, but the primary PDF could not be retrieved in the build environment (egress restricted). **Confirm against the NBC PDF before submission.** These figures are illustrative of scale and no argument in the paper depends on them. |
| No published Cambodia-specific QR-fraud incident data; circulating "146% Q1 2026 quishing surge" figures are vendor telemetry with undisclosed denominators | — | **Verified as an absence.** Searching surfaced only syndicated vendor press material with no Cambodian breakdown and no stated methodology. The paper treats the absence as a finding (§8) and does not rely on the vendor figure. |

## Claims supported by a reproducible artefact

| Claim | Artefact | How to reproduce |
|---|---|---|
| Published key material, `kid` and PEM re-derive correctly | `tools/keys.ts`, `tools/generate-vectors.ts` | `pnpm vectors:generate` — the generator aborts if the derived `kid` is not `27403764C95F4F5B` |
| The published 317-character Profile A payload verifies; CRC is `CB0C` | `vectors/vectors.json`, case `A-accept-published-reference` | `pnpm test` |
| The published 381-character Profile B payload decodes and verifies | case `B-accept-published-reference` | `pnpm test` |
| Forty conformance cases, thirty-one negative | `vectors/vectors.json` | `pnpm test`; also `kh-sqr run-vectors` |
| QR symbol versions and modules (Table 2) | `tools/measure-qr.ts`, `docs/qr-measurements.json` | `pnpm measure:qr` |
| Profile A's import graph reaches no CBOR or stream code | `tools/check-profile-a-isolation.ts` | `pnpm check:profile-a-isolation` |
| No Worker holds or uses a signing key | `tools/check-no-signing-keys.ts` | `pnpm check:no-signing-keys` |
| Verification performs no network access | `packages/core/test/no-network.test.ts` | `pnpm test` |
| The Profile B result exposes no boolean or `isValid` | `packages/core/test/profileB.test.ts` | `pnpm test` |
| The hand-written CBOR codec agrees with an independent implementation | `packages/core/test/cbor.test.ts` | `pnpm test` |
| Risk-list statuses expire at read time, with no sweep | `workers/risklist-api/test/index.test.ts` | `pnpm --filter @kh-sqr/risklist-api test` |
| Blocking and removal each require a second officer | `workers/risklist-api/test/index.test.ts` | same |
| The audit log rejects UPDATE and DELETE at the database level | `workers/*/test/index.test.ts` | same |

## Deliberately not claimed

- Any prevalence, frequency or trend figure for QR fraud in Cambodia.
- Any scan-reliability measurement at the larger symbol sizes. The paper's
  statement that a denser symbol scans less well on an inexpensive handset is
  labelled an inference, not a measurement.
- Any adoption, usability or field-deployment result. Nothing has been deployed.
- Conformance to the specification's mirror-independence requirement.
