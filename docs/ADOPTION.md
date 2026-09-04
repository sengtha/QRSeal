# Adoption: what a government would do, in what order

If a government decided to implement QRSeal — the KH-SQR specification together
with the institutional measures S0–S6 — this is the sequence, the structure, and
the conditions for moving from each phase to the next.

**It names roles, not institutions.** Every actor below is described by what it
does, because the sequencing follows from the function and not from which body
happens to hold it. A government reading this will know which of its
institutions each role maps to. That mapping is a decision for it, and one of
the first decisions the roadmap asks it to make.

**It is a proposal, not a plan.** Nothing here has been costed, trialled, or
agreed with anyone. Where a step depends on a number nobody has — how many
merchants, what fraction of loss, which threshold — the roadmap says so and
makes measuring it a step rather than assuming it.

---

## What constrains the sequence

Five things established elsewhere in this project decide the order. They are
not preferences.

1. **Coverage is a precondition, not a benefit that scales.** A signature asks a
   verifier to act on an *absence*. Below saturation an unsigned code means an
   unenrolled merchant far more often than a forgery, so a partial deployment is
   worth close to nothing and can make things worse. Verification must not be
   made *visible* to the public until coverage is near-complete.
2. **Code fails outward; statute fails late.** The cryptography (S0) and the
   institutional measures (S1–S6) address different layers and neither
   substitutes for the other. They deploy together, not as alternatives.
3. **Nothing can be evaluated without incident data.** S1 is ranked first in the
   paper because every later step's effect is otherwise unmeasurable. It
   therefore comes first here too — before any code is issued, so there is a
   baseline.
4. **Encoding version 2 is legacy-transparent.** A signed code is a valid
   unsigned code to any wallet that has never heard of the scheme. This is what
   makes silent coverage possible: issuers can sign everything before a single
   verifier changes behaviour.
5. **Two specification gaps must be closed by decision before they are hit.**
   A printed bill carrying an amount cannot be signed, and a credential's
   verification at its stated horizon is not specified. Neither blocks the
   payment rollout; both block specific issuers, and the roadmap keeps those
   issuers out until the decisions are made.

---

## The structure: roles

| Role | Holds | Must never |
|---|---|---|
| **Rail operator** | The national payment scheme; the authority to mandate what merchant codes look like | Hold the Root key alone |
| **Ceremony authority** | The Root key, under split custody, on air-gapped hardware, exercised periodically | Be online. Be one person. Be the same body that runs the registry |
| **Registry operator** | `registry-api`: issuer enrolment, CSR queue, published certificates | Hold any signing key. Hold any credential or transaction data |
| **Trust-list publishers** (three) | `trustlist-edge` and two mirrors under distinct operational control | Share a provider, an account, or a governance failure |
| **Timestamp signer** | The freshness key, separate from Root, outside the distribution provider | Be co-located with the trust list it attests |
| **Issuers, Profile A** | Their own signing keys, or access to a shared signing service | Sign credentials |
| **Issuers, Profile B** | Their own signing keys | Sign payment codes. Centralise graduate or registrant data anywhere |
| **Risk-list operator** | `risklist-api`; officer enrolment; the low-value screening threshold | Freeze an account on one officer's word. Sweep expiries by cron |
| **Financial regulator** | S1 reporting mandate; S5 liability rule; S6 exit-control tiers | Delegate the screening threshold to the operator — it is a policy parameter |
| **Communications regulator** | S2, the URL prohibition, applied to the channels that carry quishing | — |
| **Independent auditor** | Pre-pilot security audit of the reference implementation; annual review of the ceremony | Be paid by the registry operator |
| **Statistics function** | Publishes S1 incident data broken down by mechanism | Publish figures without stated provenance |

Three design rules run through that table:

- **Separation of the Root from everything online.** The ceremony authority is
  the only holder of the key that can mint an issuer, and it is never reachable
  over a network. Compromise of every online component together yields the
  ability to withhold, never the ability to issue.
- **One institution, one role, where roles conflict.** The registry operator and
  the ceremony authority are different bodies. The auditor is not paid by the
  operator it audits. The three trust-list publishers are three governance
  failures apart.
- **Per-person accountability.** Every officer holds their own certificate.
  "Institution X listed this account" is not an audit entry; a named person is.

---

## Phase 0 — Settle

*Duration: until every item is decided. Nothing is deployed.*

Decisions that cannot be revisited cheaply, and that later phases depend on.

1. **Adopt the layer boundary as policy.** Signatures close forgery. They do not
   touch deception, the attack toward which effort migrates once forgery is
   closed. Any communication that suggests otherwise is
   refused at this phase and every later one.
2. **Map the roles above to institutions.** Including who is the ceremony
   authority and who the three publishers are.
3. **Settle the scheme identifier.** The default `KH.QRSEAL.SQR` asserts no
   institution. Once an institution adopts, it may choose one that names it.
   This is part of the wire format and cannot be changed afterwards without a
   further encoding version.
4. **Confirm template identifiers `85`, `86`, `87` are unused** against the
   national merchant-presented guideline and every scheme it is linked to for
   cross-border acceptance. One linked scheme is confirmed clear; the national
   guideline itself is not.
5. **Decide key custody devolution.** Which issuers hold their own keys, and
   which sign through a shared service. A shared service reintroduces a central
   dependency and must itself be governed; the alternative is every small
   issuer holding a key it may not protect.
6. **Decide the credential horizon.** For Profile B, either validate the key
   window against the credential's issuance time, accepting that a compromised
   key's historical credentials stay valid, or keep validating against the
   present and accept that long-lived credentials need a notarisation mechanism
   the specification does not yet have. **Until decided, Profile B is scoped to
   documents whose own life is shorter than a key's** — licences, permits — and
   not to degrees or titles.
7. **Decide whether to extend the specification for printed bills.** A printed
   notice carrying an amount cannot be signed today. Either accept that bills
   authenticate the payee only, or commission a third code kind with a replay
   story. Until decided, bill issuers are out of scope.
8. **Commission the independent audit** of the reference implementation. It has
   not had one and is not represented as fit for production.
9. **Enact S1** — mandatory incident reporting broken down by mechanism, with a
   statistics function to publish it. **This is the one measure that starts in
   Phase 0**, because everything after it is unmeasurable without a baseline
   that predates the intervention.

**Gate to Phase 1:** every decision above recorded; audit findings addressed;
first S1 reporting period complete.

---

## Phase 1 — Foundation

*Infrastructure and governance. No public-facing change.*

1. **Constitute the ceremony authority** with split custody and run the first
   ceremony: Root key generated, first trust list signed.
2. **Deploy** `registry-api`, `trustlist-edge` with its two independent mirrors,
   and the timestamp signer outside the distribution provider.
3. **Enrol the first issuers.** A small number of Profile A issuers — payment
   institutions — and Profile B issuers scoped per Phase 0 decision 6.
4. **Mandate visual uniformity** for printed payment codes: fixed design, minimum
   cell size, minimum print density, prohibition on alteration. This is the
   instrument another national scheme made binding, it keeps the printed
   sticker, and it gives an inspecting merchant a fixed reference to notice
   deviation from. It costs almost nothing and it is not dependent on coverage.
5. **Enact S2** — the categorical prohibition on URL-bearing payment and official
   codes, with a public rule that requires no judgement to apply. Also
   independent of coverage.
6. **Enrol risk-list officers**, per person, at each participating institution.
   Deploy `risklist-api` with screening in **advisory mode**: decisions are
   recorded and returned, but no payment is held on them.

**Gate to Phase 2:** first trust list published at all three mirrors; timestamp
statement being reissued on schedule; at least one full key-rotation rehearsal
completed; uniformity rule in force.

---

## Phase 2 — Silent coverage

*Issuers sign everything. Verifiers change nothing visible.*

This is the phase legacy transparency exists for. Because a version 2 signed
code is a valid unsigned code to any existing wallet, coverage can be built
without a single user seeing a difference.

1. **All new codes are signed.** Every enrolled issuer signs at enrolment
   (static) and per transaction (dynamic). No exceptions for new issuance.
2. **Reprint existing merchant codes**, prioritised by exposure — markets,
   transport, tourist districts — and by the display-rule analysis: merchants
   above a turnover threshold move to screens; those below receive reprinted,
   uniform, signed stickers.
3. **Wallets add verification but display nothing negative for an unsigned
   code.** An absence means *not yet enrolled*, and a wallet that says otherwise
   during this phase is training users to ignore it. Wallets **do** display the
   payee name and the amount with its alphabetic currency for every code, signed
   or not — that instruction is true regardless of coverage.
4. **Screening runs in shadow.** Every payment is screened, every decision
   recorded, nothing held. Institutions list and appeal for real, so the
   two-officer rule, the deadlines and the lapse are exercised before they have
   consequences.
5. **Measure.** Coverage as a fraction of active merchant codes, from issuer
   enrolment data. Incident mechanisms, from S1. Screening decision
   distribution, from the shadow log.

**Gate to Phase 3 — the one that must not be waived:** coverage above a stated
threshold of active merchant codes, measured not estimated. The threshold is a
decision for the rail operator; the roadmap's only requirement is that it be
high enough that an unsigned code is genuinely anomalous. A deployment that
proceeds below it has bought the cost of every later step without the benefit.

---

## Phase 3 — Visible verification

*Verifiers begin to distinguish. Screening begins to hold.*

1. **Wallets distinguish signed from unsigned** — and the public message is the
   narrow one: *read the payee name and the amount with its currency before
   authorising*. Not *distrust printed codes*, which condemns the genuine
   artefact along with the forged one and asks the payer to judge what they
   cannot see.
2. **Screening moves from advisory to enforcing.** `hold` holds; `block` blocks.
   The **low-value threshold** — below which a restricted payee produces a
   warning rather than a hold — is set by the financial regulator, published,
   and owned by it. The safe default is zero.
3. **Screening fails open in every caller**, by rule. An unreachable risk list
   means *unscreened*, and *unscreened* is not *clear*. A payment institution
   whose integration fails closed has turned an availability incident into an
   outage, and that is a compliance finding against it.
4. **The display rule phases in by turnover**, with device provision for
   merchants below the threshold. The distributional analysis this needs is
   partly available — devices are not the scarce input — and partly not.
5. **Profile B extends** to long-lived documents only if Phase 0 decision 6 was
   taken, and in the direction it was taken.

**Gate to Phase 4:** screening enforcing for one full S1 reporting period;
appeals answered within deadline in the overwhelming majority of cases; no
sustained availability incident.

---

## Phase 4 — Steady state

1. **The public message becomes** *an unsigned code is anomalous* — which is
   true only now, and was untrue at every earlier phase.
2. **S5, liability allocation**, is enacted. It needs S1 data to calibrate, and
   it needs the screening layer to be enforcing, because a liability rule that
   turns on whether an institution screened requires that screening exist.
3. **S6, exit controls**, are designed and piloted — thresholds, risk classes
   and the cost to legitimate small traders all set from S1 data rather than
   assumed. This is the proposal the paper explicitly did not design.
4. **Key rotation is routine.** Cycles are published; reprint logistics are
   scheduled; a revocation drill has been run.
5. **Cross-border.** Template identifiers coordinated and trust lists federated
   with each linked scheme. Legibility of a signed code to a foreign wallet was
   achieved in Phase 2; *verifiability* by one requires this step.

---

## The gates, in one table

| From | To | Condition | Who certifies |
|---|---|---|---|
| 0 | 1 | Every Phase 0 decision recorded; audit addressed; S1 baseline period complete | Financial regulator |
| 1 | 2 | Trust list at three mirrors; timestamp on schedule; rotation rehearsed; uniformity in force | Rail operator, auditor |
| 2 | 3 | **Coverage above threshold, measured** | Rail operator, from enrolment data |
| 3 | 4 | Screening enforcing one reporting period; appeals within deadline; no sustained outage | Risk-list operator, statistics function |

Every gate is a **condition, not a date**. A phase that is behind schedule is
behind schedule; a phase that is entered with its gate unmet has spent the cost
of the next phase and forfeited its benefit.

---

## What not to do

Each of these is attractive at some point in the sequence, and each is
rejected in the paper for a stated reason.

- **Do not tell the public not to trust printed codes.** Before saturation it
  cannot be acted on and removes payment access from the merchants least able
  to replace it; after saturation it is redundant. It is not a cheap
  substitute for coverage; it is a consequence of having achieved it.
- **Do not deploy screening fail-closed.** Everything else in the system fails
  closed. This cannot.
- **Do not make verification visible before the coverage gate.** An unsigned
  code during rollout is an unenrolled merchant, and a wallet that flags it is
  training users to ignore the flag.
- **Do not start S0 without S1.** You will never learn whether it worked.
- **Do not put an institution's name in the scheme identifier before that
  institution has adopted.** The default asserts nothing; keep it that way until
  someone is entitled to assert something.
- **Do not brand the institutional proposals.** They are reference designs, none
  trialled. Numbered proposals cannot be cited as an adopted framework.
- **Do not let the registry hold data.** It enrols keys. The day it holds
  credentials or transactions it has become the central platform the design
  exists to avoid.

---

## What this roadmap does not know

- **How many merchants there are**, or what fraction of them could move to a
  screen. Phase 2's reprint programme cannot be sized without this.
- **What coverage threshold is sufficient.** The roadmap says "high enough that
  an unsigned code is anomalous" and leaves the number to the operator, because
  no data exists to set it.
- **What any of this costs.** Devices, reprints, ceremonies, mirrors, officers.
  No estimate is offered because none would be worth reading.
- **Whether every issuer can hold a key.** Phase 0 decision 5 asks the question;
  this document does not answer it.
- **How much of each attack actually happens.** S1 exists to find out, which is
  why it is first.
