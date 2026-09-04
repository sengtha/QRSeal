# Evidence captures

Screen captures that stand behind claims in the paper, kept in the repository so
that a reader can see what the authors saw. Each file is listed with what it
shows, where it came from, and — where anything was covered — exactly what and
why.

**Not every capture the authors hold is here, and the omissions are deliberate.**
The rule is stated first because it matters more than the manifest.

## What is not kept, and why

| Capture | Why it is not in this repository |
|---|---|
| A university degree certificate bearing a lookup QR | Shows a named graduate's full name, date of birth and document number. It is a third party's education record. The paper uses only the *structure* of the URL the code carries, which is recorded in the text; the record itself was never resolved. |
| The lookup platform's result page for that certificate | Same person, same data. |
| A generated search-engine summary of QR scams | Not a source. No author, no date, no methodology, no stable text. Rejected in `../source-verification.md`. |

No capture in this directory identifies a private individual. Where a source
did, that part is covered before the file was committed, and the covering is
done by a script in the repository rather than by hand, so it can be inspected.

## Redaction policy

Two things are always covered, on any capture, before it is committed:

1. **A scannable payment QR.** A code reproduced at figure size in a PDF or a
   README scans. Committing one republishes a working payment instrument, in
   the ministry case pointing at an account used in a fraud, with an archival
   lifetime the original post never had.
2. **A private individual's name**, where it appears next to the word fraud.
   The person named on a payment code in a scam may be its operator, a
   nominee, or a victim of account takeover; the capture does not say which,
   and a public repository is not the place to guess.

Everything else is left as published, including text a reader of Khmer could
transcribe: the originals are the issuing institution's own public posts, and a
reader who wants the wording can follow the link in the manifest.

Redaction is performed by `tools/redact-capture.py`, which takes the original,
a list of rectangles to cover and an optional crop, and writes the committed
file. The original is not committed. The rectangles used for each file are
recorded below, so the redaction is reproducible from the original by anyone
who holds it.

## Manifest

| File | Shows | Source | Covered |
|---|---|---|---|
| *(pending)* `mef-telegram-warning-post.png` | The Ministry of Economy and Finance's verified page, its warning post, the timestamp, and the reaction and share counts, with the warning graphic embedded | The Ministry's Facebook page, `facebook.com/share/p/1GgsosTuMS/`, September 2026 | The payment QR and the payee name inside the embedded graphic; the phone's status bar cropped |
| *(pending)* `jpqr-site-*.png` | The scheme operator's public onboarding pages for JPQR merchant-presented codes | `jpqr.paymentsjapan.or.jp` | Nothing — a public scheme website with no personal data |
| *(pending)* `khmertimes-verify-418k.png` | A news headline reporting the volume of digital diplomas issued through the national lookup platform | Khmer Times | Nothing |

Files marked *pending* are described from the captures as supplied to the
authors in conversation; they are added to this directory as the files are
received, and this table is updated with the exact redaction rectangles.

## How the paper cites these

The paper cites the **source**, not the capture: a capture is evidence that the
source said what the paper says it said on the day it was read, not a citation
in its own right. Where a source has since changed or disappeared, the capture
is what remains, and the manifest row says so.
