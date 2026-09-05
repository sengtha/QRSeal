# The sandbox PWA

**`demo/pwa/`** — a progressive web app that issues and verifies KH-SQR codes
on the device, offline. Serve the directory from anything static and open it
over HTTPS or `localhost`; the service worker then caches the whole app, and
it keeps working with the network off. Install it to the home screen if the
browser offers to.

The repository's own deployment is an assets-only Cloudflare Worker,
[`workers/demo-pwa`](../workers/demo-pwa/wrangler.toml).

## What it does

**The device is the whole scheme.** On first run the app generates a Root key,
a timestamp-signer key and an issuer key in Web Crypto, publishes a signed
trust list and a signed timestamp statement, and stores all of it in the
browser. From then on:

| Tab | What happens |
|---|---|
| **Issue** | Sign a Profile A payment code — static (printed, no amount) or dynamic (one transaction, amount and currency, at most 300 s) — or a Profile B credential, under the sandbox's current issuer key. Renders the QR, reports its symbol version, and offers the payload and a PNG. Untick *sign it* to see an unsigned code. |
| **Scan & verify** | Camera, image file, or pasted payload. Every scan runs the pipeline from [`docs/INTEGRATION.md`](../docs/INTEGRATION.md) §1.4: refuse URL carriers, route by profile and encoding, verify offline, then show what SPEC.md §8 obliges — the amount and alphabetic currency together, the payee, the four credential fields to compare with the paper — and never a tick. *Flip one character* shows what tampering looks like. |
| **Trust** | The sandbox's keys and list. **Revoke** the issuer key and every code it signed fails with `KEY_REVOKED`. **Enrol** a new one and issue again. **Export** the scheme bundle — public keys, trust list, timestamp, nothing private — and **import** it on a second device, which can then verify the first device's codes and nothing else. |
| **Vectors** | The published conformance suite, all 41 verification cases, run in the browser under the suite's frozen clock and test keys, with the currency-substitution pair beside it. |

The verification path is the library's. `tools/build-demo.ts` bundles
`packages/core` with esbuild, so the page cannot drift from the specification:
whatever it does is what the library does. QR rendering is `qrcode`; decoding
is the platform `BarcodeDetector` where the browser has one, else `jsQR`.

## Two devices

Issue on one device, scan on another. The second device needs the first one's
scheme: on the first, Trust → *Copy scheme bundle*; on the second, Trust →
paste → *Import*. The bundle carries no private key, so the second device can
verify but cannot issue under that scheme. Before the import the second device
rejects the code with `UNKNOWN_KID`, which is the correct answer to a key it
has never been told about.

## What it is for

Three arguments the paper makes that a page makes better:

1. **A signature verifies, and that settles almost nothing.** The page refuses
   to render a green tick because the library refuses to return a boolean.
2. **Revocation is per key.** One click, and everything the key ever signed
   is refused — right for a compromised key, wrong for one withdrawn diploma,
   which is why Profile B has no per-credential revocation.
3. **Currency substitution (P9).** Two genuine codes, same payee, same
   number; tag 53 differs.

And one thing it cannot show: a genuine code presented with a false story
verifies here exactly as it would anywhere, because there is nothing wrong
with it.

## Rebuilding and checking

```sh
pnpm build          # the demo bundles packages/core/dist
pnpm demo:build     # typechecks demo/src, writes demo/pwa/
pnpm demo:check     # drives the built app in headless Chromium (needs Playwright)
```

`demo:check` issues, verifies, flips, decodes a rendered PNG, revokes,
re-enrols, exports to a second browser profile and imports, runs the vectors,
then goes offline and reloads. It is the test that the app does what this
file says.

## Deploying

```sh
pnpm demo:build
cd workers/demo-pwa && npx wrangler deploy
```

The Worker has no script and no bindings; it hands out the files under
`demo/pwa/`, with `_headers` keeping the service worker and the shell out of
HTTP caches so that a new deployment reaches installed apps. Any other static
host works the same way, as long as it serves over HTTPS.

**Label it wherever you put it.** The keys were generated in a browser and
protect nothing; a code that verifies in the sandbox proves nothing outside it.
The page says so in its footer. Do not remove that. A demo that verifies and
looks authoritative is exactly the artefact this project warns about.
