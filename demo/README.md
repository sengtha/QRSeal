# The browser demo

**[qrseal-demo.html](qrseal-demo.html)** — one self-contained file. Open it in a
browser, or serve it anywhere static. No server, no network, no build step to
view it.

## What it is

The real verifier, running in the page. `tools/build-demo.ts` bundles
`packages/core` with esbuild and inlines it, so the demo cannot drift from the
specification: whatever the page does is what the library does. It also inlines
the trust list, the timestamp statement and all 41 verification vectors from
`vectors/vectors.json`.

Everything it claims is checkable on the page itself — all 41 vectors run in the
browser and the tally is live, not transcribed.

## What it is for

It makes three arguments that prose makes worse:

1. **A signature verifies, and that settles almost nothing.** The page refuses to
   render a green tick, because the library refuses to return a boolean. The
   disclosure ends with "Is it safe to pay?" answered "The library does not
   answer this, and neither does this page."
2. **Currency substitution (P9).** Two codes side by side — same payee, same
   account, same number, both genuinely signed, both verifying. One says
   `5303116`, the other `5303840`. A reader watches two valid signatures and
   sees that validity was never the question.
3. **Encoding v1 versus v2.** The inspector walks the payload with two-digit
   lengths only, exactly as a wallet implementing EMVCo 1.1 would. On a v1
   payload the walk fails and the page says so. That is the defect v2 exists to
   fix, demonstrated rather than described.

## Rebuilding

```sh
pnpm build          # the demo bundles packages/core/dist
pnpm demo:build     # writes demo/qrseal-demo.html
```

The build fails loudly if a curated vector id is missing from the suite, so a
renamed vector cannot leave the demo quietly showing something else.

## Deploying it

It is a single static file — any host will do, including
[`trustlist-edge`](../workers/trustlist-edge/DEVELOPMENT.md)'s bucket if you
want one origin. See [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) for which
Workers may be public.

**Label it wherever you put it.** The trust list is signed by this repository's
published test keys, whose private halves are public and protect nothing. The
page says so in its footer; do not remove that. A demo that verifies and looks
authoritative is exactly the artefact this project warns about.
