# demo-pwa — developer guide

Serves the sandbox PWA under `demo/pwa/` as Cloudflare Workers static assets.
It is not one of the S0–S6 services: it holds no key, no binding and no state,
and there is no Worker script at all. Everything the app does happens in the
browser.

## Build first

The assets directory is a build output. Nothing here runs until it exists:

```sh
pnpm build          # packages/core, which the app bundles
pnpm demo:build     # writes demo/pwa/
```

## Run locally

```sh
cd workers/demo-pwa
npx wrangler dev --port 8787
```

`wrangler dev` serves the directory exactly as production would, including the
`_headers` file, so this is the place to check that `/sw.js` comes back with
`Cache-Control: no-cache` and the manifest with its content type. Open
`http://127.0.0.1:8787/`; the service worker registers on `localhost` without
HTTPS.

Any static server works for a quick look, which is what the end-to-end check
uses:

```sh
pnpm demo:check     # python3 -m http.server + headless Chromium
```

## Deploy

```sh
pnpm demo:build && cd workers/demo-pwa && npx wrangler deploy
```

The Worker is named `qrseal` and takes a `workers.dev` hostname
(`workers_dev = true`), because it is meant to be public. If `wrangler deploy`
ends with `No targets deployed`, the Worker has no hostname: either
`workers_dev` is off, or the account's workers.dev subdomain is disabled in
the dashboard, or the Worker name in the dashboard differs from the one in
`wrangler.toml`. Requests then return not found even though the upload
succeeded.

### Workers Builds (deploy from the repository)

| Setting | Value |
|---|---|
| Root directory | `workers/demo-pwa` |
| Build command | `pnpm -w run build && pnpm -w run demo:build` |
| Deploy command | `npx wrangler deploy` |

`demo/pwa/` is committed, so a build that skips `demo:build` still deploys
the last committed output; including it makes the deployment follow
`demo/src/` rather than whatever was last checked in.

Each build hashes the shell into the service-worker cache name, so a deploy
installs a fresh cache and installed apps pick it up on their next load. The
`_headers` file exists so that an HTTP cache in front of the Worker cannot pin
the old `sw.js`; if you add a CDN, keep those rules.

## Invariants

- **No private key reaches this directory or the assets.** The sandbox
  generates its keys in the browser. `tools/check-no-signing-keys.ts` scans
  `workers/` and would flag one here as it would anywhere else.
- **The footer disclaimer stays.** The app verifies and looks authoritative,
  and its keys protect nothing.
- **`demo/pwa/` is generated.** Edit `demo/src/`, then rebuild.
