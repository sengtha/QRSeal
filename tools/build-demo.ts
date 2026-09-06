/**
 * Build the QRSeal sandbox — a progressive web app under demo/pwa/.
 *
 * The demo must not reimplement verification or signing. It bundles
 * `packages/core` itself, so whatever the page does is what the library does;
 * a divergence between the demo and the specification is not possible by
 * construction. Everything the app needs is emitted into one directory with no
 * external requests, and a service worker precaches all of it, which is what
 * lets the app issue and verify with the network unplugged.
 *
 * Two kinds of key material reach the page, and both protect nothing. The
 * published suite's test keys sign the vectors on the Vectors tab, under that
 * suite's frozen clock. The sandbox keys the app uses to issue are generated in
 * the browser on first run and never leave it. The page says so in its footer.
 */

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { signProfileA2 } from '../packages/core/dist/profileA2.js';
import { keyPairFromScalar } from './keys.ts';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const DEMO = join(ROOT, 'demo');
const SRC = join(DEMO, 'src');
const OUT = join(DEMO, 'pwa');

interface Suite {
  keys: Record<string, { scalar: string }>;
  pinned: unknown;
  trustLists: Record<string, unknown>;
  timestamps: Record<string, unknown>;
  revocations: Record<string, unknown>;
  time: { issuedAt: number; expiresAt: number; nowValid: number };
  cases: readonly {
    id: string;
    profile: string;
    type: string;
    input: Record<string, unknown>;
    state: Record<string, unknown>;
    expect: string;
    reason: string | null;
  }[];
}

if (!existsSync(join(ROOT, 'packages', 'core', 'dist', 'index.js'))) {
  throw new Error('packages/core is not built; run `pnpm build` first');
}

const suite = JSON.parse(readFileSync(join(ROOT, 'vectors', 'vectors.json'), 'utf8')) as Suite;
const bin = (name: string): string => join(ROOT, 'node_modules', '.bin', name);

/* ------------------------------------------------------------------ *
 * 1. Typecheck the app, then bundle it with the real library
 * ------------------------------------------------------------------ */

execFileSync(bin('tsc'), ['-p', join(DEMO, 'tsconfig.json')], { stdio: 'inherit' });

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

execFileSync(join(ROOT, 'node_modules', '.pnpm', 'node_modules', '.bin', 'esbuild'), [
  join(SRC, 'app.ts'),
  '--bundle',
  '--format=iife',
  '--platform=browser',
  '--target=es2022',
  '--minify',
  '--legal-comments=none',
  `--outfile=${join(OUT, 'app.js')}`,
]);

/* ------------------------------------------------------------------ *
 * 2. The published vectors, and the currency-substitution pair
 * ------------------------------------------------------------------ *
 *
 * Two codes from the same payee for the same number, differing only in tag 53.
 * Both are genuinely signed and both verify. This is P9, and a live page makes
 * the point in a way prose cannot: two valid signatures, and validity was never
 * the question.
 */

const key = await keyPairFromScalar(suite.keys['issuer']!.scalar);
const { issuedAt, expiresAt } = suite.time;

const payeeCode = (currencyNumeric: string): string =>
  '00020101021230310011abaakhppxxx0112855012345678520458125303' +
  currencyNumeric +
  '540472005802KH5908SOK DARA6010PHNOM PENH';

async function sign(currencyNumeric: string): Promise<string> {
  const signed = await signProfileA2({
    payload: payeeCode(currencyNumeric),
    privateKey: key.privateKey,
    kid: key.kid,
    issuedAt,
    expiresAt,
    payeeClass: 'M',
  });
  return signed.payload;
}

const pick = (id: string) => {
  const found = suite.cases.find((c) => c.id === id);
  if (found === undefined) throw new Error(`vector ${id} not found — the demo would ship a lie`);
  return found;
};

const verifiable = suite.cases.filter((c) => c.type === 'verify');
const generated = new Date().toISOString().slice(0, 10);

const data = {
  generated,
  pinned: suite.pinned,
  trustLists: suite.trustLists,
  timestamps: suite.timestamps,
  revocations: suite.revocations,
  pair: { khr: await sign('116'), usd: await sign('840'), state: pick('A2-accept-dynamic').state },
  suite: verifiable.map((c) => ({
    id: c.id,
    profile: c.profile,
    expect: c.expect,
    reason: c.reason,
    encodingVersion: c.input['encodingVersion'] ?? 1,
    payload: c.input['payload'],
    state: c.state,
  })),
};
writeFileSync(join(OUT, 'demo-data.json'), JSON.stringify(data));

/* ------------------------------------------------------------------ *
 * 3. Static files, then the service worker with a content hash
 * ------------------------------------------------------------------ */

const page = readFileSync(join(SRC, 'index.html'), 'utf8').replace('__BUILD_DATE__', generated);
if (page.includes('__BUILD_DATE__')) throw new Error('a placeholder survived substitution');
writeFileSync(join(OUT, 'index.html'), page);

for (const name of ['manifest.webmanifest', '_headers']) copyFileSync(join(SRC, name), join(OUT, name));
for (const name of readdirSync(join(SRC, 'icons'))) copyFileSync(join(SRC, 'icons', name), join(OUT, name));

const precache = ['./', './index.html', './app.js', './demo-data.json', './manifest.webmanifest', ...readdirSync(join(SRC, 'icons')).map((n) => `./${n}`)];
const hash = createHash('sha256');
for (const name of ['index.html', 'app.js', 'demo-data.json', 'manifest.webmanifest']) hash.update(readFileSync(join(OUT, name)));
const version = hash.digest('hex').slice(0, 12);

const sw = readFileSync(join(SRC, 'sw.js'), 'utf8')
  .replace('__CACHE_VERSION__', version)
  .replace('__PRECACHE__', JSON.stringify(precache));
if (sw.includes('__CACHE_VERSION__') || sw.includes('__PRECACHE__')) throw new Error('a placeholder survived substitution');
writeFileSync(join(OUT, 'sw.js'), sw);

const size = readdirSync(OUT).reduce((n, f) => n + readFileSync(join(OUT, f)).length, 0);
process.stdout.write(
  `wrote demo/pwa/ (${readdirSync(OUT).length} files, ${(size / 1024).toFixed(0)} KB, cache ${version})\n` +
    `  ${data.suite.length} suite cases (${data.suite.filter((c) => c.expect === 'reject').length} negative), no external requests\n`,
);
