/**
 * End-to-end check of the sandbox PWA in headless Chromium.
 *
 * Serves demo/pwa on a local port and drives the page: issue a static code,
 * verify it, flip a character, verify from a rendered PNG, issue dynamic and
 * unsigned codes, issue a credential and compare it with "the paper", revoke
 * the issuer key, enrol a new one, export the scheme bundle and import it into
 * a second, empty browser profile, run the published vectors, then go offline
 * and reload. Every step asserts what the page shows.
 *
 * Needs Playwright with a Chromium build. It is not a dependency of this
 * repository; point PLAYWRIGHT_MODULE at an installation, or install it
 * globally (`npm i -g playwright`).
 *
 *   node demo/e2e/pwa.mjs
 */

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const PWA = join(ROOT, 'demo', 'pwa');
const PORT = Number(process.env['PORT'] ?? 8123);
const out = (line) => process.stdout.write(`${line}\n`);

function loadPlaywright() {
  const require = createRequire(import.meta.url);
  const candidates = [process.env['PLAYWRIGHT_MODULE'], 'playwright', '/opt/node22/lib/node_modules/playwright'].filter(Boolean);
  for (const c of candidates) {
    try {
      return require(c);
    } catch {
      // try the next
    }
  }
  throw new Error('playwright not found; set PLAYWRIGHT_MODULE or install it globally');
}

const { chromium } = loadPlaywright();

const server = spawn('python3', ['-m', 'http.server', String(PORT), '--bind', '127.0.0.1', '--directory', PWA], { stdio: 'ignore' });
await new Promise((r) => setTimeout(r, 800));
const ORIGIN = `http://127.0.0.1:${PORT}/`;

let failures = 0;
function check(name, condition, detail = '') {
  if (condition) out(`  ok   ${name}`);
  else {
    failures += 1;
    out(`  FAIL ${name}${detail ? ` — ${detail}` : ''}`);
  }
}

const browser = await chromium.launch();
try {
  const ctx = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(ORIGIN);

  out('sandbox');
  await page.waitForFunction(() => /sandbox list v\d+/.test(document.getElementById('pill-scheme').textContent));
  check('sandbox created and trust list published', true);
  await page.waitForFunction(() => document.getElementById('pill-offline').textContent === 'works offline', null, { timeout: 15000 });
  check('service worker installed and controlling the page', true);

  out('issue and verify, profile A static');
  await page.click('#a-issue');
  await page.waitForSelector('#i-out:not([hidden])');
  const staticPayload = await page.inputValue('#i-payload');
  check('payload is EMVCo with the v2 templates', staticPayload.startsWith('000201') && staticPayload.includes('KH.QRSEAL.SQR') && /6304[0-9A-F]{4}$/.test(staticPayload));
  const meta = await page.textContent('#i-meta');
  check('symbol metadata reported', /QR version \d+/.test(meta), meta);
  await page.click('#i-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  let body = await page.textContent('#v-body');
  check('static code verifies against the sandbox', body.includes('SOK DARA') && body.includes('static'));
  check('no boolean-shaped reassurance', body.includes('The library does not answer this'));

  await page.click('#s-flip');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Rejected');
  const flipReason = await page.textContent('#v-reason');
  check('one flipped character is rejected', /^(SIGNATURE_INVALID|CRC_MISMATCH|SIGNATURE_SUBTAG_MALFORMED|MALFORMED_TLV|SIGNATURE_TEMPLATE_NOT_LAST)$/.test(flipReason), flipReason);
  await page.click('#s-reset');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');

  out('verify from a rendered image');
  const dataUrl = await page.evaluate(() => document.getElementById('i-qr').toDataURL('image/png'));
  const dir = mkdtempSync(join(tmpdir(), 'qrseal-e2e-'));
  const png = join(dir, 'code.png');
  writeFileSync(png, Buffer.from(dataUrl.split(',')[1], 'base64'));
  await page.fill('#s-payload', '');
  await page.setInputFiles('#s-file', png);
  await page.waitForFunction((p) => document.getElementById('s-payload').value === p, staticPayload);
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  check('QR image decodes to the issued payload and verifies', true);

  out('dynamic and unsigned');
  await page.click('#nav-issue');
  await page.check('#a-kind-dynamic');
  await page.click('#a-issue');
  await page.waitForFunction(() => /Dynamic: expires in \d+ s/.test(document.getElementById('i-expiry').textContent));
  const dynamicPayload = await page.inputValue('#i-payload');
  await page.click('#i-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  body = await page.textContent('#v-body');
  check('dynamic code shows amount and alphabetic currency together', body.includes('7200 KHR') && body.includes('dynamic'), body.slice(0, 200));

  await page.click('#nav-issue');
  await page.uncheck('#a-sign');
  await page.click('#a-issue');
  await page.waitForFunction(() => document.getElementById('i-meta').textContent.startsWith('Unsigned'));
  await page.click('#i-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Unsigned payment code');
  body = await page.textContent('#v-body');
  check('unsigned code is shown as unsigned, not rejected, with the amount', body.includes('7200 KHR') && body.includes('nobody'));
  await page.click('#nav-issue');
  await page.check('#a-sign');

  out('profile B');
  await page.click('#i-profile-b');
  await page.click('#b-issue');
  await page.waitForFunction(() => document.getElementById('i-payload').value.startsWith('KH1:'));
  const credential = await page.inputValue('#i-payload');
  await page.click('#i-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  body = await page.textContent('#v-body');
  check('credential verifies and shows the four fields', body.includes('CHAY SOPHEA') && body.includes('SBX-2026-000001') && body.includes('standing unknown'));
  await page.fill('#cmp-subjectName', 'CHAY SOPHEA');
  await page.fill('#cmp-documentId', 'SBX-2026-000001');
  await page.fill('#cmp-issuingOrganisation', 'Sandbox University');
  await page.fill('#cmp-issueDate', '2026-07-15');
  await page.click('#cmp-run');
  let cmp = await page.textContent('#cmp-result');
  check('matching paper fields compare as matches', cmp.includes('All four match'));
  await page.fill('#cmp-subjectName', 'CHAY SOPHEAK');
  await page.click('#cmp-run');
  cmp = await page.textContent('#cmp-result');
  check('a differing subject name is reported', cmp.includes('1 field(s) differ'));

  out('revocation and re-enrolment');
  await page.click('#nav-trust');
  await page.click('#t-revoke');
  await page.waitForFunction(() => document.querySelector('#t-sandbox .key.revoked') !== null);
  await page.click('#nav-scan');
  await page.fill('#s-payload', staticPayload);
  await page.click('#s-verify');
  await page.waitForFunction(() => document.getElementById('v-reason').textContent === 'KEY_REVOKED');
  check('a code signed by the revoked key now fails with KEY_REVOKED', true);
  await page.fill('#s-payload', credential);
  await page.click('#s-verify');
  await page.waitForFunction(() => document.getElementById('v-reason').textContent === 'KEY_REVOKED');
  check('the credential signed by it fails the same way', true);
  await page.click('#nav-trust');
  await page.click('#t-new-issuer');
  await page.waitForFunction(() => document.querySelectorAll('#t-sandbox .key.active').length === 1);
  await page.click('#nav-issue');
  await page.click('#i-profile-a');
  await page.check('#a-kind-static');
  await page.click('#a-issue');
  await page.waitForFunction((old) => document.getElementById('i-payload').value !== old && document.getElementById('i-payload').value.length > 0, staticPayload);
  const reissued = await page.inputValue('#i-payload');
  await page.click('#i-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  check('a code from the new issuer key verifies', true);

  out('export the scheme, import it on a second device');
  await page.click('#nav-trust');
  await page.click('#t-export');
  await page.waitForFunction(() => document.getElementById('t-bundle').value.includes('qrseal-scheme-bundle/1'));
  const bundle = await page.inputValue('#t-bundle');
  check('bundle carries no private key', !bundle.includes('"d"') && bundle.includes('"rootKeys"'));
  const ctx2 = await browser.newContext();
  const page2 = await ctx2.newPage();
  await page2.goto(ORIGIN);
  await page2.waitForFunction(() => /sandbox list v\d+/.test(document.getElementById('pill-scheme').textContent));
  await page2.click('#nav-scan');
  await page2.fill('#s-payload', reissued);
  await page2.click('#s-verify');
  await page2.waitForFunction(() => document.getElementById('v-reason').textContent === 'UNKNOWN_KID');
  check('second device rejects the code with UNKNOWN_KID before import', true);
  await page2.click('#nav-trust');
  await page2.fill('#t-bundle', bundle);
  await page2.click('#t-import');
  await page2.waitForFunction(() => document.getElementById('t-against-imported').checked === true);
  await page2.click('#nav-scan');
  await page2.fill('#s-payload', reissued);
  await page2.click('#s-verify');
  await page2.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  const timing = await page2.textContent('#v-timing');
  check('second device verifies it against the imported scheme', timing.includes('imported scheme'), timing);
  await page2.fill('#s-payload', dynamicPayload);
  await page2.click('#s-verify');
  await page2.waitForFunction(() => document.getElementById('v-reason').textContent === 'KEY_REVOKED');
  check('the imported list carries the revocation too', true);
  await ctx2.close();

  out('published vectors');
  await page.click('#nav-vectors');
  await page.click('#x-run');
  await page.waitForFunction(() => /^\d+ of \d+ vectors pass/.test(document.getElementById('x-tally').textContent), null, { timeout: 60000 });
  const tally = await page.textContent('#x-tally');
  check('all published vectors pass in the browser', tally.startsWith('41 of 41'), tally);
  await page.waitForFunction(() => document.querySelectorAll('#x-pair .pair-card').length === 2);
  const pair = await page.textContent('#x-pair');
  check('currency pair renders both verified codes', pair.includes('7200 KHR') && pair.includes('7200 USD'));

  out('offline');
  await ctx.setOffline(true);
  await page.reload();
  await page.waitForFunction(() => /sandbox list v\d+/.test(document.getElementById('pill-scheme').textContent), null, { timeout: 15000 });
  check('app loads from the service worker cache with the network off', true);
  await page.click('#nav-scan');
  await page.fill('#s-payload', reissued);
  await page.click('#s-verify');
  await page.waitForFunction(() => document.getElementById('v-outcome').textContent === 'Signature verified');
  check('verification works offline', true);
  await page.click('#nav-vectors');
  await page.click('#x-run');
  await page.waitForFunction(() => /^41 of 41/.test(document.getElementById('x-tally').textContent), null, { timeout: 60000 });
  check('vector data is served from the cache offline', true);

  check('no uncaught page errors', errors.length === 0, errors.join(' | '));
} finally {
  await browser.close();
  server.kill();
}

out(failures === 0 ? 'PASS' : `FAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);
