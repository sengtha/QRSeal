/**
 * Write a test key pair to disk as PEM, so the CLI can be exercised and the
 * documented examples reproduced.
 *
 * TEST MATERIAL ONLY. Every key this produces comes from a published scalar or
 * a published label and protects nothing. A real issuer key is generated
 * inside an HSM and never exists as a file; the Root key is generated in an
 * offline ceremony. Nothing in this repository should ever be pointed at a
 * private key that matters.
 *
 *   node --experimental-strip-types tools/export-test-key.ts <scalar|label> <prefix>
 */

import { writeFileSync } from 'node:fs';

import { keyPairFromScalar, scalarFromLabel } from './keys.ts';

const [, , source, prefix] = process.argv;
if (source === undefined || prefix === undefined) {
  process.stderr.write('usage: export-test-key.ts <64-hex-scalar|label> <output-prefix>\n');
  process.exit(2);
}

const scalar = /^[0-9A-Fa-f]{64}$/.test(source) ? source.toUpperCase() : await scalarFromLabel(source);
const pair = await keyPairFromScalar(scalar);

// Web Crypto cannot export a key it did not mark extractable, so re-import the
// JWK with extraction enabled purely to obtain the PKCS#8 encoding.
const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
const exportable = await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign']);
const pkcs8 = Buffer.from(await crypto.subtle.exportKey('pkcs8', exportable));
const body = (pkcs8.toString('base64').match(/.{1,64}/g) ?? []).join('\n');

writeFileSync(`${prefix}.key.pem`, `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`, {
  mode: 0o600,
});
writeFileSync(`${prefix}.pub.pem`, `${pair.publicPem}\n`);

process.stdout.write(`${pair.kid}\n`);
