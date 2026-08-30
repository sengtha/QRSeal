/**
 * Fail the build if any Worker could hold or use a signing key.
 *
 * This is specification, not caution. Certificate issuance must be impossible
 * through compromise of the online portal, so the edge must have no key
 * custody story at all: the Root signs offline in a ceremony, issuer keys live
 * in each institution's HSM, and the timestamp statement is produced by a
 * separate signer outside Cloudflare and uploaded. A Worker that could sign
 * would quietly relocate the trust boundary to a machine an attacker can
 * reach over HTTP.
 *
 * The check runs over Worker configuration and Worker source alike, because a
 * key can arrive as a binding or be constructed in code.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const WORKERS = join(ROOT, 'workers');

interface Rule {
  readonly pattern: RegExp;
  readonly why: string;
}

/** Binding or variable names that would carry private key material. */
const CONFIG_RULES: readonly Rule[] = [
  { pattern: /\b\w*PRIVATE_KEY\w*\b/i, why: 'a binding naming a private key' },
  { pattern: /\b\w*SIGNING_KEY\w*\b/i, why: 'a binding naming a signing key' },
  { pattern: /\b\w*SIGNER_KEY\w*\b/i, why: 'a binding naming a signer key' },
  { pattern: /\bROOT_KEY\b/i, why: 'a binding naming the Root key' },
  { pattern: /\bPKCS8\b/i, why: 'PKCS#8 private key material' },
  { pattern: /BEGIN (?:EC )?PRIVATE KEY/, why: 'an inline PEM private key' },
  { pattern: /"d"\s*:/, why: 'a JWK private scalar' },
];

/** Code that would perform, or prepare to perform, a signature at the edge. */
const SOURCE_RULES: readonly Rule[] = [
  ...CONFIG_RULES,
  { pattern: /crypto\.subtle\.sign\b/, why: 'a signing operation' },
  { pattern: /crypto\.subtle\.generateKey\b/, why: 'key generation' },
  { pattern: /crypto\.subtle\.deriveKey\b/, why: 'key derivation' },
  { pattern: /crypto\.subtle\.unwrapKey\b/, why: 'key unwrapping' },
  { pattern: /\bimportKey\s*\([\s\S]{0,400}?['"]sign['"]/, why: "a key imported with the 'sign' usage" },
];

/** Files whose contents are configuration or source worth checking. */
const CHECKED = /\.(toml|jsonc?|ts|js|mjs|vars|example|template)$|(^|\/)\.dev\.vars/;

function filesUnder(directory: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '.wrangler') continue;
    const full = join(directory, entry);
    if (statSync(full).isDirectory()) out.push(...filesUnder(full));
    else if (CHECKED.test(full)) out.push(full);
  }
  return out;
}

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
    .replace(/^\s*#.*$/gm, '');
}

const failures: string[] = [];
let checked = 0;

for (const file of filesUnder(WORKERS)) {
  checked += 1;
  const isConfig = /\.(toml|jsonc?|vars|example|template)$/.test(file) || file.includes('.dev.vars');
  const rules = isConfig ? CONFIG_RULES : SOURCE_RULES;
  const source = stripComments(readFileSync(file, 'utf8'));
  for (const rule of rules) {
    const match = rule.pattern.exec(source);
    if (match !== null) {
      const line = source.slice(0, match.index).split('\n').length;
      failures.push(`${relative(ROOT, file)}:${line}: ${rule.why} (matched ${JSON.stringify(match[0])})`);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write(
    'No-signing-key-at-the-edge check FAILED\n' +
      'Workers serve signed artifacts and verify signatures. They never hold a private key.\n' +
      failures.map((f) => `  - ${f}\n`).join(''),
  );
  process.exit(1);
}
process.stdout.write(`No-signing-key-at-the-edge check OK\n  ${checked} Worker files, no key custody\n`);
