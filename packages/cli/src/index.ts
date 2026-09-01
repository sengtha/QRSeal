#!/usr/bin/env node
/**
 * kh-sqr — command line tools over @kh-sqr/core.
 *
 * The signing commands exist for issuers and for the offline Root ceremony.
 * They are deliberately not available to any online service: no Worker in this
 * repository can sign, and CI fails if one gains the ability to.
 */

import { parseArgs } from 'node:util';

import {
  KhSqrError,
  TrustAnchor,
  deriveKid,
  signProfileA,
  signProfileB,
  verifyProfileA,
  verifyProfileA2,
  verifyProfileB,
  type CredentialClaims,
  type PayeeClass,
  type PinnedKey,
  type TrustedKeyRecord,
} from '@kh-sqr/core';

import { literalOrFile, loadPrivateKey, loadPublicKey, readJsonFile } from './keys.js';

const USAGE = `kh-sqr — KH-SQR reference tools

  kid --public-key <pem>
      Derive a key identifier from a P-256 public key.

  sign-a --payload <str|@file> --key <pkcs8.pem> --kid <hex16> --payee-class <M|I>
         [--issued-at <unix>] [--expires-at <unix>]
      Sign an EMVCo payment payload under Profile A. Omit --expires-at for a
      static code; a dynamic code requires it, within 300 seconds.

  sign-b --claims <@file.json> --key <pkcs8.pem> --kid <hex16>
      Sign a credential under Profile B.

  verify --payload <str|@file> --trustlist <@file> --root-keys <@file>
         [--timestamp <@file>] [--timestamp-keys <@file>] [--now <unix>]
         [--held-version <n>] [--fetched-at <unix>]
      Verify a payload of either profile. The profile is detected from the
      payload. Exits 0 on acceptance, 1 on rejection, printing the reason.

  build-trustlist --keys <@file.json> --version <n> --expires <unix>
                  --key <pkcs8.pem> --kid <hex16> [--issued-at <unix>]
      Produce a Root-signed trust list. For use in an offline ceremony.

  build-timestamp --trustlist <@file> --key <pkcs8.pem> --kid <hex16>
                  [--issued-at <unix>] [--validity-seconds <n>]
      Produce a signed timestamp statement over a trust list.

  run-vectors --file <vectors.json>
      Run a conformance suite against this implementation.

A verified signature proves who produced a code. It does not tell you whether
the payment is one you should make.
`;

const now = (): number => Math.floor(Date.now() / 1000);

function fail(message: string): never {
  process.stderr.write(`${message}\n`);
  process.exit(2);
}

function required(values: Record<string, string | boolean | undefined>, name: string): string {
  const value = values[name];
  if (typeof value !== 'string') fail(`--${name} is required`);
  return value;
}

function integer(values: Record<string, string | boolean | undefined>, name: string, fallback?: number): number {
  const value = values[name];
  if (typeof value !== 'string') {
    if (fallback !== undefined) return fallback;
    fail(`--${name} is required`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) fail(`--${name} must be an integer`);
  return parsed;
}

const OPTIONS = {
  'public-key': { type: 'string' },
  payload: { type: 'string' },
  claims: { type: 'string' },
  key: { type: 'string' },
  kid: { type: 'string' },
  'payee-class': { type: 'string' },
  'issued-at': { type: 'string' },
  'expires-at': { type: 'string' },
  trustlist: { type: 'string' },
  timestamp: { type: 'string' },
  'root-keys': { type: 'string' },
  'timestamp-keys': { type: 'string' },
  now: { type: 'string' },
  'held-version': { type: 'string' },
  'fetched-at': { type: 'string' },
  keys: { type: 'string' },
  version: { type: 'string' },
  expires: { type: 'string' },
  'validity-seconds': { type: 'string' },
  file: { type: 'string' },
  json: { type: 'boolean' },
} as const;

const encoder = new TextEncoder();
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('');

async function signStatement(statement: string, keyPath: string, kid: string): Promise<string> {
  const key = await loadPrivateKey(keyPath);
  const raw = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(statement));
  return JSON.stringify(
    { statement, signature: { alg: 'ES256', kid, value: hex(new Uint8Array(raw)) } },
    null,
    2,
  );
}

async function openAnchor(values: Record<string, string | boolean | undefined>): Promise<TrustAnchor> {
  const trustList = JSON.parse(literalOrFile(required(values, 'trustlist'))) as unknown;
  const rootKeys = JSON.parse(literalOrFile(required(values, 'root-keys'))) as PinnedKey[];
  const timestampRaw = typeof values['timestamp'] === 'string' ? literalOrFile(values['timestamp']) : undefined;
  const timestampKeys =
    typeof values['timestamp-keys'] === 'string'
      ? (JSON.parse(literalOrFile(values['timestamp-keys'])) as PinnedKey[])
      : rootKeys;

  return TrustAnchor.open({
    trustList,
    ...(timestampRaw === undefined ? {} : { timestamp: JSON.parse(timestampRaw) as unknown }),
    rootKeys,
    timestampKeys,
    now: integer(values, 'now', now()),
    ...(values['held-version'] === undefined ? {} : { heldVersion: integer(values, 'held-version') }),
    ...(values['fetched-at'] === undefined ? {} : { fetchedAt: integer(values, 'fetched-at') }),
    // Only an explicit absence of a timestamp turns freeze protection off,
    // and the verify command says so on stderr when it happens.
    allowMissingTimestamp: timestampRaw === undefined,
  });
}

/* ------------------------------------------------------------------ *
 * Commands
 * ------------------------------------------------------------------ */

async function commandKid(values: Record<string, string | boolean | undefined>): Promise<void> {
  const material = await loadPublicKey(required(values, 'public-key'));
  process.stdout.write(
    values['json'] === true
      ? `${JSON.stringify({ kid: material.kid, x: material.x, y: material.y }, null, 2)}\n`
      : `${material.kid}\n`,
  );
  // Cross-check: the derivation in core must agree with the one used here.
  const viaCore = await deriveKid(material.uncompressedPoint);
  if (viaCore !== material.kid) fail('internal inconsistency in key identifier derivation');
}

async function commandSignA(values: Record<string, string | boolean | undefined>): Promise<void> {
  const payeeClass = required(values, 'payee-class');
  if (payeeClass !== 'M' && payeeClass !== 'I') fail('--payee-class must be M or I');

  const expiresAt = values['expires-at'] === undefined ? undefined : integer(values, 'expires-at');
  const signed = await signProfileA({
    payload: literalOrFile(required(values, 'payload')),
    privateKey: await loadPrivateKey(required(values, 'key')),
    kid: required(values, 'kid'),
    issuedAt: integer(values, 'issued-at', now()),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    payeeClass: payeeClass as PayeeClass,
  });

  process.stdout.write(
    values['json'] === true
      ? `${JSON.stringify(signed, null, 2)}\n`
      : `${signed.payload}\n`,
  );
}

async function commandSignB(values: Record<string, string | boolean | undefined>): Promise<void> {
  const claims = JSON.parse(literalOrFile(required(values, 'claims'))) as CredentialClaims;
  const payload = await signProfileB({
    privateKey: await loadPrivateKey(required(values, 'key')),
    kid: required(values, 'kid'),
    claims,
  });
  process.stdout.write(`${payload}\n`);
}

async function commandVerify(values: Record<string, string | boolean | undefined>): Promise<void> {
  const payload = literalOrFile(required(values, 'payload'));
  if (values['timestamp'] === undefined) {
    process.stderr.write(
      'warning: no --timestamp supplied, so freeze protection is disabled for this check\n',
    );
  }

  try {
    const trustAnchor = await openAnchor(values);
    const at = integer(values, 'now', now());
    const result = payload.startsWith('KH1:')
      ? await verifyProfileB({ payload, trustAnchor, now: at })
      : await verifyProfileA({ payload, trustAnchor, now: at });

    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    process.stderr.write(
      payload.startsWith('KH1:')
        ? 'accepted. Compare mustMatchPrintedDocument against the document in front of you; ' +
            'a signature proves issuance, not that this code belongs to this paper.\n'
        : 'accepted. Show payeeDisclosure to the payer. A valid signature is not a reason to trust ' +
            'the reason you were given for paying.\n',
    );
  } catch (error) {
    if (error instanceof KhSqrError) {
      process.stdout.write(`${JSON.stringify({ accepted: false, reason: error.reason }, null, 2)}\n`);
      process.stderr.write(`rejected: ${error.message}\n`);
      process.exit(1);
    }
    throw error;
  }
}

async function commandBuildTrustlist(values: Record<string, string | boolean | undefined>): Promise<void> {
  const keys = JSON.parse(literalOrFile(required(values, 'keys'))) as TrustedKeyRecord[];
  const statement = JSON.stringify({
    type: 'kh-sqr/trustlist/1',
    version: integer(values, 'version'),
    issuedAt: integer(values, 'issued-at', now()),
    expires: integer(values, 'expires'),
    keys,
  });
  process.stdout.write(
    `${await signStatement(statement, required(values, 'key'), required(values, 'kid'))}\n`,
  );
}

async function commandBuildTimestamp(values: Record<string, string | boolean | undefined>): Promise<void> {
  const artifact = JSON.parse(literalOrFile(required(values, 'trustlist'))) as {
    statement: string;
  };
  const list = JSON.parse(artifact.statement) as { version: number };
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(artifact.statement)));
  const issuedAt = integer(values, 'issued-at', now());
  const statement = JSON.stringify({
    type: 'kh-sqr/timestamp/1',
    trustListVersion: list.version,
    trustListDigest: hex(digest),
    issuedAt,
    expires: issuedAt + integer(values, 'validity-seconds', 7 * 24 * 60 * 60),
  });
  process.stdout.write(
    `${await signStatement(statement, required(values, 'key'), required(values, 'kid'))}\n`,
  );
}

interface SuiteCase {
  readonly id: string;
  readonly profile: 'A' | 'B';
  readonly type: 'verify' | 'roundtrip';
  readonly input: Record<string, unknown>;
  readonly state: {
    trustList: string;
    timestamp: string | null;
    now: number;
    heldVersion?: number;
    fetchedAt?: number;
  };
  readonly expect: 'accept' | 'reject';
  readonly reason: string | null;
}

interface Suite {
  readonly pinned: { rootKeys: PinnedKey[]; timestampKeys: PinnedKey[] };
  readonly trustLists: Record<string, unknown>;
  readonly timestamps: Record<string, unknown>;
  readonly cases: readonly SuiteCase[];
}

/**
 * Run a conformance suite.
 *
 * Shipped as a command so that a Kotlin or Swift port can be checked against
 * the same file without anyone reading this TypeScript. Roundtrip cases are
 * skipped here because they need the issuer's private key, which the suite
 * publishes but which a verifier has no business loading.
 */
async function commandRunVectors(values: Record<string, string | boolean | undefined>): Promise<void> {
  const suite = readJsonFile<Suite>(required(values, 'file'));
  let passed = 0;
  const failures: string[] = [];
  let skipped = 0;

  for (const vector of suite.cases) {
    if (vector.type !== 'verify') { skipped += 1; continue; }
    const state = vector.state;
    let outcome: { accepted: boolean; reason: string | null };
    try {
      const trustAnchor = await TrustAnchor.open({
        trustList: suite.trustLists[state.trustList],
        ...(state.timestamp === null ? {} : { timestamp: suite.timestamps[state.timestamp] }),
        rootKeys: suite.pinned.rootKeys,
        timestampKeys: suite.pinned.timestampKeys,
        now: state.now,
        ...(state.heldVersion === undefined ? {} : { heldVersion: state.heldVersion }),
        ...(state.fetchedAt === undefined ? {} : { fetchedAt: state.fetchedAt }),
      });
      const payload = vector.input['payload'] as string;
      if (vector.profile === 'A') {
        await (vector.input['encodingVersion'] === 2
          ? verifyProfileA2({ payload, trustAnchor, now: state.now })
          : verifyProfileA({ payload, trustAnchor, now: state.now }));
      }
      else await verifyProfileB({ payload, trustAnchor, now: state.now });
      outcome = { accepted: true, reason: null };
    } catch (error) {
      if (!(error instanceof KhSqrError)) throw error;
      outcome = { accepted: false, reason: error.reason };
    }

    const wanted = vector.expect === 'accept';
    const reasonMatches = vector.reason === null || outcome.reason === vector.reason;
    if (outcome.accepted === wanted && reasonMatches) passed += 1;
    else {
      failures.push(
        `${vector.id}: expected ${vector.expect}${vector.reason === null ? '' : ` (${vector.reason})`}, ` +
          `got ${outcome.accepted ? 'accept' : `reject (${outcome.reason ?? 'unknown'})`}`,
      );
    }
  }

  for (const failure of failures) process.stderr.write(`FAIL ${failure}\n`);
  process.stdout.write(
    `${passed} passed, ${failures.length} failed, ${skipped} skipped (roundtrip cases need a private key)\n`,
  );
  if (failures.length > 0) process.exit(1);
}

/* ------------------------------------------------------------------ *
 * Entry point
 * ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const [, , command, ...rest] = process.argv;
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    process.stdout.write(USAGE);
    return;
  }

  const { values } = parseArgs({ args: rest, options: OPTIONS, allowPositionals: false });

  switch (command) {
    case 'kid': return commandKid(values);
    case 'sign-a': return commandSignA(values);
    case 'sign-b': return commandSignB(values);
    case 'verify': return commandVerify(values);
    case 'build-trustlist': return commandBuildTrustlist(values);
    case 'build-timestamp': return commandBuildTimestamp(values);
    case 'run-vectors': return commandRunVectors(values);
    default:
      process.stderr.write(`unknown command: ${command}\n\n${USAGE}`);
      process.exit(2);
  }
}

await main();
