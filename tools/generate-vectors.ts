/**
 * Generate vectors/vectors.json — the language-neutral conformance suite.
 *
 * The suite is the deliverable that lets a Kotlin or Swift port prove
 * conformance without reading any TypeScript. Negative cases are the point:
 * an implementation that accepts a well-formed payload has demonstrated very
 * little, whereas one that rejects each malformation for the right stated
 * reason has demonstrated most of the specification.
 *
 * Every key here is generated from a published label or a published scalar, so
 * the whole file can be regenerated from this repository alone. None of them
 * has any security value.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  appendCrc,
  encodeBase45,
  encodeCoseSign1,
  signProfileA,
  signProfileA2,
  V2_GUID,
  signProfileB,
  stripCrc,
  type CredentialClaims,
} from '../packages/core/dist/index.js';
import { keyPairFromScalar, scalarFromLabel, type TestKeyPair } from './keys.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT = join(HERE, '..', 'vectors', 'vectors.json');

/* ------------------------------------------------------------------ *
 * Fixed times. 1756512000 = 2025-08-30T00:00:00Z, the issuance instant
 * used by the published reference vectors.
 * ------------------------------------------------------------------ */
const ISSUED_AT = 1_756_512_000;
const EXPIRES_AT = ISSUED_AT + 60;
const NOW_VALID = ISSUED_AT + 30;
const DAY = 86_400;

/** The published reference scalar. Deliberately public; it protects nothing. */
const PUBLISHED_ISSUER_SCALAR = '1F2E3D4C5B6A79889796A5B4C3D2E1F00F1E2D3C4B5A69788897A6B5C4D3E2F1';

/* ------------------------------------------------------------------ *
 * Signed-artifact helpers
 * ------------------------------------------------------------------ */

const encoder = new TextEncoder();
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('');


/**
 * A GUID belonging to no scheme, for the rejection cases.
 *
 * Derived from the real one so it is always the same length. A shorter or
 * longer substitute would change the template's length prefix, and the payload
 * would then be rejected for a malformed length rather than for a foreign GUID
 * --- the test would still pass, and would no longer test what it names.
 */
const FOREIGN_GUID = V2_GUID.replace(/[A-Z]/g, 'X');

async function signStatement(statement: string, key: TestKeyPair): Promise<unknown> {
  const raw = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key.privateKey,
    encoder.encode(statement),
  );
  return { statement, signature: { alg: 'ES256', kid: key.kid, value: hex(new Uint8Array(raw)) } };
}

async function digestOf(statement: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(statement))));
}

interface KeyRecordOptions {
  readonly profiles: readonly ('A' | 'B')[];
  readonly status?: 'active' | 'revoked';
  readonly notBefore?: number;
  readonly notAfter?: number;
  readonly name: string;
}

const keyRecord = (key: TestKeyPair, o: KeyRecordOptions) => ({
  kid: key.kid,
  x: key.x,
  y: key.y,
  profiles: o.profiles,
  status: o.status ?? 'active',
  notBefore: o.notBefore ?? ISSUED_AT - 365 * DAY,
  notAfter: o.notAfter ?? ISSUED_AT + 365 * DAY,
  // The organisation identifier is what a Profile B issuer claim must equal.
  // The published reference credential names this issuer, so the test keys
  // are registered to it; a second key under the same organisation is the
  // rotated-and-withdrawn one.
  subject: { name: o.name, organisationId: 'kh.gov.mptc.moeys' },
  // The merchant-account identifiers a Profile A key may sign for: the exact
  // scheme-style GUID the reference payloads carry, and a bank suffix for
  // account-style identifiers of the form merchant@bank.
  acquirers: ['abaakhppxxx', '@abaa'],
});

/* ------------------------------------------------------------------ *
 * Low-level Profile A forging, for cases a conforming signer refuses
 * ------------------------------------------------------------------ */

interface ForgeOptions {
  readonly base: string;
  readonly key: TestKeyPair;
  readonly kid?: string;
  readonly formatVersion?: string;
  readonly algorithm?: string;
  readonly issuedAt?: number;
  readonly expiresAt?: number | null;
  readonly payeeClass?: string;
  /** Applied to the assembled signing input before signing. */
  readonly mutateSigningInput?: (input: string) => string;
  /** Applied to the full payload after the CRC is attached. */
  readonly mutatePayload?: (payload: string) => string;
}

const tlv = (tag: string, value: string): string => tag + String(value.length).padStart(2, '0') + value;

/**
 * Assemble and sign a Profile A payload from explicit field values.
 *
 * `signProfileA` refuses to produce most of the negative cases, which is the
 * correct behaviour for a signer and useless for a conformance suite, so the
 * suite forges them here instead.
 */
async function forgeProfileA(o: ForgeOptions): Promise<string> {
  const base = stripCrc(o.base);
  let template =
    tlv('00', o.formatVersion ?? '01') +
    tlv('01', o.kid ?? o.key.kid) +
    tlv('02', o.algorithm ?? 'ES256') +
    tlv('03', String(o.issuedAt ?? ISSUED_AT).padStart(10, '0'));
  if (o.expiresAt !== null && o.expiresAt !== undefined) {
    template += tlv('04', String(o.expiresAt).padStart(10, '0'));
  }
  template += tlv('05', o.payeeClass ?? 'M');

  const header = '99128';
  const templateLength = template.length + header.length + 128;
  let signingInput = base + '85' + String(templateLength).padStart(3, '0') + template + header;
  if (o.mutateSigningInput !== undefined) signingInput = o.mutateSigningInput(signingInput);

  const raw = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    o.key.privateKey,
    encoder.encode(signingInput),
  );
  const payload = appendCrc(signingInput + hex(new Uint8Array(raw)));
  return o.mutatePayload === undefined ? payload : o.mutatePayload(payload);
}

/** Replace the payload's CRC with the correct one for its current contents. */
const refreshCrc = (payload: string): string => appendCrc(stripCrc(payload));

/* ------------------------------------------------------------------ *
 * Case types
 * ------------------------------------------------------------------ */

interface CaseState {
  readonly trustList: string;
  readonly timestamp: string | null;
  readonly now: number;
  readonly heldVersion?: number;
  readonly fetchedAt?: number;
  readonly allowMissingTimestamp?: boolean;
}

interface VerifyCase {
  readonly id: string;
  readonly profile: 'A' | 'B';
  readonly type: 'verify';
  readonly description: string;
  readonly input: { readonly payload: string };
  readonly state: CaseState;
  readonly expect: 'accept' | 'reject';
  readonly reason: string | null;
  readonly accepted?: Record<string, unknown>;
}

interface RoundtripCase {
  readonly id: string;
  readonly profile: 'A' | 'B';
  readonly type: 'roundtrip';
  readonly description: string;
  readonly input: Record<string, unknown>;
  readonly state: CaseState;
  readonly expect: 'accept';
  readonly reason: null;
}

type Case = VerifyCase | RoundtripCase;

const DEFAULT_STATE: CaseState = { trustList: 'current', timestamp: 'current', now: NOW_VALID };

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const issuer = await keyPairFromScalar(PUBLISHED_ISSUER_SCALAR);
  const root = await keyPairFromScalar(await scalarFromLabel('kh-sqr/test/root/1'));
  const timestampKey = await keyPairFromScalar(await scalarFromLabel('kh-sqr/test/timestamp/1'));
  const revoked = await keyPairFromScalar(await scalarFromLabel('kh-sqr/test/revoked-issuer/1'));
  const stranger = await keyPairFromScalar(await scalarFromLabel('kh-sqr/test/untrusted-issuer/1'));

  if (issuer.kid !== '27403764C95F4F5B') {
    throw new Error(`published kid did not reproduce: got ${issuer.kid}`);
  }

  const keys = [
    keyRecord(issuer, { profiles: ['A', 'B'], name: 'ABA Bank (test issuer)' }),
    keyRecord(revoked, { profiles: ['A', 'B'], status: 'revoked', name: 'Withdrawn issuer (test)' }),
  ];

  const listStatement = (version: number, expires: number): string =>
    JSON.stringify({
      type: 'kh-sqr/trustlist/1',
      version,
      issuedAt: ISSUED_AT - 1000,
      expires,
      keys,
    });

  const currentList = listStatement(7, ISSUED_AT + 365 * DAY);
  const rolledBackList = listStatement(6, ISSUED_AT + 365 * DAY);
  const expiredList = listStatement(7, ISSUED_AT - 1);

  const timestampStatement = async (version: number, statement: string, expires: number): Promise<string> =>
    JSON.stringify({
      type: 'kh-sqr/timestamp/1',
      trustListVersion: version,
      trustListDigest: await digestOf(statement),
      issuedAt: ISSUED_AT - 100,
      expires,
    });

  const trustLists: Record<string, unknown> = {
    current: await signStatement(currentList, root),
    rolledBack: await signStatement(rolledBackList, root),
    expired: await signStatement(expiredList, root),
    forgedRootSignature: await signStatement(currentList, stranger),
  };

  const timestamps: Record<string, unknown> = {
    current: await signStatement(await timestampStatement(7, currentList, ISSUED_AT + 7 * DAY), timestampKey),
    /** Still correctly signed, but past its seven-day validity: freeze protection must fire. */
    expired: await signStatement(await timestampStatement(7, currentList, ISSUED_AT - 1), timestampKey),
    rolledBack: await signStatement(await timestampStatement(6, rolledBackList, ISSUED_AT + 7 * DAY), timestampKey),
    expiredList: await signStatement(await timestampStatement(7, expiredList, ISSUED_AT + 7 * DAY), timestampKey),
    /** A far-future timestamp so a staleness case is not masked by timestamp expiry. */
    farFuture: await signStatement(await timestampStatement(7, currentList, ISSUED_AT + 400 * DAY), timestampKey),
    mismatchedDigest: await signStatement(
      JSON.stringify({
        type: 'kh-sqr/timestamp/1',
        trustListVersion: 7,
        trustListDigest: '0'.repeat(64),
        issuedAt: ISSUED_AT - 100,
        expires: ISSUED_AT + 7 * DAY,
      }),
      timestampKey,
    ),
  };

  /* --- Profile A payloads --- */

  const DYNAMIC_BASE =
    '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM PENH';
  const STATIC_BASE =
    '00020101021130310011abaakhppxxx01128550123456785204581253031165802KH5908SOK DARA6010PHNOM PENH';

  const PUBLISHED_A =
    '00020101021230310011abaakhppxxx01128550123456785204581253031165405250005802KH5908SOK DARA6010PHNOM ' +
    'PENH85200000201011627403764C95F4F5B0205ES25603101756512000041017565120600501M991288D060DF7D9848BAA71' +
    '69DF7946242B491306E1EEBD17AC8367F0D5DA1693990D1CEB7A018D96CBAFEC1744F8A4A2B9B83374297CAF8F8C68E5DDAE' +
    'C3BB8F08DC6304CB0C';

  const canonicalDynamic = await signProfileA({
    payload: DYNAMIC_BASE,
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    payeeClass: 'M',
  });

  const canonicalStatic = await signProfileA({
    payload: STATIC_BASE,
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    payeeClass: 'I',
  });

  // Encoding version 2: EMVCo-conformant lengths, GUID at sub-tag 00, the
  // signature split across templates 86 and 87.
  const v2Dynamic = await signProfileA2({
    payload: DYNAMIC_BASE,
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    payeeClass: 'M',
  });

  // A registered key signing for an account at an institution it is not
  // registered for: the identifier at sub-tag 00 is not bound to the key.
  const v2ForeignAcquirer = await signProfileA2({
    payload: DYNAMIC_BASE.replace('0011abaakhppxxx', '0011otherbnkxxx'),
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    payeeClass: 'M',
  });
  // An account-style identifier, merchant@bank, bound through the registered
  // bank suffix rather than an exact value.
  const v2SuffixBound = await signProfileA2({
    payload: STATIC_BASE.replace('30310011abaakhppxxx', '29320012sokdara@abaa'),
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    payeeClass: 'I',
  });

  const v2Static = await signProfileA2({
    payload: STATIC_BASE,
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    issuedAt: ISSUED_AT,
    payeeClass: 'I',
  });

  // Append a data object after template 87. The signed prefix is untouched, so
  // only the tail-order rule rejects this.
  const v2Appended = (() => {
    const body = stripCrc(v2Dynamic.payload) + '6204ABCD';
    return appendCrc(body);
  })();

  // Replace the GUID in template 85 with a foreign one of the same length.
  const v2ForeignGuid = (() => {
    const body = stripCrc(v2Dynamic.payload).replace(V2_GUID, FOREIGN_GUID);
    return appendCrc(body);
  })();

  const revokedPayload = await forgeProfileA({ base: DYNAMIC_BASE, key: revoked, expiresAt: EXPIRES_AT });
  const strangerPayload = await forgeProfileA({ base: DYNAMIC_BASE, key: stranger, expiresAt: EXPIRES_AT });

  // Flip one hex character of the signature, then repair the CRC so the
  // failure is attributable to the signature and not to the checksum.
  const badSignature = refreshCrc(
    canonicalDynamic.payload.slice(0, -12) +
      (canonicalDynamic.payload[canonicalDynamic.payload.length - 12] === 'A' ? 'B' : 'A') +
      canonicalDynamic.payload.slice(-11),
  );

  // A DER SEQUENCE where raw r||s belongs. 70 bytes -> 140 hex characters.
  const derSignature = '3044' + '0220' + 'A'.repeat(64) + '0220' + 'B'.repeat(64);
  const derTemplate =
    tlv('00', '01') + tlv('01', issuer.kid) + tlv('02', 'ES256') +
    tlv('03', String(ISSUED_AT)) + tlv('04', String(EXPIRES_AT)) + tlv('05', 'M') +
    '99' + String(derSignature.length).padStart(3, '0') + derSignature;
  const derPayload = appendCrc(DYNAMIC_BASE + '85' + String(derTemplate.length).padStart(3, '0') + derTemplate);

  // Template 85 followed by another data object before the CRC: the appended
  // object lies outside the signed prefix.
  const templateNotLast = appendCrc(stripCrc(canonicalDynamic.payload) + tlv('62', '0304ABCD'));

  // Sub-tag 99 followed by another sub-tag inside template 85.
  const subtagNotLastTemplate =
    tlv('00', '01') + tlv('01', issuer.kid) + tlv('02', 'ES256') +
    tlv('03', String(ISSUED_AT)) + tlv('04', String(EXPIRES_AT)) + tlv('05', 'M');
  const subtagPrefixBody = subtagNotLastTemplate + '99128';
  const subtagTrailer = tlv('06', 'X');
  const subtagTemplateLength = subtagPrefixBody.length + 128 + subtagTrailer.length;
  const subtagSigningInput =
    DYNAMIC_BASE + '85' + String(subtagTemplateLength).padStart(3, '0') + subtagPrefixBody;
  const subtagRaw = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    issuer.privateKey,
    encoder.encode(subtagSigningInput),
  );
  const subtagNotLast = appendCrc(subtagSigningInput + hex(new Uint8Array(subtagRaw)) + subtagTrailer);

  const badCrc = canonicalDynamic.payload.slice(0, -4) +
    (canonicalDynamic.payload.slice(-4) === '0000' ? '1111' : '0000');

  // A character changed inside the signed region, CRC repaired: only the
  // signature can catch this.
  const mutatedInside = refreshCrc(
    stripCrc(canonicalDynamic.payload).replace('PHNOM PENH', 'PHNOM PENG'),
  );

  // A character changed outside the signed region with the CRC left alone.
  // The CRC covers the whole payload, so this must still fail.
  const outsideIndex = canonicalDynamic.payload.length - 10;
  const mutatedOutside =
    canonicalDynamic.payload.slice(0, outsideIndex) +
    (canonicalDynamic.payload[outsideIndex] === 'A' ? 'B' : 'A') +
    canonicalDynamic.payload.slice(outsideIndex + 1);

  const staticWithAmount = await forgeProfileA({
    base: STATIC_BASE.replace('5303116', '5303116540525000'),
    key: issuer,
    expiresAt: null,
    payeeClass: 'I',
  });

  const expiryTooLong = await forgeProfileA({ base: DYNAMIC_BASE, key: issuer, expiresAt: ISSUED_AT + 600 });
  const dynamicNoExpiry = await forgeProfileA({ base: DYNAMIC_BASE, key: issuer, expiresAt: null });
  const badPayeeClass = await forgeProfileA({ base: DYNAMIC_BASE, key: issuer, expiresAt: EXPIRES_AT, payeeClass: 'X' });
  const badAlgorithm = await forgeProfileA({ base: DYNAMIC_BASE, key: issuer, expiresAt: EXPIRES_AT, algorithm: 'ES384' });
  const badVersion = await forgeProfileA({ base: DYNAMIC_BASE, key: issuer, expiresAt: EXPIRES_AT, formatVersion: '02' });

  /* --- Profile B payloads --- */

  const CLAIMS: CredentialClaims = {
    issuer: 'kh.gov.mptc.moeys',
    issuedAt: ISSUED_AT,
    documentType: 'DEGREE',
    documentId: 'RUPP-2026-004821',
    subjectName: 'CHAY SOPHEA',
    issuingOrganisation: 'Royal University of Phnom Penh',
    issueDate: '2026-07-15',
    documentHash: '3108aa7d48933e51b68cf9366bb7c32c',
  };

  const PUBLISHED_B =
    'KH1:NCFOXN%TSMAHN-H3Q8DJO::SF$N:+UHBH7K5PL1PP63UQCZPZIEAJ9E1VBYUWM56NRTF6SKRLS4RZIOLNDNNQLN%*4HTCWP0' +
    'AY0IFTY73QKJKD3UBJ423T 4HBTHN76571E53XVYBF F7V*CH4BOX0Z0BF4T2 G-$C7*KYV290J0J5/5L:O07.S3ATIQ0V5T4R4T' +
    '2LFUCJS9D9ROR6KK9NCLC46XT6D69QR6VC6ICM.%6VW6LS9-TMW.91R6 L64H9S0A%%6E0I9BEX D3/1566DSCK3RN$DY/AQQBV-' +
    'HH.CMX25ONQQRQMUGX2L*BWU7B/464P926/JTNVGRJJLRNDEV7/7O1H7GS++E9:L.+T6.ENKT300U0V61';

  const canonicalB = await signProfileB({ privateKey: issuer.privateKey, kid: issuer.kid, claims: CLAIMS });

  // The same pipeline but compressed with deflate-raw: a different byte
  // stream that a conforming verifier must fail to inflate.
  const rawDeflated = await (async (): Promise<string> => {
    const cose = await encodeCoseSign1({
      privateKey: issuer.privateKey,
      kid: Buffer.from(issuer.kid, 'hex'),
      payload: new TextEncoder().encode('placeholder'),
    });
    const stream = new Blob([cose]).stream().pipeThrough(new CompressionStream('deflate-raw'));
    const chunks: Uint8Array[] = [];
    const reader = (stream as ReadableStream<Uint8Array>).getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const total = chunks.reduce((n, c) => n + c.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) { out.set(c, offset); offset += c.length; }
    return 'KH1:' + encodeBase45(out);
  })();

  const strangerB = await signProfileB({ privateKey: stranger.privateKey, kid: stranger.kid, claims: CLAIMS });
  // A registered key signing a credential in another institution's name.
  const wrongIssuerB = await signProfileB({
    privateKey: issuer.privateKey,
    kid: issuer.kid,
    claims: { ...CLAIMS, issuer: 'kh.edu.someone-else' },
  });
  const revokedB = await signProfileB({ privateKey: revoked.privateKey, kid: revoked.kid, claims: CLAIMS });

  const tamperedB = (() => {
    const body = canonicalB.slice(4);
    const index = body.length - 12;
    const replacement = body[index] === 'A' ? 'B' : 'A';
    return 'KH1:' + body.slice(0, index) + replacement + body.slice(index + 1);
  })();

  /* --- Cases --- */

  const cases: Case[] = [
    /* ---------- Profile A, accept ---------- */
    {
      id: 'A-accept-published-reference',
      profile: 'A',
      type: 'verify',
      description:
        'HISTORICAL, ENCODING VERSION 1, WITH A KNOWN-BAD LENGTH DECLARATION. The published ' +
        '317-character reference payload. Its template 85 declares length 200 while its content is ' +
        '201 characters. It is retained unchanged because it is published and cited, and because a ' +
        'conforming verifier accepts it: the fixed-offset rule locates the signature by position and ' +
        'does not consult that field. DO NOT COPY THIS PAYLOAD AS A MODEL FOR A SIGNER. A signer ' +
        'emitting encoding version 1 must declare 201; case A-accept-canonical-dynamic is the ' +
        'self-consistent version 1 vector. New issuance should use encoding version 2 ' +
        '(A2-accept-dynamic). See SPEC.md sections 2.4 and 2.9.',
      input: { payload: PUBLISHED_A },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'dynamic', payeeClass: 'M', declaredLengthConsistent: false },
    },
    {
      id: 'A2-accept-dynamic',
      profile: 'A',
      type: 'verify',
      description:
        'Encoding version 2. Every length field is two digits with a value of at most 99, every ' +
        'unreserved template carries a GUID at sub-tag 00, and the signature is split across ' +
        'templates 86 and 87. A strict EMVCo 1.1 parser walks this payload and reaches the CRC, ' +
        'which it cannot do for version 1. See SPEC.md, "Encoding version 2".',
      input: { payload: v2Dynamic.payload, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'dynamic', payeeClass: 'M', encodingVersion: 2 },
    },
    {
      id: 'A2-accept-static',
      profile: 'A',
      type: 'verify',
      description: 'Encoding version 2, static code, payee class I. No amount, no expiry.',
      input: { payload: v2Static.payload, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'static', payeeClass: 'I', encodingVersion: 2 },
    },
    {
      id: 'A2-reject-appended-after-signature',
      profile: 'A',
      type: 'verify',
      description:
        'A data object appended after template 87, with the CRC repaired. The signed prefix is ' +
        'byte-identical, so only the rule that templates 85, 86 and 87 are the final three data ' +
        'objects rejects it.',
      input: { payload: v2Appended, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_TEMPLATE_NOT_LAST',
      accepted: null,
    },
    {
      id: 'A2-reject-foreign-guid',
      profile: 'A',
      type: 'verify',
      description:
        'The Globally Unique Identifier in template 85 replaced with a foreign value of the same ' +
        'length. EMVCo requires a GUID at sub-tag 00; a verifier must check that it is this ' +
        "scheme's, not merely that one is present.",
      input: { payload: v2ForeignGuid, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_SUBTAG_MALFORMED',
      accepted: null,
    },
    {
      id: 'A2-reject-acquirer-key-mismatch',
      profile: 'A',
      type: 'verify',
      description:
        'A valid signature by a registered key over a payload whose merchant-account template names ' +
        'an identifier the key is not registered for. Without this rule a compromised or rogue issuer ' +
        'key could sign codes paying into any account at any institution.',
      input: { payload: v2ForeignAcquirer.payload, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'ACQUIRER_KEY_MISMATCH',
      accepted: null,
    },
    {
      id: 'A2-accept-bank-suffix-binding',
      profile: 'A',
      type: 'verify',
      description:
        'An account-style identifier of the form merchant@bank at sub-tag 00, bound to the key through ' +
        'its registered @bank suffix rather than an exact value. The form a scheme whose identifiers ' +
        'are per-merchant needs.',
      input: { payload: v2SuffixBound.payload, encodingVersion: 2 },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'static' },
    },
    {
      id: 'A-accept-canonical-dynamic',
      profile: 'A',
      type: 'verify',
      description: 'A dynamic code produced by this implementation, with a self-consistent template length.',
      input: { payload: canonicalDynamic.payload },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'dynamic', payeeClass: 'M', declaredLengthConsistent: true },
    },
    {
      id: 'A-accept-canonical-static',
      profile: 'A',
      type: 'verify',
      description: 'A static code: no amount, no expiry, individual payee.',
      input: { payload: canonicalStatic.payload },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, codeKind: 'static', payeeClass: 'I', declaredLengthConsistent: true },
    },
    {
      id: 'A-accept-at-expiry-boundary',
      profile: 'A',
      type: 'verify',
      description: 'A dynamic code verified at exactly its expiry second is still valid; expiry is exclusive.',
      input: { payload: canonicalDynamic.payload },
      state: { ...DEFAULT_STATE, now: EXPIRES_AT },
      expect: 'accept',
      reason: null,
    },

    /* ---------- Profile A, reject ---------- */
    {
      id: 'A-reject-bad-signature',
      profile: 'A',
      type: 'verify',
      description: 'One hex character of the signature altered, CRC repaired.',
      input: { payload: badSignature },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_INVALID',
    },
    {
      id: 'A-reject-der-signature',
      profile: 'A',
      type: 'verify',
      description: 'A DER SEQUENCE offered where raw r||s is required. DER MUST NOT be used.',
      input: { payload: derPayload },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_ENCODING_INVALID',
    },
    {
      id: 'A-reject-template-not-last',
      profile: 'A',
      type: 'verify',
      description: 'A data object appended after template 85, outside the signed prefix.',
      input: { payload: templateNotLast },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_TEMPLATE_NOT_LAST',
    },
    {
      id: 'A-reject-subtag-not-last',
      profile: 'A',
      type: 'verify',
      description: 'A sub-tag appended after sub-tag 99 inside template 85.',
      input: { payload: subtagNotLast },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_SUBTAG_NOT_LAST',
    },
    {
      id: 'A-reject-bad-crc',
      profile: 'A',
      type: 'verify',
      description: 'The CRC does not match the payload.',
      input: { payload: badCrc },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'CRC_MISMATCH',
    },
    {
      id: 'A-reject-mutation-inside-signed-region',
      profile: 'A',
      type: 'verify',
      description: 'The merchant city altered and the CRC repaired: only the signature detects this.',
      input: { payload: mutatedInside },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'SIGNATURE_INVALID',
    },
    {
      id: 'A-reject-mutation-outside-signed-region',
      profile: 'A',
      type: 'verify',
      description:
        'A character altered after the signed prefix, CRC left stale. Rejected on the CRC before any ' +
        'cryptography runs. This tests corruption handling, NOT a security property: a CRC is trivially ' +
        'recomputed, and an attacker who does so is then caught by the tail-order rule ' +
        '(A-reject-template-not-last) or the signature itself (A-reject-bad-signature).',
      input: { payload: mutatedOutside },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'CRC_MISMATCH',
    },
    {
      id: 'A-reject-expired-dynamic',
      profile: 'A',
      type: 'verify',
      description: 'A dynamic code presented one second after expiry.',
      input: { payload: canonicalDynamic.payload },
      state: { ...DEFAULT_STATE, now: EXPIRES_AT + 1 },
      expect: 'reject',
      reason: 'CODE_EXPIRED',
    },
    {
      id: 'A-reject-unknown-kid',
      profile: 'A',
      type: 'verify',
      description: 'Signed by a key that is not in the trust list.',
      input: { payload: strangerPayload },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'UNKNOWN_KID',
    },
    {
      id: 'A-reject-revoked-key',
      profile: 'A',
      type: 'verify',
      description: 'Signed by a key the trust list marks revoked. Distinct from an unknown key.',
      input: { payload: revokedPayload },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'KEY_REVOKED',
    },
    {
      id: 'A-reject-static-with-amount',
      profile: 'A',
      type: 'verify',
      description: 'A static code carrying tag 54. Static codes MUST NOT carry an amount.',
      input: { payload: staticWithAmount },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'STATIC_CODE_WITH_AMOUNT',
    },
    {
      id: 'A-reject-expiry-window-too-long',
      profile: 'A',
      type: 'verify',
      description: 'A dynamic code valid for 600 seconds, above the 300-second maximum.',
      input: { payload: expiryTooLong },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'EXPIRY_WINDOW_TOO_LONG',
    },
    {
      id: 'A-reject-dynamic-without-expiry',
      profile: 'A',
      type: 'verify',
      description: 'A dynamic code omitting sub-tag 04.',
      input: { payload: dynamicNoExpiry },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'DYNAMIC_CODE_MISSING_EXPIRY',
    },
    {
      id: 'A-reject-bad-payee-class',
      profile: 'A',
      type: 'verify',
      description: "Sub-tag 05 carries a value other than 'M' or 'I'.",
      input: { payload: badPayeeClass },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'MALFORMED_PAYEE_CLASS',
    },
    {
      id: 'A-reject-unsupported-algorithm',
      profile: 'A',
      type: 'verify',
      description: 'Sub-tag 02 names an algorithm other than ES256.',
      input: { payload: badAlgorithm },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'UNSUPPORTED_ALGORITHM',
    },
    {
      id: 'A-reject-unsupported-format-version',
      profile: 'A',
      type: 'verify',
      description: 'Sub-tag 00 names a format version this specification does not define.',
      input: { payload: badVersion },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'UNSUPPORTED_FORMAT_VERSION',
    },
    {
      id: 'A-reject-issued-in-future',
      profile: 'A',
      type: 'verify',
      description: 'Issued-at is beyond the permitted clock skew ahead of the verifier.',
      input: { payload: canonicalDynamic.payload },
      state: { ...DEFAULT_STATE, now: ISSUED_AT - 3600 },
      expect: 'reject',
      reason: 'ISSUED_IN_FUTURE',
    },

    /* ---------- Trust list and timestamp ---------- */
    {
      id: 'A-reject-trustlist-rollback',
      profile: 'A',
      type: 'verify',
      description: 'A trust list numbered below the version the verifier already holds.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'rolledBack', timestamp: 'rolledBack', now: NOW_VALID, heldVersion: 7 },
      expect: 'reject',
      reason: 'TRUSTLIST_ROLLBACK',
    },
    {
      id: 'A-reject-trustlist-stale',
      profile: 'A',
      type: 'verify',
      description:
        'A trust list cached for more than 30 days. The verifier stops verifying rather than trusting ' +
        'what it holds.',
      input: { payload: canonicalDynamic.payload },
      state: {
        trustList: 'current',
        timestamp: 'farFuture',
        now: ISSUED_AT + 31 * DAY,
        fetchedAt: ISSUED_AT - DAY,
      },
      expect: 'reject',
      reason: 'TRUSTLIST_STALE',
    },
    {
      id: 'A-reject-trustlist-expired',
      profile: 'A',
      type: 'verify',
      description: 'The trust list is past its own expiry.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'expired', timestamp: 'expiredList', now: NOW_VALID },
      expect: 'reject',
      reason: 'TRUSTLIST_EXPIRED',
    },
    {
      id: 'A-reject-trustlist-forged-signature',
      profile: 'A',
      type: 'verify',
      description: 'A trust list signed by a key that is not the pinned Root.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'forgedRootSignature', timestamp: 'current', now: NOW_VALID },
      expect: 'reject',
      reason: 'TRUSTLIST_SIGNATURE_INVALID',
    },
    {
      id: 'A-reject-timestamp-expired',
      profile: 'A',
      type: 'verify',
      description:
        'The freshest timestamp statement is past its seven-day validity. Freeze protection: an attacker ' +
        'who withholds updates must not be able to pin a verifier to a stale but unexpired trust list.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'current', timestamp: 'expired', now: NOW_VALID },
      expect: 'reject',
      reason: 'TIMESTAMP_EXPIRED',
    },
    {
      id: 'A-reject-timestamp-missing',
      profile: 'A',
      type: 'verify',
      description: 'No timestamp statement was supplied and the verifier has not opted out of freeze protection.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'current', timestamp: null, now: NOW_VALID },
      expect: 'reject',
      reason: 'TIMESTAMP_MISSING',
    },
    {
      id: 'A-reject-timestamp-digest-mismatch',
      profile: 'A',
      type: 'verify',
      description: 'The timestamp statement attests a trust list digest other than the one held.',
      input: { payload: canonicalDynamic.payload },
      state: { trustList: 'current', timestamp: 'mismatchedDigest', now: NOW_VALID },
      expect: 'reject',
      reason: 'TIMESTAMP_TARGET_MISMATCH',
    },

    /* ---------- Profile B ---------- */
    {
      id: 'B-accept-published-reference',
      profile: 'B',
      type: 'verify',
      description:
        'The published 381-character reference payload, produced by a different deflate implementation. ' +
        'Deflate is not canonical, so conformance requires that this decodes and verifies, not that an ' +
        'encoder reproduces it byte for byte.',
      input: { payload: PUBLISHED_B },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: {
        kid: issuer.kid,
        subjectName: 'CHAY SOPHEA',
        documentId: 'RUPP-2026-004821',
        issuingOrganisation: 'Royal University of Phnom Penh',
        issueDate: '2026-07-15',
      },
    },
    {
      id: 'B-accept-canonical',
      profile: 'B',
      type: 'verify',
      description: 'A credential produced by this implementation over the same claims.',
      input: { payload: canonicalB },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
      accepted: { kid: issuer.kid, subjectName: 'CHAY SOPHEA', documentId: 'RUPP-2026-004821' },
    },
    {
      id: 'B-reject-deflate-raw',
      profile: 'B',
      type: 'verify',
      description:
        'Compressed with deflate-raw rather than zlib-wrapped deflate. The byte stream differs and must ' +
        'not inflate.',
      input: { payload: rawDeflated },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'INFLATE_FAILED',
    },
    {
      id: 'B-reject-https-payload',
      profile: 'B',
      type: 'verify',
      description:
        'An https URL where a credential belongs. This profile never carries a URL: doing so would move ' +
        'the trust decision into a browser and ask the user to judge a domain name.',
      input: { payload: 'https://verify.example.gov.kh/c/RUPP-2026-004821' },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'URL_PAYLOAD_REJECTED',
    },
    {
      id: 'B-reject-bad-prefix',
      profile: 'B',
      type: 'verify',
      description: 'A payload without the KH1: prefix.',
      input: { payload: 'HC1:' + canonicalB.slice(4) },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'PREFIX_INVALID',
    },
    {
      id: 'B-reject-base45-alphabet',
      profile: 'B',
      type: 'verify',
      description: 'A character outside the RFC 9285 alphabet.',
      input: { payload: 'KH1:NCFOXN%TSMAHN-H3Q8DJO;;' },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'BASE45_INVALID',
    },
    {
      id: 'B-reject-tampered',
      profile: 'B',
      type: 'verify',
      description: 'A character altered inside the compressed COSE structure.',
      input: { payload: tamperedB },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: null,
    },
    {
      id: 'B-reject-unknown-kid',
      profile: 'B',
      type: 'verify',
      description: 'Signed by a key that is not in the trust list.',
      input: { payload: strangerB },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'UNKNOWN_KID',
    },
    {
      id: 'B-reject-revoked-key',
      profile: 'B',
      type: 'verify',
      description: 'Signed by a revoked key.',
      input: { payload: revokedB },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'KEY_REVOKED',
    },
    {
      id: 'B-reject-issuer-key-mismatch',
      profile: 'B',
      type: 'verify',
      description:
        'A valid signature by a registered key over a credential whose issuer claim names an ' +
        'institution the key is not registered to. Without this rule any enrolled key could issue ' +
        'in any name, and the only defence would be a reader noticing two names that differ.',
      input: { payload: wrongIssuerB },
      state: DEFAULT_STATE,
      expect: 'reject',
      reason: 'ISSUER_KEY_MISMATCH',
    },

    /* ---------- Roundtrip ---------- */
    {
      id: 'A-roundtrip-dynamic',
      profile: 'A',
      type: 'roundtrip',
      description:
        'Sign, then verify the implementation\'s own output. ECDSA is randomised, so a fresh signature ' +
        'differs from any fixed vector and must still verify.',
      input: {
        base: DYNAMIC_BASE,
        issuerScalar: PUBLISHED_ISSUER_SCALAR,
        kid: issuer.kid,
        issuedAt: ISSUED_AT,
        expiresAt: EXPIRES_AT,
        payeeClass: 'M',
      },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
    },
    {
      id: 'A-roundtrip-static',
      profile: 'A',
      type: 'roundtrip',
      description: 'Sign and verify a static code.',
      input: {
        base: STATIC_BASE,
        issuerScalar: PUBLISHED_ISSUER_SCALAR,
        kid: issuer.kid,
        issuedAt: ISSUED_AT,
        payeeClass: 'I',
      },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
    },
    {
      id: 'B-roundtrip-credential',
      profile: 'B',
      type: 'roundtrip',
      description: 'Encode, sign, then decode and verify a credential.',
      input: { issuerScalar: PUBLISHED_ISSUER_SCALAR, kid: issuer.kid, claims: CLAIMS },
      state: DEFAULT_STATE,
      expect: 'accept',
      reason: null,
    },
  ];

  const suite = {
    schema: 'kh-sqr/vectors/1',
    version: 1,
    description:
      'Conformance vectors for KH-SQR. A conforming implementation must produce the stated outcome for ' +
      'every case, and for a rejection must report the stated machine-readable reason. Where "reason" is ' +
      'null on a rejection, any rejection reason is acceptable.',
    generator: 'tools/generate-vectors.ts',
    reproducibility:
      'Every key is derived from a published scalar or a published label; regenerate with `pnpm ' +
      'vectors:generate`. These keys protect nothing and must never be used outside testing.',
    time: { issuedAt: ISSUED_AT, expiresAt: EXPIRES_AT, nowValid: NOW_VALID },
    keys: {
      issuer: { scalar: issuer.scalarHex, x: issuer.x, y: issuer.y, kid: issuer.kid, pem: issuer.publicPem },
      root: { label: 'kh-sqr/test/root/1', scalar: root.scalarHex, x: root.x, y: root.y, kid: root.kid },
      timestamp: {
        label: 'kh-sqr/test/timestamp/1',
        scalar: timestampKey.scalarHex,
        x: timestampKey.x,
        y: timestampKey.y,
        kid: timestampKey.kid,
      },
      revokedIssuer: { label: 'kh-sqr/test/revoked-issuer/1', scalar: revoked.scalarHex, x: revoked.x, y: revoked.y, kid: revoked.kid },
      untrustedIssuer: { label: 'kh-sqr/test/untrusted-issuer/1', scalar: stranger.scalarHex, x: stranger.x, y: stranger.y, kid: stranger.kid },
    },
    pinned: {
      rootKeys: [{ kid: root.kid, x: root.x, y: root.y }],
      timestampKeys: [{ kid: timestampKey.kid, x: timestampKey.x, y: timestampKey.y }],
    },
    trustLists,
    timestamps,
    cases,
  };

  const rejects = cases.filter((c) => c.expect === 'reject').length;

  // `--check` verifies that the committed suite still matches what the
  // generator would produce, without demanding byte equality: ECDSA is
  // randomised, so every regeneration carries different signatures and every
  // payload containing one differs. What must not drift is the inventory —
  // which cases exist, what each asserts, and the rejection reason each
  // expects.
  if (process.argv.includes('--check')) {
    const committed = JSON.parse(readFileSync(OUT, 'utf8')) as { cases: readonly Case[] };
    const inventory = (list: readonly Case[]): string =>
      JSON.stringify(
        list.map((c) => [c.id, c.profile, c.type, c.expect, c.reason]).sort((a, b) => String(a[0]).localeCompare(String(b[0]))),
      );
    if (inventory(committed.cases) !== inventory(cases)) {
      process.stderr.write('vectors/vectors.json is out of date; run `pnpm vectors:generate`\n');
      process.exit(1);
    }
    process.stdout.write(`vectors/vectors.json is current (${cases.length} cases)\n`);
    return;
  }

  writeFileSync(OUT, `${JSON.stringify(suite, null, 2)}\n`);
  process.stdout.write(
    `wrote ${OUT}\n  ${cases.length} cases (${rejects} negative, ${cases.length - rejects} positive)\n`,
  );
}

await main();
