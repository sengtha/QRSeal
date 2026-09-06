/**
 * QRSeal sandbox — a progressive web app that issues and verifies KH-SQR codes
 * with the real library, entirely on the device.
 *
 * The device is the whole scheme. On first run it performs a Root "ceremony"
 * (a key pair in Web Crypto), enrols an issuer key, publishes a signed trust
 * list and a signed timestamp statement, and from then on signs codes under
 * that issuer and verifies them against that list. Nothing leaves the browser,
 * which is why it works with the network unplugged, and which is also why it
 * proves nothing about any real scheme: the keys protect a sandbox.
 *
 * The verification path is the library's. This file never reimplements a
 * check; it only decides what to show, and the specification's interface
 * obligations (SPEC.md §8) decide most of that.
 */

import jsQR from 'jsqr';
import QRCode from 'qrcode';

import {
  KhSqrError,
  TrustAnchor,
  assertNotUrlCarrier,
  deriveKidFromCoordinates,
  detectProfileAEncoding,
  digestStatement,
  findObject,
  parseDataObjects,
  revocationEntryId,
  serialiseDataObject,
  signProfileA2,
  signProfileB,
  stripCrc,
  verifyProfileA,
  verifyProfileA2,
  verifyProfileB,
} from '../../packages/core/dist/index.js';
import type {
  CredentialAssertion,
  PaymentAttestation,
  PaymentAttestationV2,
  PayeeDisclosure,
  PinnedKey,
  PrintedDocumentFields,
  RejectionReason,
  SignedArtifact,
  TrustedKeyRecord,
} from '../../packages/core/dist/index.js';

/* ------------------------------------------------------------------ *
 * Small utilities
 * ------------------------------------------------------------------ */

const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id);
  if (el === null) throw new Error(`missing element #${id}`);
  return el as T;
};
const esc = (s: unknown): string =>
  String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string);
const nowSec = (): number => Math.floor(Date.now() / 1000);
const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('');
const b64urlToHex = (s: string): string => {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
  return hex(bytes).padStart(64, '0');
};
const fmtTime = (unix: number): string => new Date(unix * 1000).toLocaleString();
const encoder = new TextEncoder();

function setText(id: string, text: string): void {
  $(id).textContent = text;
}

/* ------------------------------------------------------------------ *
 * The sandbox scheme: keys, trust list, timestamp — all local
 * ------------------------------------------------------------------ */

interface StoredKey {
  readonly kid: string;
  readonly x: string;
  readonly y: string;
  /** Private JWK. A sandbox key; it protects nothing and is stored in plain localStorage on purpose. */
  readonly jwk: JsonWebKey;
}

interface SandboxIssuer extends StoredKey {
  readonly name: string;
  status: 'active' | 'revoked';
  readonly notBefore: number;
  readonly notAfter: number;
}

/** A credential this device issued: enough to name it in a revocation list, nothing more. */
interface IssuedCredential {
  readonly documentId: string;
  readonly subjectName: string;
  readonly documentType: string;
  readonly issuedAt: number;
  readonly kid: string;
}

interface WithdrawnCredential {
  readonly documentId: string;
  readonly revokedAt: number;
  readonly reason: 'withdrawn' | 'corrected';
}

interface Sandbox {
  schema?: number;
  readonly createdAt: number;
  readonly root: StoredKey;
  readonly timestampSigner: StoredKey;
  readonly issuers: SandboxIssuer[];
  version: number;
  trustList: SignedArtifact | null;
  timestamp: SignedArtifact | null;
  /** When the current list was published. This is the verifier's `fetchedAt`. */
  publishedAt: number;
  /** Credentials issued here, so that one can be withdrawn by name. */
  issued: IssuedCredential[];
  withdrawn: WithdrawnCredential[];
  /** The issuer's revocation list, signed by the active issuer key; null when no key can sign one. */
  revocations: SignedArtifact | null;
  revocationVersion: number;
}

/** A scheme exported from another device: public material only. */
interface ImportedScheme {
  readonly name: string;
  readonly rootKeys: readonly PinnedKey[];
  readonly timestampKeys: readonly PinnedKey[];
  readonly trustList: SignedArtifact;
  readonly timestamp: SignedArtifact;
  /** Every revocation list the timestamp declares; absent in bundles exported before revocation existed. */
  readonly revocations?: readonly SignedArtifact[];
  readonly importedAt: number;
}

const SANDBOX_KEY = 'qrseal.sandbox.v1';
/**
 * The organisation identifier every sandbox issuer key is registered under. A
 * Profile B credential's issuer claim must equal it, or the verifier rejects
 * the credential with ISSUER_KEY_MISMATCH; the Issue form defaults to it.
 */
const SANDBOX_ISSUER_ID = 'KH.EDU.SANDBOX';
/**
 * The merchant-account identifiers every sandbox issuer key may sign for: the
 * exact value the Issue form defaults to, and a bank suffix for account-style
 * identifiers such as merchant@abaa. A code naming anything else is refused
 * with ACQUIRER_KEY_MISMATCH.
 */
const SANDBOX_ACQUIRERS: readonly string[] = ['abaakhppxxx', '@abaa'];
/** Bumped when the published list's shape changes; an older sandbox republishes on load. */
const SANDBOX_SCHEMA = 4;
const IMPORTED_KEY = 'qrseal.imported.v1';
const VERIFY_AGAINST_KEY = 'qrseal.verifyAgainst.v1';
const LIST_LIFE_SECONDS = 365 * 24 * 60 * 60;
const TIMESTAMP_LIFE_SECONDS = 7 * 24 * 60 * 60;
const KEY_LIFE_SECONDS = 2 * 365 * 24 * 60 * 60;
/** Republish the list before the verifier's 30-day cache limit would bite. */
const REPUBLISH_AFTER_SECONDS = 25 * 24 * 60 * 60;
/** Re-stamp while at least a day of the seven remains. */
const RESTAMP_WITHIN_SECONDS = 24 * 60 * 60;

async function generateKey(): Promise<StoredKey> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  if (jwk.x === undefined || jwk.y === undefined) throw new Error('key export produced no coordinates');
  const x = b64urlToHex(jwk.x);
  const y = b64urlToHex(jwk.y);
  return { kid: await deriveKidFromCoordinates(x, y), x, y, jwk };
}

async function signingKey(key: StoredKey): Promise<CryptoKey> {
  return crypto.subtle.importKey('jwk', key.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function signArtifact(statement: string, key: StoredKey): Promise<SignedArtifact> {
  const raw = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, await signingKey(key), encoder.encode(statement));
  return { statement, signature: { alg: 'ES256', kid: key.kid, value: hex(new Uint8Array(raw)) } };
}

function saveSandbox(sb: Sandbox): void {
  localStorage.setItem(SANDBOX_KEY, JSON.stringify(sb));
}

/**
 * Sign the issuer's revocation list with the active issuer key. The list names
 * every withdrawn credential by a salted hash of its document number, and the
 * timestamp statement then declares it, so a verifier that lacks it fails
 * closed rather than reporting the credential as merely unchecked.
 */
async function publishRevocations(sb: Sandbox): Promise<void> {
  const issuer = activeIssuer(sb);
  if (issuer === null) {
    sb.revocations = null;
    return;
  }
  const entries = [];
  for (const w of sb.withdrawn) {
    entries.push({ id: await revocationEntryId(SANDBOX_ISSUER_ID, w.documentId), revokedAt: w.revokedAt, reason: w.reason });
  }
  const statement = JSON.stringify({
    type: 'kh-sqr/revocations/1',
    issuer: SANDBOX_ISSUER_ID,
    version: sb.revocationVersion,
    issuedAt: nowSec(),
    entries,
  });
  sb.revocations = await signArtifact(statement, issuer);
}

async function stamp(sb: Sandbox): Promise<void> {
  if (sb.trustList === null) throw new Error('no trust list to stamp');
  const issuedAt = nowSec();
  const revocations =
    sb.revocations === null
      ? []
      : [{ issuer: SANDBOX_ISSUER_ID, version: sb.revocationVersion, digest: await digestStatement(sb.revocations.statement) }];
  const statement = JSON.stringify({
    type: 'kh-sqr/timestamp/1',
    trustListVersion: sb.version,
    trustListDigest: await digestStatement(sb.trustList.statement),
    issuedAt,
    expires: issuedAt + TIMESTAMP_LIFE_SECONDS,
    revocations,
  });
  sb.timestamp = await signArtifact(statement, sb.timestampSigner);
  saveSandbox(sb);
}

/** Withdraw one issued credential: a new list version, signed, then declared by a fresh timestamp. */
async function withdraw(sb: Sandbox, documentId: string): Promise<void> {
  if (sb.withdrawn.some((w) => w.documentId === documentId)) return;
  sb.withdrawn.push({ documentId, revokedAt: nowSec(), reason: 'withdrawn' });
  sb.revocationVersion += 1;
  await publishRevocations(sb);
  await stamp(sb);
}

/** Publish a new trust-list version from the current issuer set, then stamp it. */
async function publish(sb: Sandbox): Promise<void> {
  const issuedAt = nowSec();
  sb.version += 1;
  const keys: TrustedKeyRecord[] = sb.issuers.map((i) => ({
    kid: i.kid,
    x: i.x,
    y: i.y,
    profiles: ['A', 'B'],
    status: i.status,
    notBefore: i.notBefore,
    notAfter: i.notAfter,
    subject: { name: i.name, organisationId: SANDBOX_ISSUER_ID },
    acquirers: SANDBOX_ACQUIRERS,
  }));
  const statement = JSON.stringify({
    type: 'kh-sqr/trustlist/1',
    version: sb.version,
    issuedAt,
    expires: issuedAt + LIST_LIFE_SECONDS,
    keys,
  });
  sb.trustList = await signArtifact(statement, sb.root);
  sb.publishedAt = issuedAt;
  sb.schema = SANDBOX_SCHEMA;
  // The list is re-signed with whichever key is active now: revoking the key
  // that signed the previous one would otherwise take the list down with it.
  await publishRevocations(sb);
  await stamp(sb);
}

async function newIssuer(sb: Sandbox): Promise<SandboxIssuer> {
  const key = await generateKey();
  const t = nowSec();
  return { ...key, name: `Sandbox issuer ${sb.issuers.length + 1}`, status: 'active', notBefore: t - 60, notAfter: t + KEY_LIFE_SECONDS };
}

async function createSandbox(): Promise<Sandbox> {
  const sb: Sandbox = {
    createdAt: nowSec(),
    root: await generateKey(),
    timestampSigner: await generateKey(),
    issuers: [],
    version: 0,
    trustList: null,
    timestamp: null,
    publishedAt: 0,
    issued: [],
    withdrawn: [],
    revocations: null,
    revocationVersion: 1,
  };
  sb.issuers.push(await newIssuer(sb));
  await publish(sb);
  return sb;
}

async function loadSandbox(): Promise<Sandbox> {
  let sb: Sandbox | null = null;
  try {
    const raw = localStorage.getItem(SANDBOX_KEY);
    if (raw !== null) sb = JSON.parse(raw) as Sandbox;
  } catch {
    sb = null;
  }
  if (sb === null || sb.trustList === null || sb.timestamp === null) return createSandbox();
  // Fields a sandbox stored before revocation lists existed.
  sb.issued ??= [];
  sb.withdrawn ??= [];
  sb.revocations ??= null;
  sb.revocationVersion ??= 1;

  const now = nowSec();
  if (sb.schema !== SANDBOX_SCHEMA || now - sb.publishedAt > REPUBLISH_AFTER_SECONDS) {
    await publish(sb);
  } else {
    const ts = JSON.parse(sb.timestamp.statement) as { expires: number };
    if (ts.expires - now < RESTAMP_WITHIN_SECONDS) await stamp(sb);
  }
  return sb;
}

function activeIssuer(sb: Sandbox): SandboxIssuer | null {
  for (let i = sb.issuers.length - 1; i >= 0; i -= 1) {
    const issuer = sb.issuers[i];
    if (issuer !== undefined && issuer.status === 'active') return issuer;
  }
  return null;
}

function loadImported(): ImportedScheme | null {
  try {
    const raw = localStorage.getItem(IMPORTED_KEY);
    return raw === null ? null : (JSON.parse(raw) as ImportedScheme);
  } catch {
    return null;
  }
}

type VerifyAgainst = 'sandbox' | 'imported';

function verifyAgainst(): VerifyAgainst {
  return localStorage.getItem(VERIFY_AGAINST_KEY) === 'imported' && loadImported() !== null ? 'imported' : 'sandbox';
}

async function openAnchor(sb: Sandbox, now: number): Promise<{ anchor: TrustAnchor; source: string }> {
  if (verifyAgainst() === 'imported') {
    const imp = loadImported();
    if (imp !== null) {
      const anchor = await TrustAnchor.open({
        trustList: imp.trustList,
        timestamp: imp.timestamp,
        rootKeys: imp.rootKeys,
        timestampKeys: imp.timestampKeys,
        revocations: imp.revocations ?? [],
        fetchedAt: imp.importedAt,
        now,
      });
      return { anchor, source: `imported scheme “${imp.name}”` };
    }
  }
  if (sb.trustList === null || sb.timestamp === null) throw new Error('sandbox has no trust list');
  const anchor = await TrustAnchor.open({
    trustList: sb.trustList,
    timestamp: sb.timestamp,
    rootKeys: [{ kid: sb.root.kid, x: sb.root.x, y: sb.root.y }],
    timestampKeys: [{ kid: sb.timestampSigner.kid, x: sb.timestampSigner.x, y: sb.timestampSigner.y }],
    revocations: sb.revocations === null ? [] : [sb.revocations],
    heldVersion: sb.version,
    fetchedAt: sb.publishedAt,
    now,
  });
  return { anchor, source: 'this device’s sandbox' };
}

/* ------------------------------------------------------------------ *
 * Classifying a scan — the pipeline from docs/INTEGRATION.md §1.4
 * ------------------------------------------------------------------ */

type ScanOutcome =
  | { kind: 'payment'; attestation: PaymentAttestation | PaymentAttestationV2 }
  | { kind: 'credential'; assertion: CredentialAssertion }
  | { kind: 'unsigned-payment'; payload: string }
  | { kind: 'rejected'; profile: 'A' | 'B'; reason: RejectionReason; detail: string }
  | { kind: 'refused-url' }
  | { kind: 'not-a-code'; payload: string };

async function classifyScan(scanned: string, anchor: TrustAnchor, now: number): Promise<ScanOutcome> {
  try {
    assertNotUrlCarrier(scanned);
  } catch {
    return { kind: 'refused-url' };
  }

  if (scanned.startsWith('KH1:')) {
    try {
      return { kind: 'credential', assertion: await verifyProfileB({ payload: scanned, trustAnchor: anchor, now }) };
    } catch (error) {
      if (error instanceof KhSqrError) return { kind: 'rejected', profile: 'B', reason: error.reason, detail: error.message };
      throw error;
    }
  }

  const encoding = detectProfileAEncoding(scanned);
  if (encoding === null) {
    return looksLikeEmvco(scanned) ? { kind: 'unsigned-payment', payload: scanned } : { kind: 'not-a-code', payload: scanned };
  }
  try {
    const attestation =
      encoding === 2
        ? await verifyProfileA2({ payload: scanned, trustAnchor: anchor, now })
        : await verifyProfileA({ payload: scanned, trustAnchor: anchor, now });
    return { kind: 'payment', attestation };
  } catch (error) {
    if (error instanceof KhSqrError) return { kind: 'rejected', profile: 'A', reason: error.reason, detail: error.message };
    throw error;
  }
}

function looksLikeEmvco(payload: string): boolean {
  try {
    const objects = parseDataObjects(stripCrc(payload), { extendedLengthTags: new Set() });
    return findObject(objects, '00')?.value === '01';
  } catch {
    return false;
  }
}

/** What to do about each rejection reason, grouped as in the integration guide. */
function adviceFor(reason: RejectionReason): string {
  if (reason.startsWith('TRUSTLIST_') || reason.startsWith('TIMESTAMP_')) {
    return 'The verifier’s own trust state is the problem, not the code. A wallet would refresh its trust list and retry once; here, open the Trust tab.';
  }
  if (reason === 'UNKNOWN_KID') {
    return 'No key on the trust list has this identifier. Either the issuer is not enrolled in the scheme you are verifying against, or the list is out of date. Check which scheme is selected in the Trust tab.';
  }
  if (reason.startsWith('KEY_')) {
    return 'The signing key is known and not usable. Refuse. Everything this key ever signed is affected — revocation is per key, not per code.';
  }
  if (reason === 'ACQUIRER_KEY_MISMATCH') {
    return 'The signature is genuine, but the code pays into an account at an institution the signing key is not registered for. A registered key vouched for someone else’s account. Refuse.';
  }
  if (reason === 'ISSUER_KEY_MISMATCH') {
    return 'The signature is genuine, but the key that made it is registered to a different organisation from the one the credential names. A registered issuer signed in someone else’s name. Refuse.';
  }
  if (reason === 'CREDENTIAL_REVOKED') {
    return 'The signature is genuine and the issuer has since withdrawn this credential: its document number is on the issuer’s signed revocation list. Refuse. This is the one thing a signature alone can never tell you.';
  }
  if (reason === 'REVOCATIONS_MISSING') {
    return 'The timestamp statement declares a revocation list for this issuer and the verifier does not hold it. Without the list a withdrawn credential would pass, so the verifier fails closed. A wallet would fetch the declared list and retry.';
  }
  if (reason.startsWith('REVOCATIONS_')) {
    return 'The issuer’s revocation list is malformed, mis-signed, stale or rolled back. The verifier refuses to check credentials against a list it cannot trust; refresh it.';
  }
  if (reason === 'CODE_EXPIRED' || reason === 'ISSUED_IN_FUTURE') {
    return 'A dynamic code lives at most 300 seconds. Ask for a fresh one. If it recurs on fresh codes, a device clock is wrong.';
  }
  return 'The code is tampered, forged or foreign. Refuse it. This is the half of the specification the negative test vectors exist for.';
}

/* ------------------------------------------------------------------ *
 * Rendering
 * ------------------------------------------------------------------ */

const CURRENCY_ALPHA: Record<string, string> = { '116': 'KHR', '840': 'USD' };

function row(label: string, value: string | null | undefined, opts: { big?: boolean; hi?: boolean; mono?: boolean } = {}): string {
  if (value === null || value === undefined || value === '') return '';
  const cls = [opts.big ? 'big' : '', opts.mono ? 'mono' : ''].filter(Boolean).join(' ');
  return `<div class="row${opts.hi ? ' hi' : ''}"><dt>${esc(label)}</dt><dd${cls ? ` class="${cls}"` : ''}>${esc(value)}</dd></div>`;
}

function renderDisclosure(p: PayeeDisclosure): string {
  const money =
    p.amount === null
      ? null
      : `${p.amount} ${p.currencyAlpha ?? `— unrecognised currency (tag 53 = ${p.currencyCode ?? '?'})`}`;
  return (
    row('Pay to', p.merchantName ?? '(no name in code)') +
    row('City', p.merchantCity) +
    row('Country', p.countryCode) +
    (money === null ? row('Amount', 'You enter it. Check the currency you are paying in.', { hi: true }) : row('Amount', money, { big: true, hi: true })) +
    row('Payee class', p.payeeClass === 'M' ? 'M — merchant' : 'I — individual') +
    row('Account', p.accounts.map((a) => `${a.tag} · ${accountFields(a.value)}`).join(' / '), { mono: true })
  );
}

/** Show a merchant-account template's sub-fields, or its raw value if it has none. */
function accountFields(value: string): string {
  try {
    return parseDataObjects(value, { extendedLengthTags: new Set() })
      .map((o) => `${o.tag}=${o.value}`)
      .join(' ');
  } catch {
    return value;
  }
}

function issuerNameFor(kid: string, sb: Sandbox): string {
  const found = sb.issuers.find((i) => i.kid === kid);
  return found === undefined ? kid : `${found.name} (${kid})`;
}

let pendingCredential: CredentialAssertion | null = null;

function renderOutcome(outcome: ScanOutcome, source: string, ms: number, sb: Sandbox): void {
  const head = $('v-outcome');
  const reason = $('v-reason');
  const body = $('v-body');
  const compare = $('v-compare');
  compare.hidden = true;
  pendingCredential = null;
  reason.hidden = true;
  setText('v-timing', `${ms.toFixed(1)} ms, on this device, against ${source}`);

  switch (outcome.kind) {
    case 'payment': {
      const a = outcome.attestation;
      head.className = 'outcome ok';
      head.textContent = 'Signature verified';
      const expires = a.expiresAt === null ? null : `${fmtTime(a.expiresAt)} (${Math.max(0, a.expiresAt - nowSec())} s left)`;
      body.innerHTML =
        `<p class="aside"><b>A verified signature is not a reason to pay.</b> It says a key on the trust list produced exactly these bytes. It does not say the person showing it to you is who they claim, or that the reason you were given is true.</p>` +
        `<dl class="disclosure">${renderDisclosure(a.payeeDisclosure)}` +
        row('Code kind', a.codeKind === 'dynamic' ? 'dynamic — one transaction' : 'static — printed, reusable') +
        row('Expires', expires) +
        row('Encoding', 'encodingVersion' in a ? 'v2 — EMVCo-conformant' : 'v1 — frozen') +
        row('Signed by', issuerNameFor(a.kid, sb), { mono: true }) +
        row('Is it safe to pay?', 'The library does not answer this, and neither does this page.') +
        `</dl>`;
      return;
    }
    case 'credential': {
      const c = outcome.assertion;
      pendingCredential = c;
      head.className = 'outcome ok';
      head.textContent = 'Signature verified';
      const m = c.mustMatchPrintedDocument;
      body.innerHTML =
        `<p class="aside"><b>Issued, yes. Belonging to this paper, unknown.</b> A genuine code photographed from a real document verifies perfectly on a forged one. Compare the four signed fields with what is printed.</p>` +
        `<dl class="disclosure">` +
        row('Issuer', c.issuer, { mono: true }) +
        row('Document type', c.documentType) +
        row('Subject name', m.subjectName, { big: true, hi: true }) +
        row('Document id', m.documentId, { hi: true }) +
        row('Issuing organisation', m.issuingOrganisation, { hi: true }) +
        row('Issue date', m.issueDate, { hi: true }) +
        row('Document hash', c.documentHash, { mono: true }) +
        row('Signed by', issuerNameFor(c.kid, sb), { mono: true }) +
        row(
          'Standing',
          c.credentialStatus === 'clear' && c.revocationList !== null
            ? `clear — not on the issuer’s revocation list v${c.revocationList.version}, signed ${fmtTime(c.revocationList.issuedAt)}. Offline, the list is as current as the last timestamp that declared it.`
            : 'unchecked — this issuer publishes no revocation list, so a withdrawal could not be seen offline',
          { hi: c.credentialStatus !== 'clear' },
        ) +
        `</dl>`;
      compare.hidden = false;
      $('cmp-result').innerHTML = '';
      for (const f of ['subjectName', 'documentId', 'issuingOrganisation', 'issueDate'] as const) {
        $<HTMLInputElement>(`cmp-${f}`).value = '';
      }
      return;
    }
    case 'unsigned-payment': {
      head.className = 'outcome plain';
      head.textContent = 'Unsigned payment code';
      const objects = parseDataObjects(stripCrc(outcome.payload), { extendedLengthTags: new Set() });
      const get = (tag: string): string | null => findObject(objects, tag)?.value ?? null;
      const cur = get('53');
      const amount = get('54');
      body.innerHTML =
        `<p class="aside"><b>No signature template.</b> During a rollout this is a merchant not yet enrolled, not a forgery, and a wallet shows it exactly as it shows a signed code — with the amount and currency together. Only after coverage is near-complete does “unsigned” become a warning.</p>` +
        `<dl class="disclosure">` +
        row('Pay to', get('59') ?? '(no name in code)') +
        row('City', get('60')) +
        (amount === null
          ? row('Amount', 'You enter it. Check the currency you are paying in.', { hi: true })
          : row('Amount', `${amount} ${cur !== null && CURRENCY_ALPHA[cur] !== undefined ? CURRENCY_ALPHA[cur] : `— unrecognised currency (tag 53 = ${cur ?? '?'})`}`, { big: true, hi: true })) +
        row('Signed by', 'nobody') +
        `</dl>`;
      return;
    }
    case 'rejected': {
      head.className = 'outcome no';
      head.textContent = 'Rejected';
      reason.hidden = false;
      reason.textContent = outcome.reason;
      body.innerHTML =
        `<p class="aside"><b>${esc(outcome.detail)}</b></p>` +
        `<dl class="disclosure">` +
        row('Profile', outcome.profile === 'A' ? 'A — payment' : 'B — credential') +
        row('Reason code', outcome.reason, { mono: true }) +
        row('What to do', adviceFor(outcome.reason)) +
        `</dl>`;
      return;
    }
    case 'refused-url': {
      head.className = 'outcome no';
      head.textContent = 'Refused: a URL';
      reason.hidden = false;
      reason.textContent = 'URL_PAYLOAD_REJECTED';
      body.innerHTML = `<p class="aside"><b>This code would open a website.</b> A payment or official code never does, so this app refuses to follow it — before knowing anything else about it. The rule is categorical because a code’s class is unknowable until it has been scanned.</p>`;
      return;
    }
    case 'not-a-code': {
      head.className = 'outcome plain';
      head.textContent = 'Not a payment or credential code';
      body.innerHTML =
        `<p class="aside">Neither an EMVCo payload nor a <code>KH1:</code> credential. Shown as text, not followed.</p>` +
        `<pre class="raw">${esc(outcome.payload.slice(0, 400))}${outcome.payload.length > 400 ? '…' : ''}</pre>`;
      return;
    }
  }
}

function renderTlv(payload: string): void {
  const el = $('v-tlv');
  const note = $('v-tlv-note');
  let objects: { tag: string; value: string }[];
  try {
    objects = parseDataObjects(stripCrc(payload), { extendedLengthTags: new Set() });
  } catch {
    el.innerHTML = `<span class="val">${esc(payload)}</span>`;
    note.hidden = false;
    note.textContent = payload.startsWith('KH1:')
      ? 'A credential is not EMVCo TLV: it is CBOR inside COSE, deflated and base45-encoded, so there is nothing for this walk to show.'
      : 'A strict two-digit EMVCo walk cannot tile this payload. For a version 1 KH-SQR code that is expected — template 85 declares a three-digit length — and it is the defect encoding version 2 fixes.';
    return;
  }
  note.hidden = true;
  const mark = new Set(['53', '54']);
  const sig = new Set(['85', '86', '87']);
  el.innerHTML = objects
    .map((o) => {
      const cls = mark.has(o.tag) ? 'seg mark' : sig.has(o.tag) ? 'seg sig' : 'seg';
      const shown = o.value.length > 74 ? `${o.value.slice(0, 60)}…${o.value.slice(-8)}` : o.value;
      return `<span class="${cls}"><span class="tag">${o.tag}</span><span class="len">${String(o.value.length).padStart(2, '0')}</span><span class="val">${esc(shown)}</span></span> `;
    })
    .join('');
}

/* ------------------------------------------------------------------ *
 * Issuing
 * ------------------------------------------------------------------ */

const CURRENCY_NUMERIC: Record<string, string> = { KHR: '116', USD: '840' };

function readA(): { payload: string; kind: 'static' | 'dynamic'; payeeClass: 'M' | 'I'; validity: number } {
  const kind = $<HTMLInputElement>('a-kind-dynamic').checked ? 'dynamic' : 'static';
  const payeeClass = $<HTMLSelectElement>('a-class').value === 'I' ? 'I' : 'M';
  const name = $<HTMLInputElement>('a-name').value.trim();
  const city = $<HTMLInputElement>('a-city').value.trim();
  const acquirer = $<HTMLInputElement>('a-acquirer').value.trim();
  const account = $<HTMLInputElement>('a-account').value.trim();
  const mcc = $<HTMLInputElement>('a-mcc').value.trim();
  const currency = $<HTMLSelectElement>('a-currency').value;
  const amount = $<HTMLInputElement>('a-amount').value.trim();
  const validity = Number($<HTMLInputElement>('a-validity').value);

  if (name.length === 0 || name.length > 25) throw new Error('Merchant name: 1 to 25 characters (EMVCo tag 59).');
  if (city.length === 0 || city.length > 15) throw new Error('City: 1 to 15 characters (EMVCo tag 60).');
  // Real acquirer identifiers carry an '@' (e.g. a bank's GUID suffixed with its own code).
  if (!/^[A-Za-z0-9@._-]{1,32}$/.test(acquirer)) throw new Error('Acquirer id: letters, digits, @ . _ and dash.');
  if (!/^[A-Za-z0-9.-]{1,32}$/.test(account)) throw new Error('Account id: letters, digits, dot and dash.');
  if (!/^\d{4}$/.test(mcc)) throw new Error('Merchant category code: four digits.');
  const numeric = CURRENCY_NUMERIC[currency];
  if (numeric === undefined) throw new Error('Currency must be KHR or USD in this sandbox.');
  if (kind === 'dynamic') {
    if (!/^\d{1,10}(\.\d{1,2})?$/.test(amount)) throw new Error('Amount: digits, with at most two decimals.');
    if (!Number.isInteger(validity) || validity < 5 || validity > 300) throw new Error('Validity: 5 to 300 seconds. The specification caps a dynamic code at 300.');
  }

  const merchantInfo = serialiseDataObject(payeeClass === 'I' ? '29' : '30', serialiseDataObject('00', acquirer) + serialiseDataObject('01', account));
  const payload =
    serialiseDataObject('00', '01') +
    serialiseDataObject('01', kind === 'dynamic' ? '12' : '11') +
    merchantInfo +
    serialiseDataObject('52', mcc) +
    serialiseDataObject('53', numeric) +
    (kind === 'dynamic' ? serialiseDataObject('54', amount) : '') +
    serialiseDataObject('58', 'KH') +
    serialiseDataObject('59', name) +
    serialiseDataObject('60', city);
  return { payload, kind, payeeClass, validity };
}

let expiryTimer: number | undefined;

async function showIssued(payload: string, expiresAt: number | null, label: string): Promise<void> {
  const canvas = $<HTMLCanvasElement>('i-qr');
  await QRCode.toCanvas(canvas, payload, { errorCorrectionLevel: 'M', margin: 2, width: 320 });
  const symbol = QRCode.create(payload, { errorCorrectionLevel: 'M' });
  setText('i-meta', `${label} · ${payload.length} characters · QR version ${symbol.version} (${symbol.modules.size}×${symbol.modules.size} modules) at level M`);
  $<HTMLTextAreaElement>('i-payload').value = payload;
  $('i-out').hidden = false;
  window.clearInterval(expiryTimer);
  const exp = $('i-expiry');
  if (expiresAt === null) {
    exp.textContent = 'Static: no expiry. Print it once; it verifies for as long as the key is trusted.';
  } else {
    const tick = (): void => {
      const left = expiresAt - nowSec();
      exp.textContent = left > 0 ? `Dynamic: expires in ${left} s. After that, scanning it gives CODE_EXPIRED.` : 'Expired. Scanning it now gives CODE_EXPIRED — a one-transaction code is not reusable.';
    };
    tick();
    expiryTimer = window.setInterval(tick, 1000);
  }
}

async function issueA(sb: Sandbox): Promise<void> {
  const issuer = activeIssuer(sb);
  if (issuer === null) throw new Error('Every sandbox issuer key is revoked. Enrol a new one in the Trust tab.');
  const { payload, kind, payeeClass, validity } = readA();
  if (!$<HTMLInputElement>('a-sign').checked) {
    await showIssued(appendPlainCrc(payload), null, `Unsigned KHQR-style ${kind} code`);
    return;
  }
  const issuedAt = nowSec();
  const expiresAt = kind === 'dynamic' ? issuedAt + validity : undefined;
  const signed = await signProfileA2({
    payload,
    privateKey: await signingKey(issuer),
    kid: issuer.kid,
    issuedAt,
    ...(expiresAt === undefined ? {} : { expiresAt }),
    payeeClass,
  });
  await showIssued(signed.payload, expiresAt ?? null, `Profile A, encoding v2, ${signed.codeKind}, signed by ${issuer.name}`);
}

function appendPlainCrc(payload: string): string {
  // The library's appendCrc is not exported under that name here to keep the
  // import list honest about what the page uses; a CRC is a checksum, not a
  // control, and computing it through the parser round-trip below keeps the
  // demo on the library's own code path.
  const withHeader = `${payload}6304`;
  return withHeader + crc16(withHeader);
}

/** CRC-16/CCITT-FALSE, as EMVCo tag 63 requires. Identical to the library's. */
function crc16(data: string): string {
  let crc = 0xffff;
  for (let i = 0; i < data.length; i += 1) {
    crc ^= data.charCodeAt(i) << 8;
    for (let b = 0; b < 8; b += 1) crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

async function issueB(sb: Sandbox): Promise<void> {
  const issuer = activeIssuer(sb);
  if (issuer === null) throw new Error('Every sandbox issuer key is revoked. Enrol a new one in the Trust tab.');
  const v = (id: string): string => $<HTMLInputElement>(id).value.trim();
  const claims = {
    issuer: v('b-issuer'),
    issuedAt: nowSec(),
    documentType: v('b-type'),
    documentId: v('b-docid'),
    subjectName: v('b-subject'),
    issuingOrganisation: v('b-org'),
    issueDate: v('b-date'),
    ...(documentHashHex === null ? {} : { documentHash: documentHashHex }),
  };
  for (const [k, val] of Object.entries(claims)) {
    if (typeof val === 'string' && val.length === 0) throw new Error(`${k} is required.`);
  }
  const payload = await signProfileB({ privateKey: await signingKey(issuer), kid: issuer.kid, claims });
  sb.issued = sb.issued.filter((c) => c.documentId !== claims.documentId);
  sb.issued.push({ documentId: claims.documentId, subjectName: claims.subjectName, documentType: claims.documentType, issuedAt: claims.issuedAt, kid: issuer.kid });
  saveSandbox(sb);
  renderTrust(sb);
  const standing = sb.withdrawn.some((w) => w.documentId === claims.documentId) ? ' — this document id is on the revocation list, so it will be refused' : '';
  await showIssued(payload, null, `Profile B credential, signed by ${issuer.name}${standing}`);
}

let documentHashHex: string | null = null;

async function hashFile(file: File): Promise<void> {
  const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
  documentHashHex = hex(new Uint8Array(digest));
  setText('b-hash', `SHA-256 of ${file.name}: ${documentHashHex}`);
}

/* ------------------------------------------------------------------ *
 * Scanning
 * ------------------------------------------------------------------ */

interface DetectedBarcode {
  rawValue: string;
}
interface BarcodeDetectorLike {
  detect(source: ImageBitmapSource): Promise<DetectedBarcode[]>;
}
declare const BarcodeDetector:
  | (new (options?: { formats?: string[] }) => BarcodeDetectorLike & { constructor: { getSupportedFormats(): Promise<string[]> } })
  | undefined;

let stream: MediaStream | null = null;
let scanning = false;

async function makeDetector(): Promise<BarcodeDetectorLike | null> {
  if (typeof BarcodeDetector === 'undefined') return null;
  try {
    const ctor = BarcodeDetector as unknown as { getSupportedFormats(): Promise<string[]> };
    const formats = await ctor.getSupportedFormats();
    if (!formats.includes('qr_code')) return null;
    return new BarcodeDetector({ formats: ['qr_code'] });
  } catch {
    return null;
  }
}

function decodeCanvas(canvas: HTMLCanvasElement): string | null {
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (ctx === null) return null;
  const image = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const found = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
  return found === null ? null : found.data;
}

async function startCamera(onCode: (text: string) => void): Promise<void> {
  const video = $<HTMLVideoElement>('s-video');
  const status = $('s-cam-status');
  stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
  video.srcObject = stream;
  await video.play();
  scanning = true;
  $('s-cam').hidden = false;
  const detector = await makeDetector();
  status.textContent = detector === null ? 'Scanning with jsQR' : 'Scanning with the platform barcode detector';
  const canvas = document.createElement('canvas');

  const loop = async (): Promise<void> => {
    if (!scanning) return;
    let text: string | null = null;
    try {
      if (detector !== null) {
        const codes = await detector.detect(video);
        text = codes[0]?.rawValue ?? null;
      } else if (video.videoWidth > 0) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        canvas.getContext('2d')?.drawImage(video, 0, 0);
        text = decodeCanvas(canvas);
      }
    } catch {
      text = null;
    }
    if (text !== null && text.length > 0) {
      stopCamera();
      onCode(text);
      return;
    }
    window.setTimeout(() => void loop(), detector === null ? 120 : 200);
  };
  void loop();
}

function stopCamera(): void {
  scanning = false;
  if (stream !== null) {
    for (const t of stream.getTracks()) t.stop();
    stream = null;
  }
  $('s-cam').hidden = true;
}

async function decodeImageFile(file: File): Promise<string | null> {
  const bitmap = await createImageBitmap(file);
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext('2d')?.drawImage(bitmap, 0, 0);
  const detector = await makeDetector();
  if (detector !== null) {
    try {
      const codes = await detector.detect(canvas);
      if (codes[0] !== undefined) return codes[0].rawValue;
    } catch {
      // fall through to jsQR
    }
  }
  return decodeCanvas(canvas);
}

/* ------------------------------------------------------------------ *
 * Trust tab
 * ------------------------------------------------------------------ */

function renderTrust(sb: Sandbox): void {
  const list = JSON.parse(sb.trustList?.statement ?? '{}') as { expires?: number; issuedAt?: number };
  const ts = JSON.parse(sb.timestamp?.statement ?? '{}') as { expires?: number };
  $('t-sandbox').innerHTML =
    `<dl class="disclosure">` +
    row('Root key', sb.root.kid, { mono: true }) +
    row('Timestamp signer', sb.timestampSigner.kid, { mono: true }) +
    row('Issuer organisation id', `${SANDBOX_ISSUER_ID} — a credential's issuer claim must equal this, or it is refused`, { mono: true }) +
    row('Payment keys bound to', `${SANDBOX_ACQUIRERS.join(', ')} — a code's account template must name one of these (exactly, or ending in the @ suffix), or it is refused`, { mono: true }) +
    row('Trust list', `version ${sb.version}, published ${fmtTime(sb.publishedAt)}, expires ${list.expires === undefined ? '?' : fmtTime(list.expires)}`) +
    row('Timestamp statement', ts.expires === undefined ? '?' : `valid until ${fmtTime(ts.expires)} — re-signed automatically while this app runs`) +
    row(
      'Revocation list',
      sb.revocations === null
        ? 'none — no active issuer key can sign one, so credentials verify as unchecked'
        : `version ${sb.revocationVersion}, ${sb.withdrawn.length} withdrawn, signed by ${issuerNameFor(sb.revocations.signature.kid, sb)} and declared by the timestamp statement`,
    ) +
    `</dl>` +
    `<div class="keys">${sb.issuers
      .map(
        (i) =>
          `<div class="key ${i.status}"><span class="key-name">${esc(i.name)}</span><span class="mono">${i.kid}</span><span class="chip ${i.status === 'active' ? 'pass' : 'fail'}">${i.status}</span></div>`,
      )
      .join('')}</div>` +
    `<h3 class="sub">Credentials issued here</h3>` +
    (sb.issued.length === 0
      ? `<p class="hint">None yet. Issue a Profile B credential and it appears here, where it can be withdrawn.</p>`
      : `<div class="keys" id="t-issued">${sb.issued
          .map((c) => {
            const gone = sb.withdrawn.find((w) => w.documentId === c.documentId);
            return (
              `<div class="key cred ${gone === undefined ? 'issued' : 'withdrawn'}" data-docid="${esc(c.documentId)}">` +
              `<span class="key-name">${esc(c.documentId)} · ${esc(c.subjectName)}</span>` +
              `<span class="chip ${gone === undefined ? 'pass' : 'fail'}">${gone === undefined ? 'issued' : 'withdrawn'}</span>` +
              (gone === undefined ? `<button class="act danger small" type="button" data-withdraw="${esc(c.documentId)}">Withdraw</button>` : `<span class="mono">${fmtTime(gone.revokedAt)}</span>`) +
              `</div>`
            );
          })
          .join('')}</div>`);

  const imp = loadImported();
  const which = verifyAgainst();
  $<HTMLInputElement>('t-against-sandbox').checked = which === 'sandbox';
  $<HTMLInputElement>('t-against-imported').checked = which === 'imported';
  $<HTMLInputElement>('t-against-imported').disabled = imp === null;
  if (imp === null) {
    $('t-imported').innerHTML = `<p class="hint">No imported scheme. Export a bundle from the device that issued a code, and import it here to verify that device’s codes.</p>`;
  } else {
    const ilist = JSON.parse(imp.trustList.statement) as { version?: number; keys?: TrustedKeyRecord[] };
    $('t-imported').innerHTML =
      `<dl class="disclosure">` +
      row('Name', imp.name) +
      row('Imported', fmtTime(imp.importedAt)) +
      row('Trust list', `version ${ilist.version ?? '?'}, ${ilist.keys?.length ?? 0} key(s)`) +
      row('Root keys pinned', imp.rootKeys.map((k) => k.kid).join(', '), { mono: true }) +
      row('Revocation lists', `${imp.revocations?.length ?? 0} held — a credential whose issuer's declared list is missing is refused, not passed`) +
      `</dl>`;
  }
}

function exportBundle(sb: Sandbox): string {
  return JSON.stringify(
    {
      format: 'qrseal-scheme-bundle/1',
      name: `Sandbox ${sb.root.kid.slice(0, 6)}`,
      rootKeys: [{ kid: sb.root.kid, x: sb.root.x, y: sb.root.y }],
      timestampKeys: [{ kid: sb.timestampSigner.kid, x: sb.timestampSigner.x, y: sb.timestampSigner.y }],
      trustList: sb.trustList,
      timestamp: sb.timestamp,
      revocations: sb.revocations === null ? [] : [sb.revocations],
      exportedAt: nowSec(),
    },
    null,
    2,
  );
}

async function importBundle(text: string): Promise<ImportedScheme> {
  const parsed = JSON.parse(text) as Partial<ImportedScheme> & { format?: string };
  if (parsed.format !== 'qrseal-scheme-bundle/1') throw new Error('Not a QRSeal scheme bundle.');
  if (!Array.isArray(parsed.rootKeys) || !Array.isArray(parsed.timestampKeys) || parsed.trustList === undefined || parsed.timestamp === undefined) {
    throw new Error('Bundle is missing keys, trust list or timestamp.');
  }
  const scheme: ImportedScheme = {
    name: typeof parsed.name === 'string' ? parsed.name : 'imported',
    rootKeys: parsed.rootKeys,
    timestampKeys: parsed.timestampKeys,
    trustList: parsed.trustList,
    timestamp: parsed.timestamp,
    revocations: Array.isArray(parsed.revocations) ? parsed.revocations : [],
    importedAt: nowSec(),
  };
  // Open it before keeping it. A bundle that does not open is not a scheme.
  await TrustAnchor.open({
    trustList: scheme.trustList,
    timestamp: scheme.timestamp,
    rootKeys: scheme.rootKeys,
    timestampKeys: scheme.timestampKeys,
    revocations: scheme.revocations ?? [],
    fetchedAt: scheme.importedAt,
    now: nowSec(),
  });
  localStorage.setItem(IMPORTED_KEY, JSON.stringify(scheme));
  localStorage.setItem(VERIFY_AGAINST_KEY, 'imported');
  return scheme;
}

/* ------------------------------------------------------------------ *
 * Vectors tab — the published suite, with its own frozen clock
 * ------------------------------------------------------------------ */

interface DemoData {
  generated: string;
  pinned: { rootKeys: PinnedKey[]; timestampKeys: PinnedKey[] };
  trustLists: Record<string, unknown>;
  timestamps: Record<string, unknown>;
  revocations: Record<string, readonly unknown[]>;
  pair: { khr: string; usd: string; state: VectorState };
  suite: { id: string; profile: 'A' | 'B'; expect: 'accept' | 'reject'; reason: string | null; encodingVersion: number; payload: string; state: VectorState }[];
}
interface VectorState {
  trustList: string;
  timestamp: string | null;
  now: number;
  heldVersion?: number;
  fetchedAt?: number;
  revocations?: string;
}

let demoData: DemoData | null = null;

async function loadDemoData(): Promise<DemoData> {
  if (demoData !== null) return demoData;
  const response = await fetch('./demo-data.json');
  demoData = (await response.json()) as DemoData;
  return demoData;
}

async function vectorAnchor(data: DemoData, state: VectorState): Promise<TrustAnchor> {
  return TrustAnchor.open({
    trustList: data.trustLists[state.trustList],
    ...(state.timestamp === null ? {} : { timestamp: data.timestamps[state.timestamp] }),
    rootKeys: data.pinned.rootKeys,
    timestampKeys: data.pinned.timestampKeys,
    now: state.now,
    ...(state.heldVersion === undefined ? {} : { heldVersion: state.heldVersion }),
    ...(state.fetchedAt === undefined ? {} : { fetchedAt: state.fetchedAt }),
    ...(state.revocations === undefined ? {} : { revocations: data.revocations[state.revocations] ?? [] }),
  });
}

async function runVector(data: DemoData, c: DemoData['suite'][number]): Promise<{ accepted: boolean; reason: string | null }> {
  try {
    const anchor = await vectorAnchor(data, c.state);
    if (c.profile === 'B') await verifyProfileB({ payload: c.payload, trustAnchor: anchor, now: c.state.now });
    else if (c.encodingVersion === 2) await verifyProfileA2({ payload: c.payload, trustAnchor: anchor, now: c.state.now });
    else await verifyProfileA({ payload: c.payload, trustAnchor: anchor, now: c.state.now });
    return { accepted: true, reason: null };
  } catch (error) {
    if (error instanceof KhSqrError) return { accepted: false, reason: error.reason };
    return { accepted: false, reason: 'MALFORMED' };
  }
}

async function runSuite(): Promise<void> {
  const btn = $<HTMLButtonElement>('x-run');
  btn.disabled = true;
  btn.textContent = 'Running…';
  const data = await loadDemoData();
  let pass = 0;
  const cells: string[] = [];
  for (const c of data.suite) {
    const o = await runVector(data, c);
    const ok = o.accepted === (c.expect === 'accept') && (c.reason === null || o.reason === c.reason);
    if (ok) pass += 1;
    cells.push(`<div class="cell ${ok ? 'ok' : 'bad'}"><span class="id">${esc(c.id)}</span><span class="mk">${ok ? '✓' : '✗'}</span></div>`);
  }
  $('x-grid').innerHTML = cells.join('');
  $('x-tally').innerHTML = `<b>${pass}</b> of <b>${cells.length}</b> vectors pass, in this browser`;
  btn.disabled = false;
  btn.textContent = 'Run again';
}

async function renderPair(): Promise<void> {
  const data = await loadDemoData();
  const anchor = await vectorAnchor(data, data.pair.state);
  const cards: string[] = [];
  for (const payload of [data.pair.khr, data.pair.usd]) {
    const a = await verifyProfileA2({ payload, trustAnchor: anchor, now: data.pair.state.now });
    const p = a.payeeDisclosure;
    cards.push(
      `<div class="pair-card"><div class="pair-amount">${esc(p.amount)} ${esc(p.currencyAlpha)}</div>` +
        `<div class="pair-tag">tag 53 = <mark>${esc(p.currencyCode)}</mark> · tag 54 = ${esc(p.amount)}</div>` +
        `<div class="pair-verdict">Signature verified · ${esc(p.merchantName)}</div></div>`,
    );
  }
  $('x-pair').innerHTML = cards.join('');
}

/* ------------------------------------------------------------------ *
 * App shell: tabs, PWA plumbing, wiring
 * ------------------------------------------------------------------ */

type Tab = 'issue' | 'scan' | 'trust' | 'vectors';

function showTab(tab: Tab): void {
  for (const t of ['issue', 'scan', 'trust', 'vectors'] as const) {
    $(`tab-${t}`).hidden = t !== tab;
    $(`nav-${t}`).setAttribute('aria-selected', String(t === tab));
  }
  if (tab !== 'scan') stopCamera();
  if (tab === 'vectors') void renderPair();
  location.hash = tab;
}

function toast(message: string, kind: 'ok' | 'err' = 'ok'): void {
  const el = $('toast');
  el.textContent = message;
  el.className = `toast ${kind}`;
  el.hidden = false;
  window.setTimeout(() => {
    el.hidden = true;
  }, 4200);
}

function registerPwa(): void {
  const pill = $('pill-offline');
  const setOnline = (): void => {
    const online = navigator.onLine;
    const p = $('pill-net');
    p.textContent = online ? 'online' : 'offline';
    p.className = `pill ${online ? '' : 'warn'}`;
  };
  setOnline();
  window.addEventListener('online', setOnline);
  window.addEventListener('offline', setOnline);

  if (!('serviceWorker' in navigator) || !location.protocol.startsWith('http')) {
    pill.textContent = 'not installable here';
    return;
  }
  navigator.serviceWorker
    .register('./sw.js')
    .then((reg) => {
      const mark = (): void => {
        pill.textContent = 'works offline';
        pill.className = 'pill good';
      };
      if (navigator.serviceWorker.controller !== null) mark();
      reg.addEventListener('updatefound', () => {
        reg.installing?.addEventListener('statechange', function () {
          if (this.state === 'activated') mark();
        });
      });
      navigator.serviceWorker.addEventListener('controllerchange', mark);
    })
    .catch(() => {
      pill.textContent = 'offline cache unavailable';
    });

  let installPrompt: (Event & { prompt(): Promise<void> }) | null = null;
  window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    installPrompt = e as Event & { prompt(): Promise<void> };
    $('btn-install').hidden = false;
  });
  $('btn-install').addEventListener('click', () => {
    if (installPrompt !== null) void installPrompt.prompt();
  });
}

async function main(): Promise<void> {
  registerPwa();
  setText('pill-scheme', 'preparing sandbox…');
  const sb = await loadSandbox();
  setText('pill-scheme', `sandbox list v${sb.version}`);
  renderTrust(sb);

  // ----- tabs
  for (const t of ['issue', 'scan', 'trust', 'vectors'] as const) {
    $(`nav-${t}`).addEventListener('click', () => showTab(t));
  }
  const initial = location.hash.replace('#', '');
  showTab(initial === 'scan' || initial === 'trust' || initial === 'vectors' ? initial : 'issue');

  // ----- issue: profile switch
  $('i-profile-a').addEventListener('click', () => {
    $('form-a').hidden = false;
    $('form-b').hidden = true;
    $('i-profile-a').setAttribute('aria-selected', 'true');
    $('i-profile-b').setAttribute('aria-selected', 'false');
  });
  $('i-profile-b').addEventListener('click', () => {
    $('form-a').hidden = true;
    $('form-b').hidden = false;
    $('i-profile-a').setAttribute('aria-selected', 'false');
    $('i-profile-b').setAttribute('aria-selected', 'true');
  });
  const syncKind = (): void => {
    const dynamic = $<HTMLInputElement>('a-kind-dynamic').checked;
    $('a-dynamic-only').hidden = !dynamic;
    $('a-static-note').hidden = dynamic;
  };
  $('a-kind-dynamic').addEventListener('change', syncKind);
  $('a-kind-static').addEventListener('change', syncKind);
  syncKind();

  $('a-issue').addEventListener('click', () => {
    issueA(sb).catch((e: unknown) => toast(e instanceof Error ? e.message : String(e), 'err'));
  });
  $('b-issue').addEventListener('click', () => {
    issueB(sb).catch((e: unknown) => toast(e instanceof Error ? e.message : String(e), 'err'));
  });
  $<HTMLInputElement>('b-file').addEventListener('change', (e) => {
    const file = (e.target as HTMLInputElement).files?.[0];
    if (file !== undefined) void hashFile(file);
  });
  $('i-copy').addEventListener('click', () => {
    void navigator.clipboard.writeText($<HTMLTextAreaElement>('i-payload').value).then(() => toast('Payload copied'));
  });
  $('i-download').addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = $<HTMLCanvasElement>('i-qr').toDataURL('image/png');
    a.download = 'qrseal-code.png';
    a.click();
  });
  $('i-verify').addEventListener('click', () => {
    $<HTMLTextAreaElement>('s-payload').value = $<HTMLTextAreaElement>('i-payload').value;
    showTab('scan');
    void verifyText($<HTMLTextAreaElement>('s-payload').value);
  });

  // ----- scan
  let lastScanned = '';
  // `remember` is false for derived payloads (a flipped character), so that
  // Reset returns to what was actually scanned or pasted.
  const verifyText = async (text: string, remember = true): Promise<void> => {
    if (remember) lastScanned = text;
    $<HTMLTextAreaElement>('s-payload').value = text;
    $('v-result').hidden = false;
    renderTlv(text);
    const t0 = performance.now();
    const now = nowSec();
    let anchor: TrustAnchor;
    let source: string;
    try {
      ({ anchor, source } = await openAnchor(sb, now));
    } catch (error) {
      const reason = error instanceof KhSqrError ? error.reason : 'TRUST_UNAVAILABLE';
      renderOutcome({ kind: 'rejected', profile: 'A', reason: reason as RejectionReason, detail: 'Verification is unavailable: the selected trust state did not open.' }, 'no scheme', performance.now() - t0, sb);
      return;
    }
    const outcome = await classifyScan(text, anchor, now);
    renderOutcome(outcome, source, performance.now() - t0, sb);
  };

  $('s-start').addEventListener('click', () => {
    startCamera((text) => void verifyText(text)).catch((e: unknown) =>
      toast(e instanceof Error ? `Camera unavailable: ${e.message}` : 'Camera unavailable', 'err'),
    );
  });
  $('s-stop').addEventListener('click', stopCamera);
  $<HTMLInputElement>('s-file').addEventListener('change', async (e) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file === undefined) return;
    try {
      const text = await decodeImageFile(file);
      if (text === null) toast('No QR code found in that image', 'err');
      else await verifyText(text);
    } catch {
      toast('Could not read that image', 'err');
    }
    input.value = '';
  });
  $('s-verify').addEventListener('click', () => void verifyText($<HTMLTextAreaElement>('s-payload').value.trim()));
  $('s-flip').addEventListener('click', () => {
    const p = $<HTMLTextAreaElement>('s-payload').value.trim();
    if (p.length < 20) return;
    // Flip one character in the middle of the payload: inside the signed
    // region for every code kind, and inside the CBOR for a credential.
    const i = Math.floor(p.length / 2);
    const c = p[i] as string;
    const swapped = c >= '0' && c <= '8' ? String.fromCharCode(c.charCodeAt(0) + 1) : c === '9' ? '0' : c >= 'A' && c <= 'Y' ? String.fromCharCode(c.charCodeAt(0) + 1) : 'A';
    void verifyText(p.slice(0, i) + swapped + p.slice(i + 1), false);
  });
  $('s-reset').addEventListener('click', () => {
    if (lastScanned.length > 0) void verifyText(lastScanned);
  });
  $('cmp-run').addEventListener('click', () => {
    if (pendingCredential === null) return;
    const observed: PrintedDocumentFields = {
      subjectName: $<HTMLInputElement>('cmp-subjectName').value,
      documentId: $<HTMLInputElement>('cmp-documentId').value,
      issuingOrganisation: $<HTMLInputElement>('cmp-issuingOrganisation').value,
      issueDate: $<HTMLInputElement>('cmp-issueDate').value,
    };
    const check = pendingCredential.compareWithPrintedDocument(observed);
    $('cmp-result').innerHTML =
      `<dl class="disclosure">` +
      check.comparisons
        .map((c) => row(c.field, `${c.matches ? 'matches' : 'DIFFERS'} — signed “${c.signed}”, on paper “${c.observed}”`, { hi: !c.matches }))
        .join('') +
      `</dl>` +
      `<p class="aside">${check.mismatches.length === 0 ? '<b>All four match.</b> The code was issued for a document bearing these fields. Whether the paper in your hand is that document is still your judgement.' : `<b>${check.mismatches.length} field(s) differ.</b> The code was not issued for this document.`}</p>`;
  });

  // ----- trust
  $('t-new-issuer').addEventListener('click', async () => {
    sb.issuers.push(await newIssuer(sb));
    await publish(sb);
    renderTrust(sb);
    setText('pill-scheme', `sandbox list v${sb.version}`);
    toast(`Enrolled ${sb.issuers[sb.issuers.length - 1]?.name ?? 'issuer'}; trust list v${sb.version} published`);
  });
  $('t-revoke').addEventListener('click', async () => {
    const issuer = activeIssuer(sb);
    if (issuer === null) {
      toast('No active issuer key to revoke', 'err');
      return;
    }
    issuer.status = 'revoked';
    await publish(sb);
    renderTrust(sb);
    setText('pill-scheme', `sandbox list v${sb.version}`);
    toast(`${issuer.name} revoked; every code it signed now fails with KEY_REVOKED`);
  });
  $('t-sandbox').addEventListener('click', async (e) => {
    const button = (e.target as HTMLElement).closest<HTMLElement>('[data-withdraw]');
    if (button === null) return;
    const documentId = button.dataset['withdraw'] ?? '';
    await withdraw(sb, documentId);
    renderTrust(sb);
    toast(`${documentId} withdrawn; revocation list v${sb.revocationVersion} signed and declared`);
  });
  $('t-restamp').addEventListener('click', async () => {
    await stamp(sb);
    renderTrust(sb);
    toast('Timestamp statement re-signed');
  });
  $('t-reset').addEventListener('click', async () => {
    if (!window.confirm('Discard this sandbox, its keys and its trust list?')) return;
    localStorage.removeItem(SANDBOX_KEY);
    localStorage.removeItem(IMPORTED_KEY);
    localStorage.removeItem(VERIFY_AGAINST_KEY);
    location.reload();
  });
  $('t-export').addEventListener('click', () => {
    const text = exportBundle(sb);
    $<HTMLTextAreaElement>('t-bundle').value = text;
    void navigator.clipboard.writeText(text).then(() => toast('Scheme bundle copied — paste it into the other device’s Trust tab'));
  });
  $('t-download').addEventListener('click', () => {
    const blob = new Blob([exportBundle(sb)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'qrseal-scheme-bundle.json';
    a.click();
  });
  $('t-import').addEventListener('click', async () => {
    try {
      const scheme = await importBundle($<HTMLTextAreaElement>('t-bundle').value);
      renderTrust(sb);
      toast(`Imported “${scheme.name}”; verifying against it now`);
    } catch (error) {
      toast(error instanceof KhSqrError ? `Bundle rejected: ${error.reason}` : error instanceof Error ? error.message : 'Import failed', 'err');
    }
  });
  $<HTMLInputElement>('t-import-file').addEventListener('change', async (e) => {
    const input = e.target as HTMLInputElement;
    const file = input.files?.[0];
    if (file === undefined) return;
    $<HTMLTextAreaElement>('t-bundle').value = await file.text();
    input.value = '';
  });
  $('t-forget').addEventListener('click', () => {
    localStorage.removeItem(IMPORTED_KEY);
    localStorage.setItem(VERIFY_AGAINST_KEY, 'sandbox');
    renderTrust(sb);
  });
  for (const which of ['sandbox', 'imported'] as const) {
    $(`t-against-${which}`).addEventListener('change', () => {
      localStorage.setItem(VERIFY_AGAINST_KEY, which);
      renderTrust(sb);
    });
  }

  // ----- vectors
  $('x-run').addEventListener('click', () => void runSuite());
}

main().catch((error: unknown) => {
  const el = document.getElementById('toast');
  if (el !== null) {
    el.textContent = `This browser cannot run the sandbox: ${error instanceof Error ? error.message : String(error)}`;
    el.className = 'toast err';
    el.hidden = false;
  }
});
