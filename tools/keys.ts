/**
 * P-256 helpers for tooling and test-vector generation.
 *
 * NOT part of `@kh-sqr/core`. The core library is Web Crypto only; Web Crypto
 * cannot import a bare private scalar, so this file does the one scalar
 * multiplication needed to turn a published test scalar into a JWK. Keeping it
 * out of the package means the shipped verification path stays dependency-free
 * and no elliptic-curve arithmetic of ours is ever on it.
 */

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const A = P - 3n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
/** Order of the base point. */
export const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

type Point = readonly [bigint, bigint] | null;

const mod = (x: bigint): bigint => ((x % P) + P) % P;

function inverse(x: bigint): bigint {
  let result = 1n;
  let base = mod(x);
  let exponent = P - 2n;
  while (exponent > 0n) {
    if ((exponent & 1n) === 1n) result = mod(result * base);
    base = mod(base * base);
    exponent >>= 1n;
  }
  return result;
}

function addPoints(p: Point, q: Point): Point {
  if (p === null) return q;
  if (q === null) return p;
  const [x1, y1] = p;
  const [x2, y2] = q;
  if (x1 === x2 && mod(y1 + y2) === 0n) return null;
  const lambda = x1 === x2 && y1 === y2
    ? mod(mod(3n * x1 * x1 + A) * inverse(mod(2n * y1)))
    : mod(mod(y2 - y1) * inverse(mod(x2 - x1)));
  const x3 = mod(lambda * lambda - x1 - x2);
  return [x3, mod(lambda * (x1 - x3) - y1)];
}

function multiply(k: bigint, point: Point): Point {
  let result: Point = null;
  let addend: Point = point;
  let scalar = k;
  while (scalar > 0n) {
    if ((scalar & 1n) === 1n) result = addPoints(result, addend);
    addend = addPoints(addend, addend);
    scalar >>= 1n;
  }
  return result;
}

const hex64 = (value: bigint): string => value.toString(16).toUpperCase().padStart(64, '0');

export interface TestKeyPair {
  readonly scalarHex: string;
  readonly x: string;
  readonly y: string;
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly publicPem: string;
}

const b64url = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function toPem(x: string, y: string): string {
  const spki = Buffer.concat([
    Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'),
    Buffer.from(`04${x}${y}`, 'hex'),
  ]);
  const body = (spki.toString('base64').match(/.{1,64}/g) ?? []).join('\n');
  return `-----BEGIN PUBLIC KEY-----\n${body}\n-----END PUBLIC KEY-----`;
}

/** Derive the full key material and an importable private key from a scalar. */
export async function keyPairFromScalar(scalarHex: string): Promise<TestKeyPair> {
  const d = BigInt(`0x${scalarHex}`);
  if (d <= 0n || d >= N) throw new RangeError('scalar is out of range for P-256');
  const point = multiply(d, [GX, GY]);
  if (point === null) throw new RangeError('scalar multiplication produced the point at infinity');
  const [x, y] = point;
  if (mod(y * y) !== mod(x * x * x + A * x + B)) throw new Error('derived point is not on the curve');

  const xHex = hex64(x);
  const yHex = hex64(y);
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    {
      kty: 'EC',
      crv: 'P-256',
      d: b64url(Buffer.from(scalarHex.padStart(64, '0'), 'hex')),
      x: b64url(Buffer.from(xHex, 'hex')),
      y: b64url(Buffer.from(yHex, 'hex')),
      ext: true,
    },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign'],
  );

  const digest = await crypto.subtle.digest('SHA-256', Buffer.from(`04${xHex}${yHex}`, 'hex'));
  const kid = Buffer.from(new Uint8Array(digest).subarray(0, 8)).toString('hex').toUpperCase();

  return { scalarHex, x: xHex, y: yHex, kid, privateKey, publicPem: toPem(xHex, yHex) };
}

/**
 * Derive a reproducible test scalar from a label.
 *
 * Test keys are generated from published labels so that anyone can regenerate
 * the entire conformance suite from this repository alone. They have no
 * security value and must never be used outside testing.
 */
export async function scalarFromLabel(label: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(label));
  let value = BigInt(`0x${Buffer.from(new Uint8Array(digest)).toString('hex')}`) % (N - 1n);
  if (value === 0n) value = 1n;
  return value.toString(16).toUpperCase().padStart(64, '0');
}
