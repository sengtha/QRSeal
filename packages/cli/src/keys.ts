/**
 * Key loading for the command line.
 *
 * PEM in, `CryptoKey` out. Private keys are read from PKCS#8, which is what
 * `openssl pkcs8` and every HSM export tool produces, and are only ever loaded
 * by the signing commands — the verifying commands cannot take one.
 */

import { readFileSync } from 'node:fs';

const PEM_BODY = /-----BEGIN [^-]+-----([A-Za-z0-9+/=\s]+)-----END [^-]+-----/;

function derFromPem(pem: string, label: string): Uint8Array<ArrayBuffer> {
  const match = PEM_BODY.exec(pem);
  if (match === null) throw new Error(`${label} is not a PEM block`);
  const decoded = Buffer.from((match[1] as string).replace(/\s+/g, ''), 'base64');
  // Copy into an array buffer TypeScript knows is not shared, which is what
  // Web Crypto's BufferSource requires.
  const der = new Uint8Array(decoded.byteLength);
  der.set(decoded);
  return der;
}

export async function loadPrivateKey(path: string): Promise<CryptoKey> {
  const der = derFromPem(readFileSync(path, 'utf8'), path);
  try {
    return await crypto.subtle.importKey('pkcs8', der, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  } catch {
    throw new Error(`${path} is not a PKCS#8 P-256 private key`);
  }
}

export interface PublicKeyMaterial {
  readonly x: string;
  readonly y: string;
  readonly kid: string;
  readonly uncompressedPoint: Uint8Array;
}

export async function loadPublicKey(path: string): Promise<PublicKeyMaterial> {
  const der = derFromPem(readFileSync(path, 'utf8'), path);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey('spki', der, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
  } catch {
    throw new Error(`${path} is not an SPKI P-256 public key`);
  }
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', key));
  const hex = (bytes: Uint8Array): string =>
    [...bytes].map((b) => b.toString(16).toUpperCase().padStart(2, '0')).join('');
  const digest = await crypto.subtle.digest('SHA-256', raw as BufferSource);
  return {
    x: hex(raw.subarray(1, 33)),
    y: hex(raw.subarray(33, 65)),
    kid: hex(new Uint8Array(digest).subarray(0, 8)),
    uncompressedPoint: raw,
  };
}

/** Read a value that is either a literal or, with a leading `@`, a file path. */
export function literalOrFile(value: string): string {
  return value.startsWith('@') ? readFileSync(value.slice(1), 'utf8').trim() : value;
}

export function readJsonFile<T>(path: string): T {
  return JSON.parse(readFileSync(path, 'utf8')) as T;
}
