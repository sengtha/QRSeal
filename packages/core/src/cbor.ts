/**
 * A minimal CBOR encoder and decoder covering only the shapes KH-SQR uses:
 * unsigned and negative integers, byte strings, text strings, arrays, maps,
 * and the COSE_Sign1 tag.
 *
 * Why not a library: a general CBOR implementation is a large audit surface on
 * a security-critical path, and this payload complexity does not need one. The
 * decoder is deliberately strict — definite lengths only, minimal integer
 * encodings only, no floats, no simple values, no indefinite-length strings —
 * because every construct accepted is a construct an attacker may use to make
 * two parsers disagree about the same bytes. Fuzzed against a reference
 * implementation in CI.
 *
 * Dependency note: Profile A must NOT reach this module.
 */

import { CborInvalidError } from './errors.js';

export type CborKey = number | string;
export type CborValue = number | string | Uint8Array | CborValue[] | CborMap | CborTagged;
export type CborMap = Map<CborKey, CborValue>;
export interface CborTagged {
  readonly tag: number;
  readonly value: CborValue;
}

const MT_UNSIGNED = 0;
const MT_NEGATIVE = 1;
const MT_BYTES = 2;
const MT_TEXT = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_TAG = 6;

/** Largest integer this codec will encode or accept, keeping everything in the safe range. */
const MAX_SAFE = Number.MAX_SAFE_INTEGER;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { fatal: true });

export function isCborTagged(value: CborValue): value is CborTagged {
  return typeof value === 'object' && value !== null && !Array.isArray(value) &&
    !(value instanceof Uint8Array) && !(value instanceof Map) &&
    typeof (value as CborTagged).tag === 'number';
}

/* ------------------------------------------------------------------ *
 * Encoder
 * ------------------------------------------------------------------ */

class Writer {
  private chunks: number[] = [];

  public byte(value: number): void {
    this.chunks.push(value & 0xff);
  }

  public bytes(value: Uint8Array): void {
    for (const b of value) this.chunks.push(b);
  }

  /** Write a major type and argument using the shortest legal form. */
  public head(major: number, argument: number): void {
    if (!Number.isSafeInteger(argument) || argument < 0) {
      throw new CborInvalidError('argument is not a non-negative safe integer');
    }
    const base = major << 5;
    if (argument < 24) this.byte(base | argument);
    else if (argument <= 0xff) { this.byte(base | 24); this.byte(argument); }
    else if (argument <= 0xffff) { this.byte(base | 25); this.byte(argument >>> 8); this.byte(argument); }
    else if (argument <= 0xffffffff) {
      this.byte(base | 26);
      this.byte(argument >>> 24); this.byte(argument >>> 16); this.byte(argument >>> 8); this.byte(argument);
    } else {
      this.byte(base | 27);
      const high = Math.floor(argument / 0x1_0000_0000);
      const low = argument >>> 0 === argument ? argument : argument - high * 0x1_0000_0000;
      this.byte(high >>> 24); this.byte(high >>> 16); this.byte(high >>> 8); this.byte(high);
      this.byte(low >>> 24); this.byte(low >>> 16); this.byte(low >>> 8); this.byte(low);
    }
  }

  public result(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

function writeValue(writer: Writer, value: CborValue): void {
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new CborInvalidError('only safe integers are supported');
    if (value >= 0) writer.head(MT_UNSIGNED, value);
    else writer.head(MT_NEGATIVE, -1 - value);
    return;
  }
  if (typeof value === 'string') {
    const encoded = textEncoder.encode(value);
    writer.head(MT_TEXT, encoded.length);
    writer.bytes(encoded);
    return;
  }
  if (value instanceof Uint8Array) {
    writer.head(MT_BYTES, value.length);
    writer.bytes(value);
    return;
  }
  if (Array.isArray(value)) {
    writer.head(MT_ARRAY, value.length);
    for (const item of value) writeValue(writer, item);
    return;
  }
  if (value instanceof Map) {
    writer.head(MT_MAP, value.size);
    // Insertion order is preserved deliberately. The signature covers the
    // payload bytes exactly as produced, and the decoder never re-encodes, so
    // no party ever needs to agree on a key ordering.
    for (const [key, item] of value) {
      writeValue(writer, key);
      writeValue(writer, item);
    }
    return;
  }
  if (isCborTagged(value)) {
    writer.head(MT_TAG, value.tag);
    writeValue(writer, value.value);
    return;
  }
  throw new CborInvalidError('unsupported value type');
}

export function encodeCbor(value: CborValue): Uint8Array {
  const writer = new Writer();
  writeValue(writer, value);
  return writer.result();
}

/* ------------------------------------------------------------------ *
 * Decoder
 * ------------------------------------------------------------------ */

interface Decoded {
  readonly value: CborValue;
  readonly next: number;
}

function readHead(data: Uint8Array, at: number): { major: number; argument: number; next: number } {
  if (at >= data.length) throw new CborInvalidError('truncated input');
  const initial = data[at] as number;
  const major = initial >> 5;
  const info = initial & 0x1f;
  let argument: number;
  let next = at + 1;

  const need = (count: number): void => {
    if (next + count > data.length) throw new CborInvalidError('truncated integer argument');
  };

  if (info < 24) {
    argument = info;
  } else if (info === 24) {
    need(1);
    argument = data[next] as number;
    next += 1;
    if (argument < 24) throw new CborInvalidError('non-minimal integer encoding');
  } else if (info === 25) {
    need(2);
    argument = ((data[next] as number) << 8) | (data[next + 1] as number);
    next += 2;
    if (argument <= 0xff) throw new CborInvalidError('non-minimal integer encoding');
  } else if (info === 26) {
    need(4);
    argument = ((data[next] as number) * 0x100_0000) + ((data[next + 1] as number) << 16) +
      ((data[next + 2] as number) << 8) + (data[next + 3] as number);
    next += 4;
    if (argument <= 0xffff) throw new CborInvalidError('non-minimal integer encoding');
  } else if (info === 27) {
    need(8);
    let high = 0;
    for (let i = 0; i < 4; i += 1) high = high * 256 + (data[next + i] as number);
    let low = 0;
    for (let i = 4; i < 8; i += 1) low = low * 256 + (data[next + i] as number);
    argument = high * 0x1_0000_0000 + low;
    next += 8;
    if (argument <= 0xffffffff) throw new CborInvalidError('non-minimal integer encoding');
    if (argument > MAX_SAFE) throw new CborInvalidError('integer exceeds the safe integer range');
  } else if (info === 31) {
    throw new CborInvalidError('indefinite-length items are not accepted');
  } else {
    throw new CborInvalidError('reserved additional information value');
  }

  return { major, argument, next };
}

function readValue(data: Uint8Array, at: number, depth: number): Decoded {
  if (depth > 8) throw new CborInvalidError('nesting is deeper than this profile permits');
  const { major, argument, next } = readHead(data, at);

  switch (major) {
    case MT_UNSIGNED:
      return { value: argument, next };
    case MT_NEGATIVE:
      return { value: -1 - argument, next };
    case MT_BYTES: {
      if (next + argument > data.length) throw new CborInvalidError('truncated byte string');
      return { value: data.slice(next, next + argument), next: next + argument };
    }
    case MT_TEXT: {
      if (next + argument > data.length) throw new CborInvalidError('truncated text string');
      let text: string;
      try {
        text = textDecoder.decode(data.subarray(next, next + argument));
      } catch {
        throw new CborInvalidError('text string is not well-formed UTF-8');
      }
      return { value: text, next: next + argument };
    }
    case MT_ARRAY: {
      const items: CborValue[] = [];
      let cursor = next;
      for (let i = 0; i < argument; i += 1) {
        const item = readValue(data, cursor, depth + 1);
        items.push(item.value);
        cursor = item.next;
      }
      return { value: items, next: cursor };
    }
    case MT_MAP: {
      const map: CborMap = new Map();
      let cursor = next;
      for (let i = 0; i < argument; i += 1) {
        const key = readValue(data, cursor, depth + 1);
        if (typeof key.value !== 'number' && typeof key.value !== 'string') {
          throw new CborInvalidError('map keys must be integers or text strings');
        }
        if (map.has(key.value)) throw new CborInvalidError('duplicate map key');
        const item = readValue(data, key.next, depth + 1);
        map.set(key.value, item.value);
        cursor = item.next;
      }
      return { value: map, next: cursor };
    }
    case MT_TAG: {
      const inner = readValue(data, next, depth + 1);
      return { value: { tag: argument, value: inner.value }, next: inner.next };
    }
    default:
      throw new CborInvalidError('floating point and simple values are not accepted');
  }
}

/** Decode exactly one CBOR item, rejecting trailing bytes. */
export function decodeCbor(data: Uint8Array): CborValue {
  const { value, next } = readValue(data, 0, 0);
  if (next !== data.length) throw new CborInvalidError('trailing bytes after the top-level item');
  return value;
}
