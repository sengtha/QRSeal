/**
 * EMVCo merchant-presented QR: TLV parse/serialise and CRC-16/CCITT-FALSE.
 *
 * Dependency note: Web Crypto only (in fact, nothing but string arithmetic).
 * Must not import CBOR or any stream API — see tools/check-profile-a-isolation.ts.
 */

import {
  CrcMalformedError,
  CrcMismatchError,
  CrcMissingError,
  DuplicateTagError,
  MalformedTlvError,
  SignatureTemplateNotLastError,
} from './errors.js';
import { constantTimeEqual } from './hex.js';

/** Tag carrying the CRC. Always the last data object, always length 04. */
export const CRC_TAG = '63';
/** Tag carrying the KH-SQR signature template, from the EMVCo unreserved range 80-99. */
export const SIGNATURE_TEMPLATE_TAG = '85';
/** Tag carrying the transaction amount. Forbidden on static codes. */
export const AMOUNT_TAG = '54';
/** Point of Initiation Method. '11' = static (reusable), '12' = dynamic (one-shot). */
export const POI_METHOD_TAG = '01';

export const POI_STATIC = '11';
export const POI_DYNAMIC = '12';

/**
 * Template 85 declares its length in three decimal digits rather than EMVCo's
 * two, because its content exceeds 99 characters once a 128-character
 * signature is inside it. This is a deliberate, documented deviation from
 * EMVCo's length encoding — see SPEC.md section "Length encoding and legacy
 * transparency", which also records that it costs the template its
 * transparency to a strict legacy parser.
 */
export const EXTENDED_LENGTH_TAGS: ReadonlySet<string> = new Set([SIGNATURE_TEMPLATE_TAG]);

export interface DataObject {
  /** Two-character tag. */
  readonly tag: string;
  /** The value, excluding tag and length characters. */
  readonly value: string;
  /** Index of the first character of the tag within the payload. */
  readonly start: number;
  /** Index one past the last character of the value. */
  readonly end: number;
  /** Number of characters used by the length declaration (2, or 3 for extended-length tags). */
  readonly lengthDigits: number;
}

const DIGITS = /^[0-9]+$/;
const HEX4 = /^[0-9A-F]{4}$/;

/**
 * CRC-16/CCITT-FALSE over the ASCII octets of `data`.
 *
 * Polynomial 0x1021, initial value 0xFFFF, no input or output reflection, no
 * final XOR. Returned as four uppercase hexadecimal characters.
 */
export function crc16CcittFalse(data: string): string {
  let crc = 0xffff;
  for (let i = 0; i < data.length; i += 1) {
    const code = data.charCodeAt(i);
    if (code > 0xff) throw new RangeError('CRC input must be single-octet characters');
    crc ^= code << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc & 0x8000) !== 0 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc.toString(16).toUpperCase().padStart(4, '0');
}

/** Serialise one data object with a two-digit length. */
export function serialiseDataObject(tag: string, value: string): string {
  if (tag.length !== 2 || !DIGITS.test(tag)) throw new RangeError('tag must be two digits');
  if (value.length > 99) {
    throw new RangeError(`value for tag ${tag} exceeds the two-digit EMVCo length maximum`);
  }
  return tag + String(value.length).padStart(2, '0') + value;
}

/** Serialise one data object with the KH-SQR three-digit extended length. */
export function serialiseExtendedDataObject(tag: string, value: string): string {
  if (tag.length !== 2 || !DIGITS.test(tag)) throw new RangeError('tag must be two digits');
  if (value.length > 999) throw new RangeError(`value for tag ${tag} exceeds 999 characters`);
  return tag + String(value.length).padStart(3, '0') + value;
}

export interface ParseOptions {
  /**
   * Tags whose length declaration occupies three digits instead of two.
   * Defaults to the KH-SQR set (`85`).
   */
  readonly extendedLengthTags?: ReadonlySet<string>;
  /**
   * When set, the content of this tag is taken to run to `boundary` rather
   * than to its declared length. This implements the fixed-offset rule: the
   * signature template's extent is determined by position, not by a length
   * field. See SPEC.md.
   */
  readonly lengthAgnosticTag?: string;
  /** Index at which a `lengthAgnosticTag` object's content ends. */
  readonly boundary?: number;
}

/**
 * Walk a payload as a flat sequence of EMVCo data objects.
 *
 * Rejects a payload whose objects do not tile the input exactly.
 */
export function parseDataObjects(payload: string, options: ParseOptions = {}): DataObject[] {
  const extended = options.extendedLengthTags ?? EXTENDED_LENGTH_TAGS;
  const objects: DataObject[] = [];
  const seen = new Set<string>();
  let pos = 0;

  while (pos < payload.length) {
    if (payload.length - pos < 4) throw new MalformedTlvError('trailing characters are too short to form a data object');
    const tag = payload.slice(pos, pos + 2);
    if (!DIGITS.test(tag)) throw new MalformedTlvError('tag is not two decimal digits');
    if (seen.has(tag)) throw new DuplicateTagError(`tag ${tag} appears more than once at this level`);
    seen.add(tag);

    const lengthDigits = extended.has(tag) ? 3 : 2;
    const lengthText = payload.slice(pos + 2, pos + 2 + lengthDigits);
    if (lengthText.length !== lengthDigits || !DIGITS.test(lengthText)) {
      throw new MalformedTlvError(`length for tag ${tag} is not ${lengthDigits} decimal digits`);
    }

    const contentStart = pos + 2 + lengthDigits;
    let contentEnd: number;
    if (options.lengthAgnosticTag === tag && options.boundary !== undefined) {
      contentEnd = options.boundary;
      if (contentEnd < contentStart) throw new MalformedTlvError(`tag ${tag} extends past its boundary`);
    } else {
      contentEnd = contentStart + Number.parseInt(lengthText, 10);
    }
    if (contentEnd > payload.length) throw new MalformedTlvError(`tag ${tag} declares a length past the end of the payload`);

    objects.push({ tag, value: payload.slice(contentStart, contentEnd), start: pos, end: contentEnd, lengthDigits });
    pos = contentEnd;
  }

  return objects;
}

/** Merchant Account Information templates occupy this range; sub-tag 00 is the GUID. */
export const MERCHANT_ACCOUNT_TEMPLATE_MIN = 26;
export const MERCHANT_ACCOUNT_TEMPLATE_MAX = 51;
export const MERCHANT_ACCOUNT_GUID_SUBTAG = '00';

/**
 * The identifier at sub-tag 00 of each merchant-account template, in payload
 * order. A template whose value does not parse as sub-objects, or has no
 * sub-tag 00, yields null: it names no acquirer a verifier could bind to.
 */
export function merchantAccountIdentifiers(
  objects: readonly DataObject[],
): { readonly tag: string; readonly guid: string | null }[] {
  return objects
    .filter((o) => Number(o.tag) >= MERCHANT_ACCOUNT_TEMPLATE_MIN && Number(o.tag) <= MERCHANT_ACCOUNT_TEMPLATE_MAX)
    .map((o) => {
      try {
        const sub = parseDataObjects(o.value, { extendedLengthTags: new Set() });
        return { tag: o.tag, guid: findObject(sub, MERCHANT_ACCOUNT_GUID_SUBTAG)?.value ?? null };
      } catch {
        return { tag: o.tag, guid: null };
      }
    });
}

/** Look up a single object by tag. */
export function findObject(objects: readonly DataObject[], tag: string): DataObject | undefined {
  return objects.find((o) => o.tag === tag);
}

export interface EmvcoEnvelope {
  /** Every top-level data object, in payload order, including the CRC object. */
  readonly objects: readonly DataObject[];
  /** The CRC value as it appears in the payload. */
  readonly declaredCrc: string;
  /** The CRC recomputed over everything up to and including `6304`. */
  readonly computedCrc: string;
  /** Index of the first character of the trailing `6304` header. */
  readonly crcStart: number;
}

/**
 * Structural parse of a complete EMVCo payload, CRC included and checked.
 *
 * `signatureTemplateLengthAgnostic` implements the verifier half of the
 * decision recorded in SPEC.md: template 85's declared length is not trusted,
 * because the signature's position, not any length field, defines the signed
 * region. Any tampering with that length still breaks the signature, since the
 * length characters fall inside the signed prefix.
 */
export function parseEmvcoPayload(
  payload: string,
  options: { readonly signatureTemplateLengthAgnostic?: boolean } = {},
): EmvcoEnvelope {
  if (payload.length < 8) throw new MalformedTlvError('payload is too short to contain a CRC');
  const crcStart = payload.length - 8;
  if (payload.slice(crcStart, crcStart + 4) !== `${CRC_TAG}04`) {
    throw new CrcMissingError();
  }
  const declaredCrc = payload.slice(crcStart + 4);
  if (!HEX4.test(declaredCrc)) throw new CrcMalformedError();

  const parseOptions: ParseOptions = options.signatureTemplateLengthAgnostic === true
    ? { lengthAgnosticTag: SIGNATURE_TEMPLATE_TAG, boundary: crcStart }
    : {};
  const objects = parseDataObjects(payload, parseOptions);

  const last = objects.at(-1);
  if (last === undefined || last.tag !== CRC_TAG) {
    throw new CrcMissingError('the CRC object is not the final data object');
  }

  const computedCrc = crc16CcittFalse(payload.slice(0, crcStart + 4));
  if (!constantTimeEqual(computedCrc, declaredCrc)) throw new CrcMismatchError();

  return { objects, declaredCrc, computedCrc, crcStart };
}

/**
 * Assert that the signature template is the last data object before the CRC.
 *
 * The rule exists so that the signed region is a plain prefix of the payload.
 * A verifier that skipped this check would accept a payload with data objects
 * appended after the signature, outside the signed region.
 */
export function assertSignatureTemplateIsLast(objects: readonly DataObject[]): DataObject {
  const index = objects.findIndex((o) => o.tag === SIGNATURE_TEMPLATE_TAG);
  if (index === -1) throw new SignatureTemplateNotLastError('template 85 is absent');
  if (index !== objects.length - 2) throw new SignatureTemplateNotLastError();
  return objects[index] as DataObject;
}

/** Append a CRC object to a payload that does not yet carry one. */
export function appendCrc(payloadWithoutCrc: string): string {
  const withHeader = `${payloadWithoutCrc}${CRC_TAG}04`;
  return withHeader + crc16CcittFalse(withHeader);
}

/** Remove a trailing CRC object if present, returning the bare payload. */
export function stripCrc(payload: string): string {
  if (payload.length >= 8 && payload.slice(-8, -4) === `${CRC_TAG}04`) return payload.slice(0, -8);
  return payload;
}
