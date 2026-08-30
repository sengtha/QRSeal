/**
 * The Profile B result exists to make the transplant attack impossible to
 * ignore. These tests pin that API shape, because a well-meaning refactor that
 * adds a convenience boolean would silently remove the only defence.
 */

import { describe, expect, it } from 'vitest';

import { UrlPayloadRejectedError } from '../src/errors.js';
import type { CredentialAssertion} from '../src/profileB.js';
import { assertNotUrlCarrier, verifyProfileB } from '../src/profileB.js';
import { anchorFor, suite } from './support/anchors.js';

const vector = suite.cases.find((c) => c.id === 'B-accept-published-reference')!;

async function assertion(): Promise<CredentialAssertion> {
  return verifyProfileB({
    payload: vector.input['payload'] as string,
    trustAnchor: await anchorFor(vector.state),
    now: vector.state.now,
  });
}

describe('CredentialAssertion', () => {
  it('exposes no boolean or isValid accessor', async () => {
    const result = await assertion();
    const names = new Set([
      ...Object.keys(result),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(result) as object),
    ]);
    expect(names.has('isValid')).toBe(false);
    expect(names.has('valid')).toBe(false);
    expect(names.has('verified')).toBe(false);
    for (const name of names) {
      expect(typeof (result as unknown as Record<string, unknown>)[name]).not.toBe('boolean');
    }
  });

  it('surfaces the four fields that must be read off the document', async () => {
    const result = await assertion();
    expect(result.mustMatchPrintedDocument).toEqual({
      subjectName: 'CHAY SOPHEA',
      documentId: 'RUPP-2026-004821',
      issuingOrganisation: 'Royal University of Phnom Penh',
      issueDate: '2026-07-15',
    });
    expect(result.documentHash).toBe('3108aa7d48933e51b68cf9366bb7c32c');
    expect(result.issuer).toBe('kh.gov.mptc.moeys');
  });

  it('reports a clean comparison when the document matches', async () => {
    const result = await assertion();
    const check = result.compareWithPrintedDocument(result.mustMatchPrintedDocument);
    expect(check.mismatches).toHaveLength(0);
    expect(check.comparisons).toHaveLength(4);
  });

  it('catches a transplanted code: genuine signature, different name on the paper', async () => {
    const result = await assertion();
    const check = result.compareWithPrintedDocument({
      ...result.mustMatchPrintedDocument,
      subjectName: 'SOK PISETH',
    });
    expect(check.mismatches.map((m) => m.field)).toEqual(['subjectName']);
    expect(check.mismatches[0]?.signed).toBe('CHAY SOPHEA');
    expect(check.mismatches[0]?.observed).toBe('SOK PISETH');
  });

  it('treats a case difference as a real difference', async () => {
    const result = await assertion();
    const check = result.compareWithPrintedDocument({
      ...result.mustMatchPrintedDocument,
      subjectName: 'Chay Sophea',
    });
    expect(check.mismatches).toHaveLength(1);
  });

  it('ignores surrounding whitespace, which a scanner adds and a document does not', async () => {
    const result = await assertion();
    const check = result.compareWithPrintedDocument({
      ...result.mustMatchPrintedDocument,
      documentId: '  RUPP-2026-004821 ',
    });
    expect(check.mismatches).toHaveLength(0);
  });
});

describe('URL carriers', () => {
  it.each([
    'https://verify.example.gov.kh/c/1',
    'http://verify.example.gov.kh/c/1',
    'HTTPS://VERIFY.EXAMPLE.GOV.KH',
    '  https://leading-whitespace.example ',
  ])('rejects %o', (payload) => {
    expect(() => assertNotUrlCarrier(payload)).toThrow(UrlPayloadRejectedError);
  });

  it('accepts a KH-SQR payload', () => {
    expect(() => assertNotUrlCarrier('KH1:NCFOXN%TSMAHN')).not.toThrow();
  });
});
