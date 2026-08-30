/**
 * Runs vectors/vectors.json in both directions: every `verify` case against
 * the recorded payload, and every `roundtrip` case by signing first and then
 * verifying this implementation's own output.
 */

import { describe, expect, it } from 'vitest';

import { KhSqrError } from '../src/errors.js';
import { signProfileA, verifyProfileA } from '../src/profileA.js';
import { signProfileB, verifyProfileB, type CredentialClaims } from '../src/profileB.js';
import { keyPairFromScalar } from '../../../tools/keys.ts';
import { anchorFor, suite, type VectorCase } from './support/anchors.js';

async function runVerify(vector: VectorCase): Promise<unknown> {
  const trustAnchor = await anchorFor(vector.state);
  const payload = vector.input['payload'] as string;
  return vector.profile === 'A'
    ? verifyProfileA({ payload, trustAnchor, now: vector.state.now })
    : verifyProfileB({ payload, trustAnchor, now: vector.state.now });
}

async function runRoundtrip(vector: VectorCase): Promise<unknown> {
  const key = await keyPairFromScalar(vector.input['issuerScalar'] as string);
  const trustAnchor = await anchorFor(vector.state);

  if (vector.profile === 'A') {
    const expiresAt = vector.input['expiresAt'] as number | undefined;
    const signed = await signProfileA({
      payload: vector.input['base'] as string,
      privateKey: key.privateKey,
      kid: vector.input['kid'] as string,
      issuedAt: vector.input['issuedAt'] as number,
      ...(expiresAt === undefined ? {} : { expiresAt }),
      payeeClass: vector.input['payeeClass'] as 'M' | 'I',
    });
    return verifyProfileA({ payload: signed.payload, trustAnchor, now: vector.state.now });
  }

  const payload = await signProfileB({
    privateKey: key.privateKey,
    kid: vector.input['kid'] as string,
    claims: vector.input['claims'] as CredentialClaims,
  });
  return verifyProfileB({ payload, trustAnchor, now: vector.state.now });
}

describe('conformance suite', () => {
  it('contains more negative cases than positive ones', () => {
    const negative = suite.cases.filter((c) => c.expect === 'reject').length;
    expect(negative).toBeGreaterThan(suite.cases.length - negative);
  });

  for (const vector of suite.cases) {
    it(`${vector.id}: ${vector.description.slice(0, 90)}`, async () => {
      const run = vector.type === 'verify' ? runVerify : runRoundtrip;

      if (vector.expect === 'accept') {
        const result = (await run(vector)) as Record<string, unknown>;
        if (vector.accepted !== undefined) {
          for (const [field, expected] of Object.entries(vector.accepted)) {
            expect(readField(result, field), `${vector.id} field ${field}`).toEqual(expected);
          }
        }
        return;
      }

      let thrown: unknown;
      try {
        await run(vector);
      } catch (error) {
        thrown = error;
      }
      expect(thrown, `${vector.id} was expected to be rejected`).toBeInstanceOf(KhSqrError);
      if (vector.reason !== null) {
        expect((thrown as KhSqrError).reason).toBe(vector.reason);
      }
    });
  }
});

/** Read a dotted-or-flat field name out of an attestation of either profile. */
function readField(result: Record<string, unknown>, field: string): unknown {
  if (field in result) return result[field];
  const container = result['container'] as Record<string, unknown> | undefined;
  if (container !== undefined && field in container) return container[field];
  const disclosure = result['payeeDisclosure'] as Record<string, unknown> | undefined;
  if (disclosure !== undefined && field in disclosure) return disclosure[field];
  const printed = result['mustMatchPrintedDocument'] as Record<string, unknown> | undefined;
  if (printed !== undefined && field in printed) return printed[field];
  return undefined;
}
