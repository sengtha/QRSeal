/**
 * The verification path must never reach the network.
 *
 * A verifier that fetches during verification can be stalled or steered by
 * whoever controls the network at the moment of payment — which, at a market
 * stall, is not a trustworthy party. Everything a verification needs is
 * supplied by the caller in a TrustAnchor.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { verifyProfileA } from '../src/profileA.js';
import { verifyProfileB } from '../src/profileB.js';
import { anchorFor, suite } from './support/anchors.js';

const NETWORK_GLOBALS = ['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource'] as const;

describe('verification performs no network access', () => {
  const originals = new Map<string, unknown>();

  beforeEach(() => {
    for (const name of NETWORK_GLOBALS) {
      const target = globalThis as unknown as Record<string, unknown>;
      originals.set(name, target[name]);
      target[name] = vi.fn(() => {
        throw new Error(`verification path called ${name}`);
      });
    }
  });

  afterEach(() => {
    const target = globalThis as unknown as Record<string, unknown>;
    for (const [name, value] of originals) target[name] = value;
    originals.clear();
  });

  it('verifies Profile A with every network global poisoned', async () => {
    const vector = suite.cases.find((c) => c.id === 'A-accept-published-reference');
    expect(vector).toBeDefined();
    const trustAnchor = await anchorFor(vector!.state);
    const result = await verifyProfileA({
      payload: vector!.input['payload'] as string,
      trustAnchor,
      now: vector!.state.now,
    });
    expect(result.kid).toBe('27403764C95F4F5B');
    for (const name of NETWORK_GLOBALS) {
      expect((globalThis as unknown as Record<string, { mock: { calls: unknown[] } }>)[name]?.mock.calls).toHaveLength(0);
    }
  });

  it('verifies Profile B with every network global poisoned', async () => {
    const vector = suite.cases.find((c) => c.id === 'B-accept-published-reference');
    expect(vector).toBeDefined();
    const trustAnchor = await anchorFor(vector!.state);
    const result = await verifyProfileB({
      payload: vector!.input['payload'] as string,
      trustAnchor,
      now: vector!.state.now,
    });
    expect(result.mustMatchPrintedDocument.subjectName).toBe('CHAY SOPHEA');
    for (const name of NETWORK_GLOBALS) {
      expect((globalThis as unknown as Record<string, { mock: { calls: unknown[] } }>)[name]?.mock.calls).toHaveLength(0);
    }
  });
});
