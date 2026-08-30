/**
 * Shared helpers for building a TrustAnchor out of the conformance suite's
 * recorded trust-list state.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { TrustAnchor } from '../../src/trustlist.js';

const HERE = dirname(fileURLToPath(import.meta.url));

export interface Suite {
  readonly time: { readonly issuedAt: number; readonly expiresAt: number; readonly nowValid: number };
  readonly keys: Record<string, { readonly scalar: string; readonly x: string; readonly y: string; readonly kid: string }>;
  readonly pinned: {
    readonly rootKeys: readonly { kid: string; x: string; y: string }[];
    readonly timestampKeys: readonly { kid: string; x: string; y: string }[];
  };
  readonly trustLists: Record<string, unknown>;
  readonly timestamps: Record<string, unknown>;
  readonly cases: readonly VectorCase[];
}

export interface CaseState {
  readonly trustList: string;
  readonly timestamp: string | null;
  readonly now: number;
  readonly heldVersion?: number;
  readonly fetchedAt?: number;
}

export interface VectorCase {
  readonly id: string;
  readonly profile: 'A' | 'B';
  readonly type: 'verify' | 'roundtrip';
  readonly description: string;
  readonly input: Record<string, unknown>;
  readonly state: CaseState;
  readonly expect: 'accept' | 'reject';
  readonly reason: string | null;
  readonly accepted?: Record<string, unknown>;
}

export const suite = JSON.parse(
  readFileSync(join(HERE, '..', '..', '..', '..', 'vectors', 'vectors.json'), 'utf8'),
) as Suite;

export async function anchorFor(state: CaseState): Promise<TrustAnchor> {
  return TrustAnchor.open({
    trustList: suite.trustLists[state.trustList],
    timestamp: state.timestamp === null ? undefined : suite.timestamps[state.timestamp],
    rootKeys: suite.pinned.rootKeys,
    timestampKeys: suite.pinned.timestampKeys,
    now: state.now,
    ...(state.heldVersion === undefined ? {} : { heldVersion: state.heldVersion }),
    ...(state.fetchedAt === undefined ? {} : { fetchedAt: state.fetchedAt }),
  });
}
