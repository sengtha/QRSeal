import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import worker, { type Env } from '../src/index.js';

const typed = env as unknown as Env;

const POINTER = {
  version: 7,
  trustListKey: 'trustlist/v7.json',
  timestampKey: 'timestamp/1756512000.json',
  applicationsKey: 'applications/v3.json',
  updatedAt: 1_756_512_000,
};

async function call(path: string, init: RequestInit = {}): Promise<Response> {
  const request = new Request(`https://trustlist.example.kh${path}`, init);
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, typed, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

beforeEach(async () => {
  await typed.POINTER.put('current', JSON.stringify(POINTER));
  await typed.ARTIFACTS.put(POINTER.trustListKey, JSON.stringify({ statement: '{}', signature: {} }));
  await typed.ARTIFACTS.put(POINTER.timestampKey, JSON.stringify({ statement: '{}', signature: {} }));
  await typed.ARTIFACTS.put(POINTER.applicationsKey, JSON.stringify({ applications: [] }));
});

describe('trustlist-edge', () => {
  it('refuses every method that implies mutation', async () => {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const response = await call('/trustlist/current', { method });
      expect(response.status, method).toBe(405);
    }
  });

  it('reports that it holds no signing key', async () => {
    const body = await (await call('/health')).json<{ holdsSigningKey: boolean; currentVersion: number }>();
    expect(body.holdsSigningKey).toBe(false);
    expect(body.currentVersion).toBe(7);
  });

  it('does not claim mirror independence', async () => {
    const body = await (await call('/health')).json<{ mirrorIndependence: string }>();
    expect(body.mirrorIndependence).toMatch(/not satisfied/);
  });

  it('serves the current trust list and points at its immutable version', async () => {
    const response = await call('/trustlist/current');
    expect(response.status).toBe(200);
    expect(response.headers.get('x-kh-sqr-version')).toBe('7');
    expect(response.headers.get('link')).toContain('/trustlist/v/7');
    expect(response.headers.get('cache-control')).toContain('must-revalidate');
  });

  it('serves a versioned object as immutable', async () => {
    const response = await call('/trustlist/v/7');
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('public, max-age=31536000, immutable');
  });

  it('caches the timestamp statement only briefly, so freeze protection stays live', async () => {
    const response = await call('/timestamp/current');
    const maxAge = Number(/max-age=(\d+)/.exec(response.headers.get('cache-control') ?? '')?.[1]);
    expect(maxAge).toBeLessThanOrEqual(60);
  });

  it('honours conditional requests', async () => {
    const first = await call('/trustlist/v/7');
    const etag = first.headers.get('etag');
    expect(etag).not.toBeNull();
    const second = await call('/trustlist/v/7', { headers: { 'if-none-match': etag! } });
    expect(second.status).toBe(304);
  });

  it('returns 503 when nothing has been published', async () => {
    await typed.POINTER.delete('current');
    expect((await call('/trustlist/current')).status).toBe(503);
  });

  it('404s an unknown version rather than falling back to the current one', async () => {
    expect((await call('/trustlist/v/999')).status).toBe(404);
  });
});
