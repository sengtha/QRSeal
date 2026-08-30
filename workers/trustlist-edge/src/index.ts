/**
 * trustlist-edge — serves the trust list, the timestamp statement, and the
 * application trust list.
 *
 * READ-ONLY, AND KEYLESS BY CONSTRUCTION
 *
 * This Worker holds no private key and performs no signing. The trust list is
 * signed offline in a Root ceremony; the timestamp statement is produced by a
 * separate signer outside Cloudflare and uploaded. Compromising this service
 * therefore yields the ability to withhold or delay artifacts — which the
 * verifier's staleness and timestamp rules already treat as hostile — but never
 * the ability to issue one. That is the property the architecture is for, and
 * the reason there is no secret binding in wrangler.toml.
 *
 * MIRRORS
 *
 * The specification requires publication at three mirrors under distinct
 * operational control. This deployment is one provider, one account, one
 * governance failure. It is the primary, not a conforming mirror set; see
 * README.md.
 */

export interface Env {
  readonly ARTIFACTS: R2Bucket;
  readonly POINTER: KVNamespace;
  readonly MIRROR_HINTS: string;
}

/** What the pointer key holds. Written by the publication job, never by a request. */
interface Pointer {
  readonly version: number;
  readonly trustListKey: string;
  readonly timestampKey: string;
  readonly applicationsKey: string;
  readonly updatedAt: number;
}

const POINTER_KEY = 'current';

/** A versioned object never changes, so it may be cached indefinitely. */
const IMMUTABLE = 'public, max-age=31536000, immutable';
/** The current-list alias may move, so revalidation must stay cheap and frequent. */
const CURRENT = 'public, max-age=300, must-revalidate';
/**
 * The timestamp statement is the freshness signal itself. Caching it for long
 * would recreate the freeze the statement exists to prevent.
 */
const TIMESTAMP = 'public, max-age=60, must-revalidate';

function json(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { 'content-type': 'application/json; charset=utf-8', ...init.headers },
  });
}

function problem(status: number, detail: string): Response {
  return json({ error: detail }, { status });
}

async function serveObject(
  env: Env,
  key: string,
  cacheControl: string,
  request: Request,
): Promise<Response> {
  const object = await env.ARTIFACTS.get(key);
  if (object === null) return problem(404, 'artifact not found');

  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': cacheControl,
    etag: object.httpEtag,
    'x-kh-sqr-object': key,
    'x-kh-sqr-mirrors': env.MIRROR_HINTS,
  });

  if (request.headers.get('if-none-match') === object.httpEtag) {
    return new Response(null, { status: 304, headers });
  }
  return new Response(request.method === 'HEAD' ? null : object.body, { headers });
}

async function readPointer(env: Env): Promise<Pointer | null> {
  return env.POINTER.get<Pointer>(POINTER_KEY, 'json');
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Read-only by construction: no route mutates anything, and any method
    // that implies mutation is refused before routing.
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return problem(405, 'this service is read-only');
    }

    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';

    if (path === '/' || path === '/health') {
      const pointer = await readPointer(env);
      return json({
        service: 'kh-sqr-trustlist-edge',
        readOnly: true,
        holdsSigningKey: false,
        currentVersion: pointer?.version ?? null,
        mirrorIndependence: 'not satisfied by this deployment; see README.md',
        mirrors: env.MIRROR_HINTS.split(',').filter((m) => m.length > 0),
      }, { headers: { 'cache-control': 'no-store' } });
    }

    const versioned = /^\/trustlist\/v\/(\d{1,10})$/.exec(path);
    if (versioned !== null) {
      return serveObject(env, `trustlist/v${versioned[1]}.json`, IMMUTABLE, request);
    }

    const pointer = await readPointer(env);
    if (pointer === null) return problem(503, 'no trust list has been published');

    switch (path) {
      case '/trustlist/current':
      case '/.well-known/kh-sqr/trustlist': {
        const response = await serveObject(env, pointer.trustListKey, CURRENT, request);
        response.headers.set('x-kh-sqr-version', String(pointer.version));
        response.headers.append(
          'link',
          `<${url.origin}/trustlist/v/${pointer.version}>; rel="canonical"`,
        );
        return response;
      }
      case '/timestamp/current':
      case '/.well-known/kh-sqr/timestamp':
        return serveObject(env, pointer.timestampKey, TIMESTAMP, request);
      case '/applications/current':
        return serveObject(env, pointer.applicationsKey, CURRENT, request);
      default:
        return problem(404, 'no such resource');
    }
  },
} satisfies ExportedHandler<Env>;
