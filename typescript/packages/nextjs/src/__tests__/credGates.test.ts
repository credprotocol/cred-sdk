import { NextRequest } from 'next/server.js';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { credGates } from '../index';
import type { TrustResult } from '../index';

const WALLET = '0x1111111111111111111111111111111111111111';

/** Raw /v1/evaluate payload (snake_case) as the Cred API returns it. */
function apiPayload(overrides: { tier?: string; allPassed?: boolean; challenge?: unknown } = {}) {
  const tier = overrides.tier ?? 'trusted';
  const allPassed = overrides.allPassed ?? true;
  return {
    trust_score: {
      wallet_address: WALLET,
      trust_score: 82,
      trust_tier: tier,
      confidence: 0.9,
      gate_results: [],
      price_multiplier: null,
      suggested_price_usdc: null,
      reputation: null,
      cached: false,
      cache_expires_at: null,
      evaluated_at: '2026-11-02T00:00:00Z',
    },
    policy_result: {
      policy_name: 'standard',
      all_passed: allPassed,
      operator: 'AND',
      passed_gates: allPassed ? ['credit'] : [],
      failed_gates: allPassed ? [] : ['credit'],
      composite_score: 82,
    },
    request_id: 'req-1',
    challenge: overrides.challenge ?? null,
    evaluation_cost_usdc: 0.01,
    cached: false,
    api_version: 'v1',
    evaluated_at: '2026-11-02T00:00:00Z',
  };
}

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  );
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function request(path: string, headers: Record<string, string> = {}) {
  return new NextRequest(`http://localhost${path}`, { headers });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('@cred-protocol/nextjs credGates', () => {
  it('passes through with trust headers on a passing wallet', async () => {
    stubFetch(200, apiPayload());
    const middleware = credGates({ apiKey: 'k', policy: 'standard' });

    const res = await middleware(request('/api/resource', { 'x-wallet-address': WALLET }));

    expect(res.status).toBe(200);
    expect(res.headers.get('x-middleware-next')).toBe('1');
    expect(res.headers.get('X-Cred-Trust-Score')).toBe('82');
    expect(res.headers.get('X-Cred-Trust-Tier')).toBe('trusted');
    expect(res.headers.get('X-Cred-Request-Id')).toBe('req-1');
  });

  it('skips routes outside the matcher without evaluating', async () => {
    const fetchMock = stubFetch(200, apiPayload());
    const middleware = credGates({ apiKey: 'k', matcher: ['/api/:path*'] });

    const res = await middleware(request('/public/page'));

    expect(res.headers.get('x-middleware-next')).toBe('1');
    expect(res.headers.get('X-Cred-Trust-Tier')).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();

    const gated = await middleware(request('/api/resource'));
    expect(gated.status).toBe(400);
  });

  it('answers 400 when no wallet is supplied, and reads the query string otherwise', async () => {
    stubFetch(200, apiPayload());
    const middleware = credGates({ apiKey: 'k' });

    const missing = await middleware(request('/api/resource'));
    expect(missing.status).toBe(400);
    expect(await missing.json()).toEqual({
      error: 'Missing wallet address. Provide X-Wallet-Address header or ?wallet= query param.',
    });

    const viaQuery = await middleware(request(`/api/resource?wallet=${WALLET}`));
    expect(viaQuery.status).toBe(200);
  });

  it('answers 402 with the challenge and trust headers on failed gates', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false, challenge }));

    const res = await credGates({ apiKey: 'k' })(request('/api/resource', { 'x-wallet-address': WALLET }));

    expect(res.status).toBe(402);
    expect(await res.json()).toEqual(challenge);
    expect(res.headers.get('X-Cred-Trust-Tier')).toBe('limited');
    expect(res.headers.get('X-Cred-Request-Id')).toBe('req-1');
  });

  it('answers 403 with failedGates when on402 is "deny"', async () => {
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false }));

    const res = await credGates({ apiKey: 'k', on402: 'deny' })(
      request('/api/resource', { 'x-wallet-address': WALLET }),
    );

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: 'Trust requirements not met',
      trustTier: 'limited',
      trustScore: 82,
      failedGates: ['credit'],
    });
  });

  it('honours onBlocked, headers: false, and fires onEvaluation with the request', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'blocked', allPassed: false, challenge }));
    const onEvaluation = vi.fn(async () => {
      throw new Error('listener failure must not block');
    });
    const req = request('/api/resource', { 'x-wallet-address': WALLET });

    const res = await credGates({ apiKey: 'k', onBlocked: 'challenge', headers: false, onEvaluation })(req);

    expect(res.status).toBe(402);
    expect(await res.json()).toEqual(challenge);
    expect(res.headers.get('X-Cred-Trust-Tier')).toBeNull();
    expect(onEvaluation).toHaveBeenCalledTimes(1);
    const [result, context] = onEvaluation.mock.calls[0] as unknown as [TrustResult, unknown];
    expect(result.trustTier).toBe('blocked');
    expect(context).toBe(req);
  });

  it('answers 403 Access denied for a blocked wallet', async () => {
    stubFetch(200, apiPayload({ tier: 'blocked', allPassed: false }));

    const res = await credGates({ apiKey: 'k' })(request('/api/resource', { 'x-wallet-address': WALLET }));

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'Access denied', trustTier: 'blocked', trustScore: 82 });
  });

  it('maps API errors to 429 / 502', async () => {
    stubFetch(429, { detail: 'slow down' });
    const limited = await credGates({ apiKey: 'k' })(request('/api/resource', { 'x-wallet-address': WALLET }));
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ error: 'Rate limit exceeded' });

    stubFetch(500, 'boom');
    const failed = await credGates({ apiKey: 'k' })(request('/api/resource', { 'x-wallet-address': WALLET }));
    expect(failed.status).toBe(502);
    expect(await failed.json()).toEqual({ error: 'Trust evaluation failed', detail: '"boom"' });
  });
});
