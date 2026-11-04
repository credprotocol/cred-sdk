import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { credGates } from '../index';
import type { CredGatesOptions, TrustResult } from '../index';

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
      price_multiplier: 1.5,
      suggested_price_usdc: 0.015,
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
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      new Response(JSON.stringify(body), {
        status,
        headers: { 'Content-Type': 'application/json' },
      }),
    ),
  );
}

function app(options: Partial<CredGatesOptions> = {}) {
  return new Hono()
    .use('/api/*', credGates({ apiKey: 'k', policy: 'standard', ...options }))
    .get('/api/resource', (c) => {
      const trust = c.get('credTrust' as never) as TrustResult;
      return c.json({ ok: true, tier: trust.trustTier });
    });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('@cred-protocol/hono credGates', () => {
  it('stores credTrust on the context and sets trust headers on a passing wallet', async () => {
    stubFetch(200, apiPayload());

    const res = await app().request('/api/resource', { headers: { 'X-Wallet-Address': WALLET } });

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, tier: 'trusted' });
    expect(res.headers.get('X-Cred-Trust-Score')).toBe('82');
    expect(res.headers.get('X-Cred-Trust-Tier')).toBe('trusted');
    expect(res.headers.get('X-Cred-Request-Id')).toBe('req-1');
    expect(res.headers.get('X-Cred-Price-Multiplier')).toBe('1.5');
  });

  it('answers 400 when no wallet is supplied', async () => {
    stubFetch(200, apiPayload());

    const res = await app().request('/api/resource');

    expect(res.status).toBe(400);
    expect(await res.json()).toEqual({
      error: 'Missing wallet address. Provide X-Wallet-Address header or ?wallet= query param.',
    });
  });

  it('reads the wallet from the query string', async () => {
    stubFetch(200, apiPayload());

    const res = await app().request(`/api/resource?wallet=${WALLET}`);

    expect(res.status).toBe(200);
  });

  it('answers 402 with the challenge and trust headers on failed gates', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false, challenge }));

    const res = await app().request('/api/resource', { headers: { 'X-Wallet-Address': WALLET } });

    expect(res.status).toBe(402);
    expect(await res.json()).toEqual(challenge);
    expect(res.headers.get('X-Cred-Trust-Tier')).toBe('limited');
  });

  it('answers 403 with failedGates when on402 is "deny"', async () => {
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false }));

    const res = await app({ on402: 'deny' }).request('/api/resource', {
      headers: { 'X-Wallet-Address': WALLET },
    });

    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({
      error: 'Trust requirements not met',
      trustTier: 'limited',
      trustScore: 82,
      failedGates: ['credit'],
    });
  });

  it('honours onBlocked and still fires onEvaluation for a blocked wallet', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'blocked', allPassed: false, challenge }));
    const onEvaluation = vi.fn(async () => {
      throw new Error('listener failure must not block');
    });

    const denied = await app({ onEvaluation }).request('/api/resource', {
      headers: { 'X-Wallet-Address': WALLET },
    });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toEqual({ error: 'Access denied', trustTier: 'blocked', trustScore: 82 });
    expect(onEvaluation).toHaveBeenCalledTimes(1);
    expect((onEvaluation.mock.calls[0] as unknown[])[0]).toMatchObject({ trustTier: 'blocked' });

    const challenged = await app({ onBlocked: 'challenge' }).request('/api/resource', {
      headers: { 'X-Wallet-Address': WALLET },
    });
    expect(challenged.status).toBe(402);
    expect(await challenged.json()).toEqual(challenge);
  });

  it('maps API errors to 429 / 502 without trust headers', async () => {
    stubFetch(429, { detail: 'slow down' });
    const limited = await app().request('/api/resource', { headers: { 'X-Wallet-Address': WALLET } });
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({ error: 'Rate limit exceeded' });
    expect(limited.headers.get('X-Cred-Trust-Tier')).toBeNull();

    stubFetch(500, 'boom');
    const failed = await app().request('/api/resource', { headers: { 'X-Wallet-Address': WALLET } });
    expect(failed.status).toBe(502);
    expect(await failed.json()).toEqual({ error: 'Trust evaluation failed', detail: '"boom"' });
  });

  it('omits trust headers when headers: false', async () => {
    stubFetch(200, apiPayload());

    const res = await app({ headers: false }).request('/api/resource', {
      headers: { 'X-Wallet-Address': WALLET },
    });

    expect(res.status).toBe(200);
    expect(res.headers.get('X-Cred-Trust-Score')).toBeNull();
  });
});
