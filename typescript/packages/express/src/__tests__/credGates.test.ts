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

function fakeRequest(headers: Record<string, string> = {}, query: Record<string, string> = {}) {
  return { headers, query } as unknown as import('express').Request;
}

function fakeResponse() {
  const headers: Record<string, string> = {};
  const res = {
    statusCode: 200,
    body: undefined as unknown,
    headers,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
    setHeader(name: string, value: string) {
      headers[name] = value;
    },
  };
  return res as typeof res & import('express').Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('@cred-protocol/express credGates', () => {
  it('attaches req.credTrust, sets trust headers and calls next on a passing wallet', async () => {
    const fetchMock = stubFetch(200, apiPayload());
    const middleware = credGates({ apiKey: 'k', policy: 'standard' });
    const req = fakeRequest({ 'x-wallet-address': WALLET });
    const res = fakeResponse();
    const next = vi.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalledWith();
    expect(req.credTrust?.trustTier).toBe('trusted');
    expect(res.headers).toEqual({
      'X-Cred-Trust-Score': '82',
      'X-Cred-Trust-Tier': 'trusted',
      'X-Cred-Request-Id': 'req-1',
    });
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('https://validator.credprotocol.com/v1/evaluate');
    expect(JSON.parse(String(init.body))).toMatchObject({
      wallet_address: WALLET,
      policy: 'standard',
      include_reputation: true,
    });
  });

  it('answers 400 when no wallet is supplied', async () => {
    const fetchMock = stubFetch(200, apiPayload());
    const res = fakeResponse();
    const next = vi.fn();

    await credGates({ apiKey: 'k' })(fakeRequest(), res, next);

    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({
      error: 'Missing wallet address. Provide X-Wallet-Address header or ?wallet= query param.',
    });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(next).not.toHaveBeenCalled();
  });

  it('reads the wallet from the query string', async () => {
    stubFetch(200, apiPayload());
    const req = fakeRequest({}, { wallet: WALLET });
    const next = vi.fn();

    await credGates({ apiKey: 'k' })(req, fakeResponse(), next);

    expect(next).toHaveBeenCalled();
  });

  it('answers 402 with the challenge body and trust headers on failed gates', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false, challenge }));
    const res = fakeResponse();
    const next = vi.fn();

    await credGates({ apiKey: 'k' })(fakeRequest({ 'x-wallet-address': WALLET }), res, next);

    expect(res.statusCode).toBe(402);
    expect(res.body).toEqual(challenge);
    expect(res.headers['X-Cred-Trust-Tier']).toBe('limited');
    expect(next).not.toHaveBeenCalled();
  });

  it('answers 403 with failedGates when on402 is "deny"', async () => {
    stubFetch(200, apiPayload({ tier: 'limited', allPassed: false }));
    const res = fakeResponse();

    await credGates({ apiKey: 'k', on402: 'deny' })(
      fakeRequest({ 'x-wallet-address': WALLET }),
      res,
      vi.fn(),
    );

    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({
      error: 'Trust requirements not met',
      trustTier: 'limited',
      trustScore: 82,
      failedGates: ['credit'],
    });
  });

  it('answers 403 Access denied for a blocked wallet', async () => {
    stubFetch(200, apiPayload({ tier: 'blocked', allPassed: false }));
    const res = fakeResponse();

    await credGates({ apiKey: 'k' })(fakeRequest({ 'x-wallet-address': WALLET }), res, vi.fn());

    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual({ error: 'Access denied', trustTier: 'blocked', trustScore: 82 });
  });

  it('honours onBlocked and fires onEvaluation with the request on a denial', async () => {
    const challenge = { x402Version: 1 };
    stubFetch(200, apiPayload({ tier: 'blocked', allPassed: false, challenge }));
    const onEvaluation = vi.fn(async () => {
      throw new Error('listener failure must not block');
    });
    const req = fakeRequest({ 'x-wallet-address': WALLET });
    const res = fakeResponse();

    await credGates({ apiKey: 'k', onBlocked: 'challenge', onEvaluation })(req, res, vi.fn());

    expect(res.statusCode).toBe(402);
    expect(res.body).toEqual(challenge);
    expect(onEvaluation).toHaveBeenCalledTimes(1);
    const [result, context] = onEvaluation.mock.calls[0] as unknown as [TrustResult, unknown];
    expect(result.trustTier).toBe('blocked');
    expect(context).toBe(req);
  });

  it('maps API errors to 429 / 502 and omits headers when headers: false', async () => {
    stubFetch(429, { detail: 'slow down' });
    const res = fakeResponse();
    await credGates({ apiKey: 'k', headers: false })(
      fakeRequest({ 'x-wallet-address': WALLET }),
      res,
      vi.fn(),
    );
    expect(res.statusCode).toBe(429);
    expect(res.body).toEqual({ error: 'Rate limit exceeded' });
    expect(res.headers).toEqual({});

    stubFetch(500, 'boom');
    const res2 = fakeResponse();
    await credGates({ apiKey: 'k' })(fakeRequest({ 'x-wallet-address': WALLET }), res2, vi.fn());
    expect(res2.statusCode).toBe(502);
    expect(res2.body).toEqual({ error: 'Trust evaluation failed', detail: '"boom"' });
  });

  it('routes unexpected errors to next(err)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new TypeError('network down');
    }));
    const next = vi.fn();

    await credGates({ apiKey: 'k' })(fakeRequest({ 'x-wallet-address': WALLET }), fakeResponse(), next);

    expect(next).toHaveBeenCalledWith(expect.any(TypeError));
  });
});
