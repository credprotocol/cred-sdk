import { describe, expect, it, vi } from 'vitest';
import { CredAPIError } from '../client';
import {
  MISSING_WALLET_MESSAGE,
  createGate,
  decideFromResult,
  evaluateGate,
  notifyEvaluation,
  toEvaluateOptions,
  trustHeaders,
  walletFromRequest,
} from '../gates';
import type { GateClient, GateDenied } from '../gates';
import type { EvaluateOptions, TrustResult } from '../types';

const WALLET = '0x1111111111111111111111111111111111111111';

function trustResult(overrides: Partial<TrustResult> = {}): TrustResult {
  const base: TrustResult = {
    walletAddress: WALLET,
    trustScore: 82,
    trustTier: 'trusted',
    confidence: 0.9,
    allPassed: true,
    gateResults: [],
    priceMultiplier: null,
    suggestedPriceUsdc: null,
    reputation: null,
    cached: false,
    requestId: 'req-1',
    challenge: null,
    raw: {
      trustScore: {
        walletAddress: WALLET,
        trustScore: 82,
        trustTier: 'trusted',
        confidence: 0.9,
        gateResults: [],
        priceMultiplier: null,
        suggestedPriceUsdc: null,
        reputation: null,
        cached: false,
        cacheExpiresAt: null,
        evaluatedAt: '2026-11-02T00:00:00Z',
      },
      policyResult: {
        policyName: 'standard',
        allPassed: true,
        operator: 'AND',
        passedGates: ['credit'],
        failedGates: [],
        compositeScore: 82,
      },
      requestId: 'req-1',
      challenge: null,
      evaluationCostUsdc: 0.01,
      cached: false,
      apiVersion: 'v1',
      evaluatedAt: '2026-11-02T00:00:00Z',
    },
  };
  return { ...base, ...overrides };
}

const CHALLENGE = { x402Version: 1, accepts: [] };

function failedResult(overrides: Partial<TrustResult> = {}): TrustResult {
  const result = trustResult({
    trustScore: 35,
    trustTier: 'limited',
    allPassed: false,
    challenge: CHALLENGE,
    ...overrides,
  });
  result.raw.policyResult.allPassed = false;
  result.raw.policyResult.failedGates = ['credit'];
  return result;
}

function fakeClient(result: TrustResult | Error): GateClient & { calls: EvaluateOptions[] } {
  const calls: EvaluateOptions[] = [];
  return {
    calls,
    async evaluate(options) {
      calls.push(options);
      if (result instanceof Error) throw result;
      return result;
    },
  };
}

function denied(decision: Awaited<ReturnType<typeof evaluateGate>>): GateDenied {
  if (decision.allow) throw new Error('expected a denial');
  return decision;
}

describe('walletFromRequest', () => {
  it('prefers the X-Wallet-Address header', () => {
    const wallet = walletFromRequest({
      header: (name) => (name === 'X-Wallet-Address' ? WALLET : undefined),
      query: () => '0xquery',
    });
    expect(wallet).toBe(WALLET);
  });

  it('falls back to the wallet query parameter', () => {
    const wallet = walletFromRequest({
      header: () => undefined,
      query: (name) => (name === 'wallet' ? WALLET : null),
    });
    expect(wallet).toBe(WALLET);
  });

  it('returns null when neither is present (empty strings count as absent)', () => {
    expect(walletFromRequest({ header: () => '', query: () => undefined })).toBeNull();
  });
});

describe('toEvaluateOptions', () => {
  it('always asks for reputation and only asks for pricing when enabled', () => {
    expect(toEvaluateOptions({ policy: 'strict' }, WALLET)).toEqual({
      walletAddress: WALLET,
      policy: 'strict',
      gates: undefined,
      operator: undefined,
      includePricing: false,
      basePriceUsdc: undefined,
      includeReputation: true,
    });
    expect(
      toEvaluateOptions({ pricing: { enabled: true, curve: 'step', basePriceUsdc: 0.05 } }, WALLET),
    ).toMatchObject({ includePricing: true, basePriceUsdc: 0.05 });
  });
});

describe('trustHeaders', () => {
  it('sets score, tier and request id, plus the multiplier only when priced', () => {
    expect(trustHeaders(trustResult())).toEqual({
      'X-Cred-Trust-Score': '82',
      'X-Cred-Trust-Tier': 'trusted',
      'X-Cred-Request-Id': 'req-1',
    });
    expect(trustHeaders(trustResult({ priceMultiplier: 1.5 }))).toMatchObject({
      'X-Cred-Price-Multiplier': '1.5',
    });
  });
});

describe('evaluateGate', () => {
  it('answers 400 without calling the API when the wallet is missing', async () => {
    const client = fakeClient(trustResult());
    for (const wallet of [null, undefined, '']) {
      const decision = denied(await evaluateGate(client, {}, wallet));
      expect(decision).toMatchObject({
        status: 400,
        reason: 'missing_wallet',
        body: { error: MISSING_WALLET_MESSAGE },
        headers: {},
      });
    }
    expect(client.calls).toHaveLength(0);
  });

  it('allows a passing wallet and attaches result and headers', async () => {
    const client = fakeClient(trustResult());
    const decision = await evaluateGate(client, { policy: 'standard' }, WALLET);
    expect(decision.allow).toBe(true);
    expect(decision.result?.walletAddress).toBe(WALLET);
    expect(decision.headers['X-Cred-Trust-Tier']).toBe('trusted');
    expect(client.calls[0]).toMatchObject({ walletAddress: WALLET, policy: 'standard' });
  });

  it('computes no headers when headers: false', async () => {
    const decision = await evaluateGate(fakeClient(trustResult()), { headers: false }, WALLET);
    expect(decision.headers).toEqual({});
  });

  it('maps a 429 from the API to a 429 decision', async () => {
    const err = new CredAPIError(429, 'slow down');
    const decision = denied(await evaluateGate(fakeClient(err), {}, WALLET));
    expect(decision).toMatchObject({
      status: 429,
      reason: 'rate_limited',
      body: { error: 'Rate limit exceeded' },
      headers: {},
      error: err,
    });
  });

  it('maps any other API error to a 502 with the body as detail', async () => {
    const err = new CredAPIError(500, 'boom');
    const decision = denied(await evaluateGate(fakeClient(err), {}, WALLET));
    expect(decision).toMatchObject({
      status: 502,
      reason: 'evaluation_failed',
      body: { error: 'Trust evaluation failed', detail: 'boom' },
      error: err,
    });
  });

  it('lets non-API errors propagate', async () => {
    await expect(evaluateGate(fakeClient(new TypeError('network')), {}, WALLET)).rejects.toThrow(
      'network',
    );
  });
});

describe('decideFromResult: blocked tier', () => {
  const blocked = () => trustResult({ trustTier: 'blocked', trustScore: 5, challenge: CHALLENGE });

  it('denies with 403 by default, headers included', () => {
    const decision = denied(decideFromResult(blocked(), {}));
    expect(decision).toMatchObject({
      status: 403,
      reason: 'blocked',
      body: { error: 'Access denied', trustTier: 'blocked', trustScore: 5 },
    });
    expect(decision.headers['X-Cred-Trust-Tier']).toBe('blocked');
    expect(decision.result?.trustTier).toBe('blocked');
  });

  it('serves the challenge with 402 when onBlocked is "challenge"', () => {
    const decision = denied(decideFromResult(blocked(), { onBlocked: 'challenge' }));
    expect(decision).toMatchObject({ status: 402, reason: 'blocked', body: CHALLENGE });
  });

  it('falls through to the gate check when onBlocked is "challenge" but no challenge came back', () => {
    const result = blocked();
    result.challenge = null;
    expect(decideFromResult(result, { onBlocked: 'challenge' }).allow).toBe(true);
  });

  it('passes a blocked wallet through when onBlocked is "pass"', () => {
    expect(decideFromResult(blocked(), { onBlocked: 'pass' }).allow).toBe(true);
  });
});

describe('decideFromResult: failed gates', () => {
  it('serves the challenge with 402 by default', () => {
    const decision = denied(decideFromResult(failedResult(), {}));
    expect(decision).toMatchObject({ status: 402, reason: 'gates_failed', body: CHALLENGE });
    expect(decision.headers['X-Cred-Trust-Score']).toBe('35');
  });

  it('allows through in challenge mode when the API returned no challenge', () => {
    expect(decideFromResult(failedResult({ challenge: null }), {}).allow).toBe(true);
  });

  it('denies with 403 and the failed gates when on402 is "deny"', () => {
    const decision = denied(decideFromResult(failedResult(), { on402: 'deny' }));
    expect(decision).toMatchObject({
      status: 403,
      reason: 'gates_failed',
      body: {
        error: 'Trust requirements not met',
        trustTier: 'limited',
        trustScore: 35,
        failedGates: ['credit'],
      },
    });
  });

  it('passes through with headers when on402 is "pass"', () => {
    const decision = decideFromResult(failedResult(), { on402: 'pass' });
    expect(decision.allow).toBe(true);
    expect(decision.headers['X-Cred-Trust-Tier']).toBe('limited');
  });
});

describe('pricing', () => {
  it('forwards the pricing request and exposes the multiplier header', async () => {
    const client = fakeClient(trustResult({ priceMultiplier: 2, suggestedPriceUsdc: 0.02 }));
    const decision = await evaluateGate(
      client,
      { pricing: { enabled: true, curve: 'linear', basePriceUsdc: 0.01 } },
      WALLET,
    );
    expect(client.calls[0]).toMatchObject({ includePricing: true, basePriceUsdc: 0.01 });
    expect(decision.headers['X-Cred-Price-Multiplier']).toBe('2');
  });
});

describe('notifyEvaluation', () => {
  it('calls the listener with the result and context for allowed and denied decisions', async () => {
    const listener = vi.fn();
    const context = { id: 'ctx' };
    const result = trustResult();

    await notifyEvaluation(decideFromResult(result, {}), listener, context);
    await notifyEvaluation(decideFromResult(trustResult({ trustTier: 'blocked' }), {}), listener, context);

    expect(listener).toHaveBeenCalledTimes(2);
    expect(listener).toHaveBeenNthCalledWith(1, result, context);
    expect((listener.mock.calls[1] as unknown[])[0]).toMatchObject({ trustTier: 'blocked' });
  });

  it('skips decisions without a result and swallows listener errors', async () => {
    const listener = vi.fn(async () => {
      throw new Error('listener failure');
    });

    await notifyEvaluation(await evaluateGate(fakeClient(trustResult()), {}, null), listener, undefined);
    expect(listener).not.toHaveBeenCalled();

    await expect(
      notifyEvaluation(decideFromResult(trustResult(), {}), listener, undefined),
    ).resolves.toBeUndefined();
    expect(listener).toHaveBeenCalledTimes(1);

    await expect(notifyEvaluation(decideFromResult(trustResult(), {}), undefined, 1)).resolves.toBeUndefined();
  });
});

describe('createGate', () => {
  it('requires an apiKey', () => {
    expect(() => createGate({ apiKey: '' })).toThrow('apiKey');
  });

  it('keeps only the gate options and binds evaluate to its client', async () => {
    const gate = createGate({
      apiKey: 'k',
      baseUrl: 'https://cred.test/',
      policy: 'standard',
      extractWallet: () => WALLET,
    } as never);
    expect(gate.options).toEqual({
      policy: 'standard',
      gates: undefined,
      operator: undefined,
      pricing: undefined,
      on402: undefined,
      onBlocked: undefined,
      headers: undefined,
    });

    const evaluate = vi.spyOn(gate.client, 'evaluate').mockResolvedValue(trustResult());
    const decision = await gate.evaluate(WALLET);
    expect(decision.allow).toBe(true);
    expect(evaluate).toHaveBeenCalledWith(expect.objectContaining({ policy: 'standard' }));
  });
});
