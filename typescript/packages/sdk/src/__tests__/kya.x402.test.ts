/**
 * The hook inside a real `@x402/core` resource server (a dev dependency
 * only; the SDK itself does not depend on it). A fake facilitator verifies
 * every payment; the Cred API is a stubbed fetch.
 */
import { x402ResourceServer } from '@x402/core/server';
import type { AfterVerifyHook, FacilitatorClient } from '@x402/core/server';
import { describe, expect, it, vi } from 'vitest';
import { credKyaHook, registerCredKya } from '../kya';

const PAYER = '0x2222222222222222222222222222222222222222';

const requirements = {
  scheme: 'exact',
  network: 'eip155:8453',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
  amount: '10000',
  payTo: '0x9999999999999999999999999999999999999999',
  maxTimeoutSeconds: 60,
  extra: {},
} as any;

const paymentPayload = {
  x402Version: 2,
  accepted: requirements,
  payload: { authorization: { from: PAYER }, signature: '0x' },
} as any;

function facilitator(isValid = true) {
  const client = {
    verify: vi.fn(async () => ({ isValid, payer: isValid ? PAYER : undefined, invalidReason: isValid ? undefined : 'invalid_signature' })),
    settle: vi.fn(async () => ({ success: true, transaction: '0xabc', network: 'eip155:8453', payer: PAYER })),
    getSupported: vi.fn(async () => ({ kinds: [], extensions: [], signers: {} })),
  };
  return client;
}

function credApi(body: unknown, status = 200) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) => new Response(JSON.stringify(body), { status }));
}

/** The EVM exact scheme's flow table (mechanisms/evm/src/exact/server/scheme.ts). */
const exactScheme = {
  scheme: 'exact',
  defaultAssetTransferMethod: 'eip3009',
  paymentFlows: {
    eip3009: { supported: ['authorization', 'upfront'], default: 'authorization' },
  },
} as any;

const BLOCKED = {
  agent_id: 22,
  verdict: 'block',
  flags: [{ code: 'K01', flag: 'sanctioned_controller', severity: 'block', description: 'x', subject: PAYER }],
  unavailable: [],
  compliance: { sanctioned: true, lists_checked: ['ofac_sdn', 'ofac_consolidated'] },
};

function server(fac: ReturnType<typeof facilitator>, fetchStub: ReturnType<typeof credApi>) {
  const hook = credKyaHook({ apiKey: 'test', fetch: fetchStub as any });
  // Compile-time check that the hook is an AfterVerifyHook.
  const typed: AfterVerifyHook = hook;
  return new x402ResourceServer(fac as unknown as FacilitatorClient).register('eip155:8453', exactScheme).onAfterVerify(typed);
}

describe('credKyaHook on an x402ResourceServer', () => {
  it('turns a blocked payer into an invalid payment with our reason', async () => {
    const fac = facilitator();
    const fetchStub = credApi(BLOCKED);
    const result = await server(fac, fetchStub).verifyPayment(paymentPayload, requirements);
    expect(result.isValid).toBe(false);
    expect(result.invalidReason).toBe('payer_sanctioned');
    expect(fac.verify).toHaveBeenCalledTimes(1);
    expect(fac.settle).not.toHaveBeenCalled();
    expect(String(fetchStub.mock.calls[0][0])).toContain(`/agents/by-wallet/${PAYER}/kya`);
  });

  it('leaves a passing payer valid', async () => {
    const fac = facilitator();
    const fetchStub = credApi({ agent_id: 22, verdict: 'pass', flags: [], unavailable: [], compliance: { sanctioned: false } });
    const result = await server(fac, fetchStub).verifyPayment(paymentPayload, requirements);
    expect(result.isValid).toBe(true);
  });

  it('never calls Cred for a payment the facilitator rejected', async () => {
    const fac = facilitator(false);
    const fetchStub = credApi({});
    const result = await server(fac, fetchStub).verifyPayment(paymentPayload, requirements);
    expect(result).toMatchObject({ isValid: false, invalidReason: 'invalid_signature' });
    expect(fetchStub).not.toHaveBeenCalled();
  });

  it('registerCredKya also stops an upfront payment before it settles', async () => {
    const fac = facilitator();
    const fetchStub = credApi(BLOCKED);
    const srv = registerCredKya(
      new x402ResourceServer(fac as unknown as FacilitatorClient).register('eip155:8453', exactScheme),
      { apiKey: 'test', fetch: fetchStub as any },
    );
    const upfront = { ...requirements, extra: { paymentFlow: 'upfront' } };
    // The upfront flow skips verify...
    expect(await srv.verifyPayment(paymentPayload, upfront)).toEqual({ isValid: true });
    expect(fetchStub).not.toHaveBeenCalled();
    // ...and the settle hook refuses before the facilitator is asked to settle.
    // x402HTTPResourceServer settles upfront payments at the before-handler phase.
    const settled = await srv
      .settlePayment(paymentPayload, upfront, undefined, undefined, undefined, 'before-handler')
      .catch((error: any) => error);
    expect(fac.settle).not.toHaveBeenCalled();
    expect(JSON.stringify(settled)).toContain('payer_sanctioned');
  });

  it('registerCredKya screens a payer once across verify and settle', async () => {
    const fac = facilitator();
    const fetchStub = credApi({ agent_id: 22, verdict: 'pass', flags: [], unavailable: [], compliance: { sanctioned: false } });
    const srv = registerCredKya(
      new x402ResourceServer(fac as unknown as FacilitatorClient).register('eip155:8453', exactScheme),
      { apiKey: 'test', fetch: fetchStub as any },
    );
    expect((await srv.verifyPayment(paymentPayload, requirements)).isValid).toBe(true);
    await srv.settlePayment(paymentPayload, requirements);
    expect(fac.settle).toHaveBeenCalledTimes(1);
    expect(fetchStub).toHaveBeenCalledTimes(1);
  });
});
