import { describe, expect, it, vi } from 'vitest';
import { CredAPIError } from '../client';
import { CredKyaClient, KYA_REASONS, credKyaHook, decideFromProfile, payerFromContext } from '../kya';
import type { CredKyaHookOptions, KyaDecision, KyaFlag, KyaProfile, KyaVerifyContext } from '../kya';

const PAYER = '0x2222222222222222222222222222222222222222';

function flag(code: string, severity: KyaFlag['severity'] = 'review'): KyaFlag {
  return { code, flag: code.toLowerCase(), severity, description: code, subject: null };
}

function profile(overrides: Partial<KyaProfile> = {}): KyaProfile {
  return {
    agentId: 22,
    verdict: 'pass',
    flags: [],
    unavailable: [],
    sanctioned: false,
    listsChecked: ['ofac_sdn', 'ofac_consolidated'],
    exposureRisk: 'none',
    resolvedFrom: PAYER,
    raw: {},
    ...overrides,
  };
}

function ctx(payer: string | undefined = PAYER, isValid = true): KyaVerifyContext {
  return { result: { isValid, payer } };
}

function fakeClient(kya: () => Promise<KyaProfile | null>, sanctioned = false) {
  return {
    kyaByWallet: vi.fn(async (_address: string) => kya()),
    sanctionsScreen: vi.fn(async (address: string) => ({
      address,
      sanctioned,
      listsChecked: ['ofac_sdn', 'ofac_consolidated'],
      matches: [],
    })),
  };
}

function hookWith(client: ReturnType<typeof fakeClient>, options: Partial<CredKyaHookOptions> = {}) {
  const decisions: KyaDecision[] = [];
  const hook = credKyaHook({
    apiKey: 'test',
    client,
    onDecision: (d) => {
      decisions.push(d);
    },
    ...options,
  });
  return { hook, decisions };
}

describe('payerFromContext', () => {
  it('prefers the facilitator payer, lowercased', () => {
    expect(payerFromContext({ result: { isValid: true, payer: '0xABCD' } })).toBe('0xabcd');
  });

  it('falls back to the EVM exact authorization signer', () => {
    const context = {
      result: { isValid: true },
      paymentPayload: { payload: { authorization: { from: '0xFEED' } } },
    };
    expect(payerFromContext(context)).toBe('0xfeed');
  });

  it('returns null when nothing names the payer', () => {
    expect(payerFromContext({ result: { isValid: true } })).toBeNull();
  });
});

describe('decideFromProfile', () => {
  const decide = (p: KyaProfile, policy = {}) => decideFromProfile(p, policy, ctx(), PAYER);

  it('accepts pass and refuses block', () => {
    expect(decide(profile()).accept).toBe(true);
    const blocked = decide(profile({ verdict: 'block', sanctioned: true, flags: [flag('K01', 'block')] }));
    expect(blocked).toMatchObject({ accept: false, reason: KYA_REASONS.sanctioned, flags: ['K01'] });
  });

  it('accepts review by default but always refuses K02/K03', () => {
    expect(decide(profile({ verdict: 'review', flags: [flag('K08')] })).accept).toBe(true);
    expect(decide(profile({ verdict: 'review', flags: [flag('K03')] }))).toMatchObject({
      accept: false,
      reason: KYA_REASONS.needsReview,
    });
  });

  it('honours review: refuse, custom refuse flags and a predicate', () => {
    const review = profile({ verdict: 'review', flags: [flag('K07')] });
    expect(decide(review, { review: 'refuse' }).accept).toBe(false);
    expect(decide(review, { refuseFlags: ['K07'] }).accept).toBe(false);
    expect(decide(review, { review: (p: KyaProfile) => p.agentId === 22 }).accept).toBe(true);
    expect(decide(review, { review: () => false }).accept).toBe(false);
  });

  it('treats a review that is only K13 as incomplete, decided by onError', () => {
    const incomplete = profile({ verdict: 'review', flags: [flag('K13')] });
    expect(decide(incomplete)).toMatchObject({ accept: true, incomplete: true });
    expect(decide(incomplete, { onError: 'refuse' })).toMatchObject({
      accept: false,
      reason: KYA_REASONS.unavailable,
      incomplete: true,
    });
    // K13 next to a real review flag is a real review
    expect(decide(profile({ verdict: 'review', flags: [flag('K08'), flag('K13')] })).incomplete).toBeUndefined();
  });
});

describe('credKyaHook', () => {
  it('aborts a blocked payer with a self-explaining reason', async () => {
    const client = fakeClient(async () => profile({ verdict: 'block', sanctioned: true, flags: [flag('K01', 'block')] }));
    const { hook } = hookWith(client);
    const result = await hook(ctx());
    expect(result).toMatchObject({ abort: true, reason: 'payer_sanctioned' });
    expect((result as any).message).toContain('K01');
    expect(client.kyaByWallet).toHaveBeenCalledWith(PAYER);
  });

  it('lets a passing payer through and records the decision', async () => {
    const { hook, decisions } = hookWith(fakeClient(async () => profile()));
    expect(await hook(ctx())).toBeUndefined();
    expect(decisions[0]).toMatchObject({ accept: true, source: 'kya', agentId: 22, verdict: 'pass' });
    expect(decisions[0].listsChecked).toEqual(['ofac_sdn', 'ofac_consolidated']);
  });

  it('ignores payments x402 did not verify', async () => {
    const client = fakeClient(async () => profile());
    const { hook } = hookWith(client);
    expect(await hook(ctx(PAYER, false))).toBeUndefined();
    expect(client.kyaByWallet).not.toHaveBeenCalled();
  });

  it('caches per payer, with block cached longer than pass', async () => {
    let clock = 0;
    const client = fakeClient(async () => profile());
    const { hook, decisions } = hookWith(client, { now: () => clock });
    await hook(ctx());
    clock = 14 * 60_000;
    await hook(ctx());
    expect(client.kyaByWallet).toHaveBeenCalledTimes(1);
    expect(decisions[1].source).toBe('cache');
    clock = 16 * 60_000;
    await hook(ctx());
    expect(client.kyaByWallet).toHaveBeenCalledTimes(2);

    let blockClock = 0;
    const blocked = fakeClient(async () => profile({ verdict: 'block', sanctioned: true }));
    const { hook: blockHook } = hookWith(blocked, { now: () => blockClock });
    await blockHook(ctx());
    blockClock = 59 * 60_000;
    expect(await blockHook(ctx())).toMatchObject({ abort: true, reason: 'payer_sanctioned' });
    expect(blocked.kyaByWallet).toHaveBeenCalledTimes(1);
  });

  it('shares one lookup between concurrent payments from the same payer', async () => {
    let release!: (p: KyaProfile) => void;
    const client = fakeClient(() => new Promise<KyaProfile>((resolve) => (release = resolve)));
    const { hook } = hookWith(client, { timeoutMs: 1000 });
    const first = hook(ctx());
    const second = hook(ctx());
    release(profile());
    expect(await Promise.all([first, second])).toEqual([undefined, undefined]);
    expect(client.kyaByWallet).toHaveBeenCalledTimes(1);
  });

  it('does not cache an incomplete check', async () => {
    const client = fakeClient(async () => profile({ verdict: 'review', flags: [flag('K13')] }));
    const { hook } = hookWith(client);
    await hook(ctx());
    await hook(ctx());
    expect(client.kyaByWallet).toHaveBeenCalledTimes(2);
  });

  describe('a wallet with no agent', () => {
    it('is screened by default: clean accepts, sanctioned refuses', async () => {
      const clean = fakeClient(async () => null);
      expect(await hookWith(clean).hook(ctx())).toBeUndefined();
      expect(clean.sanctionsScreen).toHaveBeenCalledWith(PAYER);

      const listed = fakeClient(async () => null, true);
      expect(await hookWith(listed).hook(ctx())).toMatchObject({ abort: true, reason: 'payer_sanctioned' });
    });

    it('can be refused or accepted without a screen', async () => {
      const refuse = fakeClient(async () => null);
      expect(await hookWith(refuse, { policy: { noAgent: 'refuse' } }).hook(ctx())).toMatchObject({
        abort: true,
        reason: 'payer_not_registered_agent',
      });
      expect(refuse.sanctionsScreen).not.toHaveBeenCalled();

      const accept = fakeClient(async () => null);
      expect(await hookWith(accept, { policy: { noAgent: 'accept' } }).hook(ctx())).toBeUndefined();
      expect(accept.sanctionsScreen).not.toHaveBeenCalled();
    });
  });

  describe('when Cred cannot answer', () => {
    it('fails open after the OFAC screen, and refuses a sanctioned payer even then', async () => {
      const down = fakeClient(async () => {
        throw new CredAPIError(503, 'down');
      });
      const { hook, decisions } = hookWith(down);
      expect(await hook(ctx())).toBeUndefined();
      expect(decisions[0].source).toBe('fallback_screen');

      const downListed = fakeClient(async () => {
        throw new CredAPIError(503, 'down');
      }, true);
      expect(await hookWith(downListed).hook(ctx())).toMatchObject({ abort: true, reason: 'payer_sanctioned' });
    });

    it('accepts unchecked only when the screen fails too', async () => {
      const client = fakeClient(async () => {
        throw new Error('network');
      });
      client.sanctionsScreen.mockRejectedValue(new Error('network'));
      const { hook, decisions } = hookWith(client);
      expect(await hook(ctx())).toBeUndefined();
      expect(decisions[0]).toMatchObject({ accept: true, source: 'error' });
    });

    it('refuses when failing closed', async () => {
      const client = fakeClient(async () => {
        throw new Error('network');
      });
      const { hook } = hookWith(client, { policy: { onError: 'refuse' } });
      expect(await hook(ctx())).toMatchObject({ abort: true, reason: 'payer_screening_unavailable' });
      expect(client.sanctionsScreen).not.toHaveBeenCalled();
    });

    it('decides a slow lookup by policy, then uses its answer once it lands', async () => {
      let release!: (p: KyaProfile) => void;
      const client = fakeClient(() => new Promise<KyaProfile>((resolve) => (release = resolve)));
      const { hook, decisions } = hookWith(client, { timeoutMs: 10 });
      expect(await hook(ctx())).toBeUndefined();
      expect(decisions[0].source).toBe('fallback_screen');

      release(profile({ verdict: 'block', sanctioned: true }));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(await hook(ctx())).toMatchObject({ abort: true, reason: 'payer_sanctioned' });
      expect(decisions[1].source).toBe('cache');
      expect(client.kyaByWallet).toHaveBeenCalledTimes(1);
    });

    it('never throws, even when the audit callback does', async () => {
      const { hook } = hookWith(fakeClient(async () => profile()), {
        onDecision: () => {
          throw new Error('logger down');
        },
      });
      await expect(hook(ctx())).resolves.toBeUndefined();
    });
  });

  it('with no payer to screen, refuses only when failing closed', async () => {
    const client = fakeClient(async () => profile());
    const noPayer: KyaVerifyContext = { result: { isValid: true } };
    expect(await hookWith(client).hook(noPayer)).toBeUndefined();
    expect(await hookWith(client, { policy: { onError: 'refuse' } }).hook(noPayer)).toMatchObject({
      abort: true,
      reason: 'payer_screening_unavailable',
    });
    expect(client.kyaByWallet).not.toHaveBeenCalled();
  });
});

describe('CredKyaClient', () => {
  function stubFetch(status: number, body: unknown) {
    return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
      new Response(typeof body === 'string' ? body : JSON.stringify(body), { status }),
    );
  }

  it('reads a profile by wallet with the API key', async () => {
    const fetchStub = stubFetch(200, {
      agent_id: 22,
      verdict: 'review',
      flags: [{ code: 'K08', flag: 'new_registration', severity: 'review', description: 'x', subject: null }],
      unavailable: [],
      compliance: { sanctioned: false, lists_checked: ['ofac_sdn'], exposure_risk: 'none' },
      resolved_from: PAYER,
    });
    const client = new CredKyaClient({ apiKey: 'key', baseUrl: 'https://api.example.com/', fetch: fetchStub as any });
    const result = await client.kyaByWallet(PAYER);
    expect(result).toMatchObject({ agentId: 22, verdict: 'review', listsChecked: ['ofac_sdn'], resolvedFrom: PAYER });
    expect(result?.flags[0].code).toBe('K08');
    const [url, init] = fetchStub.mock.calls[0];
    expect(url).toBe(`https://api.example.com/api/v2/agents/by-wallet/${PAYER}/kya`);
    expect((init?.headers as Record<string, string>).Authorization).toBe('Bearer key');
  });

  it('maps a 404 to null and other errors to CredAPIError', async () => {
    const missing = new CredKyaClient({ apiKey: 'k', fetch: stubFetch(404, '{"detail":"none"}') as any });
    expect(await missing.kyaByWallet(PAYER)).toBeNull();
    expect(await missing.kyaByAgentId(5)).toBeNull();

    const broken = new CredKyaClient({ apiKey: 'k', fetch: stubFetch(402, 'pay') as any });
    await expect(broken.kyaByWallet(PAYER)).rejects.toBeInstanceOf(CredAPIError);
  });

  it('screens an address', async () => {
    const client = new CredKyaClient({
      apiKey: 'k',
      fetch: stubFetch(200, { address: PAYER, sanctioned: true, lists_checked: ['ofac_sdn'], matches: [{ source: 'ofac_sdn' }] }) as any,
    });
    expect(await client.sanctionsScreen(PAYER)).toMatchObject({ sanctioned: true, matches: [{ source: 'ofac_sdn' }] });
  });

  it('requires an API key', () => {
    expect(() => new CredKyaClient({ apiKey: '' })).toThrow('apiKey');
  });
});
