/**
 * Know Your Agent (KYA) for x402 sellers.
 *
 * `credKyaHook()` builds an `onAfterVerify` hook for an `@x402/core`
 * `x402ResourceServer`. After the facilitator has verified a payment (so the
 * payer really signed it), the hook asks Cred whether the paying agent is OK
 * to accept money from, and aborts the payment before it settles when the
 * seller's policy says no. The payer then gets a 402 whose `error` is one of
 * the `KYA_REASONS` codes; nothing moves on chain.
 *
 * ```ts
 * import { x402ResourceServer } from '@x402/core/server';
 * import { credKyaHook } from '@cred-protocol/sdk';
 *
 * server.onAfterVerify(credKyaHook({ apiKey: process.env.CRED_API_KEY! }));
 * ```
 *
 * The x402 server logs and ignores a hook that throws and lets the payment
 * through, so this hook never throws: every failure is turned into an
 * explicit accept or refuse by `onError`.
 *
 * `onAfterVerify` runs only in flows that verify before the handler (the
 * default `authorization` flow of EVM `exact`). Use `registerCredKya(server,
 * options)` to also cover the `upfront` and `escrow` flows.
 *
 * See https://docs.credprotocol.com/know-your-agent for the flags.
 */

import { CredAPIError } from './client';

export const DEFAULT_API_BASE_URL = 'https://api.credprotocol.com';

/**
 * Codes the hook aborts with. They reach the payer as the 402 `error`
 * (x402 does not forward the longer message), so each one explains itself.
 */
export const KYA_REASONS = {
  sanctioned: 'payer_sanctioned',
  needsReview: 'payer_needs_review',
  notAnAgent: 'payer_not_registered_agent',
  unavailable: 'payer_screening_unavailable',
} as const;

export type KyaReason = (typeof KYA_REASONS)[keyof typeof KYA_REASONS];

export type KyaVerdict = 'pass' | 'review' | 'block';
export type KyaSeverity = 'block' | 'review' | 'info';

export interface KyaFlag {
  code: string;
  flag: string;
  severity: KyaSeverity;
  description: string;
  subject: string | null;
}

/** The decision-relevant part of a KYA profile; `raw` is the full API body. */
export interface KyaProfile {
  agentId: number;
  verdict: KyaVerdict;
  flags: KyaFlag[];
  unavailable: string[];
  sanctioned: boolean;
  listsChecked: string[];
  exposureRisk: string | null;
  resolvedFrom: string | null;
  raw: Record<string, any>;
}

export interface SanctionsScreen {
  address: string;
  sanctioned: boolean;
  listsChecked: string[];
  matches: Record<string, any>[];
}

export interface CredKyaClientConfig {
  /** A Cred API key from app.credprotocol.com. */
  apiKey: string;
  /** Defaults to https://api.credprotocol.com */
  baseUrl?: string;
  /** Injectable for tests and non-standard runtimes. Defaults to global fetch. */
  fetch?: typeof fetch;
}

function mapProfile(raw: Record<string, any>): KyaProfile {
  const compliance = raw.compliance ?? {};
  return {
    agentId: raw.agent_id,
    verdict: raw.verdict,
    flags: (raw.flags ?? []).map((f: any) => ({
      code: f.code,
      flag: f.flag,
      severity: f.severity,
      description: f.description,
      subject: f.subject ?? null,
    })),
    unavailable: raw.unavailable ?? [],
    sanctioned: Boolean(compliance.sanctioned),
    listsChecked: compliance.lists_checked ?? [],
    exposureRisk: compliance.exposure_risk ?? null,
    resolvedFrom: raw.resolved_from ?? null,
    raw,
  };
}

/** Client for the KYA and sanctions-screen routes of the Cred API. */
export class CredKyaClient {
  private apiKey: string;
  private baseUrl: string;
  private fetchImpl: typeof fetch;

  constructor(config: CredKyaClientConfig) {
    if (!config.apiKey) {
      throw new Error('CredKyaClient requires an apiKey');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || DEFAULT_API_BASE_URL).replace(/\/$/, '');
    this.fetchImpl = config.fetch ?? fetch;
  }

  private async get(path: string, signal?: AbortSignal): Promise<Response> {
    return this.fetchImpl(`${this.baseUrl}${path}`, {
      headers: { Authorization: `Bearer ${this.apiKey}`, Accept: 'application/json' },
      signal,
    });
  }

  /**
   * KYA profile of the agent a wallet controls (as owner or agentWallet),
   * or `null` when the wallet controls no ERC-8004 agent (a free 404).
   * 10 Cred Units.
   */
  async kyaByWallet(address: string, signal?: AbortSignal): Promise<KyaProfile | null> {
    const response = await this.get(`/api/v2/agents/by-wallet/${encodeURIComponent(address)}/kya`, signal);
    if (response.status === 404) return null;
    if (!response.ok) throw new CredAPIError(response.status, await response.text());
    return mapProfile(await response.json());
  }

  /** KYA profile of an agent by its ERC-8004 id, or `null` if it does not exist. 10 Cred Units. */
  async kyaByAgentId(agentId: number, signal?: AbortSignal): Promise<KyaProfile | null> {
    const response = await this.get(`/api/v2/agents/${agentId}/kya`, signal);
    if (response.status === 404) return null;
    if (!response.ok) throw new CredAPIError(response.status, await response.text());
    return mapProfile(await response.json());
  }

  /** OFAC screen of one address. 1 Cred Unit. */
  async sanctionsScreen(address: string, signal?: AbortSignal): Promise<SanctionsScreen> {
    const response = await this.get(`/api/v2/sanctions/screen/${encodeURIComponent(address)}`, signal);
    if (!response.ok) throw new CredAPIError(response.status, await response.text());
    const raw = await response.json();
    return {
      address: raw.address,
      sanctioned: Boolean(raw.sanctioned),
      listsChecked: raw.lists_checked ?? [],
      matches: raw.matches ?? [],
    };
  }
}

// ---------------------------------------------------------------------------
// The hook
// ---------------------------------------------------------------------------

/**
 * The parts of `@x402/core`'s `VerifyResultContext` the hook reads. Declared
 * structurally so the SDK does not depend on `@x402/core`; an
 * `x402ResourceServer` accepts the hook as an `AfterVerifyHook`.
 */
export interface KyaVerifyContext {
  result: { readonly isValid: boolean; readonly payer?: string };
  paymentPayload?: { readonly payload?: unknown };
  requirements?: unknown;
}

export type KyaHookResult = void | { abort: true; reason: string; message?: string };

export type KyaDecisionSource = 'kya' | 'screen' | 'cache' | 'fallback_screen' | 'error';

export interface KyaDecision {
  payer: string | null;
  accept: boolean;
  /** Set when `accept` is false. */
  reason?: KyaReason;
  source: KyaDecisionSource;
  verdict?: KyaVerdict;
  flags?: string[];
  agentId?: number;
  /** Lists the payer was screened against, for the seller's records. */
  listsChecked?: string[];
  /**
   * A check behind the profile did not complete (K13). The controllers' OFAC
   * screen always completes, so the payer was still found unsanctioned; the
   * `onError` policy decided, and the decision is not cached.
   */
  incomplete?: boolean;
  error?: unknown;
}

export interface CredKyaPolicy {
  /**
   * What to do with a `review` verdict: accept, refuse, or decide per payment.
   * Flags in `refuseFlags` refuse whatever this says. Default `'accept'`.
   */
  review?: 'accept' | 'refuse' | ((profile: KyaProfile, context: KyaVerifyContext) => boolean);
  /**
   * Review flags that always refuse. Default K02 (first funded by a sanctioned
   * address) and K03 (transacted with a sanctioned address).
   */
  refuseFlags?: string[];
  /**
   * The payer's wallet controls no ERC-8004 agent: `'screen'` runs the OFAC
   * screen (1 CU) and accepts unless it is sanctioned; `'refuse'` serves only
   * registered agents; `'accept'` skips any check. Default `'screen'`.
   */
  noAgent?: 'screen' | 'refuse' | 'accept';
  /**
   * Cred could not answer in time (or at all), or a check did not complete
   * (K13). `'accept'` still runs the fast OFAC screen first and refuses a
   * sanctioned payer; only if that also fails is the payment accepted
   * unchecked. `'refuse'` refuses. Default `'accept'`.
   */
  onError?: 'accept' | 'refuse';
}

export interface CredKyaHookOptions extends CredKyaClientConfig {
  policy?: CredKyaPolicy;
  /**
   * How long to wait for the KYA profile, in ms. A first call on a new wallet
   * builds two credit reports and can take several seconds; when it runs over,
   * the `onError` policy decides this payment and the call keeps running in
   * the background so the payer's next payment uses the full answer.
   * Default 1500.
   */
  timeoutMs?: number;
  /** Timeout of the fallback OFAC screen, in ms. Default 1000. */
  screenTimeoutMs?: number;
  /** Cache lifetime per payer decision, in ms. `block` defaults to 1 h (the lists refresh hourly), others to 15 min. */
  cacheTtlMs?: { pass?: number; review?: number; block?: number; noAgent?: number };
  /** Payers kept in the decision cache. Default 10,000. */
  cacheSize?: number;
  /** Called with every decision (cache hits included); errors it throws are swallowed. Use it for audit records. */
  onDecision?: (decision: KyaDecision, context: KyaVerifyContext) => void | Promise<void>;
  /** For tests. */
  client?: Pick<CredKyaClient, 'kyaByWallet' | 'sanctionsScreen'>;
  /** For tests. Defaults to Date.now. */
  now?: () => number;
}

const MINUTE = 60_000;
const DEFAULT_REFUSE_FLAGS = ['K02', 'K03'];
const INCOMPLETE_FLAG = 'K13';

/** The payer of a verified payment: the facilitator's `payer`, else the signer in an EVM `exact` payload. */
export function payerFromContext(context: KyaVerifyContext): string | null {
  const fromResult = context.result?.payer;
  if (typeof fromResult === 'string' && fromResult) return fromResult.toLowerCase();
  const payload = context.paymentPayload?.payload as any;
  const from = payload?.authorization?.from ?? payload?.permit2Authorization?.from;
  return typeof from === 'string' && from ? from.toLowerCase() : null;
}

class TimeoutError extends Error {
  constructor() {
    super('timed out');
    this.name = 'TimeoutError';
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout>;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new TimeoutError()), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

interface CacheEntry {
  decision: KyaDecision;
  expiresAt: number;
}

/** What a KYA profile means under the seller's policy. */
export function decideFromProfile(
  profile: KyaProfile,
  policy: CredKyaPolicy,
  context: KyaVerifyContext,
  payer: string | null,
): KyaDecision {
  const base = {
    payer,
    source: 'kya' as const,
    verdict: profile.verdict,
    flags: profile.flags.map((f) => f.code),
    agentId: profile.agentId,
    listsChecked: profile.listsChecked,
  };
  if (profile.verdict === 'block' || profile.sanctioned) {
    return { ...base, accept: false, reason: KYA_REASONS.sanctioned };
  }
  if (profile.verdict === 'pass') {
    return { ...base, accept: true };
  }

  const refuseFlags = new Set(policy.refuseFlags ?? DEFAULT_REFUSE_FLAGS);
  if (profile.flags.some((f) => refuseFlags.has(f.code))) {
    return { ...base, accept: false, reason: KYA_REASONS.needsReview };
  }
  // Review only because a check did not complete: not an answer about the
  // payer, so the onError policy decides (and nothing is cached). The direct
  // OFAC screen of the controllers always completes and found nothing, or
  // the verdict would be block.
  const reviewFlags = profile.flags.filter((f) => f.severity === 'review');
  if (reviewFlags.length > 0 && reviewFlags.every((f) => f.code === INCOMPLETE_FLAG)) {
    return policy.onError === 'refuse'
      ? { ...base, accept: false, reason: KYA_REASONS.unavailable, incomplete: true }
      : { ...base, accept: true, incomplete: true };
  }

  const review = policy.review ?? 'accept';
  const accept = typeof review === 'function' ? review(profile, context) : review === 'accept';
  return accept ? { ...base, accept: true } : { ...base, accept: false, reason: KYA_REASONS.needsReview };
}

function abortFor(decision: KyaDecision): KyaHookResult {
  if (decision.accept) return undefined;
  const flags = decision.flags?.length ? ` (flags ${decision.flags.join(', ')})` : '';
  return {
    abort: true,
    reason: decision.reason ?? KYA_REASONS.needsReview,
    message: `Cred Know Your Agent refused payer ${decision.payer ?? 'unknown'}${flags}`,
  };
}

/**
 * Build an `onAfterVerify` hook that screens the payer with Cred's Know Your
 * Agent endpoint before an x402 payment settles.
 */
export function credKyaHook(options: CredKyaHookOptions): (context: KyaVerifyContext) => Promise<KyaHookResult> {
  const screen = createScreener(options);
  return async function credKyaAfterVerify(context: KyaVerifyContext): Promise<KyaHookResult> {
    if (!context?.result?.isValid) return undefined;
    return screen(context);
  };
}

/** The parts of `@x402/core`'s `SettleContext` the settle hook reads. */
export interface KyaSettleContext {
  phase: string;
  paymentPayload?: { readonly payload?: unknown };
  requirements?: unknown;
}

/** Any `x402ResourceServer`: only its hook registration is used. */
export interface KyaHookableServer {
  onAfterVerify(hook: (context: any) => Promise<any>): unknown;
  onBeforeSettle(hook: (context: any) => Promise<any>): unknown;
}

/**
 * Register Know Your Agent screening on an `x402ResourceServer`, covering
 * every payment flow:
 *
 * - `authorization` (the default for EVM `exact`): screened in
 *   `onAfterVerify`, once the facilitator has verified the payment;
 * - `upfront` and `escrow`, which settle before the handler without a
 *   verify step: screened in `onBeforeSettle` at the `before-handler` phase.
 *   The payer there is read from the signed payload, which the facilitator
 *   checks at settle, so a forged payer costs a lookup but never settles.
 *
 * Both hooks share one decision cache, so a payer is looked up once.
 *
 * ```ts
 * registerCredKya(server, { apiKey: process.env.CRED_API_KEY! });
 * ```
 */
export function registerCredKya<S extends KyaHookableServer>(server: S, options: CredKyaHookOptions): S {
  const screen = createScreener(options);
  server.onAfterVerify(async (context: KyaVerifyContext) => {
    if (!context?.result?.isValid) return undefined;
    return screen(context);
  });
  server.onBeforeSettle(async (context: KyaSettleContext) => {
    // after-handler settles follow a verify the first hook already screened;
    // cancel settles return funds and must never be blocked.
    if (context?.phase !== 'before-handler') return undefined;
    return screen({ result: { isValid: true }, paymentPayload: context.paymentPayload, requirements: context.requirements });
  });
  return server;
}

function createScreener(options: CredKyaHookOptions): (context: KyaVerifyContext) => Promise<KyaHookResult> {
  const client = options.client ?? new CredKyaClient(options);
  const policy = options.policy ?? {};
  const now = options.now ?? Date.now;
  const timeoutMs = options.timeoutMs ?? 1500;
  const screenTimeoutMs = options.screenTimeoutMs ?? 1000;
  const ttl = {
    pass: options.cacheTtlMs?.pass ?? 15 * MINUTE,
    review: options.cacheTtlMs?.review ?? 15 * MINUTE,
    block: options.cacheTtlMs?.block ?? 60 * MINUTE,
    noAgent: options.cacheTtlMs?.noAgent ?? 15 * MINUTE,
  };
  const cacheSize = options.cacheSize ?? 10_000;
  const cache = new Map<string, CacheEntry>();
  // One KYA call per payer at a time: concurrent payments share it, and a
  // call that outlived its timeout keeps filling the cache in the background.
  const inflight = new Map<string, Promise<KyaDecision>>();

  function remember(payer: string, decision: KyaDecision) {
    const lifetime =
      decision.source === 'screen'
        ? decision.accept
          ? ttl.noAgent
          : ttl.block
        : decision.verdict === 'block' || decision.reason === KYA_REASONS.sanctioned
          ? ttl.block
          : decision.verdict === 'review'
            ? ttl.review
            : ttl.pass;
    cache.delete(payer);
    cache.set(payer, { decision, expiresAt: now() + lifetime });
    while (cache.size > cacheSize) {
      cache.delete(cache.keys().next().value as string);
    }
  }

  async function lookup(payer: string, context: KyaVerifyContext): Promise<KyaDecision> {
    const profile = await client.kyaByWallet(payer);
    let decision: KyaDecision;
    if (profile === null) {
      if (policy.noAgent === 'accept') {
        decision = { payer, accept: true, source: 'screen' };
      } else if (policy.noAgent === 'refuse') {
        decision = { payer, accept: false, reason: KYA_REASONS.notAnAgent, source: 'screen' };
      } else {
        const screen = await client.sanctionsScreen(payer);
        decision = screen.sanctioned
          ? { payer, accept: false, reason: KYA_REASONS.sanctioned, source: 'screen', listsChecked: screen.listsChecked }
          : { payer, accept: true, source: 'screen', listsChecked: screen.listsChecked };
      }
    } else {
      decision = decideFromProfile(profile, policy, context, payer);
    }
    if (!decision.incomplete) remember(payer, decision);
    return decision;
  }

  async function fallback(payer: string, error: unknown): Promise<KyaDecision> {
    if (policy.onError === 'refuse') {
      return { payer, accept: false, reason: KYA_REASONS.unavailable, source: 'error', error };
    }
    // Fail open, but never past a sanctioned payer: the screen is one fast read.
    try {
      const screen = await withTimeout(client.sanctionsScreen(payer), screenTimeoutMs);
      return screen.sanctioned
        ? { payer, accept: false, reason: KYA_REASONS.sanctioned, source: 'fallback_screen', listsChecked: screen.listsChecked, error }
        : { payer, accept: true, source: 'fallback_screen', listsChecked: screen.listsChecked, error };
    } catch (screenError) {
      return { payer, accept: true, source: 'error', error: screenError };
    }
  }

  async function decide(context: KyaVerifyContext): Promise<KyaDecision> {
    const payer = payerFromContext(context);
    if (!payer) {
      // Nothing to screen. Refuse when failing closed; otherwise let x402's
      // own verification stand.
      return policy.onError === 'refuse'
        ? { payer: null, accept: false, reason: KYA_REASONS.unavailable, source: 'error' }
        : { payer: null, accept: true, source: 'error' };
    }

    const hit = cache.get(payer);
    if (hit && hit.expiresAt > now()) {
      return { ...hit.decision, source: 'cache' };
    }
    if (hit) cache.delete(payer);

    let pending = inflight.get(payer);
    if (!pending) {
      pending = lookup(payer, context).finally(() => inflight.delete(payer));
      // Keep a rejection from surfacing as unhandled once a timed-out
      // caller has stopped waiting.
      pending.catch(() => undefined);
      inflight.set(payer, pending);
    }

    try {
      return await withTimeout(pending, timeoutMs);
    } catch (error) {
      return fallback(payer, error);
    }
  }

  return async function screen(context: KyaVerifyContext): Promise<KyaHookResult> {
    let decision: KyaDecision;
    try {
      decision = await decide(context);
    } catch (error) {
      // decide() handles its own failures; this is the last line so the hook
      // never throws (x402 would ignore the throw and settle).
      decision =
        policy.onError === 'refuse'
          ? { payer: null, accept: false, reason: KYA_REASONS.unavailable, source: 'error', error }
          : { payer: null, accept: true, source: 'error', error };
    }
    if (options.onDecision) {
      try {
        await options.onDecision(decision, context);
      } catch {
        // An audit logger must not change the payment's outcome.
      }
    }
    return abortFor(decision);
  };
}
