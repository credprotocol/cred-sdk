import { CredAPIError, CredClient } from './client';
import type { EvaluateOptions, GateOperator, PricingCurve, TrustResult } from './types';

/**
 * Framework-agnostic trust-gate logic shared by the Express, Hono and
 * Next.js middleware packages. An adapter extracts the wallet from its
 * framework's request, calls {@link Gate.evaluate} (or {@link evaluateGate}
 * directly) and maps the returned {@link GateDecision} onto its framework's
 * response: status, JSON body and headers.
 */

/** Request header the default wallet extraction reads first. */
export const WALLET_HEADER = 'X-Wallet-Address';

/** Query parameter the default wallet extraction falls back to. */
export const WALLET_QUERY_PARAM = 'wallet';

/** Body of the 400 response when no wallet address can be found. */
export const MISSING_WALLET_MESSAGE =
  'Missing wallet address. Provide X-Wallet-Address header or ?wallet= query param.';

/** Response headers set from a trust result. */
export const TRUST_HEADERS = {
  score: 'X-Cred-Trust-Score',
  tier: 'X-Cred-Trust-Tier',
  requestId: 'X-Cred-Request-Id',
  priceMultiplier: 'X-Cred-Price-Multiplier',
} as const;

/** What to do with a wallet that fails the gate checks. */
export type GateFailureAction = 'challenge' | 'deny' | 'pass';

/** What to do with a wallet whose trust tier is "blocked". */
export type GateBlockedAction = 'deny' | 'challenge' | 'pass';

/** Dynamic pricing configuration. */
export interface GatePricingOptions {
  enabled?: boolean;
  curve?: PricingCurve;
  basePriceUsdc?: number;
}

/** Gate options that do not depend on the web framework. */
export interface GateOptions {
  /** Named policy template (e.g., "standard", "strict"). */
  policy?: string;

  /** Custom gate list (alternative to policy). */
  gates?: string[];

  /** Gate stacking operator. */
  operator?: GateOperator;

  /** Dynamic pricing configuration. */
  pricing?: GatePricingOptions;

  /**
   * How to handle failed gates.
   * - "challenge": 402 with the Cred challenge body (default; falls through
   *   to allow when the API returned no challenge)
   * - "deny": 403
   * - "pass": allow through with headers set
   */
  on402?: GateFailureAction;

  /**
   * How to handle wallets with trust_tier = "blocked".
   * - "deny": 403 (default)
   * - "challenge": 402 with the Cred challenge body (falls through to the
   *   failed-gate handling when the API returned no challenge)
   * - "pass": allow through
   */
  onBlocked?: GateBlockedAction;

  /** Compute the X-Cred-* trust headers (default true). */
  headers?: boolean;
}

/** {@link GateOptions} plus what is needed to build the API client. */
export interface CredGateConfig extends GateOptions {
  /** Cred Platform API key. */
  apiKey: string;

  /** Base URL for the Cred API (defaults to production). */
  baseUrl?: string;
}

/** The part of {@link CredClient} a gate needs; lets tests pass a fake. */
export interface GateClient {
  evaluate(options: EvaluateOptions): Promise<TrustResult>;
}

/** Why a request was not allowed through. */
export type GateDecisionReason =
  | 'missing_wallet'
  | 'rate_limited'
  | 'evaluation_failed'
  | 'blocked'
  | 'gates_failed';

/** Status codes a gate can answer with. */
export type GateDenyStatus = 400 | 402 | 403 | 429 | 502;

/** The request may proceed to the handler. */
export interface GateAllowed {
  allow: true;
  result: TrustResult;
  /** Trust headers to set on the response (empty when `headers: false`). */
  headers: Record<string, string>;
}

/** The request must be answered by the middleware. */
export interface GateDenied {
  allow: false;
  status: GateDenyStatus;
  /** JSON body to send. */
  body: unknown;
  /** Trust headers to set on the response (empty before an evaluation exists). */
  headers: Record<string, string>;
  reason: GateDecisionReason;
  /** Present when the evaluation itself succeeded (blocked / failed gates). */
  result?: TrustResult;
  /** Present when the Cred API answered with an error. */
  error?: CredAPIError;
}

export type GateDecision = GateAllowed | GateDenied;

/**
 * Listener an adapter calls after every completed evaluation, whether the
 * request was allowed or denied. `C` is the framework's request/context.
 */
export type GateEvaluationListener<C> = (result: TrustResult, context: C) => void | Promise<void>;

/**
 * Call `listener` with the decision's trust result, if there is one (a
 * missing wallet or an API error produces no result). A throwing listener
 * never affects the response: the error is swallowed.
 */
export async function notifyEvaluation<C>(
  decision: GateDecision,
  listener: GateEvaluationListener<C> | undefined,
  context: C,
): Promise<void> {
  if (!listener || !decision.result) return;
  try {
    await listener(decision.result, context);
  } catch {
    // Observability hooks are non-blocking by contract.
  }
}

/** Minimal view of a request for {@link walletFromRequest}. */
export interface WalletSource {
  /** Read a request header (case-insensitive name). */
  header(name: string): string | null | undefined;
  /** Read a query-string parameter. */
  query(name: string): string | null | undefined;
}

/**
 * Default wallet extraction: the `X-Wallet-Address` header, then the
 * `?wallet=` query parameter, else `null`.
 */
export function walletFromRequest(source: WalletSource): string | null {
  return source.header(WALLET_HEADER) || source.query(WALLET_QUERY_PARAM) || null;
}

/** The X-Cred-* headers describing a trust result. */
export function trustHeaders(result: TrustResult): Record<string, string> {
  const headers: Record<string, string> = {
    [TRUST_HEADERS.score]: String(result.trustScore),
    [TRUST_HEADERS.tier]: result.trustTier,
    [TRUST_HEADERS.requestId]: result.requestId,
  };
  if (result.priceMultiplier != null) {
    headers[TRUST_HEADERS.priceMultiplier] = String(result.priceMultiplier);
  }
  return headers;
}

/** The evaluate call a gate makes for a wallet. */
export function toEvaluateOptions(options: GateOptions, wallet: string): EvaluateOptions {
  return {
    walletAddress: wallet,
    policy: options.policy,
    gates: options.gates,
    operator: options.operator,
    includePricing: !!options.pricing?.enabled,
    basePriceUsdc: options.pricing?.basePriceUsdc,
    includeReputation: true,
  };
}

/**
 * Turn a trust result into a decision: blocked tier first, then failed
 * gates, else allow. Pure; see {@link evaluateGate} for the full flow.
 */
export function decideFromResult(result: TrustResult, options: GateOptions): GateDecision {
  const on402 = options.on402 || 'challenge';
  const onBlocked = options.onBlocked || 'deny';
  const headers = options.headers ?? true ? trustHeaders(result) : {};

  const deny = (status: GateDenyStatus, reason: GateDecisionReason, body: unknown): GateDenied => ({
    allow: false,
    status,
    body,
    headers,
    reason,
    result,
  });

  if (result.trustTier === 'blocked') {
    if (onBlocked === 'deny') {
      return deny(403, 'blocked', {
        error: 'Access denied',
        trustTier: result.trustTier,
        trustScore: result.trustScore,
      });
    }
    if (onBlocked === 'challenge' && result.challenge) {
      return deny(402, 'blocked', result.challenge);
    }
    // 'pass' (or no challenge to serve) — fall through
  }

  if (!result.allPassed) {
    if (on402 === 'challenge' && result.challenge) {
      return deny(402, 'gates_failed', result.challenge);
    }
    if (on402 === 'deny') {
      return deny(403, 'gates_failed', {
        error: 'Trust requirements not met',
        trustTier: result.trustTier,
        trustScore: result.trustScore,
        failedGates: result.raw.policyResult.failedGates,
      });
    }
    // 'pass' (or no challenge to serve) — fall through
  }

  return { allow: true, result, headers };
}

/**
 * Evaluate a wallet against the gate options and decide what to do with
 * the request. API errors become 429/502 decisions; any other error
 * (network failure, a throwing `extractWallet`) propagates to the caller.
 */
export async function evaluateGate(
  client: GateClient,
  options: GateOptions,
  wallet: string | null | undefined,
): Promise<GateDecision> {
  if (!wallet) {
    return {
      allow: false,
      status: 400,
      body: { error: MISSING_WALLET_MESSAGE },
      headers: {},
      reason: 'missing_wallet',
    };
  }

  let result: TrustResult;
  try {
    result = await client.evaluate(toEvaluateOptions(options, wallet));
  } catch (err) {
    if (err instanceof CredAPIError) {
      if (err.status === 429) {
        return {
          allow: false,
          status: 429,
          body: { error: 'Rate limit exceeded' },
          headers: {},
          reason: 'rate_limited',
          error: err,
        };
      }
      return {
        allow: false,
        status: 502,
        body: { error: 'Trust evaluation failed', detail: err.body },
        headers: {},
        reason: 'evaluation_failed',
        error: err,
      };
    }
    throw err;
  }

  return decideFromResult(result, options);
}

/** A configured gate: one client plus the options every request is judged by. */
export interface Gate {
  readonly client: CredClient;
  readonly options: GateOptions;
  /** {@link evaluateGate} bound to this gate's client and options. */
  evaluate(wallet: string | null | undefined): Promise<GateDecision>;
}

/**
 * Build a gate from a config. The framework adapters call this once at
 * middleware construction and `gate.evaluate(wallet)` per request.
 *
 * @example
 * ```ts
 * const gate = createGate({ apiKey: process.env.CRED_API_KEY!, policy: 'standard' });
 * const decision = await gate.evaluate(walletFromRequest({ header, query }));
 * if (!decision.allow) return respond(decision.status, decision.body, decision.headers);
 * ```
 */
export function createGate(config: CredGateConfig): Gate {
  // Pick the known keys so an adapter can pass its own options object
  // (with framework-specific extras) straight through.
  const { apiKey, baseUrl, policy, gates, operator, pricing, on402, onBlocked, headers } = config;
  const options: GateOptions = { policy, gates, operator, pricing, on402, onBlocked, headers };
  const client = new CredClient({ apiKey, baseUrl });
  return {
    client,
    options,
    evaluate: (wallet) => evaluateGate(client, options, wallet),
  };
}
