import type { Context, MiddlewareHandler } from 'hono';
import { createGate, notifyEvaluation, walletFromRequest } from '@cred-protocol/sdk';
import type {
  CredGateConfig,
  GateEvaluationListener,
  TrustResult,
  PricingCurve,
} from '@cred-protocol/sdk';

/**
 * Middleware options: the shared gate configuration (`apiKey`, `policy`,
 * `gates`, `operator`, `pricing`, `on402`, `onBlocked`, `headers`, ...) plus
 * the Hono-specific hooks.
 */
export interface CredGatesOptions extends CredGateConfig {
  /**
   * Extract the wallet address from the request.
   * Defaults to checking X-Wallet-Address header, then query param `wallet`.
   */
  extractWallet?: (c: Context) => string | null | Promise<string | null>;

  /** Called after every completed evaluation, allowed or denied (for logging, analytics, etc.). */
  onEvaluation?: GateEvaluationListener<Context>;
}

const defaultExtractWallet = (c: Context): string | null =>
  walletFromRequest({
    header: (name) => c.req.header(name),
    query: (name) => c.req.query(name),
  });

/**
 * Hono middleware for Cred Protocol trust-gated APIs.
 *
 * @example
 * ```ts
 * import { credGates } from '@cred-protocol/hono'
 *
 * app.use('/api/*', credGates({
 *   apiKey: process.env.CRED_API_KEY,
 *   policy: 'standard',
 *   pricing: { enabled: true, curve: 'step', basePriceUsdc: 0.01 },
 *   on402: 'challenge',
 *   headers: true,
 * }))
 *
 * app.get('/api/resource', (c) => {
 *   const score = c.req.header('X-Cred-Trust-Score')
 *   return c.json({ data: '...' })
 * })
 * ```
 */
export function credGates(options: CredGatesOptions): MiddlewareHandler {
  const gate = createGate(options);
  const extractWallet = options.extractWallet || defaultExtractWallet;

  return async (c, next) => {
    const decision = await gate.evaluate(await extractWallet(c));

    // Trust headers go on every response that follows an evaluation, denials included
    for (const [name, value] of Object.entries(decision.headers)) {
      c.header(name, value);
    }

    await notifyEvaluation(decision, options.onEvaluation, c);

    if (!decision.allow) {
      return c.json(decision.body as Record<string, unknown>, decision.status);
    }

    // Store result on request for handler access
    c.set('credTrust', decision.result);

    await next();
  };
}

// Re-export SDK types for convenience
export type { TrustResult, PricingCurve } from '@cred-protocol/sdk';
