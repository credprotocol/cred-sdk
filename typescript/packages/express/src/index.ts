import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { createGate, notifyEvaluation, walletFromRequest } from '@cred-protocol/sdk';
import type {
  CredGateConfig,
  GateEvaluationListener,
  TrustResult,
  PricingCurve,
} from '@cred-protocol/sdk';

declare global {
  namespace Express {
    interface Request {
      credTrust?: TrustResult;
    }
  }
}

/**
 * Middleware options: the shared gate configuration (`apiKey`, `policy`,
 * `gates`, `operator`, `pricing`, `on402`, `onBlocked`, `headers`, ...) plus
 * the Express-specific hooks.
 */
export interface CredGatesOptions extends CredGateConfig {
  /** Extract wallet address from request. Defaults to X-Wallet-Address header or ?wallet query param. */
  extractWallet?: (req: Request) => string | null | Promise<string | null>;

  /** Called after every completed evaluation, allowed or denied (for logging, analytics, etc.). */
  onEvaluation?: GateEvaluationListener<Request>;
}

const defaultExtractWallet = (req: Request): string | null =>
  walletFromRequest({
    header: (name) => req.headers[name.toLowerCase()] as string | undefined,
    query: (name) => req.query[name] as string | undefined,
  });

/**
 * Express middleware for Cred Protocol trust-gated APIs.
 *
 * @example
 * ```ts
 * import { credGates } from '@cred-protocol/express'
 *
 * app.use('/api', credGates({
 *   apiKey: process.env.CRED_API_KEY,
 *   policy: 'standard',
 * }))
 *
 * app.get('/api/resource', (req, res) => {
 *   const trust = req.credTrust!;
 *   res.json({ score: trust.trustScore, tier: trust.trustTier });
 * })
 * ```
 */
export function credGates(options: CredGatesOptions): RequestHandler {
  const gate = createGate(options);
  const extractWallet = options.extractWallet || defaultExtractWallet;

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const decision = await gate.evaluate(await extractWallet(req));

      // Trust headers go on every response that follows an evaluation, denials included
      for (const [name, value] of Object.entries(decision.headers)) {
        res.setHeader(name, value);
      }

      await notifyEvaluation(decision, options.onEvaluation, req);

      if (!decision.allow) {
        res.status(decision.status).json(decision.body);
        return;
      }

      // Attach to request
      req.credTrust = decision.result;
      next();
    } catch (err) {
      next(err);
    }
  };
}

export type { TrustResult, PricingCurve } from '@cred-protocol/sdk';
