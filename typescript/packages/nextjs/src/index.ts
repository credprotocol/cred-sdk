import { NextRequest, NextResponse } from 'next/server';
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
 * the Next.js-specific hooks.
 */
export interface CredGatesOptions extends CredGateConfig {
  /**
   * Route matcher patterns. Only matched routes are trust-gated.
   * Supports Next.js middleware matcher patterns.
   */
  matcher?: string[];

  /** Extract wallet address from request. Defaults to X-Wallet-Address header or ?wallet query param. */
  extractWallet?: (req: NextRequest) => string | null | Promise<string | null>;

  /** Called after every completed evaluation, allowed or denied (for logging, analytics, etc.). */
  onEvaluation?: GateEvaluationListener<NextRequest>;
}

const defaultExtractWallet = (req: NextRequest): string | null =>
  walletFromRequest({
    header: (name) => req.headers.get(name),
    query: (name) => req.nextUrl.searchParams.get(name),
  });

function matchesPath(pathname: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    // Convert Next.js-style patterns to regex
    const regexStr = pattern
      .replace(/\*/g, '.*')
      .replace(/:path\*/g, '.*')
      .replace(/:(\w+)/g, '[^/]+');
    if (new RegExp(`^${regexStr}$`).test(pathname)) {
      return true;
    }
  }
  return false;
}

/**
 * Create a Next.js middleware that gates routes with Cred Protocol trust checks.
 *
 * @example
 * ```ts
 * // middleware.ts
 * import { credGates } from '@cred-protocol/nextjs'
 *
 * export const middleware = credGates({
 *   apiKey: process.env.CRED_API_KEY!,
 *   policy: 'standard',
 *   matcher: ['/api/:path*'],
 * })
 *
 * export const config = { matcher: ['/api/:path*'] }
 * ```
 */
export function credGates(
  options: CredGatesOptions,
): (req: NextRequest) => Promise<NextResponse> {
  const gate = createGate(options);
  const extractWallet = options.extractWallet || defaultExtractWallet;
  const matcher = options.matcher || [];

  return async (req: NextRequest): Promise<NextResponse> => {
    // Check matcher
    if (matcher.length > 0 && !matchesPath(req.nextUrl.pathname, matcher)) {
      return NextResponse.next();
    }

    const decision = await gate.evaluate(await extractWallet(req));

    await notifyEvaluation(decision, options.onEvaluation, req);

    const response = decision.allow
      ? NextResponse.next()
      : NextResponse.json(decision.body, { status: decision.status });

    // Trust headers go on every response that follows an evaluation, denials included
    for (const [name, value] of Object.entries(decision.headers)) {
      response.headers.set(name, value);
    }
    return response;
  };
}

export type { TrustResult, PricingCurve } from '@cred-protocol/sdk';
