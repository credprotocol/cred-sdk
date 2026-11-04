import type {
  CredClientConfig,
  EvaluateOptions,
  EvaluationResponse,
  TrustResult,
} from './types';

const DEFAULT_BASE_URL = 'https://validator.credprotocol.com';

/** Maps snake_case API response to camelCase SDK types. */
function mapResponse(raw: Record<string, any>): EvaluationResponse {
  const ts = raw.trust_score;
  return {
    trustScore: {
      walletAddress: ts.wallet_address,
      trustScore: ts.trust_score,
      trustTier: ts.trust_tier,
      confidence: ts.confidence,
      gateResults: (ts.gate_results || []).map((g: any) => ({
        gateId: g.gate_id,
        gateName: g.gate_name,
        passed: g.passed,
        score: g.score,
        provider: g.provider,
        detail: g.detail,
      })),
      priceMultiplier: ts.price_multiplier,
      suggestedPriceUsdc: ts.suggested_price_usdc,
      reputation: ts.reputation
        ? {
            totalEvaluations: ts.reputation.total_evaluations,
            servicesAccessed: ts.reputation.services_accessed,
            settlementRate: ts.reputation.settlement_rate,
            negativeReports: ts.reputation.negative_reports,
            positiveReports: ts.reputation.positive_reports,
            firstSeen: ts.reputation.first_seen,
            lastSeen: ts.reputation.last_seen,
            riskFlags: ts.reputation.risk_flags || [],
          }
        : null,
      cached: ts.cached,
      cacheExpiresAt: ts.cache_expires_at,
      evaluatedAt: ts.evaluated_at,
    },
    policyResult: {
      policyName: raw.policy_result.policy_name,
      allPassed: raw.policy_result.all_passed,
      operator: raw.policy_result.operator,
      passedGates: raw.policy_result.passed_gates,
      failedGates: raw.policy_result.failed_gates,
      compositeScore: raw.policy_result.composite_score,
    },
    requestId: raw.request_id,
    challenge: raw.challenge,
    evaluationCostUsdc: raw.evaluation_cost_usdc,
    cached: raw.cached,
    apiVersion: raw.api_version,
    evaluatedAt: raw.evaluated_at,
  };
}

function toTrustResult(res: EvaluationResponse): TrustResult {
  return {
    walletAddress: res.trustScore.walletAddress,
    trustScore: res.trustScore.trustScore,
    trustTier: res.trustScore.trustTier,
    confidence: res.trustScore.confidence,
    allPassed: res.policyResult.allPassed,
    gateResults: res.trustScore.gateResults,
    priceMultiplier: res.trustScore.priceMultiplier,
    suggestedPriceUsdc: res.trustScore.suggestedPriceUsdc,
    reputation: res.trustScore.reputation,
    cached: res.cached,
    requestId: res.requestId,
    challenge: res.challenge,
    raw: res,
  };
}

export class CredClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(config: CredClientConfig) {
    if (!config.apiKey) {
      throw new Error('CredClient requires an apiKey');
    }
    this.apiKey = config.apiKey;
    this.baseUrl = (config.baseUrl || DEFAULT_BASE_URL).replace(/\/$/, '');
  }

  /**
   * Evaluate a wallet's trust level.
   *
   * @example
   * ```ts
   * const result = await cred.evaluate({
   *   walletAddress: '0x...',
   *   policy: 'standard',
   * });
   * console.log(result.trustScore, result.trustTier);
   * ```
   */
  async evaluate(options: EvaluateOptions): Promise<TrustResult> {
    const body: Record<string, unknown> = {
      wallet_address: options.walletAddress,
    };

    if (options.policy) body.policy = options.policy;
    if (options.gates) body.gates = options.gates;
    if (options.operator) body.operator = options.operator;
    if (options.compositeThreshold != null) body.composite_threshold = options.compositeThreshold;
    if (options.thresholds) body.thresholds = options.thresholds;
    if (options.weights) body.weights = options.weights;
    if (options.includeReputation != null) body.include_reputation = options.includeReputation;
    if (options.includePricing != null) body.include_pricing = options.includePricing;
    if (options.basePriceUsdc != null) body.base_price_usdc = options.basePriceUsdc;

    const response = await fetch(`${this.baseUrl}/v1/evaluate`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const errorBody = await response.text();
      throw new CredAPIError(response.status, errorBody);
    }

    const raw = await response.json();
    const mapped = mapResponse(raw);
    return toTrustResult(mapped);
  }
}

export class CredAPIError extends Error {
  status: number;
  body: string;

  constructor(status: number, body: string) {
    super(`Cred API error ${status}: ${body}`);
    this.name = 'CredAPIError';
    this.status = status;
    this.body = body;
  }
}
