/** Trust tier classification based on composite score. */
export type TrustTier = 'trusted' | 'verified' | 'limited' | 'untrusted' | 'blocked';

/** Stacking operator for multi-gate policies. */
export type GateOperator = 'AND' | 'OR' | 'WEIGHTED';

/** Dynamic pricing curve type. */
export type PricingCurve = 'linear' | 'exponential' | 'step';

/** Per-gate score breakdown in the evaluation result. */
export interface GateScoreBreakdown {
  gateId: string;
  gateName: string;
  passed: boolean;
  score: number | null;
  provider: string;
  detail: string | null;
}

/** Behavioral reputation derived from ERC-8004 feedback records. */
export interface WalletReputation {
  totalEvaluations: number;
  servicesAccessed: number;
  settlementRate: number;
  negativeReports: number;
  positiveReports: number;
  firstSeen: string | null;
  lastSeen: string | null;
  riskFlags: string[];
}

/** The normalized trust score output. */
export interface TrustScoreOutput {
  walletAddress: string;
  trustScore: number;
  trustTier: TrustTier;
  confidence: number;
  gateResults: GateScoreBreakdown[];
  priceMultiplier: number | null;
  suggestedPriceUsdc: number | null;
  reputation: WalletReputation | null;
  cached: boolean;
  cacheExpiresAt: string | null;
  evaluatedAt: string;
}

/** Summary of the policy evaluation. */
export interface PolicyResult {
  policyName: string;
  allPassed: boolean;
  operator: string;
  passedGates: string[];
  failedGates: string[];
  compositeScore: number | null;
}

/** Full evaluation response from the API. */
export interface EvaluationResponse {
  trustScore: TrustScoreOutput;
  policyResult: PolicyResult;
  requestId: string;
  challenge: Record<string, unknown> | null;
  evaluationCostUsdc: number;
  cached: boolean;
  apiVersion: string;
  evaluatedAt: string;
}

/** Options for evaluating a wallet. */
export interface EvaluateOptions {
  walletAddress: string;

  /** Use a named policy template (e.g., "standard", "strict"). */
  policy?: string;

  /** Custom gate list (alternative to policy). */
  gates?: string[];
  operator?: GateOperator;
  compositeThreshold?: number;
  thresholds?: Record<string, Record<string, unknown>>;
  weights?: Record<string, number>;

  includeReputation?: boolean;
  includePricing?: boolean;
  basePriceUsdc?: number;
}

/** Configuration for the CredClient. */
export interface CredClientConfig {
  apiKey: string;
  baseUrl?: string;
}

/** Simplified evaluation result for middleware consumption. */
export interface TrustResult {
  walletAddress: string;
  trustScore: number;
  trustTier: TrustTier;
  confidence: number;
  allPassed: boolean;
  gateResults: GateScoreBreakdown[];
  priceMultiplier: number | null;
  suggestedPriceUsdc: number | null;
  reputation: WalletReputation | null;
  cached: boolean;
  requestId: string;
  challenge: Record<string, unknown> | null;
  raw: EvaluationResponse;
}
