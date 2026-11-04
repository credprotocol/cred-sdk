"""Type definitions for the Cred Protocol SDK."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class TrustTier(str, Enum):
    TRUSTED = "trusted"
    VERIFIED = "verified"
    LIMITED = "limited"
    UNTRUSTED = "untrusted"
    BLOCKED = "blocked"


@dataclass
class GateScoreBreakdown:
    gate_id: str
    gate_name: str
    passed: bool
    score: float | None
    provider: str
    detail: str | None


@dataclass
class WalletReputation:
    total_evaluations: int
    services_accessed: int
    settlement_rate: float
    negative_reports: int
    positive_reports: int
    first_seen: str | None
    last_seen: str | None
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class TrustScoreOutput:
    wallet_address: str
    trust_score: int
    trust_tier: TrustTier
    confidence: float
    gate_results: list[GateScoreBreakdown]
    price_multiplier: float | None
    suggested_price_usdc: float | None
    reputation: WalletReputation | None
    cached: bool
    cache_expires_at: str | None
    evaluated_at: str


@dataclass
class PolicyResult:
    policy_name: str
    all_passed: bool
    operator: str
    passed_gates: list[str]
    failed_gates: list[str]
    composite_score: float | None


@dataclass
class EvaluationResponse:
    trust_score: TrustScoreOutput
    policy_result: PolicyResult
    request_id: str
    challenge: dict[str, Any] | None
    evaluation_cost_usdc: float
    cached: bool
    api_version: str
    evaluated_at: str


@dataclass
class TrustResult:
    """Simplified evaluation result for application consumption."""

    wallet_address: str
    trust_score: int
    trust_tier: TrustTier
    confidence: float
    all_passed: bool
    gate_results: list[GateScoreBreakdown]
    price_multiplier: float | None
    suggested_price_usdc: float | None
    reputation: WalletReputation | None
    cached: bool
    request_id: str
    challenge: dict[str, Any] | None
    raw: EvaluationResponse


@dataclass
class EvaluateOptions:
    wallet_address: str
    policy: str | None = None
    gates: list[str] | None = None
    operator: str | None = None
    composite_threshold: int | None = None
    thresholds: dict[str, dict] | None = None
    weights: dict[str, float] | None = None
    include_reputation: bool = True
    include_pricing: bool = False
    base_price_usdc: float | None = None
