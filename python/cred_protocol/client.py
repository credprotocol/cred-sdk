"""Cred Protocol API client."""

from __future__ import annotations

import httpx

from .types import (
    EvaluateOptions,
    EvaluationResponse,
    GateScoreBreakdown,
    PolicyResult,
    TrustResult,
    TrustScoreOutput,
    TrustTier,
    WalletReputation,
)

DEFAULT_BASE_URL = "https://validator.credprotocol.com"


class CredAPIError(Exception):
    """Raised when the Cred API returns a non-2xx response."""

    def __init__(self, status: int, body: str):
        super().__init__(f"Cred API error {status}: {body}")
        self.status = status
        self.body = body


def _parse_reputation(data: dict | None) -> WalletReputation | None:
    if not data:
        return None
    return WalletReputation(
        total_evaluations=data["total_evaluations"],
        services_accessed=data["services_accessed"],
        settlement_rate=data["settlement_rate"],
        negative_reports=data["negative_reports"],
        positive_reports=data["positive_reports"],
        first_seen=data.get("first_seen"),
        last_seen=data.get("last_seen"),
        risk_flags=data.get("risk_flags", []),
    )


def _parse_response(raw: dict) -> EvaluationResponse:
    ts = raw["trust_score"]
    return EvaluationResponse(
        trust_score=TrustScoreOutput(
            wallet_address=ts["wallet_address"],
            trust_score=ts["trust_score"],
            trust_tier=TrustTier(ts["trust_tier"]),
            confidence=ts["confidence"],
            gate_results=[
                GateScoreBreakdown(
                    gate_id=g["gate_id"],
                    gate_name=g["gate_name"],
                    passed=g["passed"],
                    score=g.get("score"),
                    provider=g["provider"],
                    detail=g.get("detail"),
                )
                for g in ts.get("gate_results", [])
            ],
            price_multiplier=ts.get("price_multiplier"),
            suggested_price_usdc=ts.get("suggested_price_usdc"),
            reputation=_parse_reputation(ts.get("reputation")),
            cached=ts["cached"],
            cache_expires_at=ts.get("cache_expires_at"),
            evaluated_at=ts["evaluated_at"],
        ),
        policy_result=PolicyResult(
            policy_name=raw["policy_result"]["policy_name"],
            all_passed=raw["policy_result"]["all_passed"],
            operator=raw["policy_result"]["operator"],
            passed_gates=raw["policy_result"]["passed_gates"],
            failed_gates=raw["policy_result"]["failed_gates"],
            composite_score=raw["policy_result"].get("composite_score"),
        ),
        request_id=raw["request_id"],
        challenge=raw.get("challenge"),
        evaluation_cost_usdc=raw["evaluation_cost_usdc"],
        cached=raw["cached"],
        api_version=raw["api_version"],
        evaluated_at=raw["evaluated_at"],
    )


def _to_trust_result(res: EvaluationResponse) -> TrustResult:
    return TrustResult(
        wallet_address=res.trust_score.wallet_address,
        trust_score=res.trust_score.trust_score,
        trust_tier=res.trust_score.trust_tier,
        confidence=res.trust_score.confidence,
        all_passed=res.policy_result.all_passed,
        gate_results=res.trust_score.gate_results,
        price_multiplier=res.trust_score.price_multiplier,
        suggested_price_usdc=res.trust_score.suggested_price_usdc,
        reputation=res.trust_score.reputation,
        cached=res.cached,
        request_id=res.request_id,
        challenge=res.challenge,
        raw=res,
    )


class CredClient:
    """
    Async client for the Cred Protocol trust evaluation API.

    Usage::

        from cred_protocol import CredClient

        cred = CredClient(api_key="cred_sk_...")
        result = await cred.evaluate(wallet_address="0x...", policy="standard")
        print(result.trust_score, result.trust_tier)
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = DEFAULT_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
    ):
        if not api_key:
            raise ValueError("CredClient requires an api_key")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._http = http_client or httpx.AsyncClient(timeout=30.0)
        self._owns_client = http_client is None

    async def evaluate(
        self,
        wallet_address: str,
        policy: str | None = None,
        gates: list[str] | None = None,
        operator: str | None = None,
        composite_threshold: int | None = None,
        thresholds: dict[str, dict] | None = None,
        weights: dict[str, float] | None = None,
        include_reputation: bool = True,
        include_pricing: bool = False,
        base_price_usdc: float | None = None,
    ) -> TrustResult:
        """Evaluate a wallet's trust level."""
        body: dict = {"wallet_address": wallet_address}
        if policy:
            body["policy"] = policy
        if gates:
            body["gates"] = gates
        if operator:
            body["operator"] = operator
        if composite_threshold is not None:
            body["composite_threshold"] = composite_threshold
        if thresholds:
            body["thresholds"] = thresholds
        if weights:
            body["weights"] = weights
        body["include_reputation"] = include_reputation
        body["include_pricing"] = include_pricing
        if base_price_usdc is not None:
            body["base_price_usdc"] = base_price_usdc

        response = await self._http.post(
            f"{self.base_url}/v1/evaluate",
            json=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
        )

        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)

        raw = response.json()
        parsed = _parse_response(raw)
        return _to_trust_result(parsed)

    async def close(self) -> None:
        """Close the underlying HTTP client if we own it."""
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
