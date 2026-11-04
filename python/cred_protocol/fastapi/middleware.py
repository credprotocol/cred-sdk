"""FastAPI dependency for Cred Protocol trust-gated endpoints.

Usage::

    from cred_protocol.fastapi import require_trust

    @router.get("/resource")
    async def get_resource(
        trust: TrustResult = Depends(require_trust(policy="standard")),
    ):
        print(trust.trust_score, trust.trust_tier)
        ...
"""

from __future__ import annotations

from typing import Callable

from fastapi import HTTPException, Request

from ..client import CredAPIError, CredClient
from ..types import TrustResult


class CredTrustDependency:
    """
    A configurable FastAPI dependency that evaluates wallet trust.

    The wallet address is extracted from:
    1. ``X-Wallet-Address`` request header
    2. ``wallet`` query parameter
    3. A custom extractor function
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://validator.credprotocol.com",
        policy: str | None = None,
        gates: list[str] | None = None,
        operator: str | None = None,
        include_pricing: bool = False,
        base_price_usdc: float | None = None,
        on_fail: str = "deny",
        extract_wallet: Callable[[Request], str | None] | None = None,
    ):
        self.client = CredClient(api_key=api_key, base_url=base_url)
        self.policy = policy
        self.gates = gates
        self.operator = operator
        self.include_pricing = include_pricing
        self.base_price_usdc = base_price_usdc
        self.on_fail = on_fail
        self.extract_wallet = extract_wallet or self._default_extract

    @staticmethod
    def _default_extract(request: Request) -> str | None:
        return (
            request.headers.get("x-wallet-address")
            or request.query_params.get("wallet")
        )

    async def __call__(self, request: Request) -> TrustResult:
        wallet = self.extract_wallet(request)
        if not wallet:
            raise HTTPException(
                status_code=400,
                detail="Missing wallet address. Provide X-Wallet-Address header or ?wallet= query param.",
            )

        try:
            result = await self.client.evaluate(
                wallet_address=wallet,
                policy=self.policy,
                gates=self.gates,
                operator=self.operator,
                include_pricing=self.include_pricing,
                base_price_usdc=self.base_price_usdc,
                include_reputation=True,
            )
        except CredAPIError as e:
            if e.status == 429:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            raise HTTPException(
                status_code=502,
                detail=f"Trust evaluation failed: {e.body}",
            )

        # Set response headers
        request.state.cred_trust_headers = {
            "X-Cred-Trust-Score": str(result.trust_score),
            "X-Cred-Trust-Tier": result.trust_tier.value,
            "X-Cred-Request-Id": result.request_id,
        }

        if result.trust_tier.value == "blocked":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Access denied",
                    "trust_tier": result.trust_tier.value,
                    "trust_score": result.trust_score,
                },
            )

        if not result.all_passed and self.on_fail == "deny":
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "Trust requirements not met",
                    "trust_tier": result.trust_tier.value,
                    "trust_score": result.trust_score,
                },
            )

        if not result.all_passed and self.on_fail == "challenge" and result.challenge:
            raise HTTPException(status_code=402, detail=result.challenge)

        return result


def require_trust(
    api_key: str | None = None,
    base_url: str = "https://validator.credprotocol.com",
    policy: str | None = None,
    gates: list[str] | None = None,
    operator: str | None = None,
    include_pricing: bool = False,
    base_price_usdc: float | None = None,
    on_fail: str = "deny",
) -> CredTrustDependency:
    """
    Create a FastAPI dependency that gates endpoints with Cred trust evaluation.

    Usage::

        from cred_protocol.fastapi import require_trust

        @router.get("/resource")
        async def get_resource(
            trust: TrustResult = Depends(require_trust(
                api_key=os.environ["CRED_API_KEY"],
                policy="standard",
            )),
        ):
            # trust.trust_score, trust.trust_tier, trust.wallet_address
            ...

    Args:
        api_key: Cred Platform API key. Falls back to CRED_API_KEY env var.
        base_url: Cred API base URL.
        policy: Named policy template (e.g., "standard", "strict").
        gates: Custom gate list (alternative to policy).
        operator: Gate stacking operator ("AND", "OR", "WEIGHTED").
        include_pricing: Include dynamic pricing in response.
        base_price_usdc: Base price for dynamic pricing.
        on_fail: How to handle failed gates: "deny" (403), "challenge" (402), or "pass".
    """
    import os

    key = api_key or os.environ.get("CRED_API_KEY", "")
    if not key:
        raise ValueError(
            "require_trust() needs an api_key argument or CRED_API_KEY env var"
        )

    return CredTrustDependency(
        api_key=key,
        base_url=base_url,
        policy=policy,
        gates=gates,
        operator=operator,
        include_pricing=include_pricing,
        base_price_usdc=base_price_usdc,
        on_fail=on_fail,
    )
