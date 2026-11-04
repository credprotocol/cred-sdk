"""register_cred_kya on real x402 resource servers (async and sync), with a
fake facilitator and a stubbed Cred API (httpx.MockTransport)."""

from __future__ import annotations

import httpx
from x402.schemas import (
    PaymentPayload,
    PaymentRequirements,
    SettleResponse,
    SupportedKind,
    SupportedResponse,
    VerifyResponse,
)
from x402.server import x402ResourceServer, x402ResourceServerSync

from cred_protocol import CredKyaClient, CredKyaClientSync, register_cred_kya

PAYER = "0x2222222222222222222222222222222222222222"
NETWORK = "eip155:8453"

REQUIREMENTS = PaymentRequirements(
    scheme="exact",
    network=NETWORK,
    asset="0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    amount="10000",
    pay_to="0x9999999999999999999999999999999999999999",
    max_timeout_seconds=60,
    extra={},
)
UPFRONT = REQUIREMENTS.model_copy(update={"extra": {"paymentFlow": "upfront"}})


def payload(requirements: PaymentRequirements) -> PaymentPayload:
    return PaymentPayload(
        x402_version=2,
        accepted=requirements,
        payload={"authorization": {"from": PAYER}, "signature": "0x"},
    )


BLOCKED = {
    "agent_id": 22,
    "verdict": "block",
    "flags": [
        {"code": "K01", "flag": "sanctioned_controller", "severity": "block", "description": "x", "subject": PAYER}
    ],
    "unavailable": [],
    "compliance": {"sanctioned": True, "lists_checked": ["ofac_sdn", "ofac_consolidated"]},
}
PASSED = {"agent_id": 22, "verdict": "pass", "flags": [], "unavailable": [], "compliance": {"sanctioned": False}}


class ExactScheme:
    """The EVM exact scheme's flow table (mechanisms/evm exact server)."""

    scheme = "exact"
    default_asset_transfer_method = "eip3009"
    payment_flows = {"eip3009": {"supported": ["authorization", "upfront"], "default": "authorization"}}


SUPPORTED = SupportedResponse(
    kinds=[SupportedKind(x402_version=2, scheme="exact", network=NETWORK)], extensions=[], signers={}
)


class Facilitator:
    def __init__(self, valid: bool = True):
        self.valid = valid
        self.verified = 0
        self.settled = 0

    def get_supported(self):
        return SUPPORTED

    def _verify(self):
        self.verified += 1
        if self.valid:
            return VerifyResponse(is_valid=True, payer=PAYER)
        return VerifyResponse(is_valid=False, invalid_reason="invalid_signature")

    def _settle(self):
        self.settled += 1
        return SettleResponse(success=True, transaction="0xabc", network=NETWORK, payer=PAYER)


class AsyncFacilitator(Facilitator):
    async def verify(self, payload, requirements):
        return self._verify()

    async def settle(self, payload, requirements):
        return self._settle()


class SyncFacilitator(Facilitator):
    def verify(self, payload, requirements):
        return self._verify()

    def settle(self, payload, requirements):
        return self._settle()


def cred_api(body, seen: list, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


def async_server(facilitator, body, seen):
    server = x402ResourceServer(facilitator).register(NETWORK, ExactScheme())
    client = CredKyaClient("test", http_client=httpx.AsyncClient(transport=cred_api(body, seen)))
    register_cred_kya(server, client=client)
    server.initialize()
    return server


def sync_server(facilitator, body, seen):
    server = x402ResourceServerSync(facilitator).register(NETWORK, ExactScheme())
    client = CredKyaClientSync("test", http_client=httpx.Client(transport=cred_api(body, seen)))
    register_cred_kya(server, client=client)
    server.initialize()
    return server


class TestAsyncServer:
    async def test_blocked_payer_is_invalid_and_never_settles(self):
        facilitator, seen = AsyncFacilitator(), []
        result = await async_server(facilitator, BLOCKED, seen).verify_payment(payload(REQUIREMENTS), REQUIREMENTS)
        assert result.verify.is_valid is False
        assert result.verify.invalid_reason == "payer_sanctioned"
        assert facilitator.settled == 0
        assert seen == [f"https://api.credprotocol.com/api/v2/agents/by-wallet/{PAYER}/kya"]

    async def test_passing_payer_stays_valid(self):
        result = await async_server(AsyncFacilitator(), PASSED, []).verify_payment(payload(REQUIREMENTS), REQUIREMENTS)
        assert result.verify.is_valid is True

    async def test_rejected_payment_is_never_looked_up(self):
        seen: list = []
        result = await async_server(AsyncFacilitator(valid=False), PASSED, seen).verify_payment(
            payload(REQUIREMENTS), REQUIREMENTS
        )
        assert result.verify.invalid_reason == "invalid_signature"
        assert seen == []

    async def test_upfront_payment_is_stopped_before_it_settles(self):
        facilitator, seen = AsyncFacilitator(), []
        server = async_server(facilitator, BLOCKED, seen)
        # The upfront flow skips verify...
        assert (await server.verify_payment(payload(UPFRONT), UPFRONT)).verify.is_valid is True
        assert seen == []
        # ...and the settle hook refuses at the before-handler phase.
        try:
            outcome = await server.settle_payment(payload(UPFRONT), UPFRONT, phase="before-handler")
        except Exception as error:  # noqa: BLE001 - x402 raises PaymentAbortedError
            outcome = error
        assert facilitator.settled == 0
        assert "payer_sanctioned" in repr(outcome) + str(outcome)

    async def test_one_lookup_across_verify_and_settle(self):
        facilitator, seen = AsyncFacilitator(), []
        server = async_server(facilitator, PASSED, seen)
        assert (await server.verify_payment(payload(REQUIREMENTS), REQUIREMENTS)).verify.is_valid
        await server.settle_payment(payload(REQUIREMENTS), REQUIREMENTS)
        assert facilitator.settled == 1
        assert len(seen) == 1


class TestSyncServer:
    def test_blocked_payer_is_invalid(self):
        facilitator, seen = SyncFacilitator(), []
        result = sync_server(facilitator, BLOCKED, seen).verify_payment(payload(REQUIREMENTS), REQUIREMENTS)
        assert (result.verify.is_valid, result.verify.invalid_reason) == (False, "payer_sanctioned")
        assert facilitator.settled == 0

    def test_passing_payer_settles(self):
        facilitator, seen = SyncFacilitator(), []
        server = sync_server(facilitator, PASSED, seen)
        assert server.verify_payment(payload(REQUIREMENTS), REQUIREMENTS).verify.is_valid
        server.settle_payment(payload(REQUIREMENTS), REQUIREMENTS)
        assert facilitator.settled == 1
        assert len(seen) == 1
