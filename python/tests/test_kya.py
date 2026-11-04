"""Know Your Agent hooks (cred_protocol/kya.py): policy, cache, fallbacks and
the HTTP clients. The Cred API and x402 contexts are faked; tests that drive
a real x402 resource server are in test_kya_x402.py."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from x402.schemas import AbortResult

from cred_protocol import (
    CredAPIError,
    CredKyaClient,
    CredKyaClientSync,
    CredKyaPolicy,
    CredKyaScreener,
    CredKyaScreenerSync,
    KyaFlag,
    KyaProfile,
    KyaReason,
    SanctionsScreen,
    decide_from_profile,
    payer_from_context,
)

PAYER = "0x2222222222222222222222222222222222222222"


def flag(code: str, severity: str = "review") -> KyaFlag:
    return KyaFlag(code=code, flag=code.lower(), severity=severity, description=code)


def profile(**overrides) -> KyaProfile:
    base = dict(
        agent_id=22,
        verdict="pass",
        flags=[],
        unavailable=[],
        sanctioned=False,
        lists_checked=["ofac_sdn", "ofac_consolidated"],
        exposure_risk="none",
        resolved_from=PAYER,
    )
    base.update(overrides)
    return KyaProfile(**base)


def ctx(payer: str | None = PAYER, valid: bool = True):
    return SimpleNamespace(result=SimpleNamespace(is_valid=valid, payer=payer), payment_payload=None)


class FakeClient:
    """Async fake of CredKyaClient."""

    def __init__(self, kya, sanctioned: bool = False, screen_error: Exception | None = None):
        self._kya = kya
        self.sanctioned = sanctioned
        self.screen_error = screen_error
        self.kya_calls = 0
        self.screen_calls = 0

    async def kya_by_wallet(self, address):
        self.kya_calls += 1
        return await self._kya()

    async def sanctions_screen(self, address):
        self.screen_calls += 1
        if self.screen_error:
            raise self.screen_error
        return SanctionsScreen(address=address, sanctioned=self.sanctioned, lists_checked=["ofac_sdn"], matches=[])


def returning(value):
    async def kya():
        return value

    return kya


def raising(error: Exception):
    async def kya():
        raise error

    return kya


def screener(client, **options) -> tuple[CredKyaScreener, list]:
    decisions: list = []
    s = CredKyaScreener(client=client, on_decision=lambda d, c: decisions.append(d), **options)
    return s, decisions


# ---------------------------------------------------------------------------


def test_payer_from_context():
    assert payer_from_context(SimpleNamespace(result=SimpleNamespace(payer="0xABCD"))) == "0xabcd"
    from_payload = SimpleNamespace(
        result=SimpleNamespace(payer=None),
        payment_payload=SimpleNamespace(payload={"authorization": {"from": "0xFEED"}}),
    )
    assert payer_from_context(from_payload) == "0xfeed"
    assert payer_from_context(SimpleNamespace(result=None, payment_payload=None)) is None


class TestDecideFromProfile:
    def decide(self, p, **policy):
        return decide_from_profile(p, CredKyaPolicy(**policy), ctx(), PAYER)

    def test_pass_and_block(self):
        assert self.decide(profile()).accept
        blocked = self.decide(profile(verdict="block", sanctioned=True, flags=[flag("K01", "block")]))
        assert (blocked.accept, blocked.reason, blocked.flags) == (False, KyaReason.SANCTIONED, ("K01",))

    def test_review_accepts_by_default_but_refuses_k02_k03(self):
        assert self.decide(profile(verdict="review", flags=[flag("K08")])).accept
        refused = self.decide(profile(verdict="review", flags=[flag("K03")]))
        assert (refused.accept, refused.reason) == (False, KyaReason.NEEDS_REVIEW)

    def test_review_policies(self):
        review = profile(verdict="review", flags=[flag("K07")])
        assert not self.decide(review, review="refuse").accept
        assert not self.decide(review, refuse_flags=("K07",)).accept
        assert self.decide(review, review=lambda p, c: p.agent_id == 22).accept
        assert not self.decide(review, review=lambda p, c: False).accept

    def test_k13_alone_is_incomplete(self):
        incomplete = profile(verdict="review", flags=[flag("K13")])
        accepted = self.decide(incomplete)
        assert accepted.accept and accepted.incomplete
        refused = self.decide(incomplete, on_error="refuse")
        assert (refused.accept, refused.reason, refused.incomplete) == (False, KyaReason.UNAVAILABLE, True)
        assert not self.decide(profile(verdict="review", flags=[flag("K08"), flag("K13")])).incomplete


class TestAsyncScreener:
    async def test_blocked_payer_aborts_with_a_self_explaining_reason(self):
        s, _ = screener(FakeClient(returning(profile(verdict="block", sanctioned=True, flags=[flag("K01", "block")]))))
        result = await s.after_verify(ctx())
        assert isinstance(result, AbortResult)
        assert result.reason == "payer_sanctioned"
        assert "K01" in result.message

    async def test_passing_payer_is_recorded(self):
        s, decisions = screener(FakeClient(returning(profile())))
        assert await s.after_verify(ctx()) is None
        assert (decisions[0].accept, decisions[0].source, decisions[0].agent_id) == (True, "kya", 22)
        assert decisions[0].lists_checked == ("ofac_sdn", "ofac_consolidated")

    async def test_unverified_payment_is_not_looked_up(self):
        client = FakeClient(returning(profile()))
        s, _ = screener(client)
        assert await s.after_verify(ctx(valid=False)) is None
        assert client.kya_calls == 0

    async def test_cache_lifetimes(self):
        clock = [0.0]
        client = FakeClient(returning(profile()))
        s, decisions = screener(client, now=lambda: clock[0])
        await s.after_verify(ctx())
        clock[0] = 14 * 60
        await s.after_verify(ctx())
        assert client.kya_calls == 1 and decisions[1].source == "cache"
        clock[0] = 16 * 60
        await s.after_verify(ctx())
        assert client.kya_calls == 2

        blocked = FakeClient(returning(profile(verdict="block", sanctioned=True)))
        s2, _ = screener(blocked, now=lambda: clock[0])
        await s2.after_verify(ctx())
        clock[0] += 59 * 60
        assert (await s2.after_verify(ctx())).reason == "payer_sanctioned"
        assert blocked.kya_calls == 1

    async def test_concurrent_payments_share_one_lookup(self):
        release = asyncio.Event()

        async def slow():
            await release.wait()
            return profile()

        client = FakeClient(slow)
        s, _ = screener(client, timeout=1.0)
        first = asyncio.ensure_future(s.after_verify(ctx()))
        second = asyncio.ensure_future(s.after_verify(ctx()))
        await asyncio.sleep(0)
        release.set()
        assert await asyncio.gather(first, second) == [None, None]
        assert client.kya_calls == 1

    async def test_incomplete_check_is_not_cached(self):
        client = FakeClient(returning(profile(verdict="review", flags=[flag("K13")])))
        s, _ = screener(client)
        await s.after_verify(ctx())
        await s.after_verify(ctx())
        assert client.kya_calls == 2

    async def test_wallet_without_agent(self):
        clean = FakeClient(returning(None))
        assert await screener(clean)[0].after_verify(ctx()) is None
        assert clean.screen_calls == 1
        listed = FakeClient(returning(None), sanctioned=True)
        assert (await screener(listed)[0].after_verify(ctx())).reason == "payer_sanctioned"

        refuse = FakeClient(returning(None))
        result = await screener(refuse, policy=CredKyaPolicy(no_agent="refuse"))[0].after_verify(ctx())
        assert result.reason == "payer_not_registered_agent" and refuse.screen_calls == 0
        accept = FakeClient(returning(None))
        assert await screener(accept, policy=CredKyaPolicy(no_agent="accept"))[0].after_verify(ctx()) is None
        assert accept.screen_calls == 0

    async def test_fails_open_after_the_screen_and_refuses_sanctioned(self):
        down = FakeClient(raising(CredAPIError(503, "down")))
        s, decisions = screener(down)
        assert await s.after_verify(ctx()) is None
        assert decisions[0].source == "fallback_screen"
        listed = FakeClient(raising(CredAPIError(503, "down")), sanctioned=True)
        assert (await screener(listed)[0].after_verify(ctx())).reason == "payer_sanctioned"

    async def test_accepts_unchecked_only_when_the_screen_fails_too(self):
        client = FakeClient(raising(RuntimeError("net")), screen_error=RuntimeError("net"))
        s, decisions = screener(client)
        assert await s.after_verify(ctx()) is None
        assert (decisions[0].accept, decisions[0].source) == (True, "error")

    async def test_fails_closed(self):
        client = FakeClient(raising(RuntimeError("net")))
        result = await screener(client, policy=CredKyaPolicy(on_error="refuse"))[0].after_verify(ctx())
        assert result.reason == "payer_screening_unavailable"
        assert client.screen_calls == 0

    async def test_slow_lookup_is_decided_by_policy_then_cached_when_it_lands(self):
        release = asyncio.Event()

        async def slow():
            await release.wait()
            return profile(verdict="block", sanctioned=True)

        client = FakeClient(slow)
        s, decisions = screener(client, timeout=0.01)
        assert await s.after_verify(ctx()) is None
        assert decisions[0].source == "fallback_screen"
        release.set()
        await asyncio.sleep(0.01)
        assert (await s.after_verify(ctx())).reason == "payer_sanctioned"
        assert decisions[1].source == "cache"
        assert client.kya_calls == 1

    async def test_never_raises_even_when_the_audit_callback_does(self):
        def broken(decision, context):
            raise RuntimeError("logger down")

        s = CredKyaScreener(client=FakeClient(returning(profile())), on_decision=broken)
        assert await s.after_verify(ctx()) is None

    async def test_no_payer(self):
        no_payer = SimpleNamespace(result=SimpleNamespace(is_valid=True, payer=None), payment_payload=None)
        client = FakeClient(returning(profile()))
        assert await screener(client)[0].after_verify(no_payer) is None
        refused = await screener(client, policy=CredKyaPolicy(on_error="refuse"))[0].after_verify(no_payer)
        assert refused.reason == "payer_screening_unavailable"
        assert client.kya_calls == 0

    async def test_before_settle_acts_only_before_the_handler(self):
        client = FakeClient(returning(profile(verdict="block", sanctioned=True)))
        s, _ = screener(client)
        payload = SimpleNamespace(payload={"authorization": {"from": PAYER}})
        for phase in ("after-handler", "cancel"):
            assert await s.before_settle(SimpleNamespace(phase=phase, payment_payload=payload)) is None
        assert client.kya_calls == 0
        result = await s.before_settle(SimpleNamespace(phase="before-handler", payment_payload=payload))
        assert result.reason == "payer_sanctioned"


class FakeSyncClient:
    def __init__(self, kya, sanctioned=False):
        self._kya = kya
        self.sanctioned = sanctioned
        self.kya_calls = 0
        self.timeouts: list = []

    def kya_by_wallet(self, address, timeout=None):
        self.kya_calls += 1
        self.timeouts.append(timeout)
        return self._kya()

    def sanctions_screen(self, address, timeout=None):
        return SanctionsScreen(address=address, sanctioned=self.sanctioned, lists_checked=["ofac_sdn"], matches=[])


class TestSyncScreener:
    def test_decides_caches_and_bounds_the_lookup(self):
        client = FakeSyncClient(lambda: profile(verdict="block", sanctioned=True))
        s = CredKyaScreenerSync(client=client, timeout=2.5)
        assert s.after_verify(ctx()).reason == "payer_sanctioned"
        assert s.after_verify(ctx()).reason == "payer_sanctioned"
        assert client.kya_calls == 1
        assert client.timeouts == [2.5]

    def test_timeout_falls_back_to_the_screen(self):
        def timed_out():
            raise httpx.ReadTimeout("slow")

        assert CredKyaScreenerSync(client=FakeSyncClient(timed_out)).after_verify(ctx()) is None
        listed = CredKyaScreenerSync(client=FakeSyncClient(timed_out, sanctioned=True))
        assert listed.after_verify(ctx()).reason == "payer_sanctioned"
        closed = CredKyaScreenerSync(client=FakeSyncClient(timed_out), policy=CredKyaPolicy(on_error="refuse"))
        assert closed.after_verify(ctx()).reason == "payer_screening_unavailable"

    def test_wallet_without_agent_is_screened(self):
        s = CredKyaScreenerSync(client=FakeSyncClient(lambda: None, sanctioned=True))
        assert s.after_verify(ctx()).reason == "payer_sanctioned"


# ---------------------------------------------------------------------------
# HTTP clients
# ---------------------------------------------------------------------------

PROFILE_BODY = {
    "agent_id": 22,
    "verdict": "review",
    "flags": [{"code": "K08", "flag": "new_registration", "severity": "review", "description": "x", "subject": None}],
    "unavailable": [],
    "compliance": {"sanctioned": False, "lists_checked": ["ofac_sdn"], "exposure_risk": "none"},
    "resolved_from": PAYER,
}


def transport(status: int, body, seen: list):
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=body)

    return httpx.MockTransport(handler)


async def test_async_client_reads_a_profile_with_the_key():
    seen: list = []
    client = CredKyaClient(
        "key",
        base_url="https://api.example.com/",
        http_client=httpx.AsyncClient(transport=transport(200, PROFILE_BODY, seen)),
    )
    result = await client.kya_by_wallet(PAYER)
    assert (result.agent_id, result.verdict, result.flags[0].code, result.lists_checked) == (
        22,
        "review",
        "K08",
        ["ofac_sdn"],
    )
    assert str(seen[0].url) == f"https://api.example.com/api/v2/agents/by-wallet/{PAYER}/kya"
    assert seen[0].headers["authorization"] == "Bearer key"


async def test_async_client_404_and_errors():
    missing = CredKyaClient("k", http_client=httpx.AsyncClient(transport=transport(404, {"detail": "none"}, [])))
    assert await missing.kya_by_wallet(PAYER) is None
    assert await missing.kya_by_agent_id(5) is None
    broken = CredKyaClient("k", http_client=httpx.AsyncClient(transport=transport(402, {"detail": "pay"}, [])))
    with pytest.raises(CredAPIError):
        await broken.kya_by_wallet(PAYER)


def test_sync_client_screens_and_needs_a_key():
    client = CredKyaClientSync(
        "k",
        http_client=httpx.Client(
            transport=transport(
                200,
                {
                    "address": PAYER,
                    "sanctioned": True,
                    "lists_checked": ["ofac_sdn"],
                    "matches": [{"source": "ofac_sdn"}],
                },
                [],
            )
        ),
    )
    result = client.sanctions_screen(PAYER)
    assert result.sanctioned and result.matches == [{"source": "ofac_sdn"}]
    with pytest.raises(ValueError):
        CredKyaClientSync("")
