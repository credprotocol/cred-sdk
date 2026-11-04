"""Know Your Agent (KYA) for x402 sellers.

``register_cred_kya(server, api_key=...)`` screens every paying agent with
Cred's Know Your Agent endpoint before an x402 payment settles. It works
with both ``x402.server.x402ResourceServer`` (async hooks) and
``x402ResourceServerSync`` (sync hooks):

- the default ``authorization`` flow is screened in ``on_after_verify``, once
  the facilitator has verified the payment, so only a payer who really
  signed it is looked up;
- ``upfront`` and ``escrow`` settle before the handler without a verify step
  (x402 returns ``is_valid=True`` without running after-verify hooks), so
  they are screened in ``on_before_settle`` at the ``before-handler`` phase.

A refused payer gets a 402 whose ``error`` is one of ``KyaReason``; nothing
moves on chain. Install with ``pip install "cred-protocol[x402]"``.

The hooks never raise: x402 re-raises a hook's exception and fails the whole
request, so every failure is turned into an explicit accept or refuse by the
``on_error`` policy.

See https://docs.credprotocol.com/know-your-agent for the flags.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Literal

import httpx

from .client import CredAPIError

DEFAULT_API_BASE_URL = "https://api.credprotocol.com"

MINUTE = 60.0
DEFAULT_REFUSE_FLAGS = ("K02", "K03")
INCOMPLETE_FLAG = "K13"


class KyaReason(str, Enum):
    """Codes the hooks abort with. x402 forwards only the code to the payer
    (as the 402 ``error``), so each one explains itself."""

    SANCTIONED = "payer_sanctioned"
    NEEDS_REVIEW = "payer_needs_review"
    NOT_AN_AGENT = "payer_not_registered_agent"
    UNAVAILABLE = "payer_screening_unavailable"


@dataclass(frozen=True)
class KyaFlag:
    code: str
    flag: str
    severity: Literal["block", "review", "info"]
    description: str
    subject: str | None = None


@dataclass(frozen=True)
class KyaProfile:
    """The decision-relevant part of a KYA profile; ``raw`` is the API body."""

    agent_id: int
    verdict: Literal["pass", "review", "block"]
    flags: list[KyaFlag]
    unavailable: list[str]
    sanctioned: bool
    lists_checked: list[str]
    exposure_risk: str | None
    resolved_from: str | None
    raw: dict[str, Any] = field(repr=False, default_factory=dict)


@dataclass(frozen=True)
class SanctionsScreen:
    address: str
    sanctioned: bool
    lists_checked: list[str]
    matches: list[dict[str, Any]]


KyaDecisionSource = Literal["kya", "screen", "cache", "fallback_screen", "error"]


@dataclass(frozen=True)
class KyaDecision:
    payer: str | None
    accept: bool
    source: KyaDecisionSource
    reason: KyaReason | None = None
    verdict: str | None = None
    flags: tuple[str, ...] = ()
    agent_id: int | None = None
    lists_checked: tuple[str, ...] = ()
    # A check behind the profile did not complete (K13). The controllers'
    # OFAC screen always completes, so the payer was still found
    # unsanctioned; on_error decided, and the decision is not cached.
    incomplete: bool = False
    error: BaseException | None = field(default=None, compare=False)


ReviewPolicy = Literal["accept", "refuse"] | Callable[[KyaProfile, Any], bool]


@dataclass(frozen=True)
class CredKyaPolicy:
    """What to accept.

    - ``review``: a ``review`` verdict is accepted, refused, or decided per
      payment by a callable ``(profile, context) -> bool``. Default ``accept``.
    - ``refuse_flags``: review flags that always refuse. Default K02 (first
      funded by a sanctioned address) and K03 (transacted with one).
    - ``no_agent``: the wallet controls no ERC-8004 agent. ``screen`` runs
      the OFAC screen (1 CU) and accepts unless sanctioned; ``refuse`` serves
      registered agents only; ``accept`` skips any check. Default ``screen``.
    - ``on_error``: Cred could not answer in time or at all, or a check did
      not complete (K13). ``accept`` still runs the OFAC screen first and
      refuses a sanctioned payer; only if that also fails is the payment
      accepted unchecked. Default ``accept``.
    """

    review: ReviewPolicy = "accept"
    refuse_flags: tuple[str, ...] = DEFAULT_REFUSE_FLAGS
    no_agent: Literal["screen", "refuse", "accept"] = "screen"
    on_error: Literal["accept", "refuse"] = "accept"


# ---------------------------------------------------------------------------
# Clients
# ---------------------------------------------------------------------------


def _profile(raw: dict[str, Any]) -> KyaProfile:
    compliance = raw.get("compliance") or {}
    return KyaProfile(
        agent_id=raw["agent_id"],
        verdict=raw["verdict"],
        flags=[
            KyaFlag(
                code=f["code"],
                flag=f["flag"],
                severity=f["severity"],
                description=f.get("description", ""),
                subject=f.get("subject"),
            )
            for f in raw.get("flags", [])
        ],
        unavailable=raw.get("unavailable", []),
        sanctioned=bool(compliance.get("sanctioned")),
        lists_checked=compliance.get("lists_checked", []),
        exposure_risk=compliance.get("exposure_risk"),
        resolved_from=raw.get("resolved_from"),
        raw=raw,
    )


def _screen(raw: dict[str, Any]) -> SanctionsScreen:
    return SanctionsScreen(
        address=raw.get("address", ""),
        sanctioned=bool(raw.get("sanctioned")),
        lists_checked=raw.get("lists_checked", []),
        matches=raw.get("matches", []),
    )


def _headers(api_key: str) -> dict[str, str]:
    if not api_key:
        raise ValueError("A Cred API key is required")
    return {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}


class CredKyaClient:
    """Async client for the KYA and sanctions-screen routes of the Cred API."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_API_BASE_URL,
        http_client: httpx.AsyncClient | None = None,
    ):
        self._headers = _headers(api_key)
        self._base_url = base_url.rstrip("/")
        self._http = http_client or httpx.AsyncClient(timeout=30.0)

    async def _get(self, path: str) -> httpx.Response:
        return await self._http.get(f"{self._base_url}{path}", headers=self._headers)

    async def kya_by_wallet(self, address: str) -> KyaProfile | None:
        """Profile of the agent the wallet controls, or None when it controls
        none (a free 404). 10 Cred Units."""
        response = await self._get(f"/api/v2/agents/by-wallet/{address}/kya")
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _profile(response.json())

    async def kya_by_agent_id(self, agent_id: int) -> KyaProfile | None:
        """Profile of an agent by ERC-8004 id, or None if it does not exist. 10 Cred Units."""
        response = await self._get(f"/api/v2/agents/{agent_id}/kya")
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _profile(response.json())

    async def sanctions_screen(self, address: str) -> SanctionsScreen:
        """OFAC screen of one address. 1 Cred Unit."""
        response = await self._get(f"/api/v2/sanctions/screen/{address}")
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _screen(response.json())

    async def aclose(self) -> None:
        await self._http.aclose()


class CredKyaClientSync:
    """Blocking twin of :class:`CredKyaClient`, for ``x402ResourceServerSync``."""

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_API_BASE_URL,
        http_client: httpx.Client | None = None,
    ):
        self._headers = _headers(api_key)
        self._base_url = base_url.rstrip("/")
        self._http = http_client or httpx.Client(timeout=30.0)

    def _get(self, path: str, timeout: float | None = None) -> httpx.Response:
        kwargs: dict[str, Any] = {"headers": self._headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        return self._http.get(f"{self._base_url}{path}", **kwargs)

    def kya_by_wallet(self, address: str, timeout: float | None = None) -> KyaProfile | None:
        response = self._get(f"/api/v2/agents/by-wallet/{address}/kya", timeout)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _profile(response.json())

    def kya_by_agent_id(self, agent_id: int, timeout: float | None = None) -> KyaProfile | None:
        response = self._get(f"/api/v2/agents/{agent_id}/kya", timeout)
        if response.status_code == 404:
            return None
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _profile(response.json())

    def sanctions_screen(self, address: str, timeout: float | None = None) -> SanctionsScreen:
        response = self._get(f"/api/v2/sanctions/screen/{address}", timeout)
        if response.status_code >= 400:
            raise CredAPIError(response.status_code, response.text)
        return _screen(response.json())

    def close(self) -> None:
        self._http.close()


# ---------------------------------------------------------------------------
# Decision logic (shared by the async and sync hooks)
# ---------------------------------------------------------------------------


def payer_from_context(context: Any) -> str | None:
    """The payer of a payment: the facilitator's ``payer`` on a verify
    result, else the signer in an EVM ``exact`` payload."""
    result = getattr(context, "result", None)
    payer = getattr(result, "payer", None)
    if isinstance(payer, str) and payer:
        return payer.lower()
    payment_payload = getattr(context, "payment_payload", None)
    payload = getattr(payment_payload, "payload", None)
    if isinstance(payload, dict):
        for key in ("authorization", "permit2Authorization", "permit2_authorization"):
            auth = payload.get(key)
            if isinstance(auth, dict) and isinstance(auth.get("from"), str) and auth["from"]:
                return auth["from"].lower()
    return None


def decide_from_profile(profile: KyaProfile, policy: CredKyaPolicy, context: Any, payer: str | None) -> KyaDecision:
    """What a KYA profile means under the seller's policy."""
    base = {
        "payer": payer,
        "source": "kya",
        "verdict": profile.verdict,
        "flags": tuple(f.code for f in profile.flags),
        "agent_id": profile.agent_id,
        "lists_checked": tuple(profile.lists_checked),
    }
    if profile.verdict == "block" or profile.sanctioned:
        return KyaDecision(accept=False, reason=KyaReason.SANCTIONED, **base)
    if profile.verdict == "pass":
        return KyaDecision(accept=True, **base)

    if any(f.code in policy.refuse_flags for f in profile.flags):
        return KyaDecision(accept=False, reason=KyaReason.NEEDS_REVIEW, **base)

    # Review only because a check did not complete: not an answer about the
    # payer, so on_error decides and nothing is cached. The direct OFAC
    # screen of the controllers always completes and found nothing, or the
    # verdict would be block.
    review_flags = [f for f in profile.flags if f.severity == "review"]
    if review_flags and all(f.code == INCOMPLETE_FLAG for f in review_flags):
        if policy.on_error == "refuse":
            return KyaDecision(accept=False, reason=KyaReason.UNAVAILABLE, incomplete=True, **base)
        return KyaDecision(accept=True, incomplete=True, **base)

    review = policy.review
    accept = review(profile, context) if callable(review) else review == "accept"
    if accept:
        return KyaDecision(accept=True, **base)
    return KyaDecision(accept=False, reason=KyaReason.NEEDS_REVIEW, **base)


def _no_agent_decision(payer: str, policy: CredKyaPolicy, screen: SanctionsScreen | None) -> KyaDecision:
    if policy.no_agent == "accept":
        return KyaDecision(payer=payer, accept=True, source="screen")
    if policy.no_agent == "refuse":
        return KyaDecision(payer=payer, accept=False, reason=KyaReason.NOT_AN_AGENT, source="screen")
    assert screen is not None
    if screen.sanctioned:
        return KyaDecision(
            payer=payer,
            accept=False,
            reason=KyaReason.SANCTIONED,
            source="screen",
            lists_checked=tuple(screen.lists_checked),
        )
    return KyaDecision(payer=payer, accept=True, source="screen", lists_checked=tuple(screen.lists_checked))


def _fallback_from_screen(payer: str, screen: SanctionsScreen, error: BaseException) -> KyaDecision:
    if screen.sanctioned:
        return KyaDecision(
            payer=payer,
            accept=False,
            reason=KyaReason.SANCTIONED,
            source="fallback_screen",
            lists_checked=tuple(screen.lists_checked),
            error=error,
        )
    return KyaDecision(
        payer=payer, accept=True, source="fallback_screen", lists_checked=tuple(screen.lists_checked), error=error
    )


@dataclass(frozen=True)
class CacheTtl:
    """Seconds a payer decision is cached. ``block`` defaults to 1 h (the
    sanctions lists refresh hourly); the others to 15 min."""

    passed: float = 15 * MINUTE
    review: float = 15 * MINUTE
    block: float = 60 * MINUTE
    no_agent: float = 15 * MINUTE


class _DecisionCache:
    """Per-payer decisions, bounded, safe across threads."""

    def __init__(self, ttl: CacheTtl, size: int, now: Callable[[], float]):
        self._ttl = ttl
        self._size = size
        self._now = now
        self._entries: OrderedDict[str, tuple[KyaDecision, float]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, payer: str) -> KyaDecision | None:
        with self._lock:
            entry = self._entries.get(payer)
            if entry is None:
                return None
            decision, expires_at = entry
            if expires_at <= self._now():
                del self._entries[payer]
                return None
            return replace(decision, source="cache")

    def put(self, payer: str, decision: KyaDecision) -> None:
        if decision.incomplete:
            return
        if decision.source == "screen":
            lifetime = self._ttl.no_agent if decision.accept else self._ttl.block
        elif decision.verdict == "block" or decision.reason == KyaReason.SANCTIONED:
            lifetime = self._ttl.block
        elif decision.verdict == "review":
            lifetime = self._ttl.review
        else:
            lifetime = self._ttl.passed
        with self._lock:
            self._entries.pop(payer, None)
            self._entries[payer] = (decision, self._now() + lifetime)
            while len(self._entries) > self._size:
                self._entries.popitem(last=False)


def _abort_result(decision: KyaDecision) -> Any:
    if decision.accept:
        return None
    from x402.schemas import AbortResult  # optional extra, imported once x402 calls us

    flags = f" (flags {', '.join(decision.flags)})" if decision.flags else ""
    reason = (decision.reason or KyaReason.NEEDS_REVIEW).value
    return AbortResult(
        reason=reason, message=f"Cred Know Your Agent refused payer {decision.payer or 'unknown'}{flags}"
    )


def _require_x402() -> None:
    try:
        import x402.schemas  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise ImportError('KYA hooks need the x402 package: pip install "cred-protocol[x402]"') from e


DecisionListener = Callable[[KyaDecision, Any], Any]


def _is_before_handler_settle(context: Any) -> bool:
    # after-handler settles follow a verify the after-verify hook already
    # screened; cancel settles return funds and must never be blocked.
    return getattr(context, "phase", None) == "before-handler"


class _SettleContextView:
    """A settle context seen as a verify result (no facilitator payer)."""

    def __init__(self, context: Any):
        self.payment_payload = getattr(context, "payment_payload", None)
        self.requirements = getattr(context, "requirements", None)
        self.result = None
        self.settle_context = context


# ---------------------------------------------------------------------------
# Async screener
# ---------------------------------------------------------------------------


class CredKyaScreener:
    """The async decision engine behind the hooks. One instance shares its
    cache and in-flight lookups across every hook it creates."""

    def __init__(
        self,
        api_key: str = "",
        *,
        policy: CredKyaPolicy | None = None,
        timeout: float = 1.5,
        screen_timeout: float = 1.0,
        cache_ttl: CacheTtl | None = None,
        cache_size: int = 10_000,
        on_decision: DecisionListener | None = None,
        base_url: str = DEFAULT_API_BASE_URL,
        client: Any = None,
        now: Callable[[], float] = time.monotonic,
    ):
        self.client = client or CredKyaClient(api_key, base_url=base_url)
        self.policy = policy or CredKyaPolicy()
        self.timeout = timeout
        self.screen_timeout = screen_timeout
        self.on_decision = on_decision
        self._cache = _DecisionCache(cache_ttl or CacheTtl(), cache_size, now)
        # One lookup per payer at a time; a lookup that outlives its
        # timeout keeps running and fills the cache for the next payment.
        self._inflight: dict[str, asyncio.Task[KyaDecision]] = {}

    async def _lookup(self, payer: str, context: Any) -> KyaDecision:
        profile = await self.client.kya_by_wallet(payer)
        if profile is None:
            screen = await self.client.sanctions_screen(payer) if self.policy.no_agent == "screen" else None
            decision = _no_agent_decision(payer, self.policy, screen)
        else:
            decision = decide_from_profile(profile, self.policy, context, payer)
        self._cache.put(payer, decision)
        return decision

    async def _fallback(self, payer: str, error: BaseException) -> KyaDecision:
        if self.policy.on_error == "refuse":
            return KyaDecision(payer=payer, accept=False, reason=KyaReason.UNAVAILABLE, source="error", error=error)
        # Fail open, but never past a sanctioned payer: the screen is one fast read.
        try:
            screen = await asyncio.wait_for(self.client.sanctions_screen(payer), self.screen_timeout)
        except Exception as screen_error:  # noqa: BLE001 - every failure is a decision
            return KyaDecision(payer=payer, accept=True, source="error", error=screen_error)
        return _fallback_from_screen(payer, screen, error)

    async def decide(self, context: Any) -> KyaDecision:
        payer = payer_from_context(context)
        if payer is None:
            # Nothing to screen: refuse when failing closed, else let x402's own verification stand.
            if self.policy.on_error == "refuse":
                return KyaDecision(payer=None, accept=False, reason=KyaReason.UNAVAILABLE, source="error")
            return KyaDecision(payer=None, accept=True, source="error")

        cached = self._cache.get(payer)
        if cached is not None:
            return cached

        task = self._inflight.get(payer)
        if task is None:
            task = asyncio.ensure_future(self._lookup(payer, context))
            self._inflight[payer] = task
            task.add_done_callback(lambda t, p=payer: self._finish(p, t))
        try:
            return await asyncio.wait_for(asyncio.shield(task), self.timeout)
        except Exception as error:  # noqa: BLE001 - timeouts and API errors alike
            return await self._fallback(payer, error)

    def _finish(self, payer: str, task: asyncio.Task[KyaDecision]) -> None:
        if self._inflight.get(payer) is task:
            del self._inflight[payer]
        if not task.cancelled():
            task.exception()  # retrieve it, so a timed-out failure is not logged as never retrieved

    async def screen(self, context: Any) -> Any:
        """Decide and return an x402 ``AbortResult`` to refuse, or None. Never raises."""
        try:
            decision = await self.decide(context)
        except Exception as error:  # noqa: BLE001 - the hook must never raise
            decision = (
                KyaDecision(payer=None, accept=False, reason=KyaReason.UNAVAILABLE, source="error", error=error)
                if self.policy.on_error == "refuse"
                else KyaDecision(payer=None, accept=True, source="error", error=error)
            )
        await self._notify(decision, context)
        return _abort_result(decision)

    async def _notify(self, decision: KyaDecision, context: Any) -> None:
        if self.on_decision is None:
            return
        try:
            result = self.on_decision(decision, context)
            if isinstance(result, Awaitable):
                await result
        except Exception:  # noqa: BLE001 - an audit logger must not change the outcome
            pass

    async def after_verify(self, context: Any) -> Any:
        """An ``on_after_verify`` hook."""
        result = getattr(context, "result", None)
        if not getattr(result, "is_valid", False):
            return None
        return await self.screen(context)

    async def before_settle(self, context: Any) -> Any:
        """An ``on_before_settle`` hook; acts only at the ``before-handler`` phase."""
        if not _is_before_handler_settle(context):
            return None
        return await self.screen(_SettleContextView(context))


# ---------------------------------------------------------------------------
# Sync screener
# ---------------------------------------------------------------------------


class CredKyaScreenerSync:
    """The blocking decision engine, for ``x402ResourceServerSync``.

    The lookup itself is bounded by ``timeout`` (an HTTP timeout); there is
    no background completion, so a payer whose first lookup times out is
    looked up again on their next payment."""

    def __init__(
        self,
        api_key: str = "",
        *,
        policy: CredKyaPolicy | None = None,
        timeout: float = 1.5,
        screen_timeout: float = 1.0,
        cache_ttl: CacheTtl | None = None,
        cache_size: int = 10_000,
        on_decision: DecisionListener | None = None,
        base_url: str = DEFAULT_API_BASE_URL,
        client: Any = None,
        now: Callable[[], float] = time.monotonic,
    ):
        self.client = client or CredKyaClientSync(api_key, base_url=base_url)
        self.policy = policy or CredKyaPolicy()
        self.timeout = timeout
        self.screen_timeout = screen_timeout
        self.on_decision = on_decision
        self._cache = _DecisionCache(cache_ttl or CacheTtl(), cache_size, now)

    def _fallback(self, payer: str, error: BaseException) -> KyaDecision:
        if self.policy.on_error == "refuse":
            return KyaDecision(payer=payer, accept=False, reason=KyaReason.UNAVAILABLE, source="error", error=error)
        try:
            screen = self.client.sanctions_screen(payer, timeout=self.screen_timeout)
        except Exception as screen_error:  # noqa: BLE001
            return KyaDecision(payer=payer, accept=True, source="error", error=screen_error)
        return _fallback_from_screen(payer, screen, error)

    def decide(self, context: Any) -> KyaDecision:
        payer = payer_from_context(context)
        if payer is None:
            if self.policy.on_error == "refuse":
                return KyaDecision(payer=None, accept=False, reason=KyaReason.UNAVAILABLE, source="error")
            return KyaDecision(payer=None, accept=True, source="error")
        cached = self._cache.get(payer)
        if cached is not None:
            return cached
        try:
            profile = self.client.kya_by_wallet(payer, timeout=self.timeout)
            if profile is None:
                screen = (
                    self.client.sanctions_screen(payer, timeout=self.screen_timeout)
                    if self.policy.no_agent == "screen"
                    else None
                )
                decision = _no_agent_decision(payer, self.policy, screen)
            else:
                decision = decide_from_profile(profile, self.policy, context, payer)
        except Exception as error:  # noqa: BLE001
            return self._fallback(payer, error)
        self._cache.put(payer, decision)
        return decision

    def screen(self, context: Any) -> Any:
        try:
            decision = self.decide(context)
        except Exception as error:  # noqa: BLE001 - the hook must never raise
            decision = (
                KyaDecision(payer=None, accept=False, reason=KyaReason.UNAVAILABLE, source="error", error=error)
                if self.policy.on_error == "refuse"
                else KyaDecision(payer=None, accept=True, source="error", error=error)
            )
        if self.on_decision is not None:
            try:
                self.on_decision(decision, context)
            except Exception:  # noqa: BLE001
                pass
        return _abort_result(decision)

    def after_verify(self, context: Any) -> Any:
        result = getattr(context, "result", None)
        if not getattr(result, "is_valid", False):
            return None
        return self.screen(context)

    def before_settle(self, context: Any) -> Any:
        if not _is_before_handler_settle(context):
            return None
        return self.screen(_SettleContextView(context))


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def register_cred_kya(server: Any, api_key: str = "", **options: Any) -> Any:
    """Register Know Your Agent screening on an x402 resource server.

    Picks the sync engine for ``x402ResourceServerSync`` and the async one
    otherwise, registers ``on_after_verify`` and ``on_before_settle``, and
    returns the server. Keyword options are those of
    :class:`CredKyaScreener` (``policy``, ``timeout``, ``cache_ttl``,
    ``on_decision``, ...)::

        from x402.server import x402ResourceServer
        from cred_protocol import register_cred_kya

        register_cred_kya(server, api_key=os.environ["CRED_API_KEY"])
    """
    _require_x402()
    from x402.server import x402ResourceServerSync

    screener: CredKyaScreener | CredKyaScreenerSync
    if isinstance(server, x402ResourceServerSync):
        screener = CredKyaScreenerSync(api_key, **options)
    else:
        screener = CredKyaScreener(api_key, **options)
    server.on_after_verify(screener.after_verify)
    server.on_before_settle(screener.before_settle)
    return server


def cred_kya_after_verify_hook(api_key: str = "", **options: Any) -> Callable[[Any], Awaitable[Any]]:
    """The async ``on_after_verify`` hook alone (the ``authorization`` flow only)."""
    _require_x402()
    return CredKyaScreener(api_key, **options).after_verify
