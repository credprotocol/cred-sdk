# cred-protocol

Async Python client and FastAPI dependency for the [Cred Protocol](https://credprotocol.com) trust evaluation API — composite trust scores (credit, sybil resistance, identity) for any Ethereum wallet, with policy templates and gates.

```bash
pip install cred-protocol            # core client (httpx)
pip install "cred-protocol[fastapi]" # + FastAPI dependency
pip install "cred-protocol[x402]"    # + Know Your Agent hooks for x402 sellers
```

## Quick start

```python
import asyncio
from cred_protocol import CredClient

async def main():
    async with CredClient(api_key="cred_sk_...") as cred:
        result = await cred.evaluate(
            wallet_address="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            policy="standard",
        )
        print(result.trust_score)  # 0-100
        print(result.trust_tier)   # TrustTier.VERIFIED
        print(result.all_passed)   # True

asyncio.run(main())
```

Custom gates instead of a policy template:

```python
result = await cred.evaluate(
    wallet_address="0x...",
    gates=["human", "verified", "established"],
    operator="WEIGHTED",
    weights={"human": 0.4, "verified": 0.35, "established": 0.25},
    composite_threshold=60,
)
```

## FastAPI

```python
import os
from fastapi import Depends, FastAPI
from cred_protocol import TrustResult
from cred_protocol.fastapi import require_trust

app = FastAPI()

@app.get("/resource")
async def get_resource(
    trust: TrustResult = Depends(require_trust(api_key=os.environ["CRED_API_KEY"], policy="standard")),
):
    return {"wallet": trust.wallet_address, "score": trust.trust_score, "tier": trust.trust_tier.value}
```

`require_trust(..., on_fail="deny" | "challenge" | "pass")` returns 403, 402 or lets the request through when the wallet fails the policy.

## Screen x402 payers (Know Your Agent)

Selling over [x402](https://x402.org)? Screen every paying AI agent with Cred's Know Your Agent check before its payment settles:

```python
import os
from x402.server import x402ResourceServer
from cred_protocol import register_cred_kya

server = x402ResourceServer(facilitator_client).register("eip155:8453", ExactEvmServerScheme())
register_cred_kya(server, api_key=os.environ["CRED_API_KEY"])
```

- **Both servers.** Works with `x402ResourceServer` (async) and `x402ResourceServerSync`, and with every x402 payment flow.
- **Refusing a payer.** A refused payer gets a `402` with `error` set to `payer_sanctioned`, `payer_needs_review`, `payer_not_registered_agent` or `payer_screening_unavailable`, and the payment never settles.
- **Policy.** `CredKyaPolicy` sets what to do with `review` verdicts, which flags always refuse, plain (non-agent) wallets, and what to do when Cred is unavailable.
- **Failing open.** Even when failing open, a sanctioned payer is always refused.

See [the Python SDK docs](https://docs.credprotocol.com/sdks/python#screen-x402-payers-know-your-agent).

## Links

- Docs: https://docs.credprotocol.com/sdks/python
- API keys: https://app.credprotocol.com/dashboard/keys
- Trust evaluation API base URL: `https://validator.credprotocol.com` (override with `CredClient(base_url=...)`)

MIT License.
