# Cred Protocol SDKs

Client libraries for the [Cred Protocol](https://credprotocol.com) API: trust evaluation for wallets and AI agents, framework middleware that gates routes on it, and Know Your Agent screening for [x402](https://x402.org) sellers.

| Package | Registry | Docs |
|---|---|---|
| `@cred-protocol/sdk` | [npm](https://www.npmjs.com/package/@cred-protocol/sdk) | [TypeScript SDK](https://docs.credprotocol.com/sdks/typescript) |
| `@cred-protocol/hono` | [npm](https://www.npmjs.com/package/@cred-protocol/hono) | [Hono middleware](https://docs.credprotocol.com/sdks/hono) |
| `@cred-protocol/express` | [npm](https://www.npmjs.com/package/@cred-protocol/express) | [Express middleware](https://docs.credprotocol.com/sdks/express) |
| `@cred-protocol/nextjs` | [npm](https://www.npmjs.com/package/@cred-protocol/nextjs) | [Next.js middleware](https://docs.credprotocol.com/sdks/nextjs) |
| `cred-protocol` | [PyPI](https://pypi.org/project/cred-protocol/) | [Python SDK](https://docs.credprotocol.com/sdks/python) |

```bash
npm install @cred-protocol/sdk
pip install cred-protocol
```

You need a Cred API key from [app.credprotocol.com](https://app.credprotocol.com).

## Screen x402 payers (Know Your Agent)

Both SDKs register Cred's Know Your Agent check on an x402 v2 resource server, so a paying AI agent is screened (sanctions, identity, operator, history) before its payment settles:

```ts
import { registerCredKya } from '@cred-protocol/sdk';
registerCredKya(server, { apiKey: process.env.CRED_API_KEY! });
```

```python
from cred_protocol import register_cred_kya
register_cred_kya(server, api_key=os.environ["CRED_API_KEY"])
```

See [Know Your Agent](https://docs.credprotocol.com/know-your-agent).

## Repository layout

```
typescript/   pnpm workspace: packages/sdk (core), packages/{hono,express,nextjs} (adapters over the core's gates.ts)
python/       the cred-protocol package (hatchling, uv)
```

## Development

TypeScript (Node 22, pnpm 11.5.0):

```bash
cd typescript
pnpm install
pnpm -r build && pnpm -r typecheck && pnpm -r test
```

Python (3.10+, uv):

```bash
cd python
uv run --locked --extra x402 pytest
```

CI runs both on every pull request.

## Releasing

Bump the versions in `typescript/packages/*/package.json` and `python/pyproject.toml`, then either push an `sdk-v*` tag or run the **Publish** workflow by hand. It publishes to npm (with provenance) and PyPI through trusted publishing, and skips any version that is already on the registry.

## License

MIT
