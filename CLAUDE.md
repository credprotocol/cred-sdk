# CLAUDE.md

Guidance for Claude Code in the public Cred Protocol SDK repo. The API these SDKs call lives in the private monorepo `credprotocol/cred-webapp`; an SDK change that follows an API change is a separate PR here.

## Layout

- `typescript/`: pnpm workspace (pnpm pinned to 11.5.0, Node 22). `packages/sdk` is the core (`@cred-protocol/sdk`); `packages/{hono,express,nextjs}` are framework adapters that depend on it via `workspace:*`, so npm can't install the workspace. Use pnpm.
- `python/`: the `cred-protocol` package (hatchling, httpx), extras `fastapi` and `x402`, dev dependencies pinned in `uv.lock`.

## Commands

```bash
cd typescript && pnpm install && pnpm -r build && pnpm -r typecheck && pnpm -r test
cd python && uv run --locked --extra x402 pytest
```

CI (`.github/workflows/ci.yml`) runs the TypeScript workspace and the Python suite on 3.10 and 3.13.

## Gates (TypeScript)

- **Adapters are thin.** The three adapters translate between their framework and the core's `packages/sdk/src/gates.ts`. Put new gate behaviour in `gates.ts`, never in an adapter.
- **Core API.**
  - `createGate(config)` builds the client once.
  - `gate.evaluate(wallet)` / `evaluateGate(client, options, wallet)` returns a plain `GateDecision` (`allow`, `status`, `body`, `headers`, `reason`, `result`).
  - `walletFromRequest({ header, query })` is the default `X-Wallet-Address` / `?wallet=` extraction.
- **Shared options.** Each adapter's `CredGatesOptions` extends the core `CredGateConfig`, and adds only framework-typed hooks: `extractWallet`, `onEvaluation` (fired through `notifyEvaluation`, errors swallowed), and Next.js `matcher`.
- **Behaviour.** All three adapters send the core's response bodies and set the trust headers on 402/403 denials.
- **vite pin.** Every package that runs vitest pins `vite` as a devDependency: otherwise pnpm satisfies vitest's `vite` peer with a stale copy from the lock.

## Know Your Agent hooks (x402 sellers)

Both SDKs screen x402 payers with the Cred API's `/api/v2/agents/by-wallet/{payer}/kya` before a payment settles. Each registers two hooks:
- `afterVerify` for the `authorization` flow;
- `beforeSettle`, only at the `before-handler` phase, for `upfront`/`escrow`, because those flows never run after-verify hooks.

Both share the same policy, reason codes (`payer_sanctioned`, `payer_needs_review`, `payer_not_registered_agent`, `payer_screening_unavailable`), per-payer cache, and "fail open but still OFAC-screen" behaviour.

- **TypeScript** (`packages/sdk/src/kya.ts`): `registerCredKya(server, { apiKey })`.
  - **Never throw:** `@x402/core` logs a throwing hook and settles anyway.
  - **Types:** the hook types are structural. `@x402/core` is a devDependency only, used by `kya.x402.test.ts` against a real `x402ResourceServer`.
- **Python** (`python/cred_protocol/kya.py`): `register_cred_kya(server, api_key=...)`.
  - **Two engines:** it picks the sync engine for `x402ResourceServerSync`, which refuses async hooks.
  - **Abort type:** it must return x402's own `AbortResult`, because x402 checks `isinstance`, so `x402` is an optional extra imported lazily.
  - **Never raise:** x402 Python re-raises a hook's exception and fails the request.

## Releasing

- **Steps.** Bump `typescript/packages/*/package.json` and/or `python/pyproject.toml`, then push an `sdk-v*` tag or run **Publish** (`.github/workflows/publish.yml`, inputs `publish_npm`, `publish_pypi`, `dry_run`).
- **Auth.** Trusted publishing (OIDC) on both registries; no secrets.
- **npm details.** npm 11.21.1 is installed in the job, because Node 22 bundles npm 10. Each package is `pnpm pack`ed (which rewrites `workspace:*`) and published with `--provenance`. Provenance needs this repo public, and each package.json `repository.url` must name it.
- **Trusted publishers.** On npmjs.com and PyPI they must be credprotocol / cred-sdk / `publish.yml` / environment `release`. The `release` environment admits only `main` and `sdk-v*` tags, and a tag ruleset lets only admins create `sdk-v*` tags. npm expires a new trusted publisher that has not published within 2 days, so create it and publish in the same sitting.
- **Already published.** Versions already on a registry are skipped.
- **January 2027.** npm restricts direct `npm publish` then. Before that, move to `npm stage publish` + approval.

## Repository settings

- **Rulesets.** `main: CI gate` (PR + squash only + the three CI checks, strict) and `release tags: admins only` (`sdk-v*`). Admins bypass both.
- **Security features.** Secret scanning with push protection, Dependabot security updates, CodeQL default setup, and private vulnerability reporting (see `SECURITY.md`) are on.
- **Workflow token.** Read-only by default, so workflows declare their own permissions.

## Conventions

- Conventional commits.
- No `Co-Authored-By` lines naming an AI.
- Never commit secrets: this repo is public.
