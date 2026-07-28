# Reference-family issues found during Phase 0 recon

Rule of engagement §8: *source beats documentation; doc bugs get reported.* This file collects every doc-vs-code disagreement, bug, and cross-client inconsistency found while extracting the wire contract. Commits pinned per [recon-manifest.md](recon-manifest.md). Items marked **[filed]** already have a GitHub issue.

## awesome-node-auth (reference, cc01e99, v1.9.0)

| # | Kind | Finding |
|---|---|---|
| N1 | security | **OAuth `state` nonce is generated but never verified.** `encodeOAuthState` packs `{n: nonce, o: origin, p: path}` (`src/router/auth.router.ts:280`); the callback only decodes and validates the *origin* against the allowlist (`:310`, `:325`). The nonce is dead weight — no round-trip check, so the callback has no CSRF/replay protection beyond origin matching. |
| N2 | security | **HS256 `jwt.verify` has no `algorithms` allow-list** (`src/services/token.service.ts:143`, `:152`) — alg-confusion exposure. The RS256/JWKS path *does* pin `algorithms: ['RS256']` (`:102-133`). |
| N3 | security | **Inbound webhook `vm` sandbox is not a security boundary.** Node's `vm` module is escapable by design; the 5s `timeout` only bounds the synchronous phase — the wrapped async IIFE is awaited unbounded (`src/router/tools.router.ts:289-294`). `WebhookSender.verify()` exists (`src/tools/webhook-sender.ts:65`) but `POST /tools/webhook/:provider` never calls it — inbound HMAC verification is unwired. |
| N4 | design | **Refresh token is stored verbatim (not hashed) on the user row** — one token per user, not per session (`updateRefreshToken` via `IUserStore`; compared at `src/router/auth.router.ts:644`). `ITokenStore` is exported but never consumed by any router. Consequences: token theft is undetectable server-side (no hash), concurrent sessions share rotation state, and per-session family revocation (as planned for the Lambda port) exceeds reference semantics — needs an explicit decision. |
| N5 | doc-bug | **CHANGELOG 1.8.1 claims "Removed: `adminSecret` support"**, but `adminSecret` is still present and functional (`src/router/admin.router.ts:54`, `:328`, `:560`). |
| N6 | gap | **No `/.well-known/openid-configuration`** — IdP mode is a JWT issuer with a JWKS endpoint (`src/router/auth.router.ts:490`), not an OIDC provider. Docs-site framing ("IdP mode") overstates this. Affects the Lambda port's headline feature: OIDC discovery is net-new in every scenario. |
| N7 | bug | **IdP keypair is generated per process and mutated onto the live config object** when `idProvider.privateKey` is absent (`src/router/auth.router.ts:480-488`, `src/services/token.service.ts:61-69`); JWKS document is built once at router construction. Multi-instance deployments (incl. any serverless) get divergent JWKS. No file/KMS/Secrets loader exists. |
| N8 | bug | `createAuthRouter` **mutates the caller's `config` object** (`config.cookieOptions.refreshTokenPath`, `src/router/auth.router.ts:461-464`) — surprising shared-state side effect. |
| N9 | gap | **Rate limiting**: `RouterOptions.rateLimiter` is a pass-through Express handler slot (`src/router/auth.router.ts:46`); the library ships none, and the docs site has **no rate-limiting page anywhere** (sitemap-verified). The Cognito comparison must not imply otherwise. |
| N10 | gap | **The library never publishes to its own `AuthEventBus`** — no `identity.*` event is emitted from any router/strategy/middleware; events only flow via `AuthTools.track()` (tools router or app code). The 26 `AuthEventNames` are a convention, not implemented behavior, in v1.9.0. (v1.10 reportedly closes this — see F1.) |
| N11 | perf | Per-request `fs.existsSync` for UI assets (`src/router/ui.router.ts:310`, `:318`); `updateSessionLastActive` fires a store write on **every** authenticated request (`src/middleware/auth.middleware.ts:56-58`) — a cost concern on pay-per-request stores. |

## awesome-go-auth (4b2fc5c) — all **[filed]** as issues #6–#16 + audit comment on #5

Credential leak in adapter responses (#6); `Register` auto-verifies email (#7); non-JWT token format (#8); 5/30 routes (#9); OAuth state never verified / no PKCE / dead `PendingLinkStore` (#10); bundled `auth.js` incompatible with own adapters (#11); examples don't compile + no persistent stores (#12); no CI/tags (#13); IdP ephemeral keys + in-process auth codes (#14); webhook fire-and-forget + `X-Signature-SHA256` vs reference `X-Webhook-Signature` header divergence (#15); docs drift incl. README_DETAILED fictional adapter API and config-default contradictions (#16).

## Clients

| # | Repo | Finding |
|---|---|---|
| C1 | ng-awesome-node-auth | **Dual default `apiPrefix`**: `auth.config.ts` `resolveOptions()` defaults to `/auth`, but `ui-config.service.ts` independently defaults to `/api/auth` in three places. A consumer omitting `apiPrefix` gets the auth service and UI-config service talking to different paths. |
| C2 | ng vs flutter | **`GET /linked-accounts` response-shape disagreement**: Angular expects `{linkedAccounts: [...]}`, Flutter expects a bare array. Serving the object keeps Angular working and degrades Flutter to an empty list; serving the array breaks Angular. The port ships the object; Flutter-side fix recommended. |
| C3 | flutter | `DELETE /sessions/{handle}` — handle is **not** URI-escaped (Angular escapes it). Session handles containing reserved characters would break the Flutter client. |
| C4 | flutter | Multipart requests cannot be retried after a 401-refresh (`_cloneRequest` supports only `http.Request`, throws `UnsupportedError`). |
| C5 | both | Magic-link `mode` field: Angular sends `mode:'login'`, Flutter omits it — the server must default missing `mode` to `login` (reference does; contract-suite assertion needed). |

## Family-level

| # | Finding |
|---|---|
| F1 | **The public reference repo may lag the private line.** awesome-go-auth issues #4/#5 (by nik2208, 2026-05-19) reference an "awesome-node-auth v1.10" that auto-publishes identity events, linking to `nik2208/node-auth` PR #56 / issue #55 — a repo that is not public. npm `latest` is 1.9.0 (2026-04-29) and the public GitHub HEAD (cc01e99) matches it. Phase 0 specs are pinned to v1.9.0; **if v1.10 exists privately, the wire contract should be re-checked against it before P1.** |
| F2 | The Go port's parity work was aligned against the **Python** port (commits `bd9c01f`, `34de3d3`), not the Node reference — a second-order port; explains much of its drift. |
| F3 | UI-asset strategy is inconsistent across ports: Rust vendors reference assets byte-identical (same git blob SHAs, incl. `auth.js` = `ca41f0a2…`); Go hand-wrote its own incompatible 8.4KB `auth.js`. The family convention worth standardizing (and what the Lambda port will do) is byte-identical vendoring + a CI SHA drift check. |
