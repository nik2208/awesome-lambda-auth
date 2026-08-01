# Serverless gap analysis — awesome-node-auth v1.9.0 under the Lambda runtime model

Per-module verdict on the reference implementation (pinned `cc01e99`, see [recon-manifest.md](recon-manifest.md)): what survives a move to request-scoped, multi-instance, freeze-after-response execution; what needs adaptation; what must be re-architected. Section 3 corrects the project brief's §4 first pass where the code disagreed with its assumptions.

> **Verification status (2026-07-29):** this document was cross-checked against the adversarially-verified wire-contract extraction ([wire-contract.md](wire-contract.md) + `_extract/01`–`09`). All SURVIVES/ADAPT/REBUILD/NET-NEW verdicts held. Corrections applied: the SSE `lastEventId` claim (it is a dedup cursor, not resume state — `Last-Event-ID` is never read; see §1.5/§3), the `checkOn` cost note scoped to consumer middleware (§1.2), and enrichments in §1.1–§1.5 (OAuth empty-allowlist caveat, tempToken caveat, IdP HS256 fact, tools-router hosting facts, SSE wire format). Already-drafted facts confirmed by the extraction: admin router reads `admin.js`/`admin.css` once at construction + multer disk uploads (§1.1), per-request `fs.existsSync` in ui.router (§1.1), IdP keypair generation mutating the live config (§1.3), in-process webhook retry loop (§1.5).

Verdicts:
- **SURVIVES** — correct as-is under Lambda (stateless or immutable-cache only)
- **ADAPT** — bounded change: new store/integration implementation behind an existing seam, or config hardening
- **REBUILD** — the mechanism itself assumes a long-lived process; needs a serverless-native replacement
- **NET-NEW** — does not exist in the reference; building it is product work, not porting

## 1. Module-by-module

### 1.1 Routers and strategies

| Module | Verdict | Why |
|---|---|---|
| `src/router/auth.router.ts` (~40 routes) | **SURVIVES** | Handlers are stateless request/response over store interfaces. Proven behind a non-`listen()` handler by `demo/nextjs-fullstack` + `tests/demo-nextjs-api.test.ts`. Two caveats → 1.4 (rate limiter slot) and 1.3 (IdP key at construction). |
| `src/strategies/local` (login, email-verification modes) | **SURVIVES** | Pure store-backed logic; bcrypt via `bcryptjs` (pure JS — no native binding problem on Lambda; CPU cost note in §4). |
| `src/strategies/magic-link`, `sms`, `two-factor` | **SURVIVES** (library) / **ADAPT** (store) | Single-use tokens live on the user row via `IUserStore` — no process memory. But consumption is **read-then-clear** (e.g. `magic-link.strategy.ts:50`, reset clear at `auth.router.ts:820`): under concurrent invocations two Lambdas can both pass the read before either clears. The reference's stores never enforced atomicity; the DynamoDB store must (conditional write on the token attribute). This is a store-implementation obligation, not a router change. |
| 2FA step-up (`tempToken`) | **SURVIVES** | Stateless 5-min JWT (`auth.router.ts:564-576`); no server state. Verified caveat (not a serverless issue): the tempToken is a *full* access token — same secret, same verifier — so it passes `authMiddleware` for its 5-minute life ([reference-issues.md](reference-issues.md) N14); scoping it in the port is a security decision, not a porting need. |
| TOTP setup | **SURVIVES** | Stateless: secret returned to client at `/2fa/setup`, passed back at `/2fa/verify-setup` (`auth.router.ts:832-845`). |
| `src/strategies/oauth/*` + state codec | **SURVIVES** | State is fully stateless — `{n, o, p}` base64url in the `state` param, origin validated on return (`auth.router.ts:280/310/325`). Nothing to externalize. (The nonce is never verified — pre-existing gap, [reference-issues.md](reference-issues.md) N1; fixing it serverlessly = HMAC-signed state or a DynamoDB TTL nonce item. Verified addition: with an **empty** origin allowlist any state-supplied origin is accepted (`:327`) — the port's config validation should require a non-empty allowlist.) |
| `IPendingLinkStore` (link-conflict stash) | **ADAPT** | Already an interface (`stash/retrieve/remove`) — maps directly to a DynamoDB TTL item (`PENDING_LINK#`). |
| `src/router/admin.router.ts` | **ADAPT** + one **REBUILD** | REST surface is stateless. `admin.js`/`admin.css` are read once at construction (fine). **Uploads are the rebuild**: `multer.diskStorage` into a local `uploadDir` + static serving of that dir (`admin.router.ts:994-1021`, `ui.router.ts:187-189`) assumes a persistent writable disk → S3 (+ presigned or CloudFront serving). |
| `src/router/ui.router.ts` | **ADAPT** | Per-request `fs.existsSync` (`:310`, `:318`) and disk-served assets → embed assets in the artifact (byte-identical vendoring, Rust-port style) and/or CloudFront+S3; SSR config injection (`window.__AUTH_CONFIG__`) is pure string work and survives. |
| `src/router/openapi.ts` | **SURVIVES** | Pure spec builders. 74KB module — lazy-load to keep it off the cold path. |

### 1.2 Sessions, tokens, cookies

| Module | Verdict | Why |
|---|---|---|
| `ISessionStore` usage (`checkOn: allcalls/refresh/none`) | **ADAPT** | No L1/L2 cache exists in the reference — `checkOn` is only a read-frequency switch, so there is nothing illegal to remove. Verified scope correction: the auth router builds its own middleware **without** a sessionStore (`auth.router.ts:466`), so on the router's own protected routes `allcalls` never checks and `updateSessionLastActive` never fires ([reference-issues.md](reference-issues.md) N22) — both apply only to consumer middleware (`AuthConfigurator.middleware({sessionStore})`). Cost note (consumer middleware): `allcalls` = 1 DynamoDB read **and** `updateSessionLastActive` fires a best-effort write on *every* authenticated request regardless of `checkOn` (`auth.middleware.ts:55-58`). The port should batch/throttle lastActive writes (e.g. only when >60s stale) — behavior-preserving, cost-motivated — and decide whether to fix N22 (wiring the store changes revocation latency on router routes). |
| Refresh rotation | **ADAPT** + decision | Reference stores the refresh token **verbatim, one per user, on the user row** and compares at `auth.router.ts:644` ([reference-issues.md](reference-issues.md) N4). Rotation under concurrent refresh is last-write-wins read-then-write → same conditional-write obligation as other single-use paths. The brief's per-session token families + replay-triggered family revocation **exceed reference semantics** — adopting them is a (desirable) deviation that changes multi-device behavior; needs explicit sign-off and a `CompatibilityNotes()` entry. |
| `src/services/token.service.ts` (HS256, cookies) | **SURVIVES** | Pure. Cookie prefix/attribute logic (`:161-302`) depends on knowing the request is HTTPS — behind API Gateway that signal is `x-forwarded-proto`/deployment config, which the event-normalization layer must supply correctly (§1.7). Two verified reference bugs ride along (not serverless issues): cookie `Max-Age` is hardcoded (15 m/7 d) regardless of configured TTLs (`:195`, `:200`), and `__Host-` promotion discards `refreshTokenPath` scoping (`:185-188`) — [reference-issues.md](reference-issues.md) N24/N25; the port derives Max-Age from the TTL knobs. |
| CSRF (`auth.middleware.ts:35-41`, cookie init `auth.router.ts:530-538`) | **SURVIVES** | Stateless double-submit; cookie minted per request when absent. No server state. |
| `src/services/password.service.ts` | **SURVIVES** | bcrypt hash/compare, pure. |

### 1.3 IdP mode / JWKS

| Module | Verdict | Why |
|---|---|---|
| RS256 signing + keypair handling | **REBUILD** (key custody) | Keys come only from config PEM strings; when absent a keypair is **generated per process and mutated onto the config object**, and the JWKS document is built once at router construction (`auth.router.ts:480-488`, `token.service.ts:61-69`). Under Lambda every environment mints different keys → tokens unverifiable across instances. Replacement: KMS asymmetric signing (private key never in the function) or Secrets-Manager-injected PEM; multi-`kid` JWKS built from `kms:GetPublicKey`; generation-fallback refused outside dev mode. Verified scope fact: enabling `idProvider` does **not** switch router-issued session tokens to RS256 — no caller of `generateIdProviderTokenPair` exists in `src/`; `/login`//`/refresh` always issue HS256 (`auth.router.ts:441`), RS256 issuance is a host-app-level API ([reference-issues.md](reference-issues.md) N35). The rebuild is key custody + JWKS; *which* tokens the Lambda IdP mode signs is a design decision for the OIDC doc, not a ported behavior. |
| `JwksService`/`JwksClient` (resource-server side) | **SURVIVES** | In-memory JWKS cache with SWR + invalidation on unknown `kid` (`jwks.service.ts:30-81`, `token.service.ts:118`) is exactly the immutable/safely-stale caching that stays legal per instance. |
| OIDC discovery, authorize/token endpoints | **NET-NEW** | Do not exist in the reference (JWKS endpoint only, `auth.router.ts:490`). The strategic wedge (API GW JWT authorizer / ALB OIDC against our issuer) is built, not ported — sanctioned by the brief, but scoped as new surface with its own spec. |

### 1.4 Rate limiting and abuse

**NET-NEW.** The reference ships no limiter — `RouterOptions.rateLimiter` is an empty slot for a host-supplied Express handler (`auth.router.ts:46`), and demos wire `express-rate-limit` (whose MemoryStore would be per-container anyway). The port builds: DynamoDB token-bucket/fixed-window via conditional writes + TTL, per-IP/per-account/per-tenant, lockout + progressive delay on the five sensitive flows, WAF recipes as outer layer. There are no reference semantics to preserve — free design surface, but also nothing to inherit.

### 1.5 Events, webhooks, telemetry, SSE

| Module | Verdict | Why |
|---|---|---|
| `AuthEventBus` | **ADAPT** (smaller than assumed) | The library **never publishes to its own bus** in v1.9.0 — no `identity.*` emission from any router/strategy/middleware; events flow only through `AuthTools.track()` (tools router or app code). So the "event plane" port is: give `AuthTools.track` a pluggable transport (`inprocess | eventbridge | sns`). No auth-flow refactor involved. (v1.10 may change this — [reference-issues.md](reference-issues.md) F1.) |
| `WebhookSender` (outbound) | **REBUILD** (delivery) | Fire-and-forget promise with in-process `setTimeout` exponential backoff **after the response is sent** (`webhook-sender.ts:46`, dispatch `auth-tools.ts:250-268`) — killed at freeze or silently billed. Replacement: SQS consumer Lambda + DLQ. **Wire format survives untouched**: `X-Webhook-Signature: sha256=<hex>` + `X-Webhook-Event/-Delivery/-Timestamp`, payload envelope `{event, version, timestamp, data, metadata}`. |
| Inbound webhook scripts (`tools.router.ts:251-306` + `ActionRegistry`) | **REBUILD** | Two hard problems: (a) Node `vm` is not a security boundary and the 5s timeout only bounds the sync phase; (b) the capability surface is a **module-level Map of live function references** (`webhook-action.ts:57`) populated at boot by decorators — in-process code, not data. Replacement per brief §4.8: dedicated script-runner Lambda (IAM as the sandbox) with a declarative action manifest replacing the registry; the enabled∩allowed∩dependsOn intersection logic (`webhook-action.ts:108`) ports as data. Also fix: inbound HMAC verification exists but is never called (N3) — wiring it is a security improvement, note in deviations. |
| `ITelemetryStore` | **ADAPT** | Interface (`save` + optional `query` gating `GET /tools/telemetry`) → DynamoDB impl; optional Firehose sink later. |
| SSE (`SseManager`) | **REBUILD** | The irreducibly process-local piece: `connections` Map of live `res` handles + per-connection `setInterval` heartbeat (`sse-manager.ts:89`, `:156-164`). `ISseDistributor` seam exists but no impl ships, and note the subtlety: with a distributor configured, `broadcast()` publishes **only** to the distributor and relies on the echo back for local delivery (`:190-197`) — the port's DynamoDB/EventBridge distributor must preserve that. Plan (brief §4.3) stands: Function URL response streaming behind CloudFront as default, WebSocket shim and polling fallback as alternatives, Last-Event-ID resume from an event log. **Corrected (verified):** the reference has **no** resume support to port — the `Last-Event-ID` request header is never read anywhere in `src/` and there is no replay buffer; the per-connection `lastEventId` (`:214-216`) is only a single-value dedup cursor against the immediately-preceding delivered id. Resume-from-event-log is net-new surface. Confirmed wire format to preserve: **every frame is a named event** (`id:`/`event: <type>`/`data:` — never the default `message` event) with the payload re-keyed under `rawData` and no `data` key in the JSON (`sse-manager.ts:249-253`; wire-contract hard point 10 — and the reason both shipped clients' `onmessage` listeners receive nothing, [reference-issues.md](reference-issues.md) C6). |
| Tools-router hosting | **ADAPT** (event-normalization obligations) | Verified facts the Lambda HTTP layer must honor: the library **never auto-mounts** `createToolsRouter` — clients hardcode `${apiPrefix}/tools/stream`, so the port must expose the tools surface at `<apiPrefix>/tools` (wire-contract hard point 10); the router mounts **no body parser** (`POST /track`//`notify`//`webhook` throw without host JSON parsing under Express 5, `tools.router.ts:143`, `:168`) — the `lambdahttp` layer always supplies parsed JSON; `?token=` is promoted to `Authorization: Bearer` for `EventSource` clients (`:185-190`) and must survive normalization. Reference bug noted in passing: `POST /track` trusts body `userId` over the authenticated principal ([reference-issues.md](reference-issues.md) N18). |

### 1.6 Mail, SMS, templates, notifications

| Module | Verdict | Why |
|---|---|---|
| `MailerService` / `SmsService` | **SURVIVES** / **ADAPT** | Already outbound HTTP POST with API key (`mailer.service.ts`, `sms.service.ts`) — works from Lambda unchanged. SES/SNS become additional senders behind the same config seam; SQS-decoupled dispatch is an additive option so a slow provider never blocks a login. |
| Templates + i18n (`ITemplateStore`, `MemoryTemplateStore`) | **ADAPT** | Store interface → DynamoDB impl; hardcoded en/it fallback behavior preserved exactly (it's in-code and stateless). `MemoryTemplateStore` is the **only** Memory store shipped in `src/` — rename-for-dev-only concern applies to the examples' `InMemory*` stores, which must not ship in the product path. |
| `NotificationService` | **SURVIVES** | Facade over the two above. |

### 1.7 Cross-cutting NET-NEW (product work, no reference counterpart)

- **Event normalization layer** (`lambdahttp`): API GW REST (multiValueHeaders) / HTTP API v2 (cookies array) / Function URL / ALB — multi-cookie serialization, `x-forwarded-proto`, stage-path handling, base64 bodies, multi-value query strings. The single most bug-prone seam; per-shape contract tests are the mitigation (brief §4.4 confirmed in full — including the `__Host-` vs stage-path trap and mandatory custom domain in cookie mode).
- **Declarative config** replacing `AuthConfigurator` + 5 options objects (→ [config-schema.md](config-schema.md)); secrets resolution (Secrets Manager/SSM) — the reference reads exactly one env var (`NODE_ENV`).
- **DynamoDB store suite**: the reference ships interfaces (15) + one memory template store; every persistent implementation is new (single-table design → `data-model.md`, P1 pre-work).
- **Deploy CLI, IaC, migration tooling, structured logging with redaction, metrics/alarms** — product layer, no counterpart.

## 2. What stays in memory legally (per instance)

JWKS documents + public keys (`JwksClient` SWR cache), parsed config, compiled email templates, embedded UI assets, OpenAPI spec (lazy). Everything else that mutates goes through a store interface — the reference's own seams — implemented on DynamoDB with conditional writes for every single-use/rotation path.

## 3. Corrections to the brief's §4 first pass

| Brief assumption | What the code says |
|---|---|
| §4.1 "audit … the L1 session cache, rate-limit counters, OAuth state/nonce caches" | **None of these exist.** No session cache (checkOn = read frequency), no in-library rate limiting (slot only), OAuth state fully stateless. The §4.1 audit's real hits: SSE registry, ActionRegistry, IdP keypair/JWKS-built-once, webhook retry loop, multer disk state, `MemoryTemplateStore`, and one module-level warning flag. |
| §4.1 "Every Memory*Store gets a DynamoDB counterpart" | Only `MemoryTemplateStore` ships in `src/`; the other `InMemory*` stores live in `examples/`. The real work is implementing 15 store *interfaces*, not replacing memory stores. |
| §4.1 "refresh rotation … revoke the whole token family" | Reference has **no token families** — one verbatim token per user on the user row (N4). The concurrent-refresh test as specified would fail against the reference too. Adopting per-session families = deliberate, documented deviation (recommended, but it's a decision, not a port). |
| §4.7 "In-process event bus … doesn't work" | The bus is never fed by the library in v1.9.0 (N10). The event plane reduces to making `AuthTools.track` transport-pluggable — hours, not weeks. Re-check against v1.10 (F1). |
| §4.6 "Emit a full openid-configuration, then prove the payoff" | Correct as a plan; but the reference has **no** OIDC discovery/authorize/token endpoints (N6) — this is new surface in every language, and its spec cannot be "extracted from the reference." Needs its own design doc governed by the no-invented-semantics rule → explicit sign-off. |
| §4.3 SSE preference order | Confirmed; add: the distributor seam already exists (`ISseDistributor`) with the only-distributor-no-local-broadcast subtlety to preserve. **Corrected against the verified extraction:** the reference has no reconnect-resume — `Last-Event-ID` is never read and there is no replay buffer; per-connection `lastEventId` is a dedup cursor only (`sse-manager.ts:214-216`). The brief's Last-Event-ID resume is net-new, not an extension of existing state. |
| §4.8 "reference runs inbound webhook actions in a sandbox" | It runs them in Node `vm`, which is **not a sandbox** (N3), and never verifies inbound HMAC. The Lambda IAM-boundary design is a security *fix*, not just an adaptation — document as such. |
| §1 (language section) "parity_features_test.go … is the seed of the contract suite" | It is 2 service-level tests with no HTTP. The actual contract-suite seed is the reference's ~673 supertest tests (esp. `auth.router.test.ts`, `new-features.test.ts`, `auth-js.test.ts`), which drive routers in-process and can be pointed at a base URL with moderate rework. |

## 4. Runtime cost notes (feed cost-model.md in P6)

- bcrypt (`bcryptjs`, pure JS) ~10 rounds costs materially more on Lambda-per-ms than native; Go's `x/crypto/bcrypt` ≈60–80ms, Node bcryptjs slower still. Budget: 1 login ≈ 1 bcrypt compare + 1–2 DynamoDB ops + optional `kms:Sign` (IdP mode).
- `checkOn: allcalls` = read+write per authenticated request **through consumer middleware** (the auth router's own routes never session-check — §1.2/N22) → at 1M protected-API req/day ≈ 2M RCU/WCU-ops/day just for sessions; throttled lastActive writes cut this ~half.
- KMS: `kms:Sign` $0.03/10k → 1M logins/mo ≈ $3/mo (+ per-request latency ~1–3ms) — cheap; the env-key path remains for cost-zero HS256-only deployments.

## 5. Base-candidate impact per verdict class

| Verdict class | If TypeScript base (wrap reference) | If Go base (uplift awesome-go-auth) |
|---|---|---|
| SURVIVES modules | Imported as-is from npm `awesome-node-auth` | Mostly **absent** — must be built to the wire contract (see [parity-gap-node-vs-go.md](parity-gap-node-vs-go.md)) |
| ADAPT modules | New store/integration impls against existing TS interfaces | Same impls, against Go interfaces that partly don't exist yet |
| REBUILD modules | New serverless subsystems either way — language-neutral effort | Same |
| NET-NEW | Same effort either way | Same, plus Go's missing HTTP/token layer first |

The REBUILD + NET-NEW columns dominate total effort and are language-neutral; the SURVIVES column is where the bases differ radically. This is the core fact for the §9 language decision.
