## Config surface → declarative schema mapping

This section inventories every configuration knob in the reference implementation `awesome-node-auth` (pinned cc01e997) — `AuthConfig` and its nested blocks (`src/models/auth-config.model.ts`), `RouterOptions` (`src/router/auth.router.ts:30-181`), `AdminOptions` (`src/router/admin.router.ts:44-186`), `ToolsRouterOptions` (`src/router/tools.router.ts:13-102`), `AuthToolsOptions` (`src/tools/auth-tools.ts:15-82`), `UiRouterOptions` (`src/router/ui.router.ts:9-50`), and the runtime-mutable `AuthSettings` (`src/interfaces/settings-store.interface.ts:45-92`) — and maps each knob to a proposed declarative YAML path and `AWESOME_AUTH_*` env var for the future config schema (feeds `config-schema.md`). Defaults are cited from code, not doc comments; where a doc comment disagrees with code the code value is given and the disagreement noted. Function-valued and class-instance knobs are listed separately with a concrete declarative/webhook proposal or an "irreducibly code" verdict, and the file closes with the construction-time validation observed in code as seed for the refuse-to-start list.

**Env var convention.** `AWESOME_AUTH_` + YAML path upper-snaked with `_` separating segments (dots → `_`). Secrets are env-only (never in the YAML file); everything else is YAML-first with env override.

---

### 1. AuthConfig (`src/models/auth-config.model.ts:146-413`)

| Knob | Type | Default (code) | Runtime-mutable | YAML path | Env var |
|---|---|---|---|---|---|
| `accessTokenSecret` | string | **required, but never validated** — used directly at `src/services/token.service.ts:22,145`; absence surfaces as a 500 on first `jwt.sign` | no | `security.jwt.accessTokenSecret` | `AWESOME_AUTH_JWT_ACCESS_SECRET` |
| `refreshTokenSecret` | string | required, never validated (`src/services/token.service.ts:27,154`) | no | `security.jwt.refreshTokenSecret` | `AWESOME_AUTH_JWT_REFRESH_SECRET` |
| `accessTokenExpiresIn` | string (jwt ms-syntax) | `'15m'` (`src/services/token.service.ts:23`) | no | `security.jwt.accessTokenTtl` | `AWESOME_AUTH_JWT_ACCESS_TTL` |
| `refreshTokenExpiresIn` | string | `'7d'` (`src/services/token.service.ts:28`); parsed to ms for session `expiresAt` with fallback 7d on unparseable values (`src/router/auth.router.ts:357-360,423,430`) | no | `security.jwt.refreshTokenTtl` | `AWESOME_AUTH_JWT_REFRESH_TTL` |
| `apiPrefix` | string | `'/auth'` via `resolveApiPrefix` — priority `options.apiPrefix` > `config.apiPrefix` > `'/auth'` (`src/router/auth.router.ts:253-255`) | no | `http.apiPrefix` | `AWESOME_AUTH_HTTP_API_PREFIX` |
| `cookieOptions.secure` | boolean | `false` (`src/services/token.service.ts:177`) | no | `cookies.secure` | `AWESOME_AUTH_COOKIES_SECURE` |
| `cookieOptions.sameSite` | `'strict'\|'lax'\|'none'` | `'lax'` (`src/services/token.service.ts:178`) | no | `cookies.sameSite` | `AWESOME_AUTH_COOKIES_SAMESITE` |
| `cookieOptions.domain` | string | unset (`src/services/token.service.ts:190`) | no | `cookies.domain` | `AWESOME_AUTH_COOKIES_DOMAIN` |
| `cookieOptions.path` | string | `'/'` (`src/services/token.service.ts:179`) | no | `cookies.path` | `AWESOME_AUTH_COOKIES_PATH` |
| `cookieOptions.refreshTokenPath` | string | mutated at router construction to `` `${apiPrefix}/refresh` `` (`src/router/auth.router.ts:461-464`); TokenService-level fallback `'/auth/refresh'` (`src/services/token.service.ts:197-198`) | no | `cookies.refreshTokenPath` | `AWESOME_AUTH_COOKIES_REFRESH_PATH` |
| `csrf.enabled` | boolean | `false` (enforcement gate `src/middleware/auth.middleware.ts:35`; cookie set `src/services/token.service.ts:204-209`) | no | `security.csrf.enabled` | `AWESOME_AUTH_CSRF_ENABLED` |
| `bcryptSaltRounds` | number | `12` — default parameter of `PasswordService.hash` (`src/services/password.service.ts:4`), reached because call sites pass `config.bcryptSaltRounds` through (`src/router/auth.router.ts:818,926`) | no | `security.password.bcryptSaltRounds` | `AWESOME_AUTH_BCRYPT_SALT_ROUNDS` |
| `sms.endpoint` | string | required when `sms` block present (`src/services/sms.service.ts:6,18`) | no | `sms.endpoint` | `AWESOME_AUTH_SMS_ENDPOINT` |
| `sms.apiKey` | string | required; sent as `X-API-Key` header (`src/services/sms.service.ts:30`) | no | `sms.apiKey` | `AWESOME_AUTH_SMS_API_KEY` |
| `sms.username` / `sms.password` | string | required; **appended as URL query params** `username`/`password` on a `GET` request (`src/services/sms.service.ts:19-20,28`) — credentials-in-URL hazard to fix in the product | no | `sms.username`, `sms.password` | `AWESOME_AUTH_SMS_USERNAME`, `AWESOME_AUTH_SMS_PASSWORD` |
| `sms.codeExpiresInMinutes` | number | `10` (`src/strategies/sms/sms.strategy.ts:17`) | no | `sms.codeTtlMinutes` | `AWESOME_AUTH_SMS_CODE_TTL_MINUTES` |
| `email.siteUrl` | string \| string[] | `''` when unset (`getDefaultSiteUrl`, `src/router/auth.router.ts:202-206`); array form matched against request `Origin`/`Referer` (`src/router/auth.router.ts:233-246`), merged with `cors.origins` into the redirect allowlist (`src/router/auth.router.ts:213-219`) | no | `email.siteUrls` (always a list; first entry = canonical) | `AWESOME_AUTH_EMAIL_SITE_URLS` (comma-sep) |
| `email.mailer.endpoint` | string | required when mailer used; HTTP POST target (`src/services/mailer.service.ts:271` region) | no | `email.mailer.endpoint` | `AWESOME_AUTH_MAILER_ENDPOINT` |
| `email.mailer.apiKey` | string | required; sent as `X-API-Key` (`src/services/mailer.service.ts:274`) | no | `email.mailer.apiKey` | `AWESOME_AUTH_MAILER_API_KEY` |
| `email.mailer.from` / `fromName` / `provider` | string | `from` required; `fromName`, `provider` optional (`src/models/auth-config.model.ts:25-29`) | no | `email.mailer.from`, `.fromName`, `.provider` | `AWESOME_AUTH_MAILER_FROM`, `_FROM_NAME`, `_PROVIDER` |
| `email.mailer.defaultLang` | `'en'\|'it'` | `'en'` (`src/services/mailer.service.ts:258`; also UI fallback `src/router/ui.router.ts:103`); per-request override via `emailLang` body field | no | `email.mailer.defaultLang` | `AWESOME_AUTH_MAILER_DEFAULT_LANG` |
| `email.sendMagicLink` / `sendPasswordReset` / `sendWelcome` / `sendVerificationEmail` / `sendEmailChanged` | functions | see §8 — callbacks take precedence over `mailer` (`src/models/auth-config.model.ts:224-257`) | no | — (see §8) | — |
| `oauth.google.{clientId,clientSecret,callbackUrl,projectId?}` | strings | no defaults; ctor throws if block absent (`src/strategies/oauth/google.strategy.ts:15-17`) | no | `oauth.providers.google.*` | `AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_ID` etc. |
| `oauth.github.{clientId,clientSecret,callbackUrl}` | strings | no defaults; ctor throws if block absent (`src/strategies/oauth/github.strategy.ts:16`) | no | `oauth.providers.github.*` | `AWESOME_AUTH_OAUTH_GITHUB_CLIENT_ID` etc. |
| `twoFactor.appName` | string | `'awesome-node-auth'` (`src/router/auth.router.ts:830`; also default param `src/strategies/two-factor/totp.strategy.ts:11`) — TOTP issuer in the otpauth URI | no | `twoFactor.appName` | `AWESOME_AUTH_2FA_APP_NAME` |
| `emailVerificationMode` | `'none'\|'lazy'\|'strict'` | effective default `'none'`: `config.emailVerificationMode ?? (config.requireEmailVerification ? 'strict' : 'none')` (`src/strategies/local/local.strategy.ts:32-35`); `'lazy'` compares `new Date() > user.emailVerificationDeadline` (`src/strategies/local/local.strategy.ts:42`) | **stored** in AuthSettings but **not consulted at login** — see [MISMATCH] in §7 | `email.verification.mode` | `AWESOME_AUTH_EMAIL_VERIFICATION_MODE` |
| `requireEmailVerification` | boolean (deprecated) | `undefined` → `'none'` (`src/strategies/local/local.strategy.ts:35`) | see above | — (fold into `email.verification.mode`) | — |
| `buildTokenPayload` | function | see §8; merged over `{ sub, email, role, loginProvider, isEmailVerified, isTotpEnabled }` (`src/router/auth.router.ts:378-384`) | no | — (see §8) | — |
| `ui.enabled` | boolean | `false` — UI router only mounted when truthy (`src/router/auth.router.ts:1639`) | no | `ui.enabled` | `AWESOME_AUTH_UI_ENABLED` |
| `ui.headless` | boolean | `false` (`src/router/ui.router.ts:168,175`) — serves assets + `/ui/config` only; HTML pages skipped | no | `ui.headless` | `AWESOME_AUTH_UI_HEADLESS` |
| `ui.loginUrl` / `ui.registerUrl` | string | doc comment claims defaults `/auth/ui/login`, `/auth/ui/register` (`src/models/auth-config.model.ts:344-347`) — **no code in `src/` reads these two fields**; treat as dead config [MISMATCH] | no | drop, or `ui.loginUrl` if re-implemented | — |
| `ui.customCss` | string | unset; injected verbatim (`src/router/ui.router.ts:130`) | no | `ui.customCss` | — (file-only) |
| `ui.customLogo` / `ui.logoUrl` | string | unset; resolution `settings.ui.logoUrl \|\| ui.customLogo \|\| ui.logoUrl` (`src/router/ui.router.ts:128`) | yes (via `settings.ui.logoUrl`) | `ui.branding.logoUrl` | `AWESOME_AUTH_UI_LOGO_URL` |
| `ui.primaryColor` | string | `'#4a90d9'` (`src/router/ui.router.ts:126`) | yes (`settings.ui.primaryColor` wins) | `ui.branding.primaryColor` | `AWESOME_AUTH_UI_PRIMARY_COLOR` |
| `ui.secondaryColor` | string | `'#6c757d'` (`src/router/ui.router.ts:127`) | yes | `ui.branding.secondaryColor` | `AWESOME_AUTH_UI_SECONDARY_COLOR` |
| `ui.siteName` | string | `'Awesome Node Auth'` (`src/router/ui.router.ts:129`) | yes | `ui.branding.siteName` | `AWESOME_AUTH_UI_SITE_NAME` |
| `ui.bgColor` / `ui.bgImage` / `ui.cardBg` | string | unset (`src/router/ui.router.ts:131-133`) | yes | `ui.branding.bgColor` / `.bgImage` / `.cardBg` | `AWESOME_AUTH_UI_BG_COLOR` etc. |
| `session.checkOn` | `'allcalls'\|'refresh'\|'none'` | `'refresh'` at the refresh endpoint (`src/router/auth.router.ts:634`); middleware acts only on the literal `'allcalls'` (`src/middleware/auth.middleware.ts:47`), so unset ≡ `'refresh'` | no | `sessions.checkOn` | `AWESOME_AUTH_SESSIONS_CHECK_ON` |
| `templateStore` | `ITemplateStore` instance | unset; see §8 | (contents mutable via admin Email & UI tab) | `stores.templates.*` driver block | — |
| `idProvider.enabled` | boolean | `false`; mode active when `privateKey` present **or** `enabled === true` (`src/services/token.service.ts:42`, `src/router/auth.router.ts:473`) | no | `idProvider.enabled` | `AWESOME_AUTH_IDP_ENABLED` |
| `idProvider.privateKey` | PEM string | unset → ephemeral RSA keypair auto-generated with console warning (`src/services/token.service.ts:50-63`; also at router build `src/router/auth.router.ts:480-483`) | no | env-only | `AWESOME_AUTH_IDP_PRIVATE_KEY` |
| `idProvider.publicKey` | PEM string | derived from `privateKey` when omitted (`src/services/token.service.ts:67-69`, `src/router/auth.router.ts:484-486`) | no | derived; optional `AWESOME_AUTH_IDP_PUBLIC_KEY` | — |
| `idProvider.jwksPath` | string | `'/.well-known/jwks.json'` (`src/router/auth.router.ts:475`) | no | `idProvider.jwksPath` | `AWESOME_AUTH_IDP_JWKS_PATH` |
| `idProvider.issuer` | string | unset → **no `iss` claim** embedded (`src/services/token.service.ts:76`) | no | `idProvider.issuer` | `AWESOME_AUTH_IDP_ISSUER` |
| `idProvider.tokenExpiry` | string | `'30d'` (`src/services/token.service.ts:80`) | no | `idProvider.accessTokenTtl` | `AWESOME_AUTH_IDP_ACCESS_TTL` |
| `idProvider.refreshTokenExpiry` | string | priority `idp.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'` (`src/services/token.service.ts:91`) | no | `idProvider.refreshTokenTtl` | `AWESOME_AUTH_IDP_REFRESH_TTL` |
| `idProvider.jwksCorsOrigins` | string \| string[] | `'*'` (`src/router/auth.router.ts:492`) | no | `idProvider.jwksCorsOrigins` | `AWESOME_AUTH_IDP_JWKS_CORS_ORIGINS` |
| `resourceServer.enabled` | boolean | `false` (`src/models/auth-config.model.ts:118`); when true, auth-flow routes are skipped (`src/router/auth.router.ts:510,541`) | no | `resourceServer.enabled` | `AWESOME_AUTH_RS_ENABLED` |
| `resourceServer.jwksUrl` | string | required (typed required); **not validated at construction** — first token verification fails at fetch time | no | `resourceServer.jwksUrl` | `AWESOME_AUTH_RS_JWKS_URL` |
| `resourceServer.issuer` | string | unset → `iss` not validated (`src/services/token.service.ts:135-140`) | no | `resourceServer.issuer` | `AWESOME_AUTH_RS_ISSUER` |
| `resourceServer.jwksCacheTtl` | number (ms) | `3_600_000` (`src/services/jwks.service.ts:40`) | no | `resourceServer.jwksCacheTtlMs` | `AWESOME_AUTH_RS_JWKS_CACHE_TTL_MS` |
| `resourceServer.jwksFetchTimeout` | number (ms) | `5000` (`src/services/jwks.service.ts:41`) | no | `resourceServer.jwksFetchTimeoutMs` | `AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS` |

**Cookie-name resolution (derived, not a knob, but every client depends on it).** `getCookieName` (`src/services/token.service.ts:161-172`): plain name when `secure=false`; `__Host-<name>` when `secure=true` ∧ path `/` (or unset) ∧ no domain (with Path forced to `/`, Secure forced on, Domain stripped — `src/services/token.service.ts:185-188`); `__Secure-<name>` otherwise. Read priority `__Host-` > `__Secure-` > plain (`src/services/token.service.ts:276-280`). Pinned by `tests/token.service.test.ts:191-241,253-263`. This matches the client contract's CSRF cookie priority (`__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token`).

**Hardcoded values adjacent to knobs (candidates for new knobs in the product):**

- Access-token cookie `Max-Age` fixed at `15*60*1000` ms (`src/services/token.service.ts:195`) and refresh cookie at `7*24*60*60*1000` ms (`src/services/token.service.ts:200`) — **not derived from `accessTokenExpiresIn`/`refreshTokenExpiresIn`**. Setting non-default TTLs desynchronizes JWT expiry from cookie lifetime. [MISMATCH] (internal; no test pins the desync) → product schema should derive cookie Max-Age from the TTL knobs.
- CSRF cookie: name `csrf-token`, `httpOnly:false` (JS-readable, per client contract), `maxAge` 15 min, set on login (`src/services/token.service.ts:204-209`) and lazily by middleware on any request lacking it (`src/router/auth.router.ts:529-538`) — this lazy re-issue is why clients need no `/csrf` endpoint. CSRF verified only for cookie-auth + non-`GET/HEAD/OPTIONS` via header `x-csrf-token` equal to the cookie; failure = 403 `{error:'CSRF token validation failed', code:'CSRF_INVALID'}` (`src/middleware/auth.middleware.ts:34-41`). Bearer requests (`X-Auth-Strategy: bearer` → `Authorization` header) bypass CSRF (`src/middleware/auth.middleware.ts:35`).
- Password-reset token TTL 1h (`src/router/auth.router.ts:783`); email-verification token TTL 24h (`src/router/auth.router.ts:952`); email-change token TTL 1h (`src/router/auth.router.ts:1023`); account-link token TTL 1h (`src/router/auth.router.ts:1526`); magic-link token TTL 15 min (`src/strategies/magic-link/magic-link.strategy.ts:21`). → propose `tokens.{passwordReset,emailVerification,emailChange,accountLink,magicLink}TtlMinutes` knobs.
- JWKS endpoint response `Cache-Control: public, max-age=3600` (`src/router/auth.router.ts:502`).
- CORS allowed headers/methods fixed: `Content-Type,Authorization,X-CSRF-Token,X-Api-Key` / `GET,POST,PUT,PATCH,DELETE,OPTIONS`, preflight answered `204` (`src/router/auth.router.ts:517-524`).
- Magic-link/SMS/TOTP `mode` body field defaults to `'login'` when omitted (only `mode === '2fa'` branches differ: `src/router/auth.router.ts:1087,1134,1192,1255`) — so Flutter (omits `mode`) and Angular (`mode:"login"`) get identical behavior; no mismatch.

---

### 2. RouterOptions (`src/router/auth.router.ts:30-181`)

| Knob | Type | Default (code) | YAML path / env | Notes |
|---|---|---|---|---|
| `googleStrategy`, `githubStrategy` | class instances (abstract; user must implement `findOrCreateUser`) | unset → provider routes not mounted | see §8 | ctor throws when the matching `config.oauth.*` block is missing |
| `oauthStrategies` | `GenericOAuthStrategy[]` | unset | see §8 | mounts `GET /oauth/:name` + `/oauth/:name/callback` |
| `rateLimiter` | Express `RequestHandler` | none — `rl = []` (`src/router/auth.router.ts:468`) | see §8 | applied to sensitive endpoints via spread |
| `metadataStore`, `rbacStore`, `sessionStore`, `tenantStore`, `linkedAccountsStore`, `pendingLinkStore`, `settingsStore` | store instances | unset → feature routes/enrichment absent | `stores.*` driver blocks, see §8 | presence toggles routes (e.g. linked-accounts endpoints per `src/router/auth.router.ts:69-86`) |
| `onRegister` | function | unset → **`POST /register` not mounted** (`src/router/auth.router.ts:94-99`) | `registration.enabled` + policy, see §8 | |
| `apiPrefix` | string | `config.apiPrefix \|\| '/auth'` (`src/router/auth.router.ts:253-255`) | `http.apiPrefix` (single knob; per-instance override is a library-embedding concern, drop) | |
| `swagger` | `boolean \| 'auto'` | `'auto'` → enabled iff `options.swagger === true \|\| (options.swagger !== false && NODE_ENV !== 'production')` (`src/router/auth.router.ts:1652-1654`) | `docs.swagger` (`true/false/auto`) / `AWESOME_AUTH_DOCS_SWAGGER` | pinned by `tests/swagger.test.ts:250-259` |
| `swaggerBasePath` | string | `resolveApiPrefix(config, options)` (`src/router/auth.router.ts:1657`); doc comment says `'/auth'` — code default is the resolved prefix | `docs.basePath` | |
| `cors.origins` | string[] | unset → no CORS middleware at all (`src/router/auth.router.ts:513`) | `http.cors.origins` / `AWESOME_AUTH_CORS_ORIGINS` (comma-sep) | also merged into redirect allowlist (`src/router/auth.router.ts:213-219`) |
| `uiAssetsDir` | string (dir path) | candidate-list probe, first entry when nothing found (`src/router/ui.router.ts:72-93`) | `ui.assetsDir` | |
| `uploadDir` | string (dir path) | unset → uploads disabled | `ui.uploadDir` / `AWESOME_AUTH_UI_UPLOAD_DIR` | |
| `ui.{siteName,primaryColor,secondaryColor,logoUrl}` | strings | unset (duplicates `config.ui`) | fold into `ui.branding.*` | duplicate surface — collapse in product schema |

---

### 3. AdminOptions (`src/router/admin.router.ts:44-186`)

| Knob | Type | Default (code) | YAML path / env | Notes |
|---|---|---|---|---|
| `adminSecret` | string (deprecated) | unset; legacy guard compares `Authorization: Bearer <secret>`, 401 without header / 403 on wrong token (`src/router/admin.router.ts:189-203`); also usable as bootstrap password in the local login when email empty or `'admin'` (`src/router/admin.router.ts:560-564`) | `admin.bootstrapSecret` / `AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET` | keep only as bootstrap |
| `accessPolicy` | `'first-user' \| 'is-admin-flag' \| 'open' \| fn` | unset → guard priority `accessPolicy` > `adminSecret` > **open with stderr warning** `"[awesome-node-auth] WARNING: createAdminRouter called without \`accessPolicy\` or \`adminSecret\`. Admin routes are unprotected. Set accessPolicy in production."` (`src/router/admin.router.ts:516-537`) | `admin.accessPolicy` (enum + `rbac:` extension, see §8) / `AWESOME_AUTH_ADMIN_ACCESS_POLICY` | `'first-user'` returns 500 `{error:'accessPolicy: first-user requires IUserStore.listUsers to be implemented'}` when the store lacks `listUsers` (`src/router/admin.router.ts:372-379`) |
| `jwtSecret` | string | unset; **no throw when `accessPolicy` ≠ `'open'` and `jwtSecret` missing — guard simply never authenticates anyone** (`src/router/admin.router.ts:274-305`) [refuse-to-start seed] | reuse `security.jwt.accessTokenSecret` (must match per doc `src/router/admin.router.ts:73`) | |
| `sessionStore`/`rbacStore`/`tenantStore`/`userMetadataStore`/`settingsStore`/`linkedAccountsStore`/`apiKeyStore`/`webhookStore`/`templateStore` | store instances | unset → corresponding admin tab disabled (feature flags `src/router/admin.router.ts:645-656`) | `stores.*` (shared with §2) | |
| `cookiePrefix` | string (`'__Host-'`/`'__Secure-'`/custom) | unset → guard tries `__Host-accessToken` ?? `__Secure-accessToken` ?? `accessToken` (`src/router/admin.router.ts:291-294`); explicit prefix always wins (`src/router/admin.router.ts:224-227`) | `admin.cookiePrefix` | usually derivable from `cookies.secure` |
| `rootUser.{email,passwordHash}` | object | unset; bcrypt-compared at admin login (`src/router/admin.router.ts:553-557`) | `admin.rootUser.email` / `AWESOME_AUTH_ADMIN_ROOT_EMAIL`, `admin.rootUser.passwordHash` / `AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH` | hash, never plaintext |
| `uploadDir` | string | unset → upload feature off (`src/router/admin.router.ts:656`); dir auto-created with `mkdirSync recursive` (`src/router/admin.router.ts:995-999`) | `ui.uploadDir` (shared) | multer limit `fileSize: 5*1024*1024` (5 MB) hardcoded (`src/router/admin.router.ts:1015`) → `admin.upload.maxFileSizeMb` |
| `uploadBaseUrl` | string | `''`; computed `` `${apiPrefix}/ui/assets/uploads` `` when `apiPrefix` and `uploadDir` set (`src/router/admin.router.ts:639-643`) | derived — drop | |
| `apiPrefix` | string | `'/auth'` fallback in injected admin HTML config (`src/router/admin.router.ts:444`) | `http.apiPrefix` (shared) | |
| `swagger` / `swaggerBasePath` | `boolean\|'auto'` / string | `'auto'` (same NODE_ENV rule) / `'/admin'` (`src/router/admin.router.ts:160-176`) | `docs.swagger` (shared), `admin.basePath` | |
| `loginPath` | string | unset → built-in login form fallback for unauthenticated GET HTML (`src/router/admin.router.ts:311-325`); when set, 302 to `` `${loginPath}?redirect=<path>` `` (`src/router/admin.router.ts:312-315`) | `admin.loginPath` | |

Hardcoded admin values: session JWT `expiresIn: '24h'` (`src/router/admin.router.ts:585`) and cookie `maxAge: 24*60*60*1000` with `httpOnly:true, sameSite:'lax', path:'/'`, `secure` from `req.secure`/`x-forwarded-proto` (`src/router/admin.router.ts:591-611`) → propose `admin.sessionTtl`.

---

### 4. ToolsRouterOptions (`src/router/tools.router.ts:13-102`)

| Knob | Type | Default (code, `src/router/tools.router.ts:120-128`) | YAML path / env |
|---|---|---|---|
| `telemetry` | boolean | `true` | `tools.telemetry.enabled` / `AWESOME_AUTH_TOOLS_TELEMETRY` |
| `notify` | boolean | `true` | `tools.notify.enabled` |
| `stream` | boolean | `true` (only useful with `sse: true` on AuthTools) | `tools.stream.enabled` |
| `webhook` | boolean | `true`; route mounted only when additionally `onWebhook` or `webhookStore.findByProvider` exists (`src/router/tools.router.ts:250`) | `tools.inboundWebhooks.enabled` |
| `authMiddleware` | RequestHandler | unset → **tools endpoints unauthenticated** | see §8; declaratively `tools.auth: none\|session\|apiKey` |
| `telemetryStore` | instance | unset → `GET /tools/telemetry` not mounted; route mounts only when `telemetry && telemetryStore?.query` exists (`src/router/tools.router.ts:226`), so the inner 501 `{error:'Telemetry query not supported by the configured store'}` (`src/router/tools.router.ts:230-231`) is unreachable defensive code | `stores.telemetry.*` |
| `onWebhook` | function | unset; fallback after vm script (`src/router/tools.router.ts:310-313`) | see §8 |
| `webhookStore` | instance | unset | `stores.webhooks.*` |
| `settingsStore` | instance | unset → `enabledWebhookActions` treated as `[]` (`src/router/tools.router.ts:261-264`) | `stores.settings.*` |
| `swagger` / `swaggerBasePath` | `boolean\|'auto'` / string | `'auto'` / `'/tools'` (`src/router/tools.router.ts:126-127`) | `docs.swagger` (shared), `tools.basePath` |

Hardcoded: inbound-webhook vm sandbox timeout `5_000` ms (`src/router/tools.router.ts:289`) → `tools.inboundWebhooks.scriptTimeoutMs`. Sandbox exposes only `body`, `actions`, `result`, and a dev-only `console` (`src/router/tools.router.ts:272-286`).

---

### 5. AuthToolsOptions (`src/tools/auth-tools.ts:15-82`)

| Knob | Type | Default (code) | YAML path / env |
|---|---|---|---|
| `telemetryStore` | instance | unset; saves are best-effort (`src/tools/auth-tools.ts:217-219`) | `stores.telemetry.*` |
| `webhookStore` | instance | unset | `stores.webhooks.*` |
| `sse` | boolean | `false` (`src/tools/auth-tools.ts:176`) | `tools.sse.enabled` / `AWESOME_AUTH_SSE_ENABLED` |
| `sseOptions.heartbeatIntervalMs` | number | `30_000`; `<= 0` disables heartbeat (`src/tools/sse-manager.ts:105,156`) | `tools.sse.heartbeatIntervalMs` |
| `sseOptions.deduplicate` | boolean | `true` (`!== false`, `src/tools/sse-manager.ts:106`) | `tools.sse.deduplicate` |
| `sseOptions.distributor` | `ISseDistributor` instance | unset (single-instance) | see §8; `tools.sse.distributor: {type: redis, ...}` |
| `webhookVersion` | string | `'1'` (`src/tools/auth-tools.ts:175`); attached as `version` to outgoing payloads (`src/tools/auth-tools.ts:254`) | `tools.outboundWebhooks.payloadVersion` |
| `userStore` | instance | unset; required for `'email'`/`'sms'` notify channels | `stores.users.*` |
| `emailConfig` / `smsConfig` | same shapes as `email.mailer` / `sms` | unset → `NotificationService` throws `'No email transport configured...'` / `'No SMS transport configured...'` at send time (`src/services/notification.service.ts:110-129`) | reuse `email.mailer.*` / `sms.*` |

Per-webhook (data, not config — stored in `webhookStore` rows): `maxRetries` default `3`, `retryDelayMs` default `1_000` with exponential backoff (`src/tools/webhook-sender.ts:18-19,46`); HMAC-SHA256 signature header `X-Webhook-Signature: sha256=<hex>` plus `X-Webhook-Event`, `X-Webhook-Delivery`, `X-Webhook-Timestamp` (`src/tools/webhook-sender.ts:24-33`). Product schema: expose `tools.outboundWebhooks.defaults.{maxRetries,retryDelayMs}`.

---

### 6. UiRouterOptions (`src/router/ui.router.ts:9-50`)

| Knob | Default (code) | YAML path |
|---|---|---|
| `uiAssetsDir` | probe of 6 candidate dirs, falls back to `candidates[0]` (`src/router/ui.router.ts:72-93`) | `ui.assetsDir` |
| `uploadDir` | unset → `/assets/logo` and `/assets/uploads` static mounts skipped (`src/router/ui.router.ts:185-190`) | `ui.uploadDir` (shared) |
| `settingsStore` | unset → `settings = {}` (`src/router/ui.router.ts:99`) | `stores.settings.*` |
| `authConfig` | **required** (typed, not runtime-validated) | n/a — internal wiring |
| `routerOptions` | unset — `features.register` = `!!routerOptions?.onRegister` (`src/router/ui.router.ts:115`) | n/a |
| `apiPrefix` | `resolveApiPrefix` → `'/auth'` (`src/router/ui.router.ts:61`), overridden per-request from `req.baseUrl` (`src/router/ui.router.ts:97-98`) | `http.apiPrefix` (shared) |
| `templateStore` | unset → no UI translations (`src/router/ui.router.ts:106-112`) | `stores.templates.*` |

`GET /ui/config` feature flags are all **derived** from other config (`src/router/ui.router.ts:114-123`): `register`←`onRegister`, `magicLink`←`sendMagicLink||mailer`, `sms`←`config.sms`, `google`/`github`←`config.oauth.*`, `forgotPassword`←`sendPasswordReset||mailer`, `verifyEmail`←`(sendVerificationEmail||mailer) && (emailVerificationMode !== 'none' || requireEmailVerification)`, `twoFactor`←`config.twoFactor`. In a declarative schema these should stay derived, not become independent knobs.
> CORRECTED(verify): the `verifyEmail` feature-flag formula also ORs the legacy `requireEmailVerification` boolean into the mode check (`src/router/ui.router.ts:121`); the previous formula omitted it.

---

### 7. Runtime-mutable AuthSettings (`src/interfaces/settings-store.interface.ts:45-92`)

Admin endpoints: `GET /admin/api/settings` returns the raw object (`src/router/admin.router.ts:951-959`); `PUT /admin/api/settings` shallow-merges the **unvalidated request body** (`src/router/admin.router.ts:961-971`); `PATCH /admin/api/settings/ui` deep-merges only `ui` (`src/router/admin.router.ts:973-982`). 404 `{error:'Settings store not configured'}` without a settings store.

| Setting | Where it is actually read at runtime | Effective? |
|---|---|---|
| `require2FA` | `POST /auth/2fa/disable` → 403 `{error:'Cannot disable 2FA: required by system policy', code:'2FA_REQUIRED'}` when true (`src/router/auth.router.ts:890-895`) | yes |
| `enabledWebhookActions` | intersected with per-webhook `allowedActions` to build the vm sandbox context (`src/router/tools.router.ts:261-266`) | yes |
| `ui.{primaryColor,secondaryColor,logoUrl,siteName,logoPath,bgColor,bgImage,cardBg}` | `GET /ui/config` — settings win over `authConfig.ui` (`src/router/ui.router.ts:126-133`) | yes |
| `requireEmailVerification` / `emailVerificationMode` | **never read by login code** — `LocalStrategy` reads only static `config` (`src/strategies/local/local.strategy.ts:32-35`); grep shows no `settingsStore` consumer for these outside the admin UI | **[MISMATCH]** admin Control panel writes a toggle that has no server-side effect on login |
| `lazyEmailVerificationGracePeriodDays` | only the admin UI, display default `7` (`src/ui/assets/admin.js:768`); server never computes `emailVerificationDeadline` from it (deadline is set by the integrator's `onRegister`) | **[MISMATCH]** display-only |

**[MISMATCH]** naming drift: the admin OpenAPI spec documents the settings field as `emailVerificationGracePeriodDays` (`src/router/openapi.ts:1278`) while the interface and admin UI use `lazyEmailVerificationGracePeriodDays` (`src/interfaces/settings-store.interface.ts:62`, `src/ui/assets/admin.js:768,921`).

Product schema proposal: keep AuthSettings as the *only* runtime-mutable layer, declare each key under `runtimeSettings.*` with a `mutable: true` marker, and make the product actually consult the store where the reference fails to (email-verification mode), or drop the toggle. All settings mutations are [UNTESTED] (no test file exercises `/admin/api/settings`).

---

### 8. Function / class-instance knobs — declarative equivalents

| Knob | Reference default behavior | Declarative proposal | Verdict |
|---|---|---|---|
| `buildTokenPayload(user)` (`src/models/auth-config.model.ts:316`) | absent → payload is exactly `{ sub, email, role, loginProvider: user.loginProvider ?? 'local', isEmailVerified: ?? false, isTotpEnabled: ?? false }`; result merged **over** base (`src/router/auth.router.ts:378-384`) | `security.jwt.extraClaims: {claimName: {fromUserField: x} \| {const: y}}` static mapping table; anything computed → optional synchronous claims webhook (`security.jwt.claimsWebhook.url`) with strict timeout | mapping covers the common case; arbitrary computation is irreducibly code — webhook escape hatch |
| `onRegister(data, config, options)` (`src/router/auth.router.ts:109`) | absent → `POST /register` **not mounted**; when present, receives raw body and must create+return the user | `registration: {enabled: bool, fields: allowlist, passwordPolicy, autoVerify: bool}` with a built-in create-user handler; custom logic → `registration.webhook.url` (called before/after create) | built-in handler expressible; bespoke provisioning is code → webhook |
| `onWebhook(provider, body, req)` (`src/router/tools.router.ts:63-67`) | absent → only stored per-webhook `jsScript` runs; when present, fallback mapper returning `{event,data,userId,tenantId}\|null` (`src/router/tools.router.ts:310-313`) | already has a data-driven equivalent in the reference: per-provider `jsScript` in `webhookStore` executed in `vm` with 5 s timeout — the declarative path is `inboundWebhooks[provider].script` (+ `allowedActions`) | expressible today via stored scripts; keep `onWebhook` out of the product |
| `rateLimiter` (`src/router/auth.router.ts:46`) | absent → **no rate limiting anywhere** (`src/router/auth.router.ts:468`) | `rateLimit: {windowSeconds, max, keyBy: ip\|email, scope: [login, refresh, forgot-password, ...]}` implemented by a built-in limiter | fully declarative |
| `accessPolicy` as function (`src/router/admin.router.ts:38-42`) | enum values `'first-user'`/`'is-admin-flag'`/`'open'` are already declarative; fn form gets `(user, rbacStore)` | keep the enum; add `rbac:<role>` / `permission:<perm>` string forms evaluated against the RBAC store | enum + rbac reference covers it; arbitrary predicates are code |
| `googleStrategy` / `githubStrategy` (abstract classes, `src/strategies/oauth/google.strategy.ts:6-21`) | endpoints and scopes hardcoded per provider; ctor throws `OAUTH_NOT_CONFIGURED` without `config.oauth.*`; integrator implements `findOrCreateUser(profile, state)` | `oauth.providers.google: {clientId, clientSecret, callbackUrl}` + a global `oauth.provisioning: {autoCreate: bool, allowedEmailDomains: [], fieldMap: {...}, requireVerifiedEmail: bool}` replacing `findOrCreateUser` | provisioning policy is expressible declaratively; the reference forces code only because it is a library |
| `oauthStrategies` (`GenericOAuthStrategy`, config `src/strategies/oauth/generic-oauth.strategy.ts:39-78`) | `GenericOAuthProviderConfig` is already 90% declarative (`name, clientId, clientSecret, callbackUrl, authorizationUrl, tokenUrl, userInfoUrl, scope, additionalAuthParams` — `src/strategies/oauth/generic-oauth.strategy.ts:39-78`); `mapProfile` fn defaults to `id: raw.id ?? raw.sub`, `email: raw.email` (`src/strategies/oauth/generic-oauth.strategy.ts:155-156`) | `oauth.providers.<name>: {...same fields..., profileMap: {id: "$.id", email: "$.mail ?? $.userPrincipalName", ...}}` — JSONPath/fallback-chain field mapping | fully declarative incl. profile mapping |
| Store instances — `IUserStore` (required ctor arg), `ISessionStore`, `IUserMetadataStore`, `IRolesPermissionsStore`, `ITenantStore`, `ILinkedAccountsStore`, `IPendingLinkStore`, `ISettingsStore`, `IApiKeyStore`, `IWebhookStore`, `ITemplateStore`, `ITelemetryStore`, `ITokenStore` (`src/interfaces/*.ts`) | all injected; presence toggles features (§2-§4) | `stores: {driver: dynamodb\|postgres\|memory, connection: {...}, enable: {sessions: true, rbac: false, ...}}` — one shared driver, per-store enable flags; product ships the implementations | fully declarative (the product owns the implementations) |
| Email callbacks `sendMagicLink`/`sendPasswordReset`/`sendWelcome`/`sendVerificationEmail`/`sendEmailChanged` (`src/models/auth-config.model.ts:228-257`) | absent → built-in HTTP mailer + built-in en/it templates (magic-link 15 min, reset 1 h, verification 24 h wording, `src/services/mailer.service.ts:19-110`); callbacks always take precedence over `mailer` | `email.mailer.*` (transport) + `templateStore`-backed templates (already runtime-editable via admin Email & UI tab) + optional `email.deliveryWebhook.url` for fully external delivery | mailer+templates expressible; exotic transports → webhook |
| `templateStore` (`ITemplateStore`, `src/interfaces/template-store.interface.ts:13-43`) | absent → hardcoded en/it templates; present → `getMailTemplate`/`getUiTranslations` consulted | seed templates from `email.templatesDir` (files) into the templates table; runtime edits via admin API | fully declarative (data) |
| `sseOptions.distributor` (`ISseDistributor`, `src/interfaces/sse-distributor.interface.ts:10`) | absent → events fan out only within one process | `tools.sse.distributor: {type: redis\|sns\|none, ...connection}` | fully declarative (product ships drivers) |
| `authMiddleware` (ToolsRouterOptions, `src/router/tools.router.ts:43`) | absent → tools endpoints public | `tools.auth: none \| session \| apiKey \| admin` selecting built-in guards | fully declarative |
| custom strategies via `AuthConfigurator.strategy()` (`src/auth-configurator.ts:45-58`) | `'local'` returns a `LocalStrategy`; `'google'`/`'github'` **throw** `'...Strategy is abstract - extend it and pass via RouterOptions'`; unknown → `` `Unknown strategy: ${name}` `` | n/a — superseded by `oauth.providers.*` above | drop |

---

### 9. Construction-time validation observed in code (seed for the refuse-to-start list)

Throws today (the only ones):

1. `new GoogleStrategy(config)` → `AuthError('Google OAuth not configured', 'OAUTH_NOT_CONFIGURED', 500)` when `config.oauth.google` missing (`src/strategies/oauth/google.strategy.ts:15-17`).
2. `new GithubStrategy(config)` → `AuthError('GitHub OAuth not configured', 'OAUTH_NOT_CONFIGURED', 500)` (`src/strategies/oauth/github.strategy.ts:16`).
3. `createJwksAuthMiddleware(config)` → `Error('createJwksAuthMiddleware requires config.resourceServer.enabled = true')` (`src/middleware/jwks-auth.middleware.ts:38-39`).
4. `AuthConfigurator.strategy('google'|'github'|<unknown>)` → `Error` (`src/auth-configurator.ts:53-57`).

Warns but starts anyway (product should refuse to start instead):

5. Admin router with neither `accessPolicy` nor `adminSecret` → stderr warning, routes fully open (`src/router/admin.router.ts:530-537`).
6. IdP mode without `privateKey` → ephemeral keypair, console warning `'...All tokens will be invalidated on restart...'` (`src/services/token.service.ts:50-63`).

Silent misconfigurations found in code (nothing throws, nothing warns — must become startup errors in the product):

7. Missing/empty `accessTokenSecret`/`refreshTokenSecret` (first login 500s inside `jwt.sign`).
8. `accessPolicy` ≠ `'open'` with no `jwtSecret` → every admin request unauthenticated (`src/router/admin.router.ts:274-308`); doc comment says "Requires `jwtSecret`" (`src/router/admin.router.ts:64`) but code never checks. [MISMATCH doc-vs-code]
9. `resourceServer.enabled: true` without a reachable `jwksUrl` — validated only at first request (`src/services/jwks.service.ts:111`).
10. `cookieOptions.sameSite: 'none'` without `secure: true` (browsers reject the cookie; no check anywhere in `src/services/token.service.ts:174-210`).
11. Non-default `accessTokenExpiresIn`/`refreshTokenExpiresIn` silently desynchronized from hardcoded cookie Max-Age 15 min / 7 d (`src/services/token.service.ts:195,200`).
12. Unparseable `refreshTokenExpiresIn` silently becomes 7 d for session/store expiry (`src/router/auth.router.ts:357-360`) while `jwt.sign` may reject the same string — validate the ms-syntax at startup.
13. `admin.accessPolicy: 'first-user'` with a user store lacking `listUsers` — currently a 500 at request time (`src/router/admin.router.ts:372-379`).
14. `PUT /admin/api/settings` persists arbitrary unvalidated keys (`src/router/admin.router.ts:961-971`) — product must validate against the AuthSettings schema.

---

### 10. Cross-check notes against client contract facts

- CSRF: header read is `x-csrf-token` (`src/middleware/auth.middleware.ts:37`), cookie read priority `__Host-` > `__Secure-` > plain (`src/services/token.service.ts:276-280`), CSRF cookie is `httpOnly:false` (`src/services/token.service.ts:206,216`), and no `/csrf` endpoint exists — instead the router lazily sets the cookie on any request missing it when `csrf.enabled` (`src/router/auth.router.ts:529-538`). Matches the contract. Pinned by `tests/token.service.test.ts:284-332`.
- Bearer mode: `X-Auth-Strategy: bearer` switches token delivery to top-level `{success, accessToken, refreshToken}` JSON (`src/router/auth.router.ts:390-406`) and bypasses cookie CSRF (`src/middleware/auth.middleware.ts:35`). Config has no knob for this — it is per-request client behavior; no config mapping needed.
- Magic-link `mode`: router default is `'login'` when the field is omitted (`src/router/auth.router.ts:1075,1087,1109`), so Flutter (omits) and Angular (`mode:"login"`) behave identically. No mismatch; no config knob.
- `SESSION_REVOKED` 401 is only emitted when `session.checkOn === 'allcalls'` in middleware (`src/middleware/auth.middleware.ts:47-52`) — clients relying on it for instant logout implicitly require the `sessions.checkOn: allcalls` config value; document this coupling in config-schema.md.

**[UNTESTED] config behaviors** (no test in `tests/` exercises them): admin `/api/settings` GET/PUT/PATCH; `enabledWebhookActions` gating of the vm sandbox; `idProvider.jwksCorsOrigins` origin matching; `sms.codeExpiresInMinutes` override; multer 5 MB limit; `ui.headless` asset-only mode; admin `loginPath` redirect. Tested and pinned: cookie prefix/`refreshTokenPath` resolution (`tests/token.service.test.ts:72-97,191-241`), swagger `'auto'`/NODE_ENV behavior (`tests/swagger.test.ts:250-259`).
