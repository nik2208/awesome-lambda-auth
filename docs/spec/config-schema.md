# Declarative configuration schema — awesome-lambda-auth

awesome-lambda-auth is a **deployable product** (Cognito-style), not a library: users deploy a stack, they do not write an `AuthConfigurator`. Therefore every configuration knob the reference implementation `awesome-node-auth` (pinned `cc01e99`, see [recon-manifest.md](recon-manifest.md)) exposes in code — `AuthConfig`, `RouterOptions`, `AdminOptions`, `ToolsRouterOptions`, `AuthToolsOptions`, `UiRouterOptions`, runtime `AuthSettings` — must have a declarative file/env equivalent. This document is the Phase-0 specification of that schema. It is an editorial pass over the verified inventory in [\_extract/09-config-mapping.md](_extract/09-config-mapping.md); all defaults are **code** defaults with file:line evidence against the pinned SHA, never doc-comment claims. Where a doc comment disagrees with code, the code value is given and the disagreement carries a [MISMATCH] marker; behaviors no test exercises carry [UNTESTED].

**Conventions used throughout §1:**

- **Path** — dotted YAML path in the deployed config document.
- **Env var** — override name, convention `AWESOME_AUTH_` + path upper-snaked (dots → `_`); names given in the extract are kept verbatim even where they abbreviate the path (e.g. `AWESOME_AUTH_JWT_ACCESS_SECRET`). `—` = no env override (file-only or secret-store-only).
- **Secret-valued knobs** are marked `[secret]` in the Validation column. Proposed resolution order (see §4 for the open format decision): **1)** Secrets Manager reference, **2)** SSM SecureString reference, **3)** plain env var (development only; deploy-time warning in production). Secrets never appear as plaintext in the YAML document.
- **`[new]`** — knob that does not exist in the reference (value was hardcoded, or the knob is product-only). The cited file:line is the hardcoded value it replaces, where one exists.
- **Runtime-mutable** knobs (admin-editable at runtime via the settings store) are listed in §1.19; the file/env value is the boot-time seed, the settings store wins afterwards, exactly as in the reference.

---

## 1. Schema

### 1.1 Tokens and secrets (`security.jwt.*`, `security.password.*`, `tokens.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `security.jwt.accessTokenSecret` | string | **required — reference never validates it**; absence surfaces as a 500 inside the first `jwt.sign` (`src/services/token.service.ts:22,145`) | required unless `resourceServer.enabled`; min length 32 (RS-1) `[secret]` | `AWESOME_AUTH_JWT_ACCESS_SECRET` |
| `security.jwt.refreshTokenSecret` | string | required, never validated (`src/services/token.service.ts:27,154`) | required unless `resourceServer.enabled`; min length 32; must differ from access secret (RS-1) `[secret]` | `AWESOME_AUTH_JWT_REFRESH_SECRET` |
| `security.jwt.accessTokenTtl` | string (jwt ms-syntax) | `'15m'` (`src/services/token.service.ts:23`) | must parse as ms-syntax at startup (RS-9) | `AWESOME_AUTH_JWT_ACCESS_TTL` |
| `security.jwt.refreshTokenTtl` | string | `'7d'` (`src/services/token.service.ts:28`); reference silently falls back to 7d for session `expiresAt` on unparseable values (`src/router/auth.router.ts:357-360,423,430`) | must parse as ms-syntax at startup (RS-9); no silent fallback | `AWESOME_AUTH_JWT_REFRESH_TTL` |
| `security.jwt.extraClaims` | map | `[new]` — reference uses `buildTokenPayload` fn (§3.1); base payload is `{ sub, email, role, loginProvider, isEmailVerified, isTotpEnabled }` (`src/router/auth.router.ts:378-384`) | keys must not collide with the six base claims | — (file-only) |
| `security.jwt.claimsWebhook.url` | string | `[new]` — escape hatch for computed claims (§3.1) | https URL; strict timeout enforced | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL` |
| `security.password.bcryptSaltRounds` | number | `12` — default param of `PasswordService.hash` (`src/services/password.service.ts:4`), reached because call sites pass `config.bcryptSaltRounds` through (`src/router/auth.router.ts:818,926`) | integer 10–15 | `AWESOME_AUTH_BCRYPT_SALT_ROUNDS` |
| `tokens.passwordResetTtlMinutes` | number | `[new]` — hardcoded 1 h (`src/router/auth.router.ts:783`) | integer ≥ 5 | `AWESOME_AUTH_TOKENS_PASSWORD_RESET_TTL_MINUTES` |
| `tokens.emailVerificationTtlMinutes` | number | `[new]` — hardcoded 24 h (`src/router/auth.router.ts:952`) | integer ≥ 5 | `AWESOME_AUTH_TOKENS_EMAIL_VERIFICATION_TTL_MINUTES` |
| `tokens.emailChangeTtlMinutes` | number | `[new]` — hardcoded 1 h (`src/router/auth.router.ts:1023`) | integer ≥ 5 | `AWESOME_AUTH_TOKENS_EMAIL_CHANGE_TTL_MINUTES` |
| `tokens.accountLinkTtlMinutes` | number | `[new]` — hardcoded 1 h (`src/router/auth.router.ts:1526`) | integer ≥ 5 | `AWESOME_AUTH_TOKENS_ACCOUNT_LINK_TTL_MINUTES` |
| `tokens.magicLinkTtlMinutes` | number | `[new]` — hardcoded 15 min (`src/strategies/magic-link/magic-link.strategy.ts:21`) | integer ≥ 1 | `AWESOME_AUTH_TOKENS_MAGIC_LINK_TTL_MINUTES` |

### 1.2 Cookies (`cookies.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `cookies.secure` | boolean | `false` (`src/services/token.service.ts:177`) | RS-5 when combined with `sameSite: none`; RS-2 governs production | `AWESOME_AUTH_COOKIES_SECURE` |
| `cookies.sameSite` | `strict\|lax\|none` | `'lax'` (`src/services/token.service.ts:178`) | enum; `none` requires `secure: true` (RS-5) | `AWESOME_AUTH_COOKIES_SAMESITE` |
| `cookies.domain` | string | unset (`src/services/token.service.ts:190`) | valid registrable domain; setting it forfeits the `__Host-` prefix (see note) | `AWESOME_AUTH_COOKIES_DOMAIN` |
| `cookies.path` | string | `'/'` (`src/services/token.service.ts:179`) | absolute path | `AWESOME_AUTH_COOKIES_PATH` |
| `cookies.refreshTokenPath` | string | mutated at router construction to `${apiPrefix}/refresh` (`src/router/auth.router.ts:461-464`); TokenService-level fallback `'/auth/refresh'` (`src/services/token.service.ts:197-198`) | derived from `http.apiPrefix` when unset | `AWESOME_AUTH_COOKIES_REFRESH_PATH` |
| `cookies.allowInsecureCookieMode` | boolean | `[new]` — product-only escape hatch, default `false` | gates RS-2 (cookie mode on a raw execute-api stage URL) | `AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE` |

**Cookie-name resolution (derived, not a knob — every client depends on it).** `getCookieName` (`src/services/token.service.ts:161-172`): plain name when `secure=false`; `__Host-<name>` when `secure=true` ∧ path `/` (or unset) ∧ no domain (Path forced to `/`, Secure forced on, Domain stripped — `src/services/token.service.ts:185-188`); `__Secure-<name>` otherwise. Read priority `__Host-` > `__Secure-` > plain (`src/services/token.service.ts:276-280`). Pinned by `tests/token.service.test.ts:191-241,253-263` and matched by the client-contract CSRF cookie priority. The product preserves this exactly; behind API Gateway the "is HTTPS" signal comes from the event-normalization layer.

**Cookie Max-Age is derived, fixing a reference [MISMATCH].** The reference hardcodes access-cookie Max-Age at `15*60*1000` ms and refresh-cookie at `7*24*60*60*1000` ms (`src/services/token.service.ts:195,200`), **not derived from the TTL knobs** — non-default TTLs silently desynchronize JWT expiry from cookie lifetime (no test pins the desync). The product derives Max-Age from `security.jwt.accessTokenTtl`/`refreshTokenTtl`; no independent knob is exposed.

### 1.3 CSRF (`security.csrf.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `security.csrf.enabled` | boolean | `false` (enforcement gate `src/middleware/auth.middleware.ts:35`; cookie set `src/services/token.service.ts:204-209`) | RS-3: `false` is rejected while cookie delivery is active — the **effective product default is `true`**, a deliberate hardening deviation from the reference default (needs a CompatibilityNotes entry) | `AWESOME_AUTH_CSRF_ENABLED` |

Derived behavior preserved as-is (no knobs): CSRF cookie named `csrf-token`, `httpOnly:false` (JS-readable per client contract), Max-Age 15 min, set on login (`src/services/token.service.ts:204-209`) and lazily re-issued by middleware on any request lacking it (`src/router/auth.router.ts:529-538`) — this lazy re-issue is why clients need no `/csrf` endpoint. Verified only for cookie-auth non-`GET/HEAD/OPTIONS` via header `x-csrf-token` equal to the cookie; failure = 403 `{error:'CSRF token validation failed', code:'CSRF_INVALID'}` (`src/middleware/auth.middleware.ts:34-41`). Bearer requests (`X-Auth-Strategy: bearer`) bypass CSRF (`src/middleware/auth.middleware.ts:35`).

### 1.4 Sessions (`sessions.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `sessions.checkOn` | `allcalls\|refresh\|none` | `'refresh'` at the refresh endpoint (`src/router/auth.router.ts:634`); middleware acts only on the literal `'allcalls'` (`src/middleware/auth.middleware.ts:47`), so unset ≡ `'refresh'` | enum | `AWESOME_AUTH_SESSIONS_CHECK_ON` |

**Client coupling to document:** the `SESSION_REVOKED` 401 is emitted only when `sessions.checkOn: allcalls` (`src/middleware/auth.middleware.ts:47-52`). Clients relying on it for instant logout implicitly require that value.

### 1.5 Email and mailer (`email.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `email.siteUrls` | string[] (first entry = canonical) | `''` when unset (`getDefaultSiteUrl`, `src/router/auth.router.ts:202-206`); array form matched against request `Origin`/`Referer` (`src/router/auth.router.ts:233-246`), merged with `http.cors.origins` into the redirect allowlist (`src/router/auth.router.ts:213-219`) | each entry an absolute URL | `AWESOME_AUTH_EMAIL_SITE_URLS` (comma-sep) |
| `email.mailer.endpoint` | string | required when mailer used; HTTP POST target (`src/services/mailer.service.ts:271` region) | https URL when any email feature enabled | `AWESOME_AUTH_MAILER_ENDPOINT` |
| `email.mailer.apiKey` | string | required; sent as `X-API-Key` (`src/services/mailer.service.ts:274`) | required with endpoint `[secret]` | `AWESOME_AUTH_MAILER_API_KEY` |
| `email.mailer.from` | string | required (`src/models/auth-config.model.ts:25-29`) | email address | `AWESOME_AUTH_MAILER_FROM` |
| `email.mailer.fromName` | string | optional (`src/models/auth-config.model.ts:25-29`) | — | `AWESOME_AUTH_MAILER_FROM_NAME` |
| `email.mailer.provider` | string | optional (`src/models/auth-config.model.ts:25-29`) | — | `AWESOME_AUTH_MAILER_PROVIDER` |
| `email.mailer.defaultLang` | `en\|it` | `'en'` (`src/services/mailer.service.ts:258`; UI fallback `src/router/ui.router.ts:103`); per-request override via `emailLang` body field | enum | `AWESOME_AUTH_MAILER_DEFAULT_LANG` |
| `email.verification.mode` | `none\|lazy\|strict` | effective `'none'`: `config.emailVerificationMode ?? (config.requireEmailVerification ? 'strict' : 'none')` (`src/strategies/local/local.strategy.ts:32-35`); `'lazy'` compares `new Date() > user.emailVerificationDeadline` (`src/strategies/local/local.strategy.ts:42`) | enum; see §1.19 [MISMATCH] on the runtime-settings copy | `AWESOME_AUTH_EMAIL_VERIFICATION_MODE` |
| `email.templatesDir` | string (dir) | `[new]` — seeds templates into the templates store at deploy (§3.8); absent → built-in en/it templates (`src/services/mailer.service.ts:19-110`) | directory must exist at deploy | — (file-only) |
| `email.deliveryWebhook.url` | string | `[new]` — replaces the reference's send-callback functions for exotic transports (§3.8) | https URL | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL` |

Dropped: `requireEmailVerification` (deprecated boolean, `undefined` → `'none'`, `src/strategies/local/local.strategy.ts:35`) — folded into `email.verification.mode`. The five send-callback function knobs move to §3.8.

### 1.6 SMS (`sms.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `sms.endpoint` | string | required when `sms` block present (`src/services/sms.service.ts:6,18`) | https URL | `AWESOME_AUTH_SMS_ENDPOINT` |
| `sms.apiKey` | string | required; sent as `X-API-Key` header (`src/services/sms.service.ts:30`) | required with block `[secret]` | `AWESOME_AUTH_SMS_API_KEY` |
| `sms.username` | string | required; **appended as URL query param on a GET request** (`src/services/sms.service.ts:19-20,28`) — credentials-in-URL hazard the product must fix (move to header/body) | required with block `[secret]` | `AWESOME_AUTH_SMS_USERNAME` |
| `sms.password` | string | required; same credentials-in-URL hazard (`src/services/sms.service.ts:19-20,28`) | required with block `[secret]` | `AWESOME_AUTH_SMS_PASSWORD` |
| `sms.codeTtlMinutes` | number | `10` (`src/strategies/sms/sms.strategy.ts:17`) [UNTESTED] | integer ≥ 1 | `AWESOME_AUTH_SMS_CODE_TTL_MINUTES` |

### 1.7 OAuth providers (`oauth.*`)

Built-in providers (endpoints/scopes hardcoded per provider in the reference; ctor throws `OAUTH_NOT_CONFIGURED` when the block is missing — `src/strategies/oauth/google.strategy.ts:15-17`, `src/strategies/oauth/github.strategy.ts:16`):

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `oauth.providers.google.clientId` | string | none | required when block present (RS-11) | `AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_ID` |
| `oauth.providers.google.clientSecret` | string | none | required `[secret]` | `AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET` |
| `oauth.providers.google.callbackUrl` | string | none | absolute URL | `AWESOME_AUTH_OAUTH_GOOGLE_CALLBACK_URL` |
| `oauth.providers.google.projectId` | string | optional | — | `AWESOME_AUTH_OAUTH_GOOGLE_PROJECT_ID` |
| `oauth.providers.github.clientId` / `.clientSecret` / `.callbackUrl` | strings | none | as Google (secret marked) (RS-11) | `AWESOME_AUTH_OAUTH_GITHUB_CLIENT_ID` etc. |

Generic providers — `GenericOAuthProviderConfig` is already ~90% declarative in the reference (`src/strategies/oauth/generic-oauth.strategy.ts:39-78`); each entry under `oauth.providers.<name>`:

| Path (per provider) | Type | Default (code) | Validation |
|---|---|---|---|
| `clientId`, `clientSecret`, `callbackUrl` | strings | none | required; `clientSecret` `[secret]` |
| `authorizationUrl`, `tokenUrl`, `userInfoUrl` | strings | none | https URLs |
| `scope` | string | none | — |
| `additionalAuthParams` | map | none | string values |
| `profileMap` | map | `[new]` — replaces the `mapProfile` fn, whose default is `id: raw.id ?? raw.sub`, `email: raw.email` (`src/strategies/oauth/generic-oauth.strategy.ts:155-156`) | JSONPath / fallback-chain expressions, e.g. `email: "$.mail ?? $.userPrincipalName"` (§3.3) |

Provisioning policy — replaces the abstract `findOrCreateUser(profile, state)` the reference forces integrators to write (§3.3):

| Path | Type | Default | Validation | Env var |
|---|---|---|---|---|
| `oauth.provisioning.autoCreate` | boolean | `[new]` | — | `AWESOME_AUTH_OAUTH_PROVISIONING_AUTO_CREATE` |
| `oauth.provisioning.allowedEmailDomains` | string[] | `[new]` — empty = all | valid domains | `AWESOME_AUTH_OAUTH_PROVISIONING_ALLOWED_EMAIL_DOMAINS` |
| `oauth.provisioning.fieldMap` | map | `[new]` | as `profileMap` | — (file-only) |
| `oauth.provisioning.requireVerifiedEmail` | boolean | `[new]` | — | `AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL` |

### 1.8 Two-factor (`twoFactor.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `twoFactor.appName` | string | `'awesome-node-auth'` (`src/router/auth.router.ts:830`; default param `src/strategies/two-factor/totp.strategy.ts:11`) — TOTP issuer in the otpauth URI | non-empty | `AWESOME_AUTH_2FA_APP_NAME` |

`require2FA` is runtime-mutable → §1.19. The 2FA feature flag itself is derived from the presence of the `twoFactor` block (`src/router/ui.router.ts:114-123`).

### 1.9 Magic link

No dedicated block: the feature flag is derived (`magicLink` ← `sendMagicLink || mailer`, `src/router/ui.router.ts:114-123`), the token TTL knob is `tokens.magicLinkTtlMinutes` (§1.1), and delivery uses `email.mailer.*` (§1.5). The `mode` body field defaults to `'login'` when omitted (`src/router/auth.router.ts:1087,1134,1192,1255`) — per-request client behavior, no config knob.

### 1.10 Identity provider / JWKS (`idProvider.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `idProvider.enabled` | boolean | `false`; mode active when `privateKey` present **or** `enabled === true` (`src/services/token.service.ts:42`, `src/router/auth.router.ts:473`) | RS-4 in production | `AWESOME_AUTH_IDP_ENABLED` |
| `idProvider.privateKey` | PEM string | unset → ephemeral RSA keypair auto-generated with console warning (`src/services/token.service.ts:50-63`; also at router build `src/router/auth.router.ts:480-483`) — product refuses instead (RS-4) | valid PEM `[secret]` — secret-store-only, never YAML | `AWESOME_AUTH_IDP_PRIVATE_KEY` |
| `idProvider.publicKey` | PEM string | derived from `privateKey` when omitted (`src/services/token.service.ts:67-69`, `src/router/auth.router.ts:484-486`) | valid PEM; optional | `AWESOME_AUTH_IDP_PUBLIC_KEY` |
| `idProvider.jwksPath` | string | `'/.well-known/jwks.json'` (`src/router/auth.router.ts:475`) | absolute path | `AWESOME_AUTH_IDP_JWKS_PATH` |
| `idProvider.issuer` | string | unset → **no `iss` claim** embedded (`src/services/token.service.ts:76`) | https URL; deploy-time warning when unset | `AWESOME_AUTH_IDP_ISSUER` |
| `idProvider.accessTokenTtl` | string | `'30d'` (`src/services/token.service.ts:80`) | ms-syntax (RS-9) | `AWESOME_AUTH_IDP_ACCESS_TTL` |
| `idProvider.refreshTokenTtl` | string | priority `idp.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'` (`src/services/token.service.ts:91`) | ms-syntax (RS-9) | `AWESOME_AUTH_IDP_REFRESH_TTL` |
| `idProvider.jwksCorsOrigins` | string \| string[] | `'*'` (`src/router/auth.router.ts:492`) [UNTESTED origin matching] | `'*'` or list of origins | `AWESOME_AUTH_IDP_JWKS_CORS_ORIGINS` |

Hardcoded, preserved without a knob: JWKS endpoint response `Cache-Control: public, max-age=3600` (`src/router/auth.router.ts:502`).

### 1.11 Resource server (`resourceServer.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `resourceServer.enabled` | boolean | `false` (`src/models/auth-config.model.ts:118`); when true, auth-flow routes are skipped (`src/router/auth.router.ts:510,541`) | — | `AWESOME_AUTH_RS_ENABLED` |
| `resourceServer.jwksUrl` | string | required (typed required); **not validated at construction** — first token verification fails at fetch time (`src/services/jwks.service.ts:111`) | required when enabled; well-formed https URL at startup (RS-8) | `AWESOME_AUTH_RS_JWKS_URL` |
| `resourceServer.issuer` | string | unset → `iss` not validated (`src/services/token.service.ts:135-140`) | deploy-time warning when unset | `AWESOME_AUTH_RS_ISSUER` |
| `resourceServer.jwksCacheTtlMs` | number (ms) | `3_600_000` (`src/services/jwks.service.ts:40`) | integer > 0 | `AWESOME_AUTH_RS_JWKS_CACHE_TTL_MS` |
| `resourceServer.jwksFetchTimeoutMs` | number (ms) | `5000` (`src/services/jwks.service.ts:41`) | integer > 0 | `AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS` |

Internal wiring, not a knob: `createJwksAuthMiddleware` throws unless `resourceServer.enabled === true` (`src/middleware/jwks-auth.middleware.ts:38-39`).

### 1.12 UI and branding (`ui.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `ui.enabled` | boolean | `false` — UI router only mounted when truthy (`src/router/auth.router.ts:1639`) | — | `AWESOME_AUTH_UI_ENABLED` |
| `ui.headless` | boolean | `false` (`src/router/ui.router.ts:168,175`) — serves assets + `/ui/config` only, HTML pages skipped [UNTESTED] | — | `AWESOME_AUTH_UI_HEADLESS` |
| `ui.customCss` | string | unset; injected verbatim (`src/router/ui.router.ts:130`) | — | — (file-only) |
| `ui.branding.logoUrl` | string | unset; resolution `settings.ui.logoUrl \|\| ui.customLogo \|\| ui.logoUrl` (`src/router/ui.router.ts:128`) — `customLogo`/`logoUrl` collapse into one knob | URL | `AWESOME_AUTH_UI_LOGO_URL` |
| `ui.branding.primaryColor` | string | `'#4a90d9'` (`src/router/ui.router.ts:126`) | CSS color | `AWESOME_AUTH_UI_PRIMARY_COLOR` |
| `ui.branding.secondaryColor` | string | `'#6c757d'` (`src/router/ui.router.ts:127`) | CSS color | `AWESOME_AUTH_UI_SECONDARY_COLOR` |
| `ui.branding.siteName` | string | `'Awesome Node Auth'` (`src/router/ui.router.ts:129`) | non-empty | `AWESOME_AUTH_UI_SITE_NAME` |
| `ui.branding.bgColor` / `.bgImage` / `.cardBg` | string | unset (`src/router/ui.router.ts:131-133`) | — | `AWESOME_AUTH_UI_BG_COLOR` etc. |
| `ui.assetsDir` | string (dir) | candidate-list probe of 6 dirs, first entry when nothing found (`src/router/ui.router.ts:72-93`) — in the product, assets are embedded/S3-served; knob retained for override | directory exists | — (file-only) |
| `ui.uploadDir` | string (dir) | unset → uploads disabled (`src/router/admin.router.ts:656`; static mounts skipped `src/router/ui.router.ts:185-190`) — serverless target is an S3 location | valid S3 URI in product | `AWESOME_AUTH_UI_UPLOAD_DIR` |

All `ui.branding.*` values are runtime-mutable (settings win, §1.19). **Dropped as dead config [MISMATCH]:** `ui.loginUrl` / `ui.registerUrl` — doc comments claim defaults `/auth/ui/login` / `/auth/ui/register` (`src/models/auth-config.model.ts:344-347`) but **no code in `src/` reads these fields**. Also dropped: `RouterOptions.ui.{siteName,primaryColor,secondaryColor,logoUrl}` — a duplicate surface of `config.ui`, collapsed into `ui.branding.*`.

**Derived feature flags stay derived.** `GET /ui/config` flags (`src/router/ui.router.ts:114-123`): `register` ← registration enabled, `magicLink` ← mailer/callback present, `sms` ← `sms` block, `google`/`github` ← `oauth.providers.*`, `forgotPassword` ← mailer/callback, `verifyEmail` ← `(sendVerificationEmail || mailer) && (emailVerificationMode !== 'none' || requireEmailVerification)` (`src/router/ui.router.ts:121`), `twoFactor` ← `twoFactor` block. These must not become independent knobs.

### 1.13 Admin and access policy (`admin.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `admin.accessPolicy` | `first-user\|is-admin-flag\|open` (+ `rbac:<role>` / `permission:<perm>` string forms, §3.4) | unset → guard priority `accessPolicy` > `adminSecret` > **open with stderr warning** (`src/router/admin.router.ts:516-537`) — product refuses instead (RS-6) | enum or `rbac:`/`permission:` prefix; `first-user` requires a driver with `listUsers` (RS-10, cf. 500 at `src/router/admin.router.ts:372-379`) | `AWESOME_AUTH_ADMIN_ACCESS_POLICY` |
| `admin.bootstrapSecret` | string | reference `adminSecret` (deprecated): legacy bearer guard — 401 without header, 403 on wrong token (`src/router/admin.router.ts:189-203`); bootstrap password at local admin login when email empty or `'admin'` (`src/router/admin.router.ts:560-564`) — kept **only** as bootstrap | min length 32 `[secret]` | `AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET` |
| `admin.rootUser.email` | string | unset (`src/router/admin.router.ts:553-557`) | email | `AWESOME_AUTH_ADMIN_ROOT_EMAIL` |
| `admin.rootUser.passwordHash` | string | unset; bcrypt-compared at admin login (`src/router/admin.router.ts:553-557`) | bcrypt hash, never plaintext `[secret]` | `AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH` |
| `admin.cookiePrefix` | `'__Host-'\|'__Secure-'\|custom` | unset → guard tries `__Host-accessToken` ?? `__Secure-accessToken` ?? `accessToken` (`src/router/admin.router.ts:291-294`); explicit prefix always wins (`src/router/admin.router.ts:224-227`) | usually derivable from `cookies.secure`; explicit override allowed | `AWESOME_AUTH_ADMIN_COOKIE_PREFIX` |
| `admin.loginPath` | string | unset → built-in login form for unauthenticated GET HTML (`src/router/admin.router.ts:311-325`); when set, 302 to `${loginPath}?redirect=<path>` (`src/router/admin.router.ts:312-315`) [UNTESTED] | absolute path or URL | `AWESOME_AUTH_ADMIN_LOGIN_PATH` |
| `admin.basePath` | string | swagger base `'/admin'` (`src/router/admin.router.ts:160-176`) | absolute path | `AWESOME_AUTH_ADMIN_BASE_PATH` |
| `admin.sessionTtl` | string | `[new]` — hardcoded session JWT `expiresIn: '24h'` (`src/router/admin.router.ts:585`) and cookie `maxAge: 24*60*60*1000` with `httpOnly:true, sameSite:'lax', path:'/'`, `secure` from `req.secure`/`x-forwarded-proto` (`src/router/admin.router.ts:591-611`) | ms-syntax; cookie Max-Age derived | `AWESOME_AUTH_ADMIN_SESSION_TTL` |
| `admin.upload.maxFileSizeMb` | number | `[new]` — multer limit `fileSize: 5*1024*1024` hardcoded (`src/router/admin.router.ts:1015`) [UNTESTED] | integer 1–50 | `AWESOME_AUTH_ADMIN_UPLOAD_MAX_FILE_SIZE_MB` |

Folded/dropped: `AdminOptions.jwtSecret` — must equal the auth secret per its own doc (`src/router/admin.router.ts:73`), so it reuses `security.jwt.accessTokenSecret`; note the reference **never throws when it is missing — the guard simply never authenticates anyone** (`src/router/admin.router.ts:274-305`), [MISMATCH doc-vs-code] with "Requires `jwtSecret`" (`src/router/admin.router.ts:64`) → RS-7. `AdminOptions.uploadBaseUrl` — computed `${apiPrefix}/ui/assets/uploads` (`src/router/admin.router.ts:639-643`), stays derived. Admin `apiPrefix`/`swagger` fold into `http.apiPrefix`/`docs.swagger` (fallback `'/auth'` in injected admin HTML config, `src/router/admin.router.ts:444`).

### 1.14 Tools, telemetry, SSE (`tools.*`)

Reference defaults from `src/router/tools.router.ts:120-128` unless noted.

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `tools.telemetry.enabled` | boolean | `true` | route additionally requires a telemetry store with `query` (`src/router/tools.router.ts:226`); the inner 501 (`src/router/tools.router.ts:230-231`) is unreachable defensive code | `AWESOME_AUTH_TOOLS_TELEMETRY` |
| `tools.notify.enabled` | boolean | `true` | `email`/`sms` channels require `stores.users` + transport config (`src/services/notification.service.ts:110-129` throws at send time) | `AWESOME_AUTH_TOOLS_NOTIFY` |
| `tools.stream.enabled` | boolean | `true` (only useful with `tools.sse.enabled`) | — | `AWESOME_AUTH_TOOLS_STREAM` |
| `tools.auth` | `none\|session\|apiKey\|admin` | reference `authMiddleware` unset → **tools endpoints unauthenticated** (§3.7) | `none` triggers a deploy-time warning | `AWESOME_AUTH_TOOLS_AUTH` |
| `tools.basePath` | string | swagger base `'/tools'` (`src/router/tools.router.ts:126-127`) | absolute path | `AWESOME_AUTH_TOOLS_BASE_PATH` |
| `tools.sse.enabled` | boolean | `false` (`src/tools/auth-tools.ts:176`) | — | `AWESOME_AUTH_SSE_ENABLED` |
| `tools.sse.heartbeatIntervalMs` | number | `30_000`; `<= 0` disables heartbeat (`src/tools/sse-manager.ts:105,156`) | integer | `AWESOME_AUTH_TOOLS_SSE_HEARTBEAT_INTERVAL_MS` |
| `tools.sse.deduplicate` | boolean | `true` (`!== false`, `src/tools/sse-manager.ts:106`) | — | `AWESOME_AUTH_TOOLS_SSE_DEDUPLICATE` |
| `tools.sse.distributor` | block `{type: redis\|sns\|none, ...connection}` | reference `sseOptions.distributor` instance unset → events fan out only within one process (§3.9) | `type` enum; connection per driver; credentials `[secret]` | — (file-only; secrets via store refs) |

### 1.15 Webhooks (`tools.inboundWebhooks.*`, `tools.outboundWebhooks.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `tools.inboundWebhooks.enabled` | boolean | `true` (`src/router/tools.router.ts:120-128`); route mounted only when additionally `onWebhook` or `webhookStore.findByProvider` exists (`src/router/tools.router.ts:250`) | requires `stores.webhooks` enabled | `AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS` |
| `tools.inboundWebhooks.scriptTimeoutMs` | number | `[new]` — vm sandbox timeout hardcoded `5_000` ms (`src/router/tools.router.ts:289`) | integer 100–30000 | `AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_TIMEOUT_MS` |
| `tools.outboundWebhooks.payloadVersion` | string | `'1'` (`src/tools/auth-tools.ts:175`); attached as `version` to outgoing payloads (`src/tools/auth-tools.ts:254`) | — | `AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_PAYLOAD_VERSION` |
| `tools.outboundWebhooks.defaults.maxRetries` | number | `[new]` as config — per-webhook data default `3` (`src/tools/webhook-sender.ts:18-19,46`) | integer 0–10 | `AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_MAX_RETRIES` |
| `tools.outboundWebhooks.defaults.retryDelayMs` | number | `[new]` as config — per-webhook data default `1_000`, exponential backoff (`src/tools/webhook-sender.ts:18-19,46`) | integer ≥ 100 | `AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_RETRY_DELAY_MS` |

Per-webhook rows (URL, events, `jsScript`, `allowedActions`, per-row `maxRetries`/`retryDelayMs`) are **data in `stores.webhooks`, not config** — runtime-managed via the admin API. Outbound deliveries carry `X-Webhook-Signature: sha256=<hex>` (HMAC-SHA256) plus `X-Webhook-Event`, `X-Webhook-Delivery`, `X-Webhook-Timestamp` (`src/tools/webhook-sender.ts:24-33`) — preserved as-is. The vm sandbox exposes only `body`, `actions`, `result`, and a dev-only `console` (`src/router/tools.router.ts:272-286`); the action allowlist is `enabledWebhookActions` (runtime setting, §1.19) intersected with per-webhook `allowedActions` (`src/router/tools.router.ts:261-266`) [UNTESTED]; with no settings store, `enabledWebhookActions` is treated as `[]` (`src/router/tools.router.ts:261-264`).

### 1.16 Rate limiting (placeholder — no reference defaults exist)

The reference has **no rate limiting anywhere** unless the integrator injects an Express `rateLimiter` middleware — the default is `rl = []` (`src/router/auth.router.ts:468`). The product ships a built-in limiter (§3.5); every default below is a product decision, deliberately left TBD in Phase 0:

| Path | Type | Default | Validation | Env var |
|---|---|---|---|---|
| `rateLimit.enabled` | boolean | `[new]` TBD | — | `AWESOME_AUTH_RATE_LIMIT_ENABLED` |
| `rateLimit.windowSeconds` | number | `[new]` TBD | integer > 0 | `AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS` |
| `rateLimit.max` | number | `[new]` TBD | integer > 0 | `AWESOME_AUTH_RATE_LIMIT_MAX` |
| `rateLimit.keyBy` | `ip\|email` | `[new]` TBD | enum | `AWESOME_AUTH_RATE_LIMIT_KEY_BY` |
| `rateLimit.scope` | string[] | `[new]` TBD — endpoint list, e.g. `[login, refresh, forgot-password]` | known endpoint names | — (file-only) |

### 1.17 Stores and adapters (`stores.*`)

The reference injects 13 store interfaces (`src/interfaces/*.ts`); presence toggles features (routes, admin tabs — e.g. linked-accounts endpoints per `src/router/auth.router.ts:69-86`, admin tab flags `src/router/admin.router.ts:645-656`). As a product, awesome-lambda-auth **ships the implementations**; config selects a driver and enables per-store features:

| Path | Type | Default | Validation | Env var |
|---|---|---|---|---|
| `stores.driver` | `dynamodb\|postgres\|memory` | `[new]` — product decision; `memory` is dev-only | enum; `memory` rejected in production | `AWESOME_AUTH_STORES_DRIVER` |
| `stores.connection.*` | block | `[new]` — per-driver (table name / DSN / region) | per driver; credentials `[secret]` | driver-specific |
| `stores.enable.<store>` | boolean | mirrors reference presence semantics: disabled store ⇒ feature routes/tabs absent | see per-feature requirements below | `AWESOME_AUTH_STORES_ENABLE_<STORE>` |

`<store>` ∈ `users` (always on — `IUserStore` is a required ctor arg in the reference), `sessions`, `metadata`, `rbac`, `tenants`, `linkedAccounts`, `pendingLinks`, `settings`, `apiKeys`, `webhooks`, `templates`, `telemetry`, `tokens`. Cross-store requirements enforced at startup: `sessions.checkOn ≠ none` ⇒ `sessions`; `admin.accessPolicy: first-user` ⇒ driver `listUsers` capability (RS-10); `rbac:`/`permission:` policies ⇒ `rbac`; inbound webhooks ⇒ `webhooks`; runtime settings (§1.19) ⇒ `settings` (without it the reference returns 404 `{error:'Settings store not configured'}`, `src/router/admin.router.ts:951-959`); notify email/sms channels ⇒ `users` + transport.

### 1.18 HTTP surface and docs (`http.*`, `docs.*`)

| Path | Type | Default (code) | Validation | Env var |
|---|---|---|---|---|
| `http.apiPrefix` | string | `'/auth'` via `resolveApiPrefix` — priority `options.apiPrefix` > `config.apiPrefix` > `'/auth'` (`src/router/auth.router.ts:253-255`; UI router per-request override from `req.baseUrl`, `src/router/ui.router.ts:97-98`) — single knob; the per-instance override is a library-embedding concern, dropped | absolute path | `AWESOME_AUTH_HTTP_API_PREFIX` |
| `http.cors.origins` | string[] | unset → **no CORS middleware at all** (`src/router/auth.router.ts:513`); also merged into the redirect allowlist (`src/router/auth.router.ts:213-219`) | absolute origins | `AWESOME_AUTH_CORS_ORIGINS` (comma-sep) |
| `docs.swagger` | `true\|false\|auto` | `'auto'` → enabled iff `options.swagger === true \|\| (options.swagger !== false && NODE_ENV !== 'production')` (`src/router/auth.router.ts:1652-1654`); pinned by `tests/swagger.test.ts:250-259` | enum | `AWESOME_AUTH_DOCS_SWAGGER` |
| `docs.basePath` | string | `resolveApiPrefix(config, options)` (`src/router/auth.router.ts:1657`); doc comment says `'/auth'` — code default is the resolved prefix | absolute path | `AWESOME_AUTH_DOCS_BASE_PATH` |

Hardcoded, preserved without knobs: CORS allowed headers/methods `Content-Type,Authorization,X-CSRF-Token,X-Api-Key` / `GET,POST,PUT,PATCH,DELETE,OPTIONS`, preflight `204` (`src/router/auth.router.ts:517-524`). Bearer vs cookie delivery is per-request client behavior (`X-Auth-Strategy: bearer`, `src/router/auth.router.ts:390-406`) — no config knob.

### 1.19 Runtime-mutable settings (`runtimeSettings.*`)

The settings store is the **only** runtime-mutable layer. Reference admin endpoints: `GET /admin/api/settings` returns the raw object (`src/router/admin.router.ts:951-959`); `PUT /admin/api/settings` shallow-merges the **unvalidated request body** (`src/router/admin.router.ts:961-971`); `PATCH /admin/api/settings/ui` deep-merges `ui` (`src/router/admin.router.ts:973-982`). The product must validate mutations against this schema (see RS note below). All settings mutations are [UNTESTED] in the reference.

| Setting (`runtimeSettings.*`) | Boot seed | Where read at runtime | Effective in reference? |
|---|---|---|---|
| `require2FA` | file/env | `POST /auth/2fa/disable` → 403 `{error:'Cannot disable 2FA: required by system policy', code:'2FA_REQUIRED'}` when true (`src/router/auth.router.ts:890-895`) | yes |
| `enabledWebhookActions` | file/env | intersected with per-webhook `allowedActions` for the vm sandbox (`src/router/tools.router.ts:261-266`) [UNTESTED] | yes |
| `ui.{primaryColor,secondaryColor,logoUrl,siteName,logoPath,bgColor,bgImage,cardBg}` | `ui.branding.*` (§1.12) | `GET /ui/config` — settings win over static config (`src/router/ui.router.ts:126-133`) | yes |
| `requireEmailVerification` / `emailVerificationMode` | `email.verification.mode` | **never read by login code** — `LocalStrategy` reads only static config (`src/strategies/local/local.strategy.ts:32-35`); no `settingsStore` consumer outside the admin UI | **[MISMATCH]** — admin toggle with no server-side effect; the product must either consult the store at login or drop the toggle |
| `lazyEmailVerificationGracePeriodDays` | — | only the admin UI, display default `7` (`src/ui/assets/admin.js:768`); the server never computes `emailVerificationDeadline` from it | **[MISMATCH]** display-only; also naming drift: admin OpenAPI documents `emailVerificationGracePeriodDays` (`src/router/openapi.ts:1278`) vs interface/UI `lazyEmailVerificationGracePeriodDays` (`src/interfaces/settings-store.interface.ts:62`, `src/ui/assets/admin.js:768,921`) |

---

## 2. Refuse-to-start rules

Deployment (stack create/update) and cold start MUST abort with a loud, named error when any rule below fires. The reference's posture — four constructor throws, two warnings, and eight fully silent misconfigurations (extract §9) — is not acceptable for a product whose operators never see stderr.

| # | Rule | Reference behavior today | Evidence |
|---|---|---|---|
| RS-1 | `security.jwt.accessTokenSecret` or `refreshTokenSecret` missing, empty, or shorter than 32 chars (HS256) while `resourceServer.enabled` is false | **silent** — first login 500s inside `jwt.sign` | `src/services/token.service.ts:22,27,145,154` (length floor is a product rule) |
| RS-2 | Cookie delivery active on a raw execute-api stage URL (no custom domain) — cookie scoping/`__Host-` semantics and CSRF assumptions break on shared AWS domains — unless `cookies.allowInsecureCookieMode: true` (dev/testing) | n/a — Lambda-specific product rule, no reference counterpart | prefix logic assumes controlled host: `src/services/token.service.ts:161-188` |
| RS-3 | `security.csrf.enabled: false` while cookie delivery is active | reference **defaults** to disabled — flagged deviation, needs CompatibilityNotes entry | gate `src/middleware/auth.middleware.ts:35` |
| RS-4 | `idProvider` mode active (`enabled: true` or key material present) **without externally supplied `privateKey`** in production | warns and generates an ephemeral keypair — "All tokens will be invalidated on restart"; fatal under Lambda (every cold start = new keypair) | `src/services/token.service.ts:50-63`, `src/router/auth.router.ts:480-483` |
| RS-5 | `cookies.sameSite: none` without `cookies.secure: true` | **silent** — browsers reject the cookie | no check anywhere in `src/services/token.service.ts:174-210` |
| RS-6 | Admin surface deployed with neither `admin.accessPolicy` nor `admin.bootstrapSecret` | stderr warning, admin routes fully open | `src/router/admin.router.ts:516-537` |
| RS-7 | `admin.accessPolicy` ≠ `open` with no usable JWT secret | **silent** — guard never authenticates anyone; doc claims "Requires `jwtSecret`" but code never checks [MISMATCH doc-vs-code] | `src/router/admin.router.ts:274-305` vs `:64`; folded into RS-1 since the product reuses `security.jwt.accessTokenSecret` |
| RS-8 | `resourceServer.enabled: true` without a well-formed https `jwksUrl` | **silent** — validated only at first request | `src/services/jwks.service.ts:111` (deploy-time reachability probe: warn-only, endpoints may come up later) |
| RS-9 | Any TTL knob (`security.jwt.*Ttl`, `idProvider.*Ttl`, `admin.sessionTtl`) fails ms-syntax parsing | **silent** — refresh TTL falls back to 7 d for session expiry while `jwt.sign` may reject the same string | `src/router/auth.router.ts:357-360` |
| RS-10 | `admin.accessPolicy: first-user` with a store driver lacking `listUsers` | 500 at request time `{error:'accessPolicy: first-user requires IUserStore.listUsers to be implemented'}` | `src/router/admin.router.ts:372-379` |
| RS-11 | Any `oauth.providers.<name>` block present but missing `clientId`, `clientSecret`, or `callbackUrl` | constructor throw `AuthError('… OAuth not configured', 'OAUTH_NOT_CONFIGURED', 500)` — the one case the reference already fails fast | `src/strategies/oauth/google.strategy.ts:15-17`, `src/strategies/oauth/github.strategy.ts:16` |
| RS-12 | `stores.driver: memory` in a production deployment | n/a — product rule (multi-instance Lambda makes in-memory stores incoherent) | — |

Related but not startup rules: **(a)** cookie Max-Age desync (extract seed 11) is eliminated structurally — Max-Age is derived from the TTL knobs (§1.2), so there is nothing to check; **(b)** `PUT /admin/api/settings` persisting arbitrary unvalidated keys (`src/router/admin.router.ts:961-971`, extract seed 14) becomes a **runtime** validation: mutations are validated against the §1.19 schema and unknown keys rejected with 400.

---

## 3. Extension points that cannot be pure config

The reference is a library, so it delegates to integrator code in eleven places. For each: what the code hook does, the serverless-native replacement, and whether the replacement is fully declarative or keeps a webhook escape hatch. Verdicts follow extract §8.

| # | Code hook | Reference behavior | Product replacement | Verdict |
|---|---|---|---|---|
| 3.1 | `buildTokenPayload(user)` (`src/models/auth-config.model.ts:316`) | absent → payload is exactly `{ sub, email, role, loginProvider: ?? 'local', isEmailVerified: ?? false, isTotpEnabled: ?? false }`; result merged **over** the base (`src/router/auth.router.ts:378-384`) | `security.jwt.extraClaims` static mapping table (`{claimName: {fromUserField: x} \| {const: y}}`); computed claims → synchronous `security.jwt.claimsWebhook.url` with strict timeout | mapping covers the common case; arbitrary computation is irreducibly code → webhook |
| 3.2 | `onRegister(data, config, options)` (`src/router/auth.router.ts:109`) | absent → **`POST /register` not mounted** (`src/router/auth.router.ts:94-99`); when present, receives the raw body and must create+return the user | `registration: {enabled, fields: allowlist, passwordPolicy, autoVerify}` with a built-in create-user handler; bespoke provisioning → `registration.webhook.url` (before/after create) | built-in handler expressible; bespoke provisioning is code → webhook |
| 3.3 | `googleStrategy` / `githubStrategy` abstract subclasses (`src/strategies/oauth/google.strategy.ts:6-21`) and `GenericOAuthStrategy.mapProfile` (`src/strategies/oauth/generic-oauth.strategy.ts:155-156`) | integrator must implement `findOrCreateUser(profile, state)`; generic config already 90% declarative (`src/strategies/oauth/generic-oauth.strategy.ts:39-78`) | `oauth.providers.<name>.*` + `profileMap` (JSONPath/fallback chains) + global `oauth.provisioning.*` (§1.7) | fully declarative incl. profile mapping — the reference forces code only because it is a library |
| 3.4 | `accessPolicy` as function (`src/router/admin.router.ts:38-42`) | enum values `first-user`/`is-admin-flag`/`open` already declarative; fn form receives `(user, rbacStore)` | keep the enum; add `rbac:<role>` / `permission:<perm>` string forms evaluated against the RBAC store | enum + rbac reference covers it; arbitrary predicates are code (no escape hatch — deliberate) |
| 3.5 | `rateLimiter` Express middleware (`src/router/auth.router.ts:46`) | absent → no rate limiting anywhere (`rl = []`, `src/router/auth.router.ts:468`) | built-in limiter driven by `rateLimit.*` (§1.16) | fully declarative |
| 3.6 | `onWebhook(provider, body, req)` (`src/router/tools.router.ts:63-67`) + per-webhook `jsScript` | stored `jsScript` runs in a `vm` sandbox (5 s timeout); `onWebhook` is only a fallback mapper returning `{event,data,userId,tenantId}\|null` (`src/router/tools.router.ts:310-313`) | already data-driven in the reference: keep per-provider `inboundWebhooks[provider].script` + `allowedActions` as store data; **drop `onWebhook` from the product** | expressible today via stored scripts |
| 3.7 | `authMiddleware` on ToolsRouter (`src/router/tools.router.ts:43`) | absent → tools endpoints public | `tools.auth: none\|session\|apiKey\|admin` selecting built-in guards (§1.14) | fully declarative |
| 3.8 | Email callbacks `sendMagicLink`/`sendPasswordReset`/`sendWelcome`/`sendVerificationEmail`/`sendEmailChanged` (`src/models/auth-config.model.ts:228-257`) | absent → built-in HTTP mailer + built-in en/it templates (`src/services/mailer.service.ts:19-110`); callbacks always take precedence over `mailer` | `email.mailer.*` transport + template-store-backed templates (runtime-editable via admin Email & UI tab, seeded from `email.templatesDir`) + optional `email.deliveryWebhook.url` for fully external delivery | mailer+templates expressible; exotic transports → webhook |
| 3.9 | Store instances (13 interfaces, `src/interfaces/*.ts`) and `sseOptions.distributor` (`src/interfaces/sse-distributor.interface.ts:10`) | all injected; presence toggles features; distributor absent → single-process fan-out | `stores.*` driver blocks (§1.17); `tools.sse.distributor: {type: redis\|sns\|none, ...}` — the product ships the implementations | fully declarative (product owns the drivers) |
| 3.10 | `templateStore` (`ITemplateStore`, `src/interfaces/template-store.interface.ts:13-43`) | absent → hardcoded en/it templates; present → `getMailTemplate`/`getUiTranslations` consulted | templates are **data**: seeded from `email.templatesDir` at deploy, edited at runtime via admin API | fully declarative (data) |
| 3.11 | Custom strategies via `AuthConfigurator.strategy()` (`src/auth-configurator.ts:45-58`) | `'local'` returns a `LocalStrategy`; `'google'`/`'github'` **throw** "Strategy is abstract — extend it and pass via RouterOptions"; unknown → `Unknown strategy: <name>` | superseded by `oauth.providers.*` | **dropped** — no product equivalent needed |

Summary: 3.3, 3.4, 3.5, 3.6, 3.7, 3.9, 3.10 are fully config-expressible; 3.1, 3.2, 3.8 are config-expressible for the common case with a webhook escape hatch for genuinely custom code; 3.11 is dropped.

---

## 4. Config format and versioning (decision open — project brief §9.8)

Three candidate formats, presented neutrally; the decision is explicitly **open** at Phase 0. All three share the §1 dotted-path schema, the `AWESOME_AUTH_*` env override layer, and the secrets rule (secret-tagged knobs resolve Secrets Manager → SSM SecureString → env, never plaintext YAML).

| Option | Shape | Pros | Cons |
|---|---|---|---|
| **A. YAML file** | single document shipped with the stack (S3 or baked into the deployment artifact), parsed at cold start | reviewable/diffable in git; one source of truth; trivially validated in CI against the JSON-Schema derived from §1 | config change = redeploy; no per-environment mutation without a pipeline |
| **B. SSM parameter tree** | one parameter per dotted path under `/awesome-auth/<stage>/…`, read (batched) at cold start with a short in-memory TTL cache | per-knob change without redeploy; native IAM auditing; SecureString gives secrets a home in the same tree | no atomic multi-knob change (risk of half-applied config across concurrently cold-starting instances); harder review story; 4 KB/param limits |
| **C. Both (layered)** | YAML file is canonical and validated in CI; deploy step compiles it into the SSM tree; runtime reads only SSM; env vars override individual knobs last | git review **and** runtime introspection; env overrides for emergencies; secrets stay in SSM/Secrets Manager references | most moving parts; two representations to keep in sync (mitigated by making the compiler the only writer) |

Layering order (all options): file/tree value → `AWESOME_AUTH_*` env var → runtime settings store (only for §1.19 keys). Anything not in §1.19 is immutable at runtime by design.

**`schemaVersion`** — the document root carries a required `schemaVersion: <int>` field. Startup rejects a document whose major version is unknown (refuse-to-start, same posture as §2). Additive knobs with defaults do not bump the major; renames/removals/semantic changes do, and ship with a deploy-time migrator (option C: the compiler migrates; options A/B: a standalone `migrate` command). The upgrade path mirrors the wire-contract discipline: old documents either migrate cleanly or fail loudly — never silently reinterpret.

Open questions for §9.8 sign-off: (1) A vs B vs C; (2) whether runtime settings (§1.19) live in the same SSM tree (option B/C) or stay in the settings store as in the reference; (3) whether `cookies.allowInsecureCookieMode` is honored in production or dev-stage only.

---

Provenance: editorial pass over [\_extract/09-config-mapping.md](_extract/09-config-mapping.md); all defaults and file:line references resolve against `nik2208/awesome-node-auth` @ `cc01e9975fe9e425dc6d938a9c5d0738b59c79d8` (npm 1.9.0), extracted 2026-07-28 — see [recon-manifest.md](recon-manifest.md).
