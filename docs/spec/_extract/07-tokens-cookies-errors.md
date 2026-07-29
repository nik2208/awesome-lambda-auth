## Token claim sets, cookie serialization matrix, JWKS, error catalog

Scope: exact JWT payloads (HS256 access/refresh, 2FA tempToken, admin JWT, RS256 IdP pair), the full cookie name/attribute matrix produced by `TokenService`, the JWKS document/endpoint/client behaviour, and the complete error catalog (every `new AuthError(` site plus every plain-object error emission carrying a `code`). All claims are grounded in awesome-node-auth @ cc01e997; file:line references are relative to that repo root. Where README/JSDoc prose disagrees with code, the code is documented and the disagreement flagged.

---

## 1. JWT claim sets

### 1.1 HS256 access token (cookie/bearer session token)

Signing — `src/services/token.service.ts:17-31` (`generateTokenPair`):

```ts
const { iat, exp, ...claims } = payload;                       // :19 — jwt-managed fields stripped
jwt.sign(claims, config.accessTokenSecret,
         { expiresIn: config.accessTokenExpiresIn ?? '15m' })  // :20-24
```

- Algorithm: **HS256** (jsonwebtoken default for a string secret; no `algorithm` option passed).
- Default TTL: **`15m`** (`accessTokenExpiresIn ?? '15m'`, src/services/token.service.ts:23).

Payload — `buildPayload` at `src/router/auth.router.ts:378-384`:

```ts
const base = { sub: user.id, email: user.email, role: user.role,
               loginProvider: user.loginProvider ?? 'local',
               isEmailVerified: user.isEmailVerified ?? false,
               isTotpEnabled: user.isTotpEnabled ?? false };    // :379
if (config.buildTokenPayload) return { ...base, ...config.buildTokenPayload(user) }; // :380-381
```

**Merge order:** custom claims from `config.buildTokenPayload(user)` are spread **after** `base` (src/router/auth.router.ts:381), so custom claims **override** any base claim including `sub`, `email`, `role`. Exception: `sid` is assigned **after** the merge, at `issueTokens` (src/router/auth.router.ts:422 builds payload, :433 sets `payload.sid = session.sessionHandle` when `options.sessionStore` exists) — `sid` can therefore never be clobbered by `buildTokenPayload`.

| Claim | Type | Presence |
|---|---|---|
| `sub` | string (user.id) | always |
| `email` | string | always |
| `role` | string | only when `user.role !== undefined` (undefined values are dropped by JSON serialization in `jwt.sign`) |
| `loginProvider` | string | always (`?? 'local'`, src/router/auth.router.ts:379) |
| `isEmailVerified` | boolean | always (`?? false`) |
| `isTotpEnabled` | boolean | always (`?? false`) |
| `sid` | string | only when `options.sessionStore` configured (src/router/auth.router.ts:425-433) |
| `iat`, `exp` | number | always (jwt-managed; stripped from input at token.service.ts:19/:73) |
| `iss` | string | **never** in HS256 router-issued tokens (only IdP mode, §1.5) |
| custom | unknown | whatever `buildTokenPayload` returns (index signature, src/models/token.model.ts:22) |

Type declarations: `AccessTokenPayload`, src/models/token.model.ts:6-23. `kid` is intentionally absent from the payload — it is a JOSE **header** parameter set via `keyid` (comment src/models/token.model.ts:19-20; consistent with code at token.service.ts:73, :84).

Tests: round-trip of `sub`/`email`/`role` — tests/token.service.test.ts:26-32; custom claims in access token — tests/token.service.test.ts:171-179; `sid` embedded on login — tests/auth.router.test.ts:1142-1151.

### 1.2 HS256 refresh token

`src/services/token.service.ts:25-29`: **identical claim set** (same `claims` object as the access token, including `sid` and custom claims), signed with `config.refreshTokenSecret`, `expiresIn: config.refreshTokenExpiresIn ?? '7d'`. Algorithm HS256 (default, unpinned).

Tests: custom claims survive in refresh token — tests/token.service.test.ts:181-188; refresh verification — tests/token.service.test.ts:34-38.

`parseExpiryMs` (src/router/auth.router.ts:357-372) converts `refreshTokenExpiresIn` to ms for the session `expiresAt` and the stored refresh-token expiry (defaults to `7d` = 604 800 000 ms when unparseable, :360); it does **not** drive cookie Max-Age (see §2.3).

### 1.3 2FA tempToken

Generated at three sites, always as **the accessToken half of a `generateTokenPair` call with both expiries overridden to `'5m'`**:

- Password login, no 2FA method configured: `src/router/auth.router.ts:564-567`, returned in `403 { requires2FASetup: true, tempToken, code: '2FA_SETUP_REQUIRED' }` (:568).
- Password login, 2FA challenge: `src/router/auth.router.ts:572-575`, returned in `200 { requiresTwoFactor: true, tempToken, available2faMethods }` (:576).
- OAuth login with 2FA: `src/router/auth.router.ts:1306-1309`, delivered via redirect `${redirectTo}/auth/2fa?tempToken=<urlencoded>&methods=<csv>` (:1312).

Properties:
- **Claims: exactly the standard access-token claim set** (`buildPayload`, §1.1) — there is **no marker claim** distinguishing it from a real access token, and no `sid` (issued outside `issueTokens`).
- **TTL: 5 minutes** (`accessTokenExpiresIn: '5m'`; the refresh half is also `'5m'` but is discarded — only `.accessToken` is used).
- Signed with `config.accessTokenSecret`, HS256.
- Verified by the 2FA/second-step routes via plain `verifyAccessToken` (src/router/auth.router.ts:862, :1094, :1142, :1198, :1261).

[MISMATCH-risk / security note] Because the tempToken **is** a fully valid 5-minute access token, `createAuthMiddleware` (src/middleware/auth.middleware.ts:44) accepts it on any protected route for 5 minutes before the second factor is presented; with `session.checkOn: 'allcalls'` the session check is also skipped because the tempToken has no `sid` (auth.middleware.ts:47 requires `payload.sid`). [UNTESTED — no test asserts either the 5m TTL or middleware rejection of tempTokens.]

Tests: `2FA_SETUP_REQUIRED` — tests/new-features.test.ts:651-655; `TEMP_TOKEN_REQUIRED` / `INVALID_TEMP_TOKEN` — tests/auth.router.test.ts:441-478.

### 1.4 Admin JWT (`src/router/admin.router.ts`)

Issued by the admin router's self-contained `POST /login` (only registered when `accessPolicy` is set to a value **other than `'open'`** AND `jwtSecret` is present — `sessionBased && secret`, where `sessionBased = options.accessPolicy !== 'open'` only when `accessPolicy` is defined, admin.router.ts:516, :526, :542-543):
> CORRECTED(verify): registration condition was "accessPolicy is set and jwtSecret present" — imprecise: `accessPolicy: 'open'` sets the policy but does NOT register the login route (`sessionBased` is false, admin.router.ts:526); made the `!== 'open'` requirement explicit.

```ts
jwt.sign({ sub: authedUser.id, email: authedUser.email, isRoot: authedUser.isRoot },
         secret /* = options.jwtSecret */, { expiresIn: '24h' });   // admin.router.ts:582-586
```

- Claims: `sub` (string; `'root'` for rootUser, `'admin'` for the adminSecret bootstrap, otherwise `user.id` — admin.router.ts:555, :562, :571), `email` (`'admin@bootstrap'` for the bootstrap path, :562), `isRoot` (boolean or absent), plus `iat`/`exp`. TTL **`'24h'`**. Algorithm HS256 (default, string secret).
- `options.jwtSecret` "Must match `AuthConfig.accessTokenSecret`" per JSDoc (admin.router.ts:71-78) — the admin cookie is deliberately name-compatible with the auth access-token cookie.
- Cookie: name via `resolveAdminCookieName` (admin.router.ts:218-232 — explicit `cookiePrefix` override, else plain/`__Host-`/`__Secure-` using the same rules as TokenService), attributes `{ httpOnly: true, secure: isSecure, sameSite: 'lax', path: '/', maxAge: 24*60*60*1000 }` unless an explicit `cookieOptions` object is passed (admin.router.ts:603-612). `isSecure` = `req.secure || x-forwarded-proto === 'https'` (:591). `__Host-` requirements enforced by `applyHostCookieRequirements` (:243-250).
- Guard verification: `jwt.verify(rawToken, jwtSecret)` with **no `algorithms` allow-list** (admin.router.ts:300). Cookie read priority `__Host-accessToken` → `__Secure-accessToken` → `accessToken` (:294); bearer header wins over cookie (:296). `payload.isRoot === true` bypasses the user-store lookup entirely (:343-352). [UNTESTED for algorithm pinning]
- Admin `POST /logout` clears the same cookie (admin.router.ts:618-635).

### 1.5 RS256 IdP-mode pair (`src/services/token.service.ts:40-96`)

Activation: `config.idProvider.privateKey` present **or** `idProvider.enabled === true` (:42); otherwise `AuthError('IdP mode is not enabled', 'IDP_NOT_ENABLED', 500)` (:44). Missing privateKey → ephemeral RSA-2048 keypair auto-generated with a **once-per-process** console warning (:50-66; warning text "auto-generating an ephemeral RSA keypair… All tokens will be invalidated on restart"); missing publicKey → derived from privateKey (:67-69). Tests: tests/jwks.service.test.ts:153-171, :211-232, :234-273.

Payload: `{ iat, exp, kid: _kid, ...claims }` destructured out (:73), then `iss: idp.issuer` added **only when configured** (:74-77; no issuer → no `iss` claim, pinned by tests/jwks.service.test.ts:228-231).

Header: `algorithm: 'RS256'`, `keyid: 'provisioner-key-1'` — the kid is a **hardcoded constant** (:78) used for both tokens (:81-85, :89-93). Pinned by tests/jwks.service.test.ts:147-150.

Expiries:
- Access token: `idp.tokenExpiry ?? '30d'` (:80).
- Refresh token: **also RS256-signed with the same private key** (:89-93), `expiresIn: idp.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'` (:91). The code comment (:87-88) states the intent: refresh is RS256 with a longer expiry — in IdP mode there is no shared HS256 secret with downstream verifiers, so both halves must verify against the JWKS. [UNTESTED — no test asserts refresh-token alg or the 30d/90d defaults.]

**[MISMATCH] The auth router never calls `generateIdProviderTokenPair`.** Grep over `src/` finds no caller — `/login`, `/refresh`, etc. always issue HS256 pairs via `generateTokenPair` (src/router/auth.router.ts:441). Enabling `idProvider` registers the JWKS endpoint (§3) but does **not** switch router-issued session tokens to RS256; RS256 issuance is a host-app-level API only. README.detailed.md implies IdP mode signs "JWTs" generally — code wins.

### 1.6 `jwt.verify` options — the missing algorithms allow-list

| Verifier | Call | `algorithms` pinned? |
|---|---|---|
| `verifyAccessToken` | `jwt.verify(token, config.accessTokenSecret)` — src/services/token.service.ts:145 | **NO** |
| `verifyRefreshToken` | `jwt.verify(token, config.refreshTokenSecret)` — src/services/token.service.ts:154 | **NO** |
| `_verifyRsaToken` (JWKS path) | `jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] })` — src/services/token.service.ts:136 | yes, `['RS256']`; manual `iss` equality check at :137-138 |
| Admin policy guard | `jwt.verify(rawToken, jwtSecret)` — src/router/admin.router.ts:300 | **NO** |

Dependency is `jsonwebtoken ^9.0.3` (package.json:61); v9 limits a string secret to the HMAC family by key type, so RS→HS key-confusion is mitigated by the library, but HS384/HS512 tokens signed with the same secret string would still verify on the HS256 paths. [UNTESTED]

Failure mapping: `verifyAccessToken` catch → `AuthError('Invalid or expired access token', 'INVALID_ACCESS_TOKEN', 401)` (:148); `verifyRefreshToken` catch → `AuthError('Invalid or expired refresh token', 'INVALID_REFRESH_TOKEN', 401)` (:157). Note the route handlers and middleware usually catch these and emit their own bodies (§4.2, §4.4).

### 1.7 Bearer-mode delivery (cross-check)

`sendTokens` (src/router/auth.router.ts:399-406): when `req.headers['x-auth-strategy'] === 'bearer'` (:390-392) the response is `{ success: true, accessToken, refreshToken }` **top-level** and **no cookies are set**; otherwise cookies are set and the body is `{ success: true }`. Pinned by tests/auth.router.test.ts:534-545 (login) and :566-577 (refresh; `set-cookie` asserted undefined). `POST /refresh` accepts `refreshToken` from the body first, cookie fallback (src/router/auth.router.ts:625-626), so cookie-mode refresh with an empty body works — matches the client contract. ✓ no mismatch.

---

## 2. Cookie serialization matrix (`src/services/token.service.ts:161-302`)

### 2.1 Name-prefix resolution — `getCookieName` (:161-172)

| Condition (from `config.cookieOptions`) | Resulting name |
|---|---|
| `secure` falsy (incl. unset) | `<name>` (plain) — :162 |
| `secure: true` AND (`path` unset or `'/'`) AND no `domain` | `__Host-<name>` — :166-169 |
| `secure: true` otherwise (custom path or domain set) | `__Secure-<name>` — :171 |

Tests: `__Host-` — tests/token.service.test.ts:191-200; `__Secure-` via path — :227-233; `__Secure-` via domain — :235-242; no prefix when insecure — :244-251.

### 2.2 `setCookie` enforcement (:182-193)

Common options (:175-180): `httpOnly: true`, `secure: cookieOptions?.secure ?? false`, `sameSite: cookieOptions?.sameSite ?? 'lax'`, `path: cookieOptions?.path ?? '/'`.

For a finalised `__Host-` name (:185-188): `domain` deleted, `path` forced to `'/'`, `secure` forced `true` — this **overrides even the refresh cookie's restricted path** (pinned with rationale by tests/token.service.test.ts:202-214). Otherwise `domain = config.cookieOptions?.domain` (:190).

### 2.3 The matrix

| Cookie (base name) | Set at | HttpOnly | Max-Age | Path | Secure / SameSite / Domain |
|---|---|---|---|---|---|
| `accessToken` | token.service.ts:195 | `true` | **`15 * 60 * 1000` ms — hardcoded 15 min** | `cookieOptions.path ?? '/'` | per §2.1/§2.2; SameSite `lax` default |
| `refreshToken` | token.service.ts:199-202 | `true` | **`7 * 24 * 60 * 60 * 1000` ms — hardcoded 7 d** | `cookieOptions.refreshTokenPath ?? (config.apiPrefix ? apiPrefix + '/refresh' : '/auth/refresh')` (:197-198); forced `'/'` under `__Host-` | same |
| `csrf-token` | token.service.ts:205-208 (only if `config.csrf.enabled`) | **`false`** (:206) | `15 * 60 * 1000` ms | `cookieOptions.path ?? '/'` | same |
| `csrf-token` (init) | token.service.ts:212-230 (`initCsrfToken`) | **`false`** (:216) | `15 * 60 * 1000` ms (:220) | same rules incl. `__Host-` enforcement :222-228 | same |

- CSRF value: `generateSecureToken(16)` = **16 random bytes hex-encoded = 32 hex chars** (:205, :229; `crypto.randomBytes(bytes).toString('hex')` at :270-272). Default `generateSecureToken()` is 32 bytes / 64 hex chars (pinned tests/token.service.test.ts:48-53).
- Refresh-path defaulting responsibility: `createAuthRouter` writes it into the config at router creation — `config.cookieOptions.refreshTokenPath = cookieOptions?.refreshTokenPath ?? \`${options.apiPrefix || config.apiPrefix || '/auth'}/refresh\`` (src/router/auth.router.ts:460-464) — and `TokenService.setTokenCookies` independently mirrors the same fallback (token.service.ts:197-198) so direct service use behaves identically. Pinned: default `/auth/refresh` — tests/token.service.test.ts:65-70; derived from `apiPrefix` — :80-86; explicit path wins — :88-94.
- **[MISMATCH — comment vs code]** `AuthConfig.cookieOptions.refreshTokenPath` JSDoc claims "Defaults to `'/'`" (src/models/auth-config.model.ts:165-172). Code defaults it to `{apiPrefix}/refresh` as above. Code wins.
- **[MISMATCH-risk] Cookie Max-Age values ignore `accessTokenExpiresIn` / `refreshTokenExpiresIn`** — a config with `accessTokenExpiresIn: '1h'` still emits a 15-minute cookie, and a 30-day refresh expiry still emits a 7-day cookie. JWT `exp` and cookie lifetime diverge for any non-default config. [UNTESTED]
- CSRF auto-init: router-level middleware sets the csrf cookie on any auth-router request when no `csrf-token` cookie variant is present (src/router/auth.router.ts:530-538). **There is no `/csrf` endpoint** (no such route registered anywhere in `src/`) — matches the client contract. csrf cookie is JS-readable (`httpOnly: false`) — matches. Tests: tests/token.service.test.ts:123-130, :157-169, :284-353.

### 2.4 `clearTokenCookies` (:232-268)

Clears **all name variants defensively**: `possibleNames = new Set([primaryName, '__Host-<name>', '__Secure-<name>', '<name>'])` (:243) — up to 3 distinct `clearCookie` calls per logical cookie (4 entries, Set-deduped). Per variant: `__Host-` cleared with `path: '/'`, `secure: true`, no domain (:247-250); others get `domain: config?.cookieOptions?.domain` (:252). Cleared cookies and options:

- `accessToken` (:258) — path `cookieOptions.path ?? '/'`.
- `refreshToken` (:261-263) — path mirrors the set-time refresh-path resolution (`refreshTokenPath ?? apiPrefix/refresh ?? '/auth/refresh'`), because clearing requires exact name+path+domain match (comments :241, :260).
- `csrf-token` (:265-267) — **only when `config?.csrf?.enabled`**.

Config is optional (`config?`): calling with no config clears plain+prefixed `accessToken`/`refreshToken` with defaults but **not** csrf-token. Tests: all variants cleared — tests/token.service.test.ts:269-282; `__Host-refreshToken` cleared with `path=/` — :216-225; refresh-path parity — :96-114; csrf variants — :335-343.

### 2.5 `extractTokenFromCookie` (:274-302)

Read priority: **`__Host-<name>` → `__Secure-<name>` → `<name>`** (:276-280). Sources: `req.cookies` (cookie-parser) first (:282-287); fallback manual parse of the raw `Cookie` header, splitting on `;` / first `=`, `decodeURIComponent` on values (:289-296), then the same priority order again (:298-300); returns `null` when absent (:301). Matches the client contract's cookie read priority exactly. Tests: priority — tests/token.service.test.ts:253-267; header fallback — :139-143; `req.cookies` — :145-149; null — :151-155.

---

## 3. JWKS

### 3.1 Document shape (`src/services/jwks.service.ts`)

`JWK` interface (:5-12) and `publicKeyToJwk` (:168-179) produce exactly:

```json
{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "<kid>", "n": "<base64url>", "e": "<base64url>" }
```

`buildJwksDocument(publicKeyPem, kid = 'provisioner-key-1')` → `{ "keys": [ <single JWK> ] }` (:184-186). Default kid pinned by tests/jwks.service.test.ts:67-71; field shape by :42-50; PEM↔JWK round-trip by :80-89.

### 3.2 Endpoint registration (`src/router/auth.router.ts:471-505`)

- Registered only when `config.idProvider?.privateKey || config.idProvider?.enabled === true` (:473), **before any auth middleware — always public** (comment :472; it is the first route registered).
- Path: `idp.jwksPath ?? '/.well-known/jwks.json'` (:475). Custom path honored (pinned tests/jwks.service.test.ts:318-338).
- Keypair initialised at router-creation time (:480-486) and the JWKS document is **built once** (:488) — key rotation requires recreating the router.
- Handler (:490-504):
  - CORS: `idp.jwksCorsOrigins ?? '*'` → `Access-Control-Allow-Origin: *` (:492-494); when a list/string is configured, the request `Origin` is echoed back only if it matches (:496-500), otherwise **no ACAO header at all**. [UNTESTED — no test asserts CORS headers]
  - `Cache-Control: public, max-age=3600` (:502). [UNTESTED]
  - Body: the prebuilt JWKS document as JSON (:503). Pinned (status 200, `keys[0].kty === 'RSA'`, `alg === 'RS256'`, `kid === 'provisioner-key-1'`) by tests/jwks.service.test.ts:293-316.
- **There is NO `/.well-known/openid-configuration`.** A repo-wide grep for `openid-configuration` returns zero hits in `src/` and `tests/`; the only `.well-known` path anywhere is the JWKS one. Confirmed.

### 3.3 JwksClient — SWR caching (`src/services/jwks.service.ts:29-141`)

- Defaults: `cacheTtl = 3_600_000` ms (:40), `fetchTimeout = 5000` ms (:41).
- `getJwks()` (:49-92): fresh cache (now < expiry) returned directly (:51-53); in-flight fetch deduped via `fetchPromise` (:56-58); **stale-while-revalidate**: with a stale cache, returns the stale doc immediately and refreshes in background, a failed background refresh silently keeps the stale doc (:62-76); no cache → awaits the initial fetch (:79-91).
- `getKey(kid)` → `doc.keys.find(k => k.kid === kid) ?? null` (:95-98). `invalidateCache()` nulls doc/expiry/fetchPromise (:101-105).
- `_fetch` rejects on non-200, timeout, or a body without a `keys` array (:107-140).

### 3.4 Unknown-kid invalidation retry (`src/services/token.service.ts:102-133`)

`verifyWithJwks`: decode unverified to read header `kid` (:105-113; missing/garbled → `INVALID_TOKEN` 401). If `getKey(kid)` is null → `invalidateCache()` and retry **once** (:117-124, supports key rotation); still null → `AuthError('Unknown signing key', 'INVALID_TOKEN', 401)` (:121). Verification pins `['RS256']` and checks `iss` equality when `expectedIssuer` given (:135-141). Any non-AuthError failure is normalized to `INVALID_TOKEN` 401 (:129-132). Tests: unknown kid → 401 — tests/jwks-auth.middleware.test.ts:152-173; wrong issuer → 401 — :107-125; expired → 401 — :127-150.

Resource-server middleware keeps one module-level `JwksClient` per `jwksUrl`, shared across middleware instances (src/middleware/jwks-auth.middleware.ts:10-23).

---

## 4. Error catalog

### 4.1 Error body shape

`AuthError` (src/models/errors.ts:1-11): `message`, `code: string`, `statusCode: number = 401`, optional `data?: Record<string, unknown>`. **`data` is never serialized into any HTTP response.**

Emitters that translate AuthError → HTTP:
- `handleError` (src/router/auth.router.ts:189-196): `res.status(err.statusCode).json({ error: err.message, code: err.code })`; non-AuthError → `500 { "error": "Internal server error" }` (no `code`).
- Router-level catch-all error middleware (src/router/auth.router.ts:1682-1689): identical mapping.
- API-key middleware (src/middleware/api-key.middleware.ts:48-54): identical mapping.

So the canonical error body is `{ "error": "<message>", "code": "<CODE>" }`; unexpected errors are `{ "error": "Internal server error" }` **without** `code`.

### 4.2 Complete `new AuthError(` table (all 38 sites in `src/`)

| `code` | message | HTTP | Emission site |
|---|---|---|---|
| `CSRF_INVALID` | CSRF validation failed | 403 | src/router/auth.router.ts:1493 (`/link-request` manual check) |
| `EMAIL_REQUIRED` | email is required | 400 | src/router/auth.router.ts:1498 |
| `UNAUTHORIZED` | Authentication required | 401 | src/router/auth.router.ts:1515 |
| `UNAUTHORIZED` | Authentication required or no pending link found | 401 | src/router/auth.router.ts:1519 |
| `USER_NOT_FOUND` | Target user not found | 404 | src/router/auth.router.ts:1522 |
| `IDP_NOT_ENABLED` | IdP mode is not enabled | 500 | src/services/token.service.ts:44 |
| `INVALID_TOKEN` | Invalid token format | 401 | src/services/token.service.ts:107 |
| `INVALID_TOKEN` | Token missing kid header | 401 | src/services/token.service.ts:112 |
| `INVALID_TOKEN` | Unknown signing key | 401 | src/services/token.service.ts:121 |
| `INVALID_TOKEN` | Invalid or expired token | 401 | src/services/token.service.ts:131 |
| `INVALID_TOKEN` | Token issuer mismatch | 401 | src/services/token.service.ts:138 |
| `INVALID_ACCESS_TOKEN` | Invalid or expired access token | 401 | src/services/token.service.ts:148 |
| `INVALID_REFRESH_TOKEN` | Invalid or expired refresh token | 401 | src/services/token.service.ts:157 |
| `INVALID_CREDENTIALS` | Invalid credentials | 401 | src/strategies/local/local.strategy.ts:21, :24, :28 (user missing / no password / bad password — same message on purpose) |
| `EMAIL_NOT_VERIFIED` | Email address is not verified | 403 | src/strategies/local/local.strategy.ts:39 (strict mode) |
| `EMAIL_VERIFICATION_REQUIRED` | Email verification required | 403 | src/strategies/local/local.strategy.ts:43 (lazy mode, past deadline) |
| `EMAIL_NOT_CONFIGURED` | Email not configured | 500 | src/strategies/magic-link/magic-link.strategy.ts:13 |
| `NOT_IMPLEMENTED` | UserStore does not implement findByMagicLinkToken | 500 | src/strategies/magic-link/magic-link.strategy.ts:38 |
| `INVALID_MAGIC_LINK` | Invalid magic link token | 401 | src/strategies/magic-link/magic-link.strategy.ts:42, :45 |
| `MAGIC_LINK_EXPIRED` | Magic link token has expired | 401 | src/strategies/magic-link/magic-link.strategy.ts:48 |
| `API_KEY_MISSING` | API key is required | 401 | src/strategies/api-key/api-key.strategy.ts:80 |
| `API_KEY_INVALID` | Invalid API key | 401 | src/strategies/api-key/api-key.strategy.ts:92 |
| `API_KEY_REVOKED` | API key has been revoked | 401 | src/strategies/api-key/api-key.strategy.ts:98 |
| `API_KEY_EXPIRED` | API key has expired | 401 | src/strategies/api-key/api-key.strategy.ts:104 |
| `API_KEY_IP_BLOCKED` | IP address not allowed for this API key | 403 | src/strategies/api-key/api-key.strategy.ts:112 |
| `API_KEY_INSUFFICIENT_SCOPE` | API key missing required scopes: `<csv>` (dynamic) | 403 | src/strategies/api-key/api-key.strategy.ts:123-127 |
| `OAUTH_NOT_CONFIGURED` | Google OAuth not configured | 500 | src/strategies/oauth/google.strategy.ts:16 |
| `OAUTH_NOT_CONFIGURED` | GitHub OAuth not configured | 500 | src/strategies/oauth/github.strategy.ts:16 |
| `OAUTH_TOKEN_EXCHANGE_FAILED` | Google token exchange failed | 401 | src/strategies/oauth/google.strategy.ts:47 |
| `OAUTH_TOKEN_EXCHANGE_FAILED` | GitHub token exchange failed | 401 | src/strategies/oauth/github.strategy.ts:44 |
| `OAUTH_TOKEN_EXCHANGE_FAILED` | `${name}` token exchange failed (dynamic) | 401 | src/strategies/oauth/generic-oauth.strategy.ts:137 |
| `OAUTH_PROFILE_FAILED` | Failed to get Google user profile | 401 | src/strategies/oauth/google.strategy.ts:56 |
| `OAUTH_PROFILE_FAILED` | Failed to get GitHub user profile | 401 | src/strategies/oauth/github.strategy.ts:58 |
| `OAUTH_PROFILE_FAILED` | Failed to get `${name}` user profile (dynamic) | 401 | src/strategies/oauth/generic-oauth.strategy.ts:148 |
| `SMS_NOT_CONFIGURED` | SMS not configured | 500 | src/strategies/sms/sms.strategy.ts:12 |

(Counts per file: auth.router.ts 5, token.service.ts 8, local 5, magic-link 5, api-key 6, google 3, github 3, generic-oauth 2, sms 1 = 38 — matches the grep count.)

### 4.3 Coded errors emitted as plain objects (not AuthError)

| `code` | HTTP | Body / site |
|---|---|---|
| `2FA_SETUP_REQUIRED` | 403 | `{ requires2FASetup: true, tempToken, code }` — src/router/auth.router.ts:568. Test: tests/new-features.test.ts:651-655 |
| `SESSION_REVOKED` | 401 | `{ error: 'Session has been revoked', code }` — src/router/auth.router.ts:638 (`/refresh`, `checkOn !== 'none'`); src/middleware/auth.middleware.ts:50 (`checkOn === 'allcalls'`). Tests: tests/auth.router.test.ts:1162-1172; tests/auth.middleware.test.ts:177. Matches the client contract (clients skip refresh and logout immediately). ✓ |
| `CSRF_INVALID` | 403 | `{ error: 'CSRF token validation failed', code }` — src/middleware/auth.middleware.ts:39 (double-submit: cookie via §2.5 priority vs `req.headers['x-csrf-token']`; skipped for GET/HEAD/OPTIONS and for bearer requests, :34-38). Tests: tests/auth.middleware.test.ts:58-99 |
| `2FA_REQUIRED` | 403 | 'Cannot disable 2FA: required for your account' — src/router/auth.router.ts:886; '…required by system policy' — :893 |
| `PASSWORD_REQUIRED` | 403 | 'You must set a password before you can change your email address.' — src/router/auth.router.ts:1016-1019 |
| `TEMP_TOKEN_REQUIRED` | 400 | 'tempToken is required for 2FA mode' — src/router/auth.router.ts:1089, :1136, :1194, :1257. Tests: tests/auth.router.test.ts:441-452, :467-478 |
| `INVALID_TEMP_TOKEN` | 401 | 'Invalid or expired temp token' — src/router/auth.router.ts:1096, :1144, :1201, :1264. Test: tests/auth.router.test.ts:454-465 |
| `TOKEN_MISMATCH` | 401 | 'Token mismatch' (magic-link 2FA: link user ≠ tempToken user) — src/router/auth.router.ts:1151 |
| `SMS_NOT_CONFIGURED` | 500 | 'SMS is not configured' — src/router/auth.router.ts:1179 (route-level duplicate of the strategy AuthError) |
| `PHONE_NOT_SET` | 400 | 'User does not have a phone number configured' — src/router/auth.router.ts:1228 |
| `NOT_IMPLEMENTED` | 500 | 'UserStore does not implement updateAccountLinkToken' — src/router/auth.router.ts:1485; '…account-link methods' — :1547 |
| `TOKEN_REQUIRED` | 400 | 'token is required' — src/router/auth.router.ts:1552 |
| `INVALID_LINK_TOKEN` | 400 | 'Invalid account-link token' — src/router/auth.router.ts:1557 |
| `LINK_TOKEN_EXPIRED` | 400 | 'Account-link token has expired' — src/router/auth.router.ts:1561 |
| `INVALID_STATE` | 400 | 'No pending email found for this link token' — src/router/auth.router.ts:1565 |
| `INVALID_TOKEN` | 401 | 'Invalid or expired access token' — src/middleware/jwks-auth.middleware.ts:77 (resource-server middleware catch-all) |

### 4.4 Code-less error bodies clients must not pattern-match on `code`

- `createAuthMiddleware`: `403 { error: 'No access token provided' }` (src/middleware/auth.middleware.ts:30) and `403 { error: 'Invalid or expired access token' }` (:63) — **no `code`**, and note both are **403**, not 401.
- `POST /refresh`: `401 { error: 'No refresh token provided' }` (src/router/auth.router.ts:628) and `401 { error: 'Invalid refresh token' }` (:645) — **no `code`**. `SESSION_REVOKED` (:638) is the **only** coded 401 on the refresh path; clients distinguishing revocation from ordinary refresh failure by `code` are compatible. ✓
- `jwks-auth.middleware`: `403 { error: 'No access token provided' }` (src/middleware/jwks-auth.middleware.ts:57) — no code.
- The entire admin router emits plain `{ error: '<msg>' }` bodies without `code` (e.g. src/router/admin.router.ts:193, :198, :328, :388, :784), and admin `/login` failure is `401 { error: 'Invalid credentials' }` (:577).

### 4.5 Cross-checks against the client contract (this section's scope)

- CSRF header `X-CSRF-Token` (read as `req.headers['x-csrf-token']`, src/middleware/auth.middleware.ts:37) ✓; cookie priority `__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token` (token.service.ts:276-280) ✓; JS-readable (`httpOnly: false`, :206/:216) ✓; no `/csrf` endpoint (auto-init middleware instead, auth.router.ts:530-538) ✓.
- `SESSION_REVOKED` 401 body shape ✓ (§4.3).
- Bearer login/refresh return top-level `accessToken`/`refreshToken` ✓; cookie-mode refresh works with an empty body ✓ (§1.7).
- CSRF cookie Max-Age is 15 min; if it expires, protected state-changing calls fail `CSRF_INVALID` until any auth-router request re-initializes the cookie (auth.router.ts:530-538). Clients that hit `/refresh` first (an auth-router route) recover automatically. [UNTESTED]
