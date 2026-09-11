# Wire contract — awesome-node-auth v1.9.0 (reference)

This document is the reference wire contract of `awesome-node-auth` v1.9.0 — the contract the Lambda port (`awesome-lambda-auth`) is **forbidden to break**. It was extracted from source pinned to commit `cc01e997` and adversarially verified against the test suite and the client contracts (ng-awesome-node-auth, awesome-node-auth-flutter, served `auth.js`); see `recon-manifest.md` for extraction provenance. Every status code, body shape, header, cookie attribute, and error code below is normative. Markers: `[MISMATCH]` flags divergences between the reference implementation and its clients/docs (reproduce them, do not fix them, unless a phase decision says otherwise); `[UNTESTED]` flags behaviors with no test pin (still normative — grounded in source); `CORRECTED(verify)` records where adversarial verification overturned an earlier claim. All `file:line` references point into awesome-node-auth @ `cc01e997`.

## Table of contents

- [Contract hard points](#contract-hard-points)
- [1. Core auth, profile, sessions, account deletion, auth middleware](#1-core-auth-profile-sessions-account-deletion-auth-middleware)
- [2. Password management, email verification, email change](#2-password-management-email-verification-email-change)
- [3. Magic link, SMS OTP, TOTP 2FA](#3-magic-link-sms-otp-totp-2fa)
- [4. OAuth and account linking](#4-oauth-and-account-linking)
- [5. Admin router (complete surface)](#5-admin-router-complete-surface)
- [6. Tools router, SSE, UI router](#6-tools-router-sse-ui-router)
- [7. Token claim sets, cookie serialization matrix, JWKS, error catalog](#7-token-claim-sets-cookie-serialization-matrix-jwks-error-catalog)

## Contract hard points

The client-pinned invariants. Break any of these and at least one shipped client stops working. Full detail in the referenced sections.

1. **CSRF header is `X-CSRF-Token`, and there is no `/csrf` endpoint.** Double-submit: the `csrf-token` cookie (JS-readable, `httpOnly:false`, 32 hex chars, 15 min Max-Age) must strictly equal the `X-CSRF-Token` header, enforced only for cookie-authenticated non-GET/HEAD/OPTIONS requests through `authMiddleware`; failure is `403 {"error":"CSRF token validation failed","code":"CSRF_INVALID"}` (auth.middleware.ts:33-42). The cookie is distributed solely by router-level auto-init middleware (auth.router.ts:530-538). — §1 (0.4, 1.2), §7 (2.3, 4.3)
2. **`SESSION_REVOKED` is the fast-logout signal.** `401 {"error":"Session has been revoked","code":"SESSION_REVOKED"}` is emitted at exactly two sites: `POST /refresh` when `checkOn !== 'none'` (auth.router.ts:635-641) and `createAuthMiddleware` when built with a sessionStore and `checkOn === 'allcalls'` (auth.middleware.ts:47-53). Clients skip token refresh and log out immediately on it. — §1 (1.4), §7 (4.3)
3. **Empty-body refresh works in cookie mode.** `POST /refresh` reads `req.body?.refreshToken` (optional-chained — a missing/empty body is safe) then falls back to the `refreshToken` cookie in any prefix variant (auth.router.ts:625-626). — §1 (3.3)
4. **`GET /me` is unwrapped.** The profile object is the top-level response body — no envelope; rebuilt from the DB user via `buildPayload`, never containing `sid`/`iat`/`exp` or sensitive user fields (auth.router.ts:656-680). — §1 (3.4)
5. **`GET /sessions` returns `{"sessions":[...]}`.** Wrapped in a `sessions` key (auth.router.ts:752). — §1 (3.9)
6. **`GET /linked-accounts` returns `{"linkedAccounts":[...]}`.** Wrapped object, not a bare array (auth.router.ts:1461); the Flutter client's bare-array expectation is a known client [MISMATCH], not license to change the server shape. — §4
7. **Magic-link/SMS `mode` is optional and defaults to login.** All four routes branch on the literal check `mode === '2fa'`; absent, `"login"`, or any other value takes the login branch — Angular's explicit `mode:"login"` and Flutter's omitted `mode` are equivalent (auth.router.ts:1087, :1134, :1192, :1255). — §3
8. **Bearer mode is opt-in via `X-Auth-Strategy: bearer`.** Exact, case-sensitive value match, and the only place the header is read is `sendTokens`/`issueTokens` (auth.router.ts:390-392): bearer responses are `200 {"success":true,"accessToken":"<jwt>","refreshToken":"<jwt>"}` top-level with **no Set-Cookie**; cookie mode (default) sets cookies and returns `200 {"success":true}`. — §1 (2), §7 (1.7)
9. **Cookie name prefixes are contract.** Write side: `secure` falsy → bare name; `secure:true` + root/unset path + no domain → `__Host-<name>`; `secure:true` otherwise → `__Secure-<name>` (token.service.ts:161-172). Read side, everywhere: priority `__Host-<name>` → `__Secure-<name>` → `<name>`, including the raw `Cookie`-header fallback (token.service.ts:274-302). — §7 (2)
10. **SSE lives at `GET <apiPrefix>/tools/stream`.** Clients hardcode `${apiPrefix}/tools/stream`; the host app must mount `createToolsRouter` there (the library never auto-mounts it). Every frame carries an explicit `event:` line (named events — never the default `message` event) with the payload re-keyed under `rawData`; `?token=` is promoted to `Authorization: Bearer` for `EventSource` clients. — §6 (2.3, 3, 6.1)

---

## 1. Core auth, profile, sessions, account deletion, auth middleware

Wire contract extracted from `awesome-node-auth` @ cc01e997, grounded exclusively in `src/router/auth.router.ts`, `src/middleware/auth.middleware.ts`, `src/services/token.service.ts`, `src/models/errors.ts`, `src/strategies/local/local.strategy.ts` and pinned by `tests/auth.router.test.ts`, `tests/auth.middleware.test.ts`, `tests/new-features.test.ts`. Covers POST /login, POST /logout, POST /refresh, GET /me, PATCH /profile, POST /add-phone, POST /register, POST /sessions/cleanup, GET /sessions, DELETE /sessions/:handle, DELETE /account, plus the full `createAuthMiddleware` contract, `issueTokens()`/`sendTokens()` behavior in cookie vs bearer mode, and the login 2FA temp-token branch. All paths are relative to the router mount point (`options.apiPrefix || config.apiPrefix || '/auth'`, src/router/auth.router.ts:253-255). Client-contract mismatches are flagged `[MISMATCH]`; behaviors with no test coverage are flagged `[UNTESTED]`.

---

### 0. Shared conventions

#### 0.1 Error envelope (`handleError`)

src/router/auth.router.ts:189-196. Every route `catch` funnels here:

- `AuthError` (src/models/errors.ts:1-11) → status = `err.statusCode` (default 401), body `{ "error": <message>, "code": <code> }`.
- Any other error → `500 { "error": "Internal server error" }` (**no `code` field**), plus a `console.error('[node-auth] Unhandled error:', err)`.

#### 0.2 Cookie name resolution (`__Host-` / `__Secure-`)

`TokenService.getCookieName` (src/services/token.service.ts:161-172):

| Condition | Resulting name |
|---|---|
| `cookieOptions.secure` falsy (default) | bare name (`accessToken`, `refreshToken`, `csrf-token`) |
| `secure: true` AND (`cookieOptions.path` unset or `'/'`) AND no `cookieOptions.domain` | `__Host-<name>` |
| `secure: true` otherwise | `__Secure-<name>` |

When the resolved name starts with `__Host-`, the write path force-overrides: `domain` deleted, `path = '/'`, `secure = true` (token.service.ts:185-188, 222-225, 247-250).

#### 0.3 Cookie read priority

`extractTokenFromCookie` (src/services/token.service.ts:274-302) tries, in order: `__Host-<name>` → `__Secure-<name>` → `<name>`; first from `req.cookies` (cookie-parser), then by manually parsing the raw `Cookie` header (raw-header fallback pinned by tests/auth.middleware.test.ts:44-52). This matches the client contract's read priority (`__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token`). ✓ no mismatch.

#### 0.4 Cookies written by `setTokenCookies`

src/services/token.service.ts:174-210. Common attributes: `HttpOnly: true`, `Secure: config.cookieOptions?.secure ?? false`, `SameSite: config.cookieOptions?.sameSite ?? 'lax'`, `Path: config.cookieOptions?.path ?? '/'`, `Domain: config.cookieOptions?.domain` (only for non-`__Host-` names).

| Cookie | Extra attributes | Notes |
|---|---|---|
| `accessToken` (resolved per §0.2) | `Max-Age: 900000 ms` (15 min, **hardcoded** at token.service.ts:195) | HttpOnly |
| `refreshToken` (resolved per §0.2) | `Max-Age: 604800000 ms` (7 d, **hardcoded** at :200), `Path: config.cookieOptions.refreshTokenPath` — the router pre-fills this default to `` `${options.apiPrefix || config.apiPrefix || '/auth'}/refresh` `` at router creation (auth.router.ts:461-464); token.service's own fallback is `config.apiPrefix ? `${apiPrefix}/refresh` : '/auth/refresh'` (:197-198) | HttpOnly |
| `csrf-token` (resolved per §0.2) — only when `config.csrf.enabled` | `httpOnly: false` (**JS-readable** — matches client contract ✓), `Max-Age: 900000 ms`, value = `generateSecureToken(16)` = 32 hex chars (:204-209, 270-272) | Rotated on every cookie-mode login/refresh |

- **[MISMATCH] (code vs comment)** `auth-config.model.ts:166-172` documents `refreshTokenPath` as "Defaults to `'/'`"; the code defaults it to `<apiPrefix>/refresh` (auth.router.ts:461-464). Code wins.
- **Caveat**: cookie `Max-Age` values (15 m / 7 d) do **not** track `accessTokenExpiresIn`/`refreshTokenExpiresIn` (JWT sign defaults `'15m'`/`'7d'`, token.service.ts:23,28). Configuring longer token lifetimes leaves cookies expiring earlier. [UNTESTED]
- **Caveat**: in `__Host-` mode the refresh cookie's scoped path is discarded — `getCookieName` only inspects `cookieOptions.path`, so `refreshToken` becomes `__Host-refreshToken` and the write path then forces `Path=/` (token.service.ts:185-188), losing the `/auth/refresh` path scoping. [UNTESTED]

#### 0.5 `clearTokenCookies`

src/services/token.service.ts:232-268. For each of `accessToken`, `refreshToken` (with the refresh path from §0.4), and `csrf-token` (only when `config.csrf.enabled`), it clears **all four** name variants: resolved-primary, `__Host-<name>`, `__Secure-<name>`, and bare `<name>`, with matching path/domain rules per variant (`__Host-` variants cleared with `Path=/`, no Domain).

#### 0.6 Router-level middleware (applies to every route below)

- **Dynamic CORS** (only when `options.cors.origins` non-empty): echoes allowed `Origin`, sets `Access-Control-Allow-Credentials: true`, `Access-Control-Allow-Methods: GET,POST,PUT,PATCH,DELETE,OPTIONS`, `Access-Control-Allow-Headers: Content-Type,Authorization,X-CSRF-Token,X-Api-Key`, always `Vary: Origin`; `OPTIONS` short-circuits to `204` (auth.router.ts:513-527).
- **CSRF auto-init** (only when `config.csrf.enabled`): on any request lacking a readable `csrf-token` cookie (any prefix variant), sets a fresh one via `initCsrfToken` — `httpOnly: false`, `Max-Age: 900000`, name per §0.2, value 32 hex chars (auth.router.ts:530-538; token.service.ts:212-230). Pinned by tests/auth.router.test.ts:1019-1044 (set when enabled) and :1046-1070 (absent when disabled). **There is no `GET /csrf` endpoint anywhere in src/** (grep for `/csrf` route: no matches) — the auto-init cookie is the only distribution mechanism. Matches client contract ("no /csrf endpoint") ✓.
- **Resource-server gating**: when `config.resourceServer.enabled === true` (auth.router.ts:510), `/login`, `/logout`, `/refresh`, `/register`, `/forgot-password` etc. are **not mounted** (each guarded by `if (!isResourceServer)` — :541, :590, :622, :713). `/me`, `/profile`, `/add-phone`, `/sessions*`, `DELETE /account` are always mounted.
- **Rate limiter**: `options.rateLimiter`, when provided, is prepended to every route in this section (`...rl`, auth.router.ts:468).

---

### 1. `createAuthMiddleware` — src/middleware/auth.middleware.ts

Signature: `createAuthMiddleware(config: AuthConfig, sessionStore?: ISessionStore): RequestHandler` (auth.middleware.ts:17).

#### 1.1 Token extraction order

1. `Authorization` header starting with exactly `'Bearer '` → token = substring(7), `usingBearer = true` (auth.middleware.ts:20-25). Pinned: tests/auth.middleware.test.ts:117-126.
2. Else cookie `accessToken` (priority `__Host-` > `__Secure-` > bare, incl. raw-header fallback) (auth.middleware.ts:27). Pinned: tests/auth.middleware.test.ts:16-26, 44-52.
3. No token → **`403 { "error": "No access token provided" }`** (auth.middleware.ts:29-32). Pinned: tests/auth.middleware.test.ts:28-34.

#### 1.2 CSRF double-submit enforcement matrix

auth.middleware.ts:33-42. Enforced **only** when ALL of: token came from cookie (`!usingBearer`), `config.csrf.enabled`, and method ∉ `['GET','HEAD','OPTIONS']`.

| Auth mode | Method | CSRF check |
|---|---|---|
| Cookie | GET / HEAD / OPTIONS | skipped |
| Cookie | POST / PATCH / DELETE / PUT | required: cookie `csrf-token` (any prefix variant) must exist, header `X-CSRF-Token` (read as `req.headers['x-csrf-token']`, :37) must exist, and be strictly equal |
| Bearer (`Authorization` header) | any | skipped entirely (auth.middleware.ts:35) |
| any, `csrf.enabled` falsy | any | skipped |

Failure → **`403 { "error": "CSRF token validation failed", "code": "CSRF_INVALID" }`** (auth.middleware.ts:39). Pinned: match passes (tests/auth.middleware.test.ts:58-69); missing header 403 `CSRF_INVALID` (:71-79); mismatched header 403 (:81-92); missing cookie 403 (:94-104); disabled → skipped (:106-115); bearer skip (:128-138). Header name matches client contract `X-CSRF-Token` ✓.

Note: the test helper drives the middleware with `req.method` undefined, which is not in `safeMethods`, so CSRF is enforced in those tests — i.e. the enforced branch is what's pinned; per-method skipping for GET is [UNTESTED] directly but unambiguous in code (:34-35).

#### 1.3 Token verification

`tokenService.verifyAccessToken` = `jwt.verify(token, config.accessTokenSecret)` (token.service.ts:143-150). Any failure inside the middleware's try → **`403 { "error": "Invalid or expired access token" }`** (auth.middleware.ts:62-64; note the middleware's own catch produces this body without a `code`). Pinned: tests/auth.middleware.test.ts:36-42.

**[MISMATCH] (client expectation risk)**: an *expired* access token yields **403** (not 401) with **no `code`** from every middleware-protected route. Clients that key their refresh-retry on HTTP 401 will never see 401 here; the only 401s in this section are `SESSION_REVOKED` and the /refresh route's own errors.

#### 1.4 Session `checkOn` modes and `SESSION_REVOKED` emission points

`config.session.checkOn?: 'allcalls' | 'refresh' | 'none'`, default `'refresh'` (src/models/auth-config.model.ts:393-395; default applied at auth.router.ts:634).

`{ "code": "SESSION_REVOKED" }` is emitted in **exactly two places** in src (grep-verified):

1. **Middleware** (auth.middleware.ts:47-53): only when a `sessionStore` was *passed to the middleware factory* AND the token payload has `sid` AND `checkOn === 'allcalls'`. Missing session → **`401 { "error": "Session has been revoked", "code": "SESSION_REVOKED" }`**. Pinned: tests/auth.middleware.test.ts:166-178 (revoked → 401 + code), :153-164 (present → pass), :180-191 (`checkOn:'refresh'` → `getSession` never called).
2. **POST /refresh route** (auth.router.ts:635-641): when `options.sessionStore` AND `payload.sid` AND `checkOn !== 'none'` (i.e. fires for both `'refresh'` and `'allcalls'`). Missing session → **`401 { "error": "Session has been revoked", "code": "SESSION_REVOKED" }`**. Pinned: tests/auth.router.test.ts:1162-1172.

**[MISMATCH] (dead config path)**: the router builds its own middleware as `createAuthMiddleware(config)` **without a sessionStore** (auth.router.ts:466). Consequently, on all router-mounted protected routes (`/me`, `/profile`, `/add-phone`, `/sessions`, `/sessions/:handle`, `/account`) the `'allcalls'` check **never runs** and `updateSessionLastActive` **never fires** — a revoked session keeps working against these routes until the access token expires. Middleware-emitted `SESSION_REVOKED` is only reachable through `AuthConfigurator.middleware({sessionStore})` / `createAuthMiddleware(config, sessionStore)` used on the host app's own routes (src/auth-configurator.ts:26-28). [UNTESTED at router level — the session-mode middleware tests construct the middleware directly with a store.]

#### 1.5 `updateSessionLastActive`

auth.middleware.ts:55-58: after successful token verification, if the factory received a `sessionStore` and payload has `sid`, calls `sessionStore.updateSessionLastActive(payload.sid)` on **every** authenticated request **regardless of `checkOn`** (including `'refresh'` and `'none'`); rejections swallowed via `.catch(() => {})`. Pinned: tests/auth.middleware.test.ts:193-202 (`allcalls`), :204-215 (`refresh` mode, non-blocking).

On success the middleware sets `req.user = payload` (the raw JWT claims incl. `sid`, custom claims) and calls `next()` (auth.middleware.ts:60-61).

---

### 2. `issueTokens()` / `sendTokens()` — cookie vs bearer mode

`isBearerRequest(req)`: `req.headers['x-auth-strategy'] === 'bearer'` — exact, case-sensitive value match on the (lowercased-by-Node) **`X-Auth-Strategy`** header; this is the **only** place in src the header is read (auth.router.ts:390-392, grep-verified; openapi.ts merely documents it).

`sendTokens` (auth.router.ts:399-406):
- **Bearer mode** → `200` JSON **`{ "success": true, "accessToken": "<jwt>", "refreshToken": "<jwt>" }`** (top-level tokens — matches native client contract ✓); **no Set-Cookie** from this path. Pinned: tests/auth.router.test.ts:534-545 (login), :566-577 (refresh).
- **Cookie mode** (default) → `setTokenCookies` per §0.4 then `200 { "success": true }`. Pinned: tests/auth.router.test.ts:94-99, :547-555 (`accessToken` absent from body).

`issueTokens(req, res, user, config, options, userStore, redirectTo?, oldSid?)` (auth.router.ts:412-451):
1. `payload = buildPayload(user, config)` — base claims `{ sub: user.id, email, role, loginProvider: user.loginProvider ?? 'local', isEmailVerified: ?? false, isTotpEnabled: ?? false }` merged with `config.buildTokenPayload(user)` custom claims (auth.router.ts:378-384). Custom-claim embedding pinned: tests/auth.router.test.ts:481-503 (login), :505-530 (refresh).
2. If `options.sessionStore`: `createSession({ userId, userAgent: req.headers['user-agent'], ipAddress: req.ip || req.socket.remoteAddress, expiresAt: now + parseExpiryMs(config.refreshTokenExpiresIn), createdAt: now })`, then `payload.sid = session.sessionHandle`; if `oldSid` given, `revokeSession(oldSid)` **after** the new session exists (rotation; errors swallowed) (auth.router.ts:425-439). Pinned: tests/auth.router.test.ts:1135-1151 (session created, `sid` embedded in JWT), :1174-1191 (rotation: old handle gone, exactly one new).
   - `parseExpiryMs` accepts `<num><ms|s|m|h|d|w>`, falls back to 7 d when absent/unparseable (auth.router.ts:357-372).
3. `generateTokenPair(payload, config)` — HS256 `jwt.sign`, `expiresIn` = `accessTokenExpiresIn ?? '15m'` / `refreshTokenExpiresIn ?? '7d'` (token.service.ts:17-31).
4. `userStore.updateRefreshToken(user.id, tokens.refreshToken, now + refreshExpiryMs)` — single stored refresh token per user (auth.router.ts:442-443).
5. `redirectTo` set (OAuth flows only, not this section's routes) → always cookies + `res.redirect`; else `sendTokens` (auth.router.ts:445-450).

---

### 3. Routes

#### 3.1 POST /login — auth.router.ts:541-585

- **Mounting**: skipped when resource-server mode (§0.6). **Auth gate**: none. **CSRF**: not checked (no authMiddleware).
- **Request body**: `{ email: string (required), password: string (required) }` (:543). Missing/unknown email or wrong password → `LocalStrategy.authenticate` throws `AuthError('Invalid credentials','INVALID_CREDENTIALS',401)` (src/strategies/local/local.strategy.ts:18-29) → **`401 { "error": "Invalid credentials", "code": "INVALID_CREDENTIALS" }`**. Pinned (status): tests/auth.router.test.ts:101-109.
- **Email-verification errors** (local.strategy.ts:31-47): mode = `config.emailVerificationMode ?? (requireEmailVerification ? 'strict' : 'none')`.
  - strict + unverified → **`403 { "error": "Email address is not verified", "code": "EMAIL_NOT_VERIFIED" }`** — pinned tests/new-features.test.ts:707-715, legacy-flag equivalence :726-734, tests/auth.router.test.ts:360-369.
  - lazy + unverified + `emailVerificationDeadline` in the past → **`403 { "error": "Email verification required", "code": "EMAIL_VERIFICATION_REQUIRED" }`** — pinned tests/new-features.test.ts:745-759. Lazy within grace / none-mode → login proceeds (:736-743, :761-768).
- **2FA challenge branch** (auth.router.ts:546-578): triggers when `(user.isTotpEnabled && user.totpSecret)` OR `user.require2FA`.
  - `available2faMethods` built as: `'totp'` if TOTP enabled; `'sms'` if `user.phoneNumber && config.sms`; `'magic-link'` if `config.email.sendMagicLink || config.email.mailer` (:556-559).
  - If `require2FA` but **zero** methods available → `tempToken` = access token signed with overridden expiries `accessTokenExpiresIn:'5m'`, `refreshTokenExpiresIn:'5m'` (:564-567) → **`403 { "requires2FASetup": true, "tempToken": "<jwt>", "code": "2FA_SETUP_REQUIRED" }`**. Pinned: tests/new-features.test.ts:651-658.
  - Otherwise → **`200 { "requiresTwoFactor": true, "tempToken": "<jwt 5m>", "available2faMethods": string[] }`** (:572-577) — note **200**, no cookies, identical in bearer and cookie mode (no tokens issued yet). Pinned: tests/auth.router.test.ts:208-219 (totp), :221-236 (sms), :238-252 (magic-link), tests/new-features.test.ts:660-683. The 5-minute tempToken lifetime is code-only [UNTESTED].
- **Success**: `updateLastLogin(user.id)` (:580) then `issueTokens` → §2 (cookie mode `200 {success:true}` + 3 cookies (2 if csrf disabled); bearer mode `200 {success:true, accessToken, refreshToken}` no cookies). Pinned: tests/auth.router.test.ts:94-99, :534-555.

#### 3.2 POST /logout — auth.router.ts:590-619

- **Mounting**: skipped in resource-server mode. **Auth gate**: *deliberately not* authMiddleware (comment :588-589) — a best-effort pre-handler reads the **cookie only**: `extractTokenFromCookie(req, 'accessToken')` (:592); if the token verifies, sets `req.user` and revokes `payload.sid` in `options.sessionStore` (errors swallowed) (:593-605). Invalid/expired/absent token does **not** block. **CSRF**: never checked.
- **Effects**: when `req.user.sub` known → `updateRefreshToken(sub, null, null)` (:609-611); always `clearTokenCookies` (§0.5) (:612).
- **Success**: **`200 { "success": true }`**. Pinned: tests/auth.router.test.ts:131-137 (status), :1153-1160 (session revoked by sid).
- **Error**: if the DB update throws, cookies are still cleared and `handleError` runs → typically `500 { "error": "Internal server error" }` (:614-618). [UNTESTED]
- **[MISMATCH] Bearer mode**: the pre-handler ignores the `Authorization` header entirely (:592 reads cookie only), so for a native/bearer client logout returns `200 {success:true}` but **neither the stored refresh token nor the stateful session is revoked server-side**. Clients treating logout as server-side invalidation (Flutter bearer flow) get a silent no-op. [UNTESTED — no test exercises bearer logout.]
- Angular no-retry cross-check: `/login`, `/logout`, `/refresh`, `/register` from the no-retry substring list are all in this section; nothing router-side conflicts with the client skipping retries on them (informational).

#### 3.3 POST /refresh — auth.router.ts:622-653

- **Mounting**: skipped in resource-server mode. **Auth gate**: none (token is the credential). **CSRF**: not checked (no authMiddleware) — an empty-body cookie-mode call needs no `X-CSRF-Token`.
- **Token acceptance order**: `req.body?.refreshToken` (optional-chained, so a missing/empty body is safe — **empty body works in cookie mode** ✓ client contract) then cookie `refreshToken` (any prefix variant) (:625-626).
- **Errors** (all 401):
  - No token anywhere → **`401 { "error": "No refresh token provided" }`** — **no `code`** (:627-630). [UNTESTED]
  - JWT invalid/expired → via `verifyRefreshToken` (token.service.ts:152-159) → **`401 { "error": "Invalid or expired refresh token", "code": "INVALID_REFRESH_TOKEN" }`**. Pinned (status): tests/auth.router.test.ts:148-151.
  - Session check (default `checkOn:'refresh'`; skipped only for `'none'`; requires `options.sessionStore` and `payload.sid`): missing session → **`401 { "error": "Session has been revoked", "code": "SESSION_REVOKED" }`** (:634-641). Pinned: tests/auth.router.test.ts:1162-1172. Matches client contract (skip refresh, logout immediately) ✓.
  - `findById(payload.sub)` null OR `user.refreshToken !== refreshToken` (single stored token — an older rotated-out token is rejected) → **`401 { "error": "Invalid refresh token" }`** — **no `code`** (:643-647). [UNTESTED for the token-mismatch arm]
- **Success**: `issueTokens(..., oldSid = payload.sid)` → §2: new session created, old revoked (rotation), refresh token rotated in the user store. Cookie mode → `200 {success:true}` + fresh cookies (incl. rotated `csrf-token` when csrf enabled); bearer mode (`X-Auth-Strategy: bearer`) → `200 {success:true, accessToken, refreshToken}`, no Set-Cookie ✓ native contract. Pinned: tests/auth.router.test.ts:140-146 (cookie), :566-577 (bearer body → tokens in body), :1174-1191 (rotation).
- Note: the response *mode* depends solely on the `X-Auth-Strategy` header, not on where the token came from — a client sending `{refreshToken}` in the body **without** the header receives cookies and a body without tokens. [UNTESTED]

#### 3.4 GET /me — auth.router.ts:656-680

- **Auth gate**: `authMiddleware` (§1). **CSRF**: exempt (GET is a safe method).
- **Errors**: middleware 403s per §1; user deleted after token issued → **`404 { "error": "User not found" }`** (:659-662). Pinned: tests/new-features.test.ts:974-983.
- **Success `200`**: the profile object **UNWRAPPED** (top-level, no envelope — matches client contract ✓): `buildPayload(user, config)` re-computed from the **DB user** (not the presented token): `{ "sub", "email", "role", "loginProvider" (default "local"), "isEmailVerified" (default false), "isTotpEnabled" (default false), ...customClaims }` (:663-666, :378-384). **No `sid`, no `iat`/`exp`** (payload is rebuilt, never signed). Additional fields only when stores configured: `"metadata"` (object) when `options.metadataStore` (:667-669); `"roles"` (string[]) and `"permissions"` (string[]) when `options.rbacStore` (:670-675). Sensitive/extra user fields (`id`, `password`, `refreshToken`, `totpSecret`, `resetToken`, `firstName`, `lastName`, `phoneNumber`) are **not** present. Pinned: tests/new-features.test.ts:891-915 (claims + omissions), :917-933 (custom claims), :935-951 (metadata), :953-972 (roles/permissions); tests/auth.router.test.ts:112-128; bearer-header access pinned :557-564.
- **Bearer mode**: identical response; only the credential transport differs.

#### 3.5 PATCH /profile — auth.router.ts:683-695 [UNTESTED — no test in tests/ exercises this route]

- **Auth gate**: `authMiddleware`. **CSRF**: enforced in cookie mode (PATCH is state-changing).
- Store capability gate: `userStore.updateProfile` missing → **`501 { "error": "UserStore does not implement updateProfile" }`** (:685-688).
- **Request body**: `{ firstName?: string | null, lastName?: string | null }` (both optional/nullable; passed through verbatim to `updateProfile(sub, {firstName, lastName})` — interface at src/interfaces/user-store.interface.ts:136) (:689-690).
- **Success**: **`200 { "success": true }`** (:691).

#### 3.6 POST /add-phone — auth.router.ts:698-710 [UNTESTED]

- **Auth gate**: `authMiddleware`. **CSRF**: enforced in cookie mode.
- `userStore.updatePhoneNumber` missing → **`501 { "error": "UserStore does not implement updatePhoneNumber" }`** (:700-703).
- **Request body**: `{ phoneNumber: string | null }` (null clears; interface src/interfaces/user-store.interface.ts:142) (:704-705).
- **Success**: **`200 { "success": true }`** (:706).

#### 3.7 POST /register — auth.router.ts:713-731

- **Mounting gate**: the route exists **only** when `options.onRegister` is provided AND not resource-server mode (`if (options.onRegister && !isResourceServer)`, :713). There is **no built-in default handler** (grep-verified — no `defaultOnRegister` anywhere in src): when `onRegister` is omitted the route is simply not mounted, so the "default" behavior is Express's **404** fall-through for `POST /register`. Pinned: tests/new-features.test.ts:1018-1026 (404 when not configured). RouterOptions doc: auth.router.ts:93-109.
- **Auth gate**: none. **CSRF**: not checked.
- **Request body**: the raw JSON body (`Record<string, unknown>`) is passed verbatim to `onRegister(data, config, options)`; all validation (duplicate email, missing password, etc.) is the callback's responsibility (:717-718). Callback signature pinned: tests/new-features.test.ts:1015.
- **Side effect**: welcome email via `config.email.sendWelcome(user.email, data)` or, failing that, `MailerService.sendWelcome(user.email, { loginUrl: `${siteUrl}/login` })` when `config.email.mailer` set (:719-725).
- **Success**: **`201 { "success": true, "userId": "<user.id>" }`** (:726). Pinned: tests/new-features.test.ts:1000-1016.
- **Errors**: whatever `onRegister` throws goes through `handleError` — plain `Error` → `500 { "error": "Internal server error" }` (pinned: tests/new-features.test.ts:1028-1037); an `AuthError` thrown by the callback surfaces its own status/`code`. No tokens are issued and no cookies set by this route (registration ≠ login).
- **dev line (node-auth@e8af923):** the mounting gate is `if (registerHandler && !isResourceServer)` (auth.router.ts:801) where `registerHandler = options.onRegister ?? (typeof userStore.create === 'function' ? <built-in> : undefined)` (:515-525); since `IUserStore.create` is a required member (src/interfaces/user-store.interface.ts:6) the route is **mounted by default** on every non-resource-server deployment. Built-in handler (:517-523): `email`/`password` missing, non-string or empty → `AuthError('Email and password are required', 'INVALID_INPUT', 400)` (:519) → **`400 { "error": "Email and password are required", "code": "INVALID_INPUT" }`** via `handleError` (:197-204); otherwise bcrypt hash (:521) and `userStore.create({ ...data, email: data['email'], password: hash })` (:522) — the **entire raw body is spread into the store** (mass assignment; reference-issues.md N41). Response unchanged: `201 { "success": true, "userId" }` (:817); still no tokens/cookies. The same resolved handler drives `GET <apiPrefix>/ui/config` `features.register` (`routerOptions: { ...options, onRegister: registerHandler }`, :1793 — §6 5.1) and the auth router's `GET <apiPrefix>/openapi.json`, which therefore lists `POST <basePath>/register` by default (`hasRegister: !!registerHandler`, :1808 → src/router/openapi.ts:154-169: 201 `{success, userId}` + 400 "Validation error"). The v1.9.0 pin tests/new-features.test.ts:1018-1026 (404) was rewritten to expect 201 (tests/new-features.test.ts:1052-1062); hashing + the `create` call are pinned at tests/auth.router.test.ts:142-166.

#### 3.8 POST /sessions/cleanup — auth.router.ts:733-744

- **Mounting gate**: only when `options.sessionStore` exists AND implements `deleteExpiredSessions` (:734); otherwise 404. Pinned: tests/new-features.test.ts:1068-1078 (store without method → 404), :1080-1086 (no store → 404).
- **Auth gate**: **none** — no authMiddleware, no admin secret. **CSRF**: not checked. **Anyone who can reach the router can trigger cleanup** (intended for cron per RouterOptions doc :57-61, but the route itself is public). [Code-only; the tests call it unauthenticated, confirming public access — tests/new-features.test.ts:1061.]
- **Request body**: ignored.
- **Success**: **`200 { "success": true, "deleted": <number> }`** (:738-739). Pinned: tests/new-features.test.ts:1052-1066.

#### 3.9 GET /sessions — auth.router.ts:747-756 [UNTESTED — user-facing route has no test; only the admin variant is tested]

- **Mounting gate**: only when `options.sessionStore` provided (:747); otherwise 404.
- **Auth gate**: `authMiddleware`. **CSRF**: exempt (GET).
- **Success**: **`200 { "sessions": SessionInfo[] }`** — **wrapped** in a `sessions` key (:751-752), matching the client contract ✓. Each `SessionInfo` (src/models/session.model.ts:8-27): `sessionHandle: string`, `userId: string`, `createdAt: Date→ISO string`, `expiresAt: Date→ISO string`, optional `tenantId`, `lastActiveAt`, `userAgent`, `ipAddress`, `data: object`. Content is whatever the store returns for `getSessionsForUser(req.user.sub)` — no field filtering.

#### 3.10 DELETE /sessions/:handle — auth.router.ts:758-773 [UNTESTED]

- **Mounting gate**: `options.sessionStore` (:747). **Auth gate**: `authMiddleware`. **CSRF**: enforced in cookie mode (DELETE).
- Path param is `decodeURIComponent`-ed (:761). Ownership check: session must exist AND `session.userId === req.user.sub`, else **`404 { "error": "Session not found" }`** (same body for not-found and not-owned — no information leak) (:762-767).
- **Success**: `revokeSession(handle)` → **`200 { "success": true }`** (:768-769).

#### 3.11 DELETE /account — auth.router.ts:1597-1636

- **Auth gate**: `authMiddleware` (403 without token — pinned tests/new-features.test.ts:1113-1116). **CSRF**: enforced in cookie mode (DELETE).
- **Request body**: none read.
- **Cleanup sequence** (all for `req.user.sub`):
  1. Sessions: `sessionStore.revokeAllSessionsForUser(userId)` when available (:1602-1603, pinned tests/new-features.test.ts:1142-1157); else fallback `updateRefreshToken(userId, null, null)` (:1605-1606).
  2. RBAC: `getRolesForUser` then `removeRoleFromUser` for each, when `options.rbacStore` (:1608-1612). [UNTESTED]
  3. Tenants: `getTenantsForUser` then `disassociateUserFromTenant` for each, when `options.tenantStore?.getTenantsForUser` (:1613-1617). [UNTESTED]
  4. Metadata: `metadataStore.clearMetadata(userId)` when implemented (:1618-1621, pinned :1159-1172).
  5. User record: duck-typed `deleteUser(userId)` if the store has one (:1622-1625, pinned :1118-1126); else soft-scrub `updateRefreshToken(null)` + `updateResetToken(null)` (:1626-1630, pinned :1128-1140).
- **Success**: `clearTokenCookies` (§0.5) then **`200 { "success": true }`** (:1631-1632).
- **Bearer mode**: works via `Authorization` header; the Set-Cookie clears are sent regardless (harmless to native clients). [UNTESTED]

---

### 4. Client-contract cross-check summary

| Client fact | Router reality | Verdict |
|---|---|---|
| CSRF header `X-CSRF-Token`; cookie priority `__Host-` > `__Secure-` > bare; cookie JS-readable; no /csrf endpoint | auth.middleware.ts:36-38; token.service.ts:276-280; `httpOnly:false` token.service.ts:206,216; no /csrf route in src | ✓ match |
| 401 `{code:"SESSION_REVOKED"}` → skip refresh, logout | Emitted at exactly auth.middleware.ts:50 (`allcalls` + store passed to factory) and auth.router.ts:638 (refresh, `checkOn !== 'none'`); both 401 | ✓ match, **but** middleware arm unreachable on the router's own routes (§1.4 [MISMATCH]) |
| POST /refresh works with empty body (cookie mode) | optional-chained body read, cookie fallback (auth.router.ts:625-626) | ✓ match |
| Native: `{refreshToken}` + `X-Auth-Strategy: bearer` → top-level `accessToken`/`refreshToken` in login/refresh | sendTokens bearer branch (auth.router.ts:400-401); pinned tests/auth.router.test.ts:534-545, 566-577 | ✓ match |
| GET /me unwrapped | `res.json(profile)` top-level (auth.router.ts:676) | ✓ match |
| GET /sessions → `{sessions:[...]}` | auth.router.ts:752 | ✓ match |
| Clients expect logout to invalidate server state | Bearer logout is a server-side no-op (cookie-only token read, auth.router.ts:592) | **[MISMATCH]** (§3.2) |
| Clients keying token-refresh on 401 | Middleware returns **403** for missing/expired access tokens (auth.middleware.ts:30,63) | **[MISMATCH]** risk (§1.3) |
| `/linked-accounts` shape (Angular `{linkedAccounts}` vs Flutter bare array) and magic-link `mode` default | Routes outside this section — see the linked-accounts / magic-link extract | n/a here |
| Angular no-retry list includes `/login /logout /refresh /register` | All four mounted here; no router behavior depends on client retry | informational ✓ |

---

## 2. Password management, email verification, email change

Wire contract for the seven password/email routes in `awesome-node-auth` (pinned cc01e997), extracted from `src/router/auth.router.ts` with supporting code in `src/middleware/auth.middleware.ts`, `src/services/token.service.ts`, `src/services/password.service.ts`, `src/services/mailer.service.ts`, `src/strategies/local/local.strategy.ts`, and `src/interfaces/user-store.interface.ts`. Every claim carries a file:line reference; behaviors pinned by tests cite `tests/auth.router.test.ts`, `tests/new-features.test.ts`, or `tests/auth-flow-improvements.test.ts` (`tests/mailer.service.test.ts` for mail transport). Behaviors with no test are marked [UNTESTED]; divergences from the client contracts (ng-awesome-node-auth / Flutter / served auth.js) are marked [MISMATCH].

### Shared conventions for this section

- **Error envelope.** All handlers funnel exceptions through `handleError`: an `AuthError` becomes `err.statusCode` + `{error: <message>, code: <code>}`; anything else becomes `500 {"error":"Internal server error"}` (src/router/auth.router.ts:189-196). The inline validation errors in these routes are plain `{error: "..."}` objects **without a `code` field** unless noted.
- **Rate limiting.** Every route below takes `...rl`, which is `[options.rateLimiter]` when a limiter was passed and `[]` otherwise (src/router/auth.router.ts:468). No built-in limiter exists.
- **Resource-server gating.** Only `/forgot-password` and `/reset-password` are skipped when `config.resourceServer.enabled === true` (`isResourceServer`, src/router/auth.router.ts:510, 777, 802). `/change-password`, `/send-verification-email`, `/verify-email`, and both `/change-email/*` routes are mounted unconditionally even in resource-server mode (src/router/auth.router.ts:905, 935, 969, 998, 1040) — they would fail at runtime against a store-less deployment. [UNTESTED]
- **Auth gate.** `authMiddleware` (where present) accepts `Authorization: Bearer <accessToken>` first, falling back to the `accessToken` cookie (resolved `__Host-accessToken` > `__Secure-accessToken` > `accessToken`, src/services/token.service.ts:274-302). Failures: `403 {"error":"No access token provided"}` (src/middleware/auth.middleware.ts:30), `403 {"error":"Invalid or expired access token"}` (src/middleware/auth.middleware.ts:63). Note the status is **403, not 401**, for missing/expired tokens (pinned by tests/new-features.test.ts:144-149).
- **`SESSION_REVOKED` never comes from these routes.** The router builds its middleware as `createAuthMiddleware(config)` with **no sessionStore** (src/router/auth.router.ts:466), so the `401 {"error":"Session has been revoked","code":"SESSION_REVOKED"}` branch (src/middleware/auth.middleware.ts:47-52) is unreachable inside the auth router. Clients that rely on `SESSION_REVOKED` to skip refresh (Angular/Flutter contract) can only receive it from consumer-created middleware via `AuthConfigurator.middleware()` (src/auth-configurator.ts:27). [MISMATCH — client contract expects this code from protected endpoints; the router itself cannot emit it]
- **CSRF.** Applies only to the three `authMiddleware` routes, only in cookie mode, and only for non-GET/HEAD/OPTIONS: when `config.csrf.enabled`, the `X-CSRF-Token` header must equal the CSRF cookie or the request fails `403 {"error":"CSRF token validation failed","code":"CSRF_INVALID"}` (src/middleware/auth.middleware.ts:33-42). Bearer requests skip CSRF entirely (src/middleware/auth.middleware.ts:35). Cookie read priority is `__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token` (src/services/token.service.ts:276-280) — matches the client contract. The cookie is auto-initialized by router-level middleware on any request when missing (src/router/auth.router.ts:529-538) with attributes: `httpOnly:false` (JS-readable, per contract), `secure` = `config.cookieOptions.secure ?? false`, `sameSite` = `config.cookieOptions.sameSite ?? 'lax'`, `path` = `config.cookieOptions.path ?? '/'`, `maxAge: 15*60*1000` (15 min), `domain` = `config.cookieOptions.domain`; name is prefixed `__Host-csrf-token` when secure with root path and no domain (then path forced `/`, secure forced true, domain dropped), else `__Secure-csrf-token` when secure (src/services/token.service.ts:161-172, 212-230). There is **no `/csrf` endpoint** — consistent with the client contract. CSRF checks on these specific routes are [UNTESTED].
- **Bearer-mode differences.** None of these routes issue or clear tokens, so `X-Auth-Strategy: bearer` has no effect on them (the header is only consulted in `sendTokens`/`issueTokens`, src/router/auth.router.ts:388-391). The only bearer-mode difference is the auth-gate/CSRF behavior described above.
- **Token generation.** All three flows use `tokenService.generateSecureToken()` = `crypto.randomBytes(32).toString('hex')` — a 64-char hex string (src/services/token.service.ts:270-272).
- **Link building.** `link = buildUiLink(siteUrl, path, config, options)` produces `<siteUrl><apiPrefix>/ui/<path>` when `config.ui.enabled` and `<siteUrl><apiPrefix>/<path>` otherwise, where `apiPrefix` = `options.apiPrefix || config.apiPrefix || '/auth'` (src/router/auth.router.ts:253-271).
- **siteUrl resolution (incl. `string[]`).** `resolveSiteUrl(req, config, allowedOrigins)`: when the merged allowlist (`config.email.siteUrl` string-or-array ∪ `options.cors.origins`, deduped, src/router/auth.router.ts:213-219) is non-empty, the request `Origin` header is echoed if allowlisted, else the `Referer` origin if allowlisted; otherwise falls back to `getDefaultSiteUrl` = first array entry (or the string, or `''`) (src/router/auth.router.ts:202-206, 233-246). Array/allowlist semantics are pinned by the OAuth tests (tests/auth-flow-improvements.test.ts:815-963, esp. :916-919 and :945-963); the Origin-echo path for these email routes specifically is [UNTESTED].
- **Mailer dispatch order.** Each route prefers the config callback (`config.email.sendPasswordReset` / `sendVerificationEmail` / `sendEmailChanged`), falling back to `new MailerService(config.email.mailer, config.templateStore)` when only `mailer` transport is configured; if neither exists, no email is sent and the route still succeeds (src/router/auth.router.ts:787-792, 956-961, 1027-1032, 1061-1066). Callback signatures: `sendPasswordReset(to, token, link, lang?)`, `sendVerificationEmail(to, token, link, lang?)` (src/models/auth-config.model.ts:238, 250), `sendEmailChanged(to, newEmail, lang?)` (src/models/auth-config.model.ts:257). The MailerService POSTs JSON `{to, subject, html, text, from, fromName, provider?}` with header `X-API-Key` to `config.email.mailer.endpoint` and rejects on non-2xx (src/services/mailer.service.ts:133-141, 261-291; pinned by tests/mailer.service.test.ts:71-85, 167-182).

---

### POST /forgot-password

- **Mounted:** only when `!isResourceServer` (src/router/auth.router.ts:777).
- **Auth gate:** none. **CSRF:** not checked (no authMiddleware; router-level CSRF middleware only *sets* the cookie).
- **Request body:** `{email: string (required in effect), emailLang?: string}` (src/router/auth.router.ts:779). No validation — a missing email simply fails the `findByEmail` lookup and still returns success. [UNTESTED]
- **Behavior (known user):** `token = generateSecureToken()` (64-hex); `expiry = Date.now() + 60*60*1000` (**1 hour**, src/router/auth.router.ts:782-783); persisted via `IUserStore.updateResetToken(user.id, token, expiry)` (src/router/auth.router.ts:784; interface src/interfaces/user-store.interface.ts:9). A repeat request **overwrites** the previous token — one active token per user, no invalidation list.
- **Link:** `buildUiLink(siteUrl, '/reset-password?token=<token>')` → `<siteUrl><prefix>/reset-password?token=...` or `<siteUrl><prefix>/ui/reset-password?token=...` with UI enabled (src/router/auth.router.ts:785-786). Note: with UI disabled the emailed path coincides with the POST-only API route — the SPA at `siteUrl` must route it client-side; a browser GET on the auth server 404s. [UNTESTED]
- **Mailer:** template `password-reset` (built-in EN subject `Reset your password`, IT `Reimposta la tua password`, body embeds `link` and says "valid for 1 hour"; data keys `link`, `token`) (src/services/mailer.service.ts:19-38, 185-188; pinned tests/mailer.service.test.ts:71-105).
- **Success:** **always** `200 {"success":true}` whether or not the user exists — explicit anti-enumeration (src/router/auth.router.ts:794-795). Pinned: unknown email → 200 success (tests/auth.router.test.ts:155-159); known email → mailer called (tests/auth.router.test.ts:161-165).
- **Errors:** only `500 {"error":"Internal server error"}` if the store or mailer throws (src/router/auth.router.ts:796-798). **Anti-enumeration caveat:** a throwing mailer produces a 500 only for existing users, which is an observable oracle. [UNTESTED]
- **Client fact:** `/forgot-password` is on the Angular no-retry list — consistent, the route never returns 401.

### POST /reset-password

- **Mounted:** only when `!isResourceServer` (src/router/auth.router.ts:802).
- **Auth gate:** none. **CSRF:** not checked.
- **Request body:** `{token: string (required in effect), password: string (required in effect)}` (src/router/auth.router.ts:804). No password-policy validation of any kind.
- **Errors:**
  - `500 {"error":"UserStore does not implement findByResetToken"}` when the optional store method is absent (src/router/auth.router.ts:805-808 — note **500**, not 501). [UNTESTED]
  - `400 {"error":"Invalid reset token"}` when no user found, `user.resetToken` empty, or stored token ≠ submitted token (src/router/auth.router.ts:810-813). [UNTESTED — only the expired case is test-pinned]
  - `400 {"error":"Reset token has expired"}` when `resetTokenExpiry` is set and `new Date() > resetTokenExpiry` (src/router/auth.router.ts:814-817; pinned tests/auth.router.test.ts:178-184). A `null` expiry means the token **never expires**. [UNTESTED]
- **Success:** bcrypt-hash the new password with `config.bcryptSaltRounds` (default **12**, src/services/password.service.ts:4); `updatePassword(user.id, hashed)` (src/router/auth.router.ts:818-819); **single-use clear** `updateResetToken(user.id, null, null)` (src/router/auth.router.ts:820); respond `200 {"success":true}` (src/router/auth.router.ts:821; pinned tests/auth.router.test.ts:169-176).
- **Not done:** no refresh-token revocation, no session revocation, no cookie clearing — existing sessions survive a password reset. [UNTESTED]
- **Client fact:** on the Angular no-retry list — consistent (route never returns 401).

### POST /change-password

- **Mounted:** unconditionally (src/router/auth.router.ts:905). **Auth gate:** `authMiddleware`. **CSRF:** enforced in cookie mode (see conventions).
- **Request body:** `{currentPassword: string, newPassword: string}` (src/router/auth.router.ts:907-910).
- **Errors:**
  - `403` auth-middleware failures (pinned unauthenticated → 403, tests/new-features.test.ts:144-149).
  - `404 {"error":"User not found"}` when the JWT `sub` no longer resolves (src/router/auth.router.ts:912-915). [UNTESTED]
  - `401 {"error":"Current password is incorrect"}` when the user has a password and the compare fails (src/router/auth.router.ts:916-921; pinned tests/new-features.test.ts:135-142). No `code` field.
  - `400 {"error":"New password is required"}` only when the user has **no** password (OAuth-only account) and both fields are falsy (src/router/auth.router.ts:922-925). [UNTESTED]
- **Passwordless-account path:** a user without a stored password skips the current-password check entirely and may set an initial password by supplying `newPassword` (src/router/auth.router.ts:916-925). [UNTESTED]
- **Success:** hash (`bcryptSaltRounds` default 12) + `updatePassword`, `200 {"success":true}` (src/router/auth.router.ts:926-928; pinned tests/new-features.test.ts:124-133). Sessions/refresh tokens are **not** revoked; cookies untouched.
- **[MISMATCH] Angular retry hazard:** `/change-password` is **not** on the Angular no-retry substring list, and this route returns **401** for a wrong current password. The Angular interceptor will treat that 401 as an expired session, attempt a token refresh, and replay the request once — a wasted round-trip (the replay 401s again). Native clients keying on 401 should special-case this endpoint.

### POST /send-verification-email

- **Mounted:** unconditionally (src/router/auth.router.ts:935). **Auth gate:** `authMiddleware`. **CSRF:** enforced in cookie mode.
- **Store requirements:** both `updateEmailVerificationToken` **and** `updateEmailVerified` must exist, else `500 {"error":"UserStore does not implement email verification"}` (src/router/auth.router.ts:937-940 — 500, not 501; `updateEmailVerified` is required even though this route never calls it). [UNTESTED]
- **Request body:** `{emailLang?: string}`; an empty `{}` body is valid (src/router/auth.router.ts:941; pinned tests/new-features.test.ts:171-181).
- **Errors:** `404 {"error":"User not found"}` (src/router/auth.router.ts:943-946) [UNTESTED]; `400 {"error":"Email is already verified"}` when `user.isEmailVerified` (src/router/auth.router.ts:947-950; pinned tests/new-features.test.ts:183-191).
- **Token:** 64-hex via `generateSecureToken()`; `expiry = Date.now() + 24*60*60*1000` (**24 hours**, src/router/auth.router.ts:951-952); stored via `updateEmailVerificationToken(user.id, token, expiry)` (src/router/auth.router.ts:953; interface src/interfaces/user-store.interface.ts:33-37; call shape pinned tests/new-features.test.ts:179).
- **Link:** `buildUiLink(siteUrl, '/verify-email?token=<token>')` (src/router/auth.router.ts:954-955).
- **Mailer:** template `verify-email` (built-in EN subject `Verify your email address`, "valid for 24 hours"; data keys `link`, `token`), sent to `user.email` (src/router/auth.router.ts:956-961; src/services/mailer.service.ts:91-110, 200-203).
- **Success:** `200 {"success":true}` (src/router/auth.router.ts:962).

### GET /verify-email

- **Mounted:** unconditionally (src/router/auth.router.ts:969). **Auth gate:** none. **CSRF:** not applicable (GET is a safe method; no authMiddleware).
- **Query:** `token` (required) → `400 {"error":"Token is required"}` when absent (src/router/auth.router.ts:971-975; pinned tests/new-features.test.ts:217-220).
- **Store requirements:** `findByEmailVerificationToken`, `updateEmailVerificationToken`, `updateEmailVerified` all required, else `500 {"error":"UserStore does not implement email verification"}` (src/router/auth.router.ts:976-979). [UNTESTED]
- **Errors:** `400 {"error":"Invalid verification token"}` on no match or token mismatch (src/router/auth.router.ts:980-984; pinned tests/new-features.test.ts:212-215); `400 {"error":"Verification token has expired"}` when expiry set and passed (src/router/auth.router.ts:985-988; pinned tests/new-features.test.ts:204-210). Null expiry never expires. [UNTESTED]
- **Success:** `updateEmailVerified(user.id, true)` (src/router/auth.router.ts:989; pinned tests/new-features.test.ts:193-202) then **single-use clear** `updateEmailVerificationToken(user.id, null, null)` (src/router/auth.router.ts:990); respond `200 {"success":true}` (src/router/auth.router.ts:991).
- **HTML vs JSON — exact behavior:** the route performs **no content negotiation and no redirect**; it always returns JSON regardless of `Accept` (src/router/auth.router.ts:969-995). The HTML experience is delivered by the optional static UI instead: with `config.ui.enabled`, the emailed link targets `<siteUrl><prefix>/ui/verify-email?token=...` (src/router/auth.router.ts:265-267, 955); that static page (src/ui/assets/verify-email.html:45-56) fetches `GET <prefix>/verify-email?token=...` client-side and renders the JSON result. With UI disabled, the emailed link points directly at the JSON endpoint path under `siteUrl`, so a browser hitting the auth server itself sees raw JSON, and a SPA-hosted `siteUrl` must route the path. [UNTESTED — HTML page flow has no test]
- **Adjacent behavior:** a successful `POST /magic-link/verify` also marks the email verified when the store implements `updateEmailVerified` (pinned tests/auth-flow-improvements.test.ts:71-80, 82-102).
- **Client fact:** `/verify-email` is on the Angular no-retry list — consistent (never returns 401).

### POST /change-email/request

- **Mounted:** unconditionally (src/router/auth.router.ts:998). **Auth gate:** `authMiddleware`. **CSRF:** enforced in cookie mode.
- **Store requirement:** `updateEmailChangeToken`, else `500 {"error":"UserStore does not implement change-email"}` (src/router/auth.router.ts:1000-1003). [UNTESTED]
- **Request body:** `{newEmail: string (required in effect), emailLang?: string}` (src/router/auth.router.ts:1004). No email-format validation.
- **Errors:**
  - `409 {"error":"Email address is already in use"}` when `findByEmail(newEmail)` matches (src/router/auth.router.ts:1005-1009; pinned tests/new-features.test.ts:254-262). **Anti-enumeration note:** unlike `/forgot-password`, this deliberately reveals address existence to any authenticated user.
  - `404 {"error":"User not found"}` (src/router/auth.router.ts:1010-1014). [UNTESTED]
  - `403 {"error":"You must set a password before you can change your email address.","code":"PASSWORD_REQUIRED"}` when the account has no password (src/router/auth.router.ts:1015-1021). [UNTESTED — no test references PASSWORD_REQUIRED]
- **Token:** 64-hex; `expiry = Date.now() + 60*60*1000` (**1 hour**, src/router/auth.router.ts:1022-1023); stored with the pending address via `updateEmailChangeToken(user.id, newEmail, token, expiry)` (src/router/auth.router.ts:1024; interface src/interfaces/user-store.interface.ts:59-64; call shape pinned tests/new-features.test.ts:250).
- **Link:** `buildUiLink(siteUrl, '/change-email/confirm?token=<token>')` (src/router/auth.router.ts:1025-1026).
- **Mailer:** sent **to the new address**, reusing the *verification* sender/template — `config.email.sendVerificationEmail(newEmail, token, link, emailLang)` or `mailer.sendVerificationEmail` (template `verify-email`); there is **no dedicated change-email template** (src/router/auth.router.ts:1027-1032; args pinned tests/new-features.test.ts:251).
- **Success:** `200 {"success":true}` (src/router/auth.router.ts:1033; pinned tests/new-features.test.ts:242-252).

### POST /change-email/confirm

- **Mounted:** unconditionally (src/router/auth.router.ts:1040). **Auth gate:** none — the token is the credential, so the link works from any browser/session. **CSRF:** not checked.
- **Store requirements:** `findByEmailChangeToken`, `updateEmail`, `updateEmailChangeToken`, else `500 {"error":"UserStore does not implement change-email"}` (src/router/auth.router.ts:1042-1045). [UNTESTED]
- **Request body:** `{token: string}` (src/router/auth.router.ts:1046).
- **Errors:** `400 {"error":"Invalid email-change token"}` (src/router/auth.router.ts:1047-1051; pinned tests/new-features.test.ts:289-292); `400 {"error":"Email-change token has expired"}` when expiry set and passed (src/router/auth.router.ts:1052-1055; pinned tests/new-features.test.ts:278-287). Null expiry never expires. [UNTESTED]
- **Success:** `oldEmail = user.email`, `newEmail = user.pendingEmail!` (non-null assertion — a store row with a token but no `pendingEmail` would call `updateEmail(user.id, undefined)`; [UNTESTED] edge); `updateEmail(user.id, newEmail)` (src/router/auth.router.ts:1056-1058; pinned tests/new-features.test.ts:274); **single-use clear** `updateEmailChangeToken(user.id, null, null, null)` (src/router/auth.router.ts:1059); notification email **to the old address** via `sendEmailChanged(oldEmail, newEmail)` or `mailer.sendEmailChanged` (template `email-changed`, built-in EN subject `Your email address has been updated`; src/router/auth.router.ts:1060-1066; src/services/mailer.service.ts:112-127, 205-208; args pinned tests/new-features.test.ts:275); respond `200 {"success":true}` (src/router/auth.router.ts:1067; pinned tests/new-features.test.ts:264-276).
- **Not done:** existing access/refresh tokens still carry the old email claim until refresh; sessions are not revoked. [UNTESTED]

---

### emailVerificationMode: 'none' | 'lazy' | 'strict'

- **Resolution:** `config.emailVerificationMode ?? (config.requireEmailVerification ? 'strict' : 'none')` — the enum wins over the deprecated boolean (src/strategies/local/local.strategy.ts:31-35; src/models/auth-config.model.ts:290-298; legacy equivalence pinned tests/new-features.test.ts:726-734).
- **Effect on POST /login (via LocalStrategy) when `user.isEmailVerified` is falsy:**
  - `strict` → `403 {"error":"Email address is not verified","code":"EMAIL_NOT_VERIFIED"}` (src/strategies/local/local.strategy.ts:38-39, mapped by handleError src/router/auth.router.ts:189-196; pinned tests/new-features.test.ts:707-715, verified-user pass :717-724).
  - `lazy` → login allowed until `user.emailVerificationDeadline` passes, then `403 {"error":"Email verification required","code":"EMAIL_VERIFICATION_REQUIRED"}` (src/strategies/local/local.strategy.ts:40-44; pinned tests/new-features.test.ts:736-743 no-deadline pass, :745-759 past-deadline block). The library **never sets** `emailVerificationDeadline` — the consuming store must populate it at signup; `null` means a permanent grace period (src/models/user.model.ts:44-51).
  - `none` → always allowed (src/strategies/local/local.strategy.ts:46; pinned tests/new-features.test.ts:761-768).
- **Effect on the routes in this section: none.** No handler in :777-1071 consults `emailVerificationMode` — send/verify/forgot/reset/change-email behave identically in all three modes. The mode only additionally drives the vanilla UI's `verifyEmail` feature flag: shown when a verification sender or mailer is configured AND (`emailVerificationMode !== 'none'` OR legacy `requireEmailVerification`) (src/router/ui.router.ts:121). [UNTESTED]

### Single-use clearing summary (exact calls)

| Flow | Clear call | Location |
|---|---|---|
| reset-password | `userStore.updateResetToken(user.id, null, null)` | src/router/auth.router.ts:820 |
| verify-email | `userStore.updateEmailVerificationToken(user.id, null, null)` | src/router/auth.router.ts:990 |
| change-email/confirm | `userStore.updateEmailChangeToken(user.id, null, null, null)` | src/router/auth.router.ts:1059 |

All three clears run **after** the state mutation (password/verified-flag/email update), so a store failure in the clear step leaves a consumed-but-valid token; there is no transactional guarantee. [UNTESTED]

### Cross-checks against client contracts

| Client fact | Router reality |
|---|---|
| CSRF header `X-CSRF-Token`, cookie priority `__Host-` > `__Secure-` > bare, JS-readable, no `/csrf` endpoint | Matches exactly: header read src/middleware/auth.middleware.ts:37; priority src/services/token.service.ts:276-280; `httpOnly:false` src/services/token.service.ts:206,216; cookie auto-set by middleware src/router/auth.router.ts:529-538; no `/csrf` route exists. |
| 401 `{code:"SESSION_REVOKED"}` → skip refresh, logout | [MISMATCH] The auth router's own middleware is built without a sessionStore (src/router/auth.router.ts:466), so none of these routes can ever return `SESSION_REVOKED`; only consumer middleware from `AuthConfigurator.middleware()` (src/auth-configurator.ts:27) can. Also note protected routes return **403** (not 401) for missing/invalid tokens (src/middleware/auth.middleware.ts:30,63). |
| Angular no-retry substring list includes `/forgot-password`, `/reset-password`, `/verify-email` | Consistent — those three never return 401. [MISMATCH] `/change-password` is **absent** from the list yet returns `401` for a wrong current password (src/router/auth.router.ts:919), so Angular will refresh-and-retry a request that can never succeed. |
| Served auth.js call shapes | Match: `POST /forgot-password {email}` (src/ui/assets/auth.js:548), `POST /reset-password {token,password}` (:553), `POST /change-password {currentPassword,newPassword}` (:558-560), `POST /send-verification-email` with no body (:644), `GET /verify-email?token=` (:650), `POST /change-email/request {newEmail}` (:660), `POST /change-email/confirm {token}` (:665). Note auth.js omits `emailLang` everywhere — the optional field is server-supported but unused by the served client. |

---

## 3. Magic link, SMS OTP, TOTP 2FA

Wire contract for the passwordless and second-factor routes of `awesome-node-auth` (pinned cc01e997): `POST /magic-link/send`, `POST /magic-link/verify`, `POST /sms/send`, `POST /sms/verify`, `POST /2fa/setup`, `POST /2fa/verify-setup`, `POST /2fa/verify`, `POST /2fa/disable`. All paths are relative to the router mount (default `apiPrefix` = `/auth`, src/router/auth.router.ts:253-255). Every claim is grounded in `src/router/auth.router.ts` (router), `src/strategies/magic-link/magic-link.strategy.ts`, `src/strategies/sms/sms.strategy.ts`, `src/strategies/two-factor/totp.strategy.ts`, `src/services/token.service.ts`, `src/services/sms.service.ts`, `src/middleware/auth.middleware.ts`, cross-checked against `tests/`. All eight routes are also mounted in resource-server mode (none is guarded by the `isResourceServer` skip that protects `/login`, `/logout`, `/refresh` etc., src/router/auth.router.ts:510, :541, :590, :622 vs. :828, :843, :859, :880, :1078, :1126, :1176, :1244).

### Shared mechanics

**Error envelope.** Handlers `catch` into `handleError` (src/router/auth.router.ts:189-196): an `AuthError` becomes `res.status(err.statusCode).json({ error: err.message, code: err.code })`; anything else becomes `500 {"error":"Internal server error"}` (no `code`). Inline `res.status(...).json(...)` responses listed per-route below sometimes omit `code` — omissions are exact, not oversights.

**The tempToken (step-up token).**
- Created by `POST /login` when 2FA is required: `tokenService.generateTokenPair(buildPayload(user, config), { ...config, accessTokenExpiresIn: '5m', refreshTokenExpiresIn: '5m' }).accessToken` (src/router/auth.router.ts:572-575; the `2FA_SETUP_REQUIRED` variant at :564-567; the OAuth-redirect variant at :1306-1309).
- **TTL: `5m`. Signed with `config.accessTokenSecret`, HS256 via `jwt.sign`** (src/services/token.service.ts:20-24).
- **Claims** (`buildPayload`, src/router/auth.router.ts:378-384): `sub` (user id), `email`, `role`, `loginProvider` (default `'local'`), `isEmailVerified` (default `false`), `isTotpEnabled` (default `false`), plus any custom claims from `config.buildTokenPayload(user)`. There is **no claim marking it as a temp token**.
- Verified with `tokenService.verifyAccessToken` (`jwt.verify` against `accessTokenSecret`, src/services/token.service.ts:143-150). Consequence (code fact, no dedicated scoping): any live full access token also passes as a `tempToken`, and a `tempToken` passes `authMiddleware` as a normal access token for its 5-minute life (same secret, same verifier, src/middleware/auth.middleware.ts:44). E.g. a tempToken can call `POST /2fa/setup`. [UNTESTED]
- Login 2FA challenge response (context for these routes): `200 {"requiresTwoFactor":true,"tempToken":"<jwt>","available2faMethods":[...]}"` where methods are `'totp'` (if `user.isTotpEnabled && user.totpSecret`), `'sms'` (if `user.phoneNumber && config.sms`), `'magic-link'` (if `config.email?.sendMagicLink || config.email?.mailer`) (src/router/auth.router.ts:551-577; pinned tests/auth.router.test.ts:208-252, tests/new-features.test.ts:660-683). If **no** method is available: `403 {"requires2FASetup":true,"tempToken":"<jwt>","code":"2FA_SETUP_REQUIRED"}` (src/router/auth.router.ts:563-570; pinned tests/new-features.test.ts:651-658). OAuth logins requiring 2FA instead 302-redirect to `${redirectTo}/auth/2fa?tempToken=<urlencoded jwt>&methods=<urlencoded comma-joined list — commas appear as %2C, e.g. totp%2Csms>` (both values pass through `encodeURIComponent`, src/router/auth.router.ts:1298-1313; pinned tests/auth-flow-improvements.test.ts:727-733).
> CORRECTED(verify): `methods` query param is `encodeURIComponent`-encoded — the comma separator is `%2C` on the wire, not a literal comma (auth.router.ts:1312).

**Token issuance on success (`issueTokens` → `sendTokens`).** `/magic-link/verify`, `/sms/verify`, `/2fa/verify` all finish via `issueTokens` (src/router/auth.router.ts:412-451):
- Rebuilds full payload, creates a session when `options.sessionStore` is configured (payload gains `sid`), signs a fresh pair, persists the refresh token via `userStore.updateRefreshToken(user.id, refreshToken, expiry)`.
- **Cookie mode (default):** `200 {"success":true}` plus `Set-Cookie` (below).
- **Bearer mode (`X-Auth-Strategy: bearer` request header, src/router/auth.router.ts:390-392):** `200 {"success":true,"accessToken":"<jwt>","refreshToken":"<jwt>"}` — top-level fields, **no** `Set-Cookie` (src/router/auth.router.ts:399-406; pinned for `/2fa/verify` at tests/auth-flow-improvements.test.ts:769-777, including `set-cookie` undefined).
- None of the three verify routes calls `userStore.updateLastLogin` (only password login :580 and OAuth :1315 do). [UNTESTED]

**Cookies set on success (cookie mode)** (`setTokenCookies`, src/services/token.service.ts:174-210):
- Name resolution (src/services/token.service.ts:161-172): if `cookieOptions.secure` is falsy → bare name; if secure **and** (`path` unset or `'/'`) **and** no `domain` → `__Host-<name>`; otherwise → `__Secure-<name>`.
- `accessToken` / `__Host-accessToken` / `__Secure-accessToken`: `HttpOnly`, `Secure`=`config.cookieOptions.secure ?? false`, `SameSite`=`config.cookieOptions.sameSite ?? 'lax'`, `Path`=`config.cookieOptions.path ?? '/'`, `Domain`=`config.cookieOptions.domain` (never on `__Host-`), **Express `maxAge` option 900000 ms (15 min) hardcoded → wire attribute `Max-Age=900` (seconds)** — it does NOT track `accessTokenExpiresIn` (src/services/token.service.ts:195). [UNTESTED]
> CORRECTED(verify): Max-Age clarified — 900000 is the Express `maxAge` option in ms; the emitted `Set-Cookie` attribute is `Max-Age=900` (Express divides by 1000).
- `refreshToken` variant: same, but **Express `maxAge` option 604800000 ms (7 d) hardcoded → wire `Max-Age=604800`** and `Path` = `config.cookieOptions.refreshTokenPath`, which the router defaults to `` `${apiPrefix}/refresh` `` = `/auth/refresh` (src/router/auth.router.ts:461-464; src/services/token.service.ts:197-202). Caveat: when the name resolves to `__Host-refreshToken`, `Path` is forced back to `/` and the refresh-path scoping is lost (src/services/token.service.ts:185-188). [UNTESTED]
> CORRECTED(verify): Max-Age clarified — 604800000 is the `maxAge` option in ms; the wire attribute is `Max-Age=604800` (seconds).
- `csrf-token` variant (only when `config.csrf.enabled`): **`httpOnly: false`** (JS-readable), `maxAge` option 900000 ms → wire `Max-Age=900`, fresh 16-byte hex value (32 chars) on every issuance (src/services/token.service.ts:204-209, :270-272).
> CORRECTED(verify): Max-Age clarified — wire attribute is `Max-Age=900` (seconds), matching the access-token cookie.

**CSRF.** When `config.csrf.enabled`, every request through the router auto-initializes a `csrf-token` cookie if none is readable (src/router/auth.router.ts:530-538; `initCsrfToken` src/services/token.service.ts:212-230 — same attributes as above). Enforcement lives **only in `authMiddleware`** (src/middleware/auth.middleware.ts:33-42): cookie-based auth + non-`GET/HEAD/OPTIONS` requires request header `x-csrf-token` equal to the `csrf-token` cookie (read priority `__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token`, src/services/token.service.ts:274-302); failure → `403 {"error":"CSRF token validation failed","code":"CSRF_INVALID"}` (pinned tests/auth.middleware.test.ts:58-99). Bearer-header auth skips the CSRF check entirely (src/middleware/auth.middleware.ts:23-25, :35).
- CSRF therefore applies to: `/2fa/setup`, `/2fa/verify-setup`, `/2fa/disable` (authMiddleware POSTs).
- CSRF does **not** apply to: `/magic-link/send`, `/magic-link/verify`, `/sms/send`, `/sms/verify`, `/2fa/verify` (no authMiddleware).

**authMiddleware gate** (used by `/2fa/setup`, `/2fa/verify-setup`, `/2fa/disable`; created **without** a sessionStore at src/router/auth.router.ts:466):
- Token source: `Authorization: Bearer <jwt>` preferred, else `accessToken` cookie (`__Host-`/`__Secure-`/bare priority) (src/middleware/auth.middleware.ts:20-28).
- No token → **`403`** `{"error":"No access token provided"}` (src/middleware/auth.middleware.ts:29-32; pinned via `GET /me` tests/auth.router.test.ts:125-128).
- Invalid/expired token → **`403`** `{"error":"Invalid or expired access token"}` (no `code`) (src/middleware/auth.middleware.ts:62-64).
- Note: these are 403, **not** 401 — an interceptor that refreshes on 401 will never auto-refresh these routes.
- `401 {"error":"Session has been revoked","code":"SESSION_REVOKED"}` exists in the middleware (src/middleware/auth.middleware.ts:47-53) but requires a sessionStore argument **and** `config.session.checkOn === 'allcalls'`; since the router passes no sessionStore (src/router/auth.router.ts:466), **SESSION_REVOKED can never be emitted by any route in this section** — for this codebase it only comes from `POST /refresh` (src/router/auth.router.ts:635-641).

**`mode` branching (all four magic-link/SMS routes).** The check is literally `if (mode === '2fa')` (src/router/auth.router.ts:1087, :1134, :1192, :1255). **Every other value — absent, `"login"`, or garbage — takes the login branch.** So Angular's explicit `mode:"login"` and Flutter's omitted `mode` hit the identical default branch; the router default when `mode` is absent is `login`. (Default-mode behavior pinned by tests that send no `mode`: tests/auth.router.test.ts:275, :292.)

---

### POST /magic-link/send  (src/router/auth.router.ts:1078-1119)

- **Auth gate:** none. **CSRF:** not enforced. Rate limiter applied when configured (`...rl`).
- **Body:** `email?: string` (required in login mode), `emailLang?: string` (optional, forwarded to the mail sender), `mode?: 'login'|'2fa'` (default login), `tempToken?: string` (required in 2fa mode).

**mode `'2fa'`** (src/router/auth.router.ts:1087-1107) — email is derived from the tempToken; `email` in the body is ignored:
| Condition | Response |
|---|---|
| `tempToken` missing | `400 {"error":"tempToken is required for 2FA mode","code":"TEMP_TOKEN_REQUIRED"}` (:1089) — pinned tests/auth.router.test.ts:313-322 |
| `tempToken` invalid/expired | `401 {"error":"Invalid or expired temp token","code":"INVALID_TEMP_TOKEN"}` (:1096) [UNTESTED for this route; the same literal is pinned for `/sms/send` at tests/auth.router.test.ts:454-465] |
| user from `payload.sub` not found | `404 {"error":"User not found"}` (:1101) [UNTESTED] |
| success | `200 {"success":true}` (:1105) — pinned tests/auth.router.test.ts:297-311 |

**mode login (default)** (src/router/auth.router.ts:1109-1115):
| Condition | Response |
|---|---|
| `email` missing | `400 {"error":"email is required"}` (no `code`) (:1111) [UNTESTED] |
| email unknown | `200 {"success":true}` — strategy silently returns, anti-enumeration (magic-link.strategy.ts:16-19; pinned tests/magic-link.strategy.test.ts:44-54) |
| email not configured (`!config.email?.sendMagicLink && !config.email?.mailer`) | `500 {"error":"Email not configured","code":"EMAIL_NOT_CONFIGURED"}` (magic-link.strategy.ts:12-14 via handleError) [UNTESTED] |
| success | `200 {"success":true}` (:1115) — pinned tests/auth.router.test.ts:269-278 |

- Link construction: router passes `siteUrlOverride = buildUiLink(resolveSiteUrl(req, config, allowedOrigins), '', config, options)` (:1104, :1114), i.e. `${origin}${apiPrefix}/` (or `${origin}${apiPrefix}/ui/` when `config.ui.enabled`, src/router/auth.router.ts:261-271); the strategy strips a trailing `/` and emits `${base}/magic-link/verify?token=<token>` (magic-link.strategy.ts:23-27).
- No 2FA-availability precondition: the 2fa branch sends a magic link even if login never offered `magic-link` in `available2faMethods` (no check in :1087-1106).

### POST /magic-link/verify  (src/router/auth.router.ts:1126-1168)

- **Auth gate:** none. **CSRF:** not enforced.
- **Body:** `token: string` (required — the emailed magic-link token), `mode?: 'login'|'2fa'` (default login), `tempToken?: string` (required in 2fa mode).

**mode `'2fa'`** (src/router/auth.router.ts:1134-1156):
| Condition | Response |
|---|---|
| `tempToken` missing | `400 {"error":"tempToken is required for 2FA mode","code":"TEMP_TOKEN_REQUIRED"}` (:1136) — pinned tests/auth.router.test.ts:345-356 |
| `tempToken` invalid/expired | `401 {"error":"Invalid or expired temp token","code":"INVALID_TEMP_TOKEN"}` (:1144) [UNTESTED] |
| magic-link token invalid | `401 {"error":"Invalid magic link token","code":"INVALID_MAGIC_LINK"}` (magic-link.strategy.ts:41-46) [UNTESTED at router level] |
| magic-link token expired | `401 {"error":"Magic link token has expired","code":"MAGIC_LINK_EXPIRED"}` (magic-link.strategy.ts:47-49; AuthError pinned tests/magic-link.strategy.test.ts:65-70) |
| `user.id !== tempPayload.sub` | `401 {"error":"Token mismatch","code":"TOKEN_MISMATCH"}` (:1150-1152) [UNTESTED]. Note: the magic-link token has already been consumed by `verify()` before this comparison (magic-link.strategy.ts:50) — burned even on mismatch. |
| success | tokens issued (:1154) — cookie mode `200 {"success":true}` + cookies; bearer mode `200 {"success":true,"accessToken","refreshToken"}` — pinned tests/auth.router.test.ts:324-343 |

**mode login (default)** (src/router/auth.router.ts:1158-1164):
- Same strategy errors as above (`INVALID_MAGIC_LINK` 401, `MAGIC_LINK_EXPIRED` 401, plus `500 {"error":"UserStore does not implement findByMagicLinkToken","code":"NOT_IMPLEMENTED"}` when the store lacks `findByMagicLinkToken`, magic-link.strategy.ts:37-39).
- **First-login email verification:** if `!user.isEmailVerified && userStore.updateEmailVerified`, calls `updateEmailVerified(user.id, true)` (:1161-1163; pinned tests/auth-flow-improvements.test.ts:71-80, :82-102, :104-113). This side effect exists **only** in login mode, not in the 2fa branch.
- Success → `issueTokens` — pinned tests/auth.router.test.ts:280-295.
- **Policy note (grounded):** login mode issues full tokens with **no** `require2FA`/`isTotpEnabled` check — a user with TOTP enabled logs in with the magic link alone (:1159-1164 contain no 2FA branch). [UNTESTED]

### POST /sms/send  (src/router/auth.router.ts:1176-1236)

- **Auth gate:** none. **CSRF:** not enforced.
- **Precondition:** `config.sms` must exist, else `500 {"error":"SMS is not configured","code":"SMS_NOT_CONFIGURED"}` (:1178-1181; 500 pinned tests/auth.router.test.ts:396-399).
- **Body:** `userId?: string`, `email?: string` (login mode: one of the two), `mode?: 'login'|'2fa'` (default login), `tempToken?: string` (required in 2fa mode).

**mode `'2fa'`** (:1192-1203): user id = `payload.sub` from the tempToken.
| Condition | Response |
|---|---|
| `tempToken` missing | `400 {"error":"tempToken is required for 2FA mode","code":"TEMP_TOKEN_REQUIRED"}` (:1194) — pinned tests/auth.router.test.ts:441-452 |
| `tempToken` invalid | `401 {"error":"Invalid or expired temp token","code":"INVALID_TEMP_TOKEN"}` (:1201) — pinned tests/auth.router.test.ts:454-465 |

**mode login (default)** (:1204-1220): lookup precedence is `email` first, then `userId`.
| Condition | Response |
|---|---|
| `email` given, no user | `200 {"success":true}` silently — anti-enumeration (:1208-1212) — pinned tests/auth.router.test.ts:413-425 |
| neither `email` nor `userId` | `400 {"error":"userId or email is required"}` (no `code`) (:1217) [UNTESTED] |

**Common tail** (:1222-1232):
| Condition | Response |
|---|---|
| `findById(resolvedUserId)` returns nothing | `404 {"error":"User not found"}` (:1224) — pinned tests/auth.router.test.ts:401-411. Asymmetry: unknown `userId` leaks existence via 404 while unknown `email` returns 200. |
| `!user.phoneNumber` | `400 {"error":"User does not have a phone number configured","code":"PHONE_NOT_SET"}` (:1228) — pinned tests/auth.router.test.ts:383-394, :427-439 |
| success | `200 {"success":true}` (:1232) |

- Code generation/storage (sms.strategy.ts:10-21): 6-digit code, first digit 1-9 (`SmsService.generateCode`, src/services/sms.service.ts:48-52); **bcrypt-hashed with cost 10** before storage (`passwordService.hash(code, 10)`, sms.strategy.ts:16; hashing pinned tests/sms.strategy.test.ts:43-61); **TTL `config.sms.codeExpiresInMinutes ?? 10` minutes** (sms.strategy.ts:17-18); stored via `userStore.updateSmsCode(userId, hashedCode, expiry)`; SMS text is exactly `` `Your verification code is: ${code}` `` (sms.strategy.ts:20). Delivery is an HTTP GET to `config.sms.endpoint` with `username`, `password`, `phone`, `message` query params and an `X-API-Key` header (src/services/sms.service.ts:16-46).

### POST /sms/verify  (src/router/auth.router.ts:1244-1289)

- **Auth gate:** none. **CSRF:** not enforced. No `config.sms` precondition (unlike `/sms/send`).
- **Body:** `code: string` (required), plus **either** `userId: string` (login mode) **or** `tempToken: string` with `mode:'2fa'`.

| Condition | Response |
|---|---|
| 2fa mode, `tempToken` missing | `400 {"error":"tempToken is required for 2FA mode","code":"TEMP_TOKEN_REQUIRED"}` (:1257) — pinned tests/auth.router.test.ts:467-478 |
| 2fa mode, `tempToken` invalid | `401 {"error":"Invalid or expired temp token","code":"INVALID_TEMP_TOKEN"}` (:1264) [UNTESTED for this route] |
| login mode, `userId` missing | `400 {"error":"userId is required"}` (no `code`) (:1269) [UNTESTED] |
| code wrong / expired / none stored | `401 {"error":"Invalid or expired SMS code"}` (no `code` field) (:1277) [UNTESTED at router level; strategy true/false pinned tests/sms.strategy.test.ts:63-100] |
| user vanished after verify | `404 {"error":"User not found"}` (:1282) [UNTESTED] |
| success | `issueTokens` — cookie mode `200 {"success":true}` + cookies; bearer `200 {"success":true,"accessToken","refreshToken"}` (:1285) [UNTESTED at router level] |

- Single-use semantics (sms.strategy.ts:23-36): stored hash is cleared (`updateSmsCode(userId, null, null)`) on **successful** compare (:32-34) and eagerly on **expiry detection** (:27-30); a **wrong** code does not clear it — retries are allowed until expiry, with no attempt counter (only the optional route rate limiter throttles).
- **Policy note (grounded):** like magic-link, login mode issues full tokens without any `require2FA`/TOTP check (:1275-1285). [UNTESTED]

### POST /2fa/setup  (src/router/auth.router.ts:828-840)

- **Auth gate:** `authMiddleware` (403s above). **CSRF:** enforced in cookie mode.
- **Body:** none read.
- **Success:** `200 {"secret":"<base32>","otpauthUrl":"otpauth://totp/<email>?issuer=<appName>...","qrCode":"data:image/png;base64,..."}` (:832-835). `secret` = `totp.generateSecret()`; `otpauthUrl` = `totp.toURI({ label: email, issuer: appName, secret })` with `appName = config.twoFactor?.appName ?? 'awesome-node-auth'` (:830; totp.strategy.ts:16-17; `twoFactor.appName` config at src/models/auth-config.model.ts:272-274); `qrCode` = `qrcode.toDataURL(otpauthUrl)` PNG data URL (totp.strategy.ts:18). Pinned: tests/auth.router.test.ts:188-194 (`secret` truthy, `qrCode` contains `data:image`), tests/totp.strategy.test.ts:29-35 (`otpauth://totp/`, `data:image/png;base64,`).
- **Stateless:** nothing is persisted server-side at setup; the secret round-trips through the client and comes back on `/2fa/verify-setup` (:832 → :845). Repeat calls just mint new secrets.
- **Errors:** authMiddleware 403s; a `qrCode` promise rejection reaches `handleError` → `500 {"error":"Internal server error"}` (:836). [UNTESTED]

### POST /2fa/verify-setup  (src/router/auth.router.ts:843-856)

- **Auth gate:** `authMiddleware`. **CSRF:** enforced in cookie mode.
- **Body:** `token: string` (the 6-digit TOTP code — field name is `token`, **not** `code`), `secret: string` (the base32 secret from `/2fa/setup`).
- Invalid code → `400 {"error":"Invalid TOTP code"}` (no `code` field) (:847-850). [UNTESTED]
- Success → `totpStrategy.enable(req.user.sub, secret, userStore)` = `userStore.updateTotpSecret(userId, secret)` (totp.strategy.ts:27-29; pinned tests/totp.strategy.test.ts:48-53) → `200 {"success":true}` (:852). Pinned end-to-end: tests/auth.router.test.ts:196-206.
- The server never validates that `secret` came from `/2fa/setup` — any client-supplied secret whose code verifies gets enabled (statelessness consequence, :845-851). Whether `isTotpEnabled` flips is a store contract (test store derives it: `isTotpEnabled = secret !== null`, tests/auth.router.test.ts:58); the library only calls `updateTotpSecret`.

### POST /2fa/verify  (src/router/auth.router.ts:859-877)

- **Auth gate:** none (pre-login step-up). **CSRF:** not enforced.
- **Body:** `tempToken: string`, `totpCode: string` (field name is `totpCode`, **not** `code`).
| Condition | Response |
|---|---|
| `tempToken` invalid/expired | `401 {"error":"Invalid or expired access token","code":"INVALID_ACCESS_TOKEN"}` — thrown by `verifyAccessToken` (src/services/token.service.ts:148) through handleError. **Not** `INVALID_TEMP_TOKEN`; also unlike siblings there is no missing-`tempToken` 400 — an absent `tempToken` fails JWT verification and lands here too (:862). [UNTESTED] |
| user missing or `!user.totpSecret` | `400 {"error":"User not found or 2FA not set up"}` (no `code`) (:864-867) [UNTESTED] |
| TOTP code invalid | `401 {"error":"Invalid TOTP code"}` (no `code`) (:869-872) [UNTESTED] |
| success | `issueTokens` (:873) — cookie mode pinned tests/auth.router.test.ts:254-265; bearer mode (top-level `accessToken`/`refreshToken`, no `Set-Cookie`) pinned tests/auth-flow-improvements.test.ts:767-777 |
- Verification is against `user.totpSecret` from the store (:868), otplib TOTP defaults (30 s step, 6 digits — nothing overridden, totp.strategy.ts:5-8, :22-25; valid/invalid pinned tests/totp.strategy.test.ts:37-46).

### POST /2fa/disable  (src/router/auth.router.ts:880-902)

- **Auth gate:** `authMiddleware`. **CSRF:** enforced in cookie mode. **Body:** none read.
| Condition | Response |
|---|---|
| `user.require2FA` truthy | `403 {"error":"Cannot disable 2FA: required for your account","code":"2FA_REQUIRED"}` (:885-888) — pinned tests/auth-flow-improvements.test.ts:151-164 |
| `options.settingsStore` present and `settings.require2FA` truthy | `403 {"error":"Cannot disable 2FA: required by system policy","code":"2FA_REQUIRED"}` (:890-896) — pinned tests/auth-flow-improvements.test.ts:166-183 |
| success | `totpStrategy.disable(userId, userStore)` = `updateTotpSecret(userId, null)` (totp.strategy.ts:31-33; pinned tests/totp.strategy.test.ts:55-59) → `200 {"success":true}` (:898) — pinned tests/auth-flow-improvements.test.ts:135-149, :185-203 |
- Per-user check reads a fresh `findById` (not the JWT), so a just-set `require2FA` flag is honored (:884). System-wide check only runs when a `settingsStore` was passed to the router (:890).

---

### Strategy internals (summary of literals)

| Item | Value | Source |
|---|---|---|
| Magic-link token | 32-byte hex (64 chars), `crypto.randomBytes` | magic-link.strategy.ts:20; token.service.ts:270-272 |
| Magic-link TTL | **15 min** (`Date.now() + 15*60*1000`) | magic-link.strategy.ts:21 |
| Magic-link single-use | cleared via `updateMagicLinkToken(user.id, null, null)` on successful verify, before the router's 2fa id comparison | magic-link.strategy.ts:50; pinned tests/magic-link.strategy.test.ts:56-63 |
| SMS code | 6 digits (no leading zero) | sms.service.ts:48-52 |
| SMS code storage | **bcrypt, cost 10** (`passwordService.hash(code, 10)`) | sms.strategy.ts:16; pinned tests/sms.strategy.test.ts:43-74 |
| SMS code TTL | **`config.sms.codeExpiresInMinutes ?? 10` minutes** | sms.strategy.ts:17-18 |
| SMS single-use | cleared on success and on detected expiry; wrong guess leaves it stored | sms.strategy.ts:27-35 |
| TOTP library | otplib `TOTP` + `NobleCryptoPlugin` + `ScureBase32Plugin`, default step/digits | totp.strategy.ts:5-8 |
| TOTP persistence | only `updateTotpSecret(userId, secret\|null)`; no server-side setup state | totp.strategy.ts:27-33 |

### Cross-checks against client contracts

- **CSRF:** header name `x-csrf-token` matches clients' `X-CSRF-Token`; cookie read priority `__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token` matches (src/services/token.service.ts:274-302); cookie is `httpOnly:false` (JS-readable) (:207, :217); no `/csrf` endpoint — the cookie is auto-initialized by router middleware on any request (src/router/auth.router.ts:530-538). Consistent.
- **`mode` default:** router special-cases only `'2fa'`; Angular's `mode:"login"` and Flutter's omitted `mode` are equivalent (default = login). Served auth.js also sends `mode:'login'` explicitly (src/ui/assets/auth.js:576-578, :583-585, :617-619, :624-626). Consistent.
- **Bearer contract:** `X-Auth-Strategy: bearer` on `/magic-link/verify`, `/sms/verify`, `/2fa/verify` yields top-level `accessToken`/`refreshToken` and no cookies (src/router/auth.router.ts:399-406; pinned tests/auth-flow-improvements.test.ts:769-777). Consistent with native clients.
- **`SESSION_REVOKED` logout trigger:** cannot originate from any route in this section (router's authMiddleware is built without a sessionStore, src/router/auth.router.ts:466); only `/refresh` emits it (:638). Clients keying immediate logout on it are safe here.
- **Angular no-retry list** includes `/2fa/verify`: appropriate — its 401s (`INVALID_ACCESS_TOKEN`, bad TOTP) are not refresh-recoverable. Note the other section routes (`/magic-link/*`, `/sms/*`) are **not** on that list but are unauthenticated, so a 401 from them (e.g. `INVALID_TEMP_TOKEN`) could trigger an Angular refresh-then-retry cycle; harmless but wasteful. [UNTESTED]
- **[MISMATCH] (internal inconsistency, client-visible):** a bad/expired `tempToken` returns `code:"INVALID_TEMP_TOKEN"` (401) on `/magic-link/send`, `/magic-link/verify`, `/sms/send`, `/sms/verify`, but `code:"INVALID_ACCESS_TOKEN"` (401) on `/2fa/verify` (src/router/auth.router.ts:862 vs :1096/:1144/:1201/:1264). A client with uniform tempToken-expiry handling across 2FA methods must special-case TOTP.
- **[MISMATCH] (router implements, clients don't call):** the router's magic-link `mode:'2fa'` branch (send :1087-1107, verify :1134-1156) and its `'magic-link'` entry in `available2faMethods` (:559) have no caller in the served auth.js (only `mode:'login'`, src/ui/assets/auth.js:574-588), and the stated Angular/Flutter contracts likewise only use login mode. A user whose only advertised 2FA method is `magic-link` can stall in these clients even though the server supports the flow.
- **403-not-401 on authMiddleware routes:** `/2fa/setup`, `/2fa/verify-setup`, `/2fa/disable` return **403** for missing/expired access tokens (src/middleware/auth.middleware.ts:30, :63) — clients whose refresh interceptor triggers only on 401 will not auto-refresh these calls.
- **Field-name pitfalls (exact):** `/2fa/verify-setup` takes `token` + `secret`; `/2fa/verify` takes `tempToken` + `totpCode`; `/sms/verify` takes `code` (+ `userId` or `tempToken`). Served auth.js matches all three (src/ui/assets/auth.js:599-601, :606-608, :624-626, :633-635).
- **2FA bypass via passwordless login (grounded observation):** `/magic-link/verify` and `/sms/verify` in login mode issue full tokens without evaluating `require2FA`/`isTotpEnabled` (src/router/auth.router.ts:1159-1164, :1275-1285), so the 2FA policy enforced by `/login` (:546-578) and OAuth (:1298-1313) does not apply to passwordless entry points. [UNTESTED]

---

## 4. OAuth and account linking

This section documents the wire contract of the OAuth login/callback routes, the OAuth `state` codec, the linked-accounts CRUD routes, and the email-verified account-linking flow (`/link-request`, `/link-verify`) as implemented in `awesome-node-auth` at commit `cc01e997` (`src/router/auth.router.ts`), with the provider strategy contract (`src/abstract/base-oauth-strategy.abstract.ts`, `src/strategies/oauth/*.ts`) and cross-checks against the Angular client (`ng-awesome-node-auth`), the Flutter client (`awesome-node-auth-flutter`), the served `auth.js`, and the test suite. All routes below are mounted under the API prefix (`options.apiPrefix || config.apiPrefix || '/auth'`, src/router/auth.router.ts:253-255). Every claim carries a `file:line` reference; behaviors with no test coverage are marked [UNTESTED]; client/router disagreements are marked [MISMATCH].

### Shared machinery

#### Rate limiting and mounting conditions

- All routes in this section are wrapped with `...rl`, which is `[options.rateLimiter]` when provided, else empty (src/router/auth.router.ts:468) — **except** the Google/GitHub 404 stubs, which are registered without `rl` (src/router/auth.router.ts:1361-1362, 1407-1408).
- `/oauth/google[/callback]` mounts only when `options.googleStrategy` is set (:1320); `/oauth/github[/callback]` only with `options.githubStrategy` (:1366); `/oauth/:name[/callback]` is registered per entry of `options.oauthStrategies` with the **literal** strategy name in the path (`router.get(\`/oauth/${s.name}\`)`, :1415) — it is not an Express `:param` route.
- `GET /linked-accounts`, `DELETE /linked-accounts/...`, `POST /link-request`, `POST /link-verify` mount only when `options.linkedAccountsStore` is provided (:1456). Without it they fall through to Express's default 404 (HTML body, not JSON) — pinned by tests/auth-flow-improvements.test.ts:277-287 (GET) and :565-582 (link-request/link-verify).
- RouterOptions fields: `googleStrategy` (:31), `githubStrategy` (:32), `oauthStrategies` (:40), `linkedAccountsStore` (:77), `pendingLinkStore` (:86).

#### State codec — `encodeOAuthState` / `decodeOAuthStateOrigin` / `resolveOAuthRedirect`

- `encodeOAuthState(nonce, redirectOrigin, returnPath?)` (src/router/auth.router.ts:280-284): builds `{ n: <nonce>, o: <origin>, p?: <returnPath> }`, JSON-serializes it, and encodes with `Buffer.toString('base64url')`. Shape pinned by the `OAuthState` interface (:287-294) and by tests/auth-flow-improvements.test.ts:893-898 (decodes `state` as base64url JSON `{n, o}`).
- The nonce is `tokenService.generateSecureToken(16)` = 16 random bytes hex-encoded → 32 hex chars (src/services/token.service.ts:270-272).
- `decodeOAuthStateOrigin(state)` (:310-317): base64url-decode → JSON.parse → return `o` if the shape validates (`isOAuthState`, :296-303); returns `null` for legacy plain-nonce states or any parse error.
- `resolveOAuthRedirect(state, config, allowedOrigins)` (:325-351):
  - Accepts the state origin `o` when `allowedOrigins.length === 0 || allowedOrigins.includes(fromState)` (:327). **When the allowlist is empty (no `email.siteUrl` and no `options.cors.origins`), any origin embedded in the state is accepted** — the open-redirect protection only exists when an allowlist is configured. [UNTESTED]
  - If the state has `p`, it is normalized to a leading `/` and appended to the origin; when the origin itself has a path (e.g. `https://ex.com/example`) and `p` starts with that same base path, the base path is deduplicated (:333-344).
  - Otherwise falls back to `getDefaultSiteUrl(config)` = first entry of `config.email.siteUrl` (array) or the string value, else `''` (:202-206).
  - Allowlist = `config.email.siteUrl` entries merged with `options.cors.origins`, deduplicated (`buildAllowedOrigins`, :213-219).
  - Pinned: redirect to the state-embedded allowed origin (tests/auth-flow-improvements.test.ts:901-920), fallback to first siteUrl for a non-allowlisted origin (:922-943), plain-nonce state falls back to siteUrl (:945-963).
- **The nonce `n` is never verified.** Initiation generates it (:1323, :1369, :1416) but nothing persists it (no cookie, no store), and the callbacks never read `n` — `resolveOAuthRedirect` only consumes `o` and `p`. The doc comment at :288 calls `n` "CSRF protection"; the code provides none. Code wins: **state provides origin pinning only, not CSRF protection.** [UNTESTED — no test asserts nonce validation, consistent with it not existing]

#### `resolveSiteUrl` (initiation-time origin resolution)

`resolveSiteUrl(req, config, allowedOrigins)` (:233-246): if the allowlist is non-empty, match `Origin` header first, then the origin of `Referer`; otherwise (or on no match) return `getDefaultSiteUrl(config)`. Pinned by tests/auth-flow-improvements.test.ts:877-899 (Origin header ends up as `o` in the state).

#### `buildUiLink`

`buildUiLink(siteUrl, path, config, options)` (:261-270): result is `${siteUrl}${prefix}/ui/${path}` when `config.ui?.enabled`, else `${siteUrl}${prefix}/${path}` (prefix = resolved apiPrefix, trailing `/` stripped; leading `/` of path stripped). Used by the account-conflict redirect and the link-verify email link.

#### Token issuance on redirect flows

`issueTokens(req, res, user, config, options, userStore, redirectTo?)` (:412-451):

- When `options.sessionStore` is set, creates a session and puts `sid = session.sessionHandle` into the JWT payload (:425-433).
- Persists the refresh token: `userStore.updateRefreshToken(user.id, refreshToken, now + parseExpiryMs(refreshTokenExpiresIn))` (:442-443; `parseExpiryMs` default 7d, :357-372).
- **With `redirectTo` (all OAuth callbacks): always cookie mode — `setTokenCookies` + `res.redirect(redirectTo)` (302).** The `X-Auth-Strategy: bearer` header has no effect on redirect flows (:445-447); `sendTokens`/bearer JSON (:399-406) is only reachable when `redirectTo` is absent (e.g. `/link-verify` with `loginAfterLinking`).

Cookies set by `setTokenCookies` (src/services/token.service.ts:174-210):

| Cookie | Value | HttpOnly | Path | Max-Age | Other |
|---|---|---|---|---|---|
| `accessToken` | access JWT | true | `config.cookieOptions.path ?? '/'` | **900s (15m, fixed — not derived from `accessTokenExpiresIn`)** (:195) | Secure = `cookieOptions.secure ?? false`; SameSite = `cookieOptions.sameSite ?? 'lax'`; Domain = `cookieOptions.domain` |
| `refreshToken` | refresh JWT | true | `cookieOptions.refreshTokenPath` — defaulted at router creation to `${apiPrefix}/refresh` (src/router/auth.router.ts:461-464), i.e. `/auth/refresh` | **604800s (7d, fixed)** (:199-202) | same |
| `csrf-token` (only if `config.csrf.enabled`) | new 32-hex random | **false** (JS-readable) | as above | 900s (15m) (:204-209) | same |

Cookie-name prefix resolution (`getCookieName`, token.service.ts:161-172): `secure` unset/false → bare name; `secure: true` + path `/` (or unset) + no `domain` → `__Host-<name>` (Path forced to `/`, Secure forced, Domain deleted, :185-188); `secure: true` otherwise → `__Secure-<name>`. This matches the client read priority `__Host-csrf-token > __Secure-csrf-token > csrf-token` (`extractTokenFromCookie`, token.service.ts:274-302). Note the prefix decision is **global, not per cookie**: `getCookieName` reads only `config.cookieOptions.path`/`domain` and ignores the per-cookie `refreshTokenPath` override (token.service.ts:161-172), so with `secure: true`, root/unset global `path`, and no `domain` **all three cookies — including `refreshToken` — become `__Host-`-prefixed**, and `__Host-refreshToken` then has its `Path` forced back to `/` (token.service.ts:185-188), losing the refresh-path scoping. `__Secure-refreshToken` occurs only when the global `cookieOptions.path` is non-root or a `domain` is set — in which case access/CSRF cookies are `__Secure-` as well.
> CORRECTED(verify): previous text claimed a per-cookie split (`__Secure-refreshToken` vs `__Host-accessToken`); refuted — `getCookieName` never sees the refresh cookie's path override, all cookies share one prefix decision, and `__Host-refreshToken` (with Path forced to `/`) is the actual default-secure outcome.

Also: any request into the router when `config.csrf.enabled` and no `csrf-token` cookie is present triggers `initCsrfToken` (auto-init middleware, src/router/auth.router.ts:530-538; cookie attributes at token.service.ts:212-230, HttpOnly=false, Max-Age 900s). Pinned by tests/auth.router.test.ts:1018+.

#### Error envelope

`handleError` (:189-196): `AuthError` → `err.statusCode` + `{ error: <message>, code: <code> }`; anything else → `500 { error: 'Internal server error' }` (no `code`). `AuthError` carries an optional `data` payload (src/models/errors.ts:1-11), pinned by tests/auth.router.test.ts:763-776.

---

### GET /oauth/google (src/router/auth.router.ts:1322-1329), GET /oauth/github (:1368-1375), GET /oauth/:name (:1415-1421)

- **Auth gate:** none. **CSRF:** not applicable (GET; no token checks).
- **Query params:** `return_path` (string, optional) — embedded as `p` in the state (:1325-1326).
- **Behavior:** generate 32-hex nonce → `resolved = resolveSiteUrl(...)` → `state = resolved ? encodeOAuthState(nonce, resolved, returnPath) : nonce` (plain nonce whenever `resolved === ''`: no `email.siteUrl` default **and** no allowlist match on the request's `Origin`/`Referer` — this can happen even with `options.cors.origins` configured, e.g. a direct address-bar navigation that sends neither header, since `getDefaultSiteUrl` returns `''` when `email.siteUrl` is unset, :202-206, :233-246) → **302 redirect** to `strategy.getAuthorizationUrl(state)`.
> CORRECTED(verify): plain-nonce condition widened — previous text said it occurs "only when no siteUrl/cors is configured at all"; refuted — `resolveSiteUrl` falls back to `getDefaultSiteUrl` (empty when `email.siteUrl` is unset) whenever no Origin/Referer matches, regardless of `cors.origins`.
- **Success:** 302, `Location` = provider authorization URL with the `state` query param. No auth cookies set.
- **Errors:** none produced by the route itself.
- **Bearer mode:** no difference (header ignored).
- Tests: 302 to provider URL with `client_id` (tests/auth-flow-improvements.test.ts:670-686, :344-365; tests/examples-generic-oauth.test.ts:306-315); state encodes Origin-header origin (tests/auth-flow-improvements.test.ts:877-899).

### GET /oauth/google/callback (:1330-1359), GET /oauth/github/callback (:1376-1405), GET /oauth/:name/callback (:1422-1451)

- **Auth gate:** none. **CSRF:** none (and the state nonce is not verified — see above).
- **Query params:** `code` (string; passed to the strategy — the router does not itself validate presence), `state` (string, optional).
- **Flow:**
  1. `redirectTo = resolveOAuthRedirect(state, config, allowedOrigins)` (:1333).
  2. `user = strategy.handleCallback(code, state)` (:1334).
  3. If `options.linkedAccountsStore` **and** `user.providerAccountId` is set: `linkAccount(user.id, { provider: '<google|github|s.name>', providerAccountId, email: user.email, linkedAt: new Date() })`; failures are swallowed with a `console.error` (:1336-1343). Pinned: tests/auth-flow-improvements.test.ts:780-809.
  4. `handleOAuthLogin(req, res, user, config, redirectTo)` (:1298-1317):
     - `requires2fa = (user.isTotpEnabled && user.totpSecret) || user.require2FA` (:1299-1300).
     - **2FA path:** builds `available2faMethods` from `'totp'` (TOTP enabled), `'sms'` (`user.phoneNumber && config.sms`), `'magic-link'` (`config.email.sendMagicLink || config.email.mailer`) (:1302-1305); mints a `tempToken` = access token signed with `accessTokenExpiresIn: '5m'` (:1306-1309); **302 redirect to `${redirectTo}/auth/2fa?tempToken=<urlenc>&methods=<urlenc comma-joined list>`** (:1310-1313). Note this does **not** go through `buildUiLink` — no apiPrefix or `/ui/` segment is inserted (unlike the account-conflict redirect); the front-end origin must serve `/auth/2fa` itself. No auth cookies are set on this response. Pinned: tests/auth-flow-improvements.test.ts:708-734; bearer completion of the tempToken via `POST /2fa/verify` with `X-Auth-Strategy: bearer` returning top-level `accessToken`/`refreshToken` and no cookies: :736-778.
     - **No-2FA path:** `updateLastLogin(user.id)`; `issueTokens(..., redirectTo || '/')` → sets `accessToken`/`refreshToken` (+ `csrf-token` if enabled) cookies and **302 redirects to `redirectTo`** with no query params appended (:1315-1316, :445-447). Pinned: redirect to custom mobile scheme `myapp://auth` (tests/auth-flow-improvements.test.ts:688-706), redirect to state-embedded origin (:901-920). **dev line (node-auth@e8af923):** before `handleOAuthLogin` each callback pre-fills `user.loginProvider = user.loginProvider ?? '<google|github|s.name>'` (auth.router.ts:1476, :1526, :1576), so the callback-issued JWT pair carries `loginProvider: '<provider>'` where v1.9.0 signed `'local'` for strategies whose user lacks the field; the mutation is in-memory only, so `/me` and later `/refresh` pairs still derive from the DB user (§7 1.1, reference-issues.md N42). After `issueTokens` the no-2FA path also publishes `AUTH_OAUTH_SUCCESS` when a bus is set (:1443-1448); the 2FA redirect path emits nothing (§6 (8)).
- **Account-conflict flow** (`catch` on `AuthError` with `code === 'OAUTH_ACCOUNT_CONFLICT'` — google :1346-1356, github :1392-1401, generic :1438-1447). This error is thrown by the application's `findOrCreateUser`/`handleCallback`, never by the library itself; `err.data` may carry `{ email, providerAccountId }`:
  1. `siteUrl = resolveOAuthRedirect(state, ...)`.
  2. If `options.pendingLinkStore` and both `email` and `providerAccountId` are present: `pendingLinkStore.stash(email, provider, providerAccountId)` (failures swallowed, console.error).
  3. **302 redirect** to `buildUiLink(siteUrl, '/account-conflict?provider=<name>&code=OAUTH_ACCOUNT_CONFLICT[&email=<urlencoded>]', ...)` — i.e. `<siteUrl><prefix>/ui/account-conflict?...` with the built-in UI enabled (page exists: src/ui/assets/account-conflict.html, served by src/router/ui.router.ts:295-326), else `<siteUrl><prefix>/account-conflict?...`. The `email` param is omitted when `err.data` has no email. For generic providers the provider name is URL-encoded (:1445); for google/github it is interpolated literally (:1353, :1399).
  - Pinned: stash called with `(email, providerName, providerAccountId)`, location contains `account-conflict`, `provider=fakeprovider`, `email=conflict%40test.com` (tests/auth.router.test.ts:959-992); no `email=` param when `AuthError` has no data (:994-1015).
- **Other callback errors:** `handleError` returns **JSON, not a redirect** — e.g. `401 { error: 'Google token exchange failed', code: 'OAUTH_TOKEN_EXCHANGE_FAILED' }` or `401 { ..., code: 'OAUTH_PROFILE_FAILED' }` from the strategies; unexpected errors → `500 { error: 'Internal server error' }` (:1357, :1403, :1449). A browser mid-flow lands on a raw JSON page. [UNTESTED]
- **Bearer mode:** no difference; tokens are only ever delivered via cookies on this route. Native apps get credentials from the OAuth flow only via (a) the cookie jar, or (b) the `tempToken` query param on the 2FA variant (tests/auth-flow-improvements.test.ts:736-778 shows the intended native pattern; Flutter's `handleOAuthCallback` relies on the cookie session via `checkSession()`, awesome-node-auth-flutter/lib/src/platform/base_auth_client.dart:615-621).

### 404 stubs when a strategy is absent (:1360-1363, :1406-1409)

- Google not configured: `GET /oauth/google` and `GET /oauth/google/callback` → **404 `{ error: 'Google OAuth not configured' }`** (no `code` field). GitHub: **404 `{ error: 'GitHub OAuth not configured' }`**. Registered without the rate limiter. [UNTESTED — only route *presence* is pinned indirectly via OpenAPI (tests/swagger.test.ts:110-129); no test asserts the stub body]
- **No stubs exist for generic providers**: a request to `/oauth/<unregistered-name>` falls through to Express's default 404 HTML.

### GET /linked-accounts (:1458-1465)

- **Auth gate:** `authMiddleware` (created at :466 as `createAuthMiddleware(config)` — **without** a sessionStore, so the middleware's `SESSION_REVOKED` branch (src/middleware/auth.middleware.ts:47-52) is unreachable on this router's routes). Token source: `Authorization: Bearer` preferred, else `accessToken` cookie with `__Host-`/`__Secure-` resolution (auth.middleware.ts:19-28).
  - No token → **403 `{ error: 'No access token provided' }`** (no `code`; auth.middleware.ts:29-32). Pinned: tests/auth-flow-improvements.test.ts:255-261; tests/examples-generic-oauth.test.ts:288-292.
  - Invalid/expired token → **403 `{ error: 'Invalid or expired access token' }`** (no `code`; auth.middleware.ts:62-64).
  - Note these are **403, not 401** — client refresh interceptors keyed on 401 will not fire here.
- **CSRF:** skipped (GET is a safe method, auth.middleware.ts:34-35).
- **Success:** **200 `{ linkedAccounts: LinkedAccount[] }`** — object wrapper, not a bare array (:1461). `LinkedAccount` = `{ provider: string, providerAccountId: string, email?: string, name?: string, picture?: string, linkedAt?: Date }` (src/interfaces/linked-accounts-store.interface.ts:4-17). Pinned: `res.body.linkedAccounts` has length 2 (tests/auth-flow-improvements.test.ts:241-253).
- **Errors:** store failures → `handleError`.
- **Bearer mode:** identical response body.
- **Client cross-check:**
  - Angular reads `res.linkedAccounts || []` (ng-awesome-node-auth/projects/ng-awesome-node-auth/src/lib/auth.service.ts:350-351) — matches.
  - served auth.js expects `{ linkedAccounts: [...] }` (tests/auth-js.test.ts:663-668) — matches.
  - **[MISMATCH] Flutter** `getLinkedAccounts()` only accepts a bare JSON array (`if (data is List) return data;` else returns `[]`, awesome-node-auth-flutter/lib/src/platform/base_auth_client.dart:552-561). Against this router it always yields an empty list even when accounts exist.

### DELETE /linked-accounts/:provider/:providerAccountId (:1468-1476)

- **Auth gate:** `authMiddleware` (same as GET above).
- **CSRF:** applies in cookie mode when `config.csrf.enabled` (DELETE is not a safe method): double-submit `csrf-token` cookie vs `X-CSRF-Token` header, mismatch → **403 `{ error: 'CSRF token validation failed', code: 'CSRF_INVALID' }`** (auth.middleware.ts:33-42). Bearer-authenticated requests are exempt (`usingBearer`). [UNTESTED for this specific route]
- **Path params:** `provider`, `providerAccountId` (both strings, raw from URL).
- **Success:** **200 `{ success: true }`** — unconditional; no existence check (unlinking an unknown pair still returns success if the store resolves). Pinned: tests/auth-flow-improvements.test.ts:263-275 (also pins `unlinkAccount('u1','google','g123')` args).
- **Errors:** store failures → `handleError`.
- **Bearer mode:** identical body; CSRF skipped.

### POST /link-request (:1482-1540)

Supports both authenticated linking (add a secondary email/provider) and unauthenticated conflict-linking (after an `OAUTH_ACCOUNT_CONFLICT` stashed a pending link).

- **Auth gate:** none (deliberately no `authMiddleware`, comment :1488). Identity is resolved manually — see below.
- **CSRF:** manual check when `config.csrf.enabled` (:1489-1495): `csrf-token` cookie (prefix-resolved) must equal the `x-csrf-token` header, else **403 `{ error: 'CSRF validation failed', code: 'CSRF_INVALID' }`** (note the message differs from the middleware's "CSRF token validation failed"). **[MISMATCH] Unlike `authMiddleware`, there is no bearer exemption: a native client with `X-Auth-Strategy: bearer` and no cookie jar will fail this check whenever CSRF is enabled server-side.** [UNTESTED — all tests run with CSRF disabled]
- **Precondition:** `userStore.updateAccountLinkToken` must exist, else **500 `{ error: 'UserStore does not implement updateAccountLinkToken', code: 'NOT_IMPLEMENTED' }`** (:1484-1487). Pinned: tests/auth-flow-improvements.test.ts:457-483.
- **Request body:** `{ email: string (required), provider?: string (default `'email'`, :1496), emailLang?: string }`.
  - Missing `email` → **400 `{ error: 'email is required', code: 'EMAIL_REQUIRED' }`** (:1497-1499). Pinned: :429-443.
- **Identity resolution (:1500-1524):**
  1. `accessToken` cookie or `Authorization: Bearer <token>` → verify → `userId = payload.sub`; invalid/expired tokens are silently ignored (fall through).
  2. Fallback (conflict flow): no `pendingLinkStore` → **401 `{ error: 'Authentication required', code: 'UNAUTHORIZED' }`** (:1514-1516; pinned :445-455). With a store: `pendingLinkStore.retrieve(email, provider)`; no entry → **401 `{ error: 'Authentication required or no pending link found', code: 'UNAUTHORIZED' }`** (:1517-1520; pinned :612-628); then `userStore.findByEmail(email)`; not found → **404 `{ error: 'Target user not found', code: 'USER_NOT_FOUND' }`** (:1521-1522). [UNTESTED: the 404 branch]
- **Effect:** `tokenCode = generateSecureToken()` (32 bytes → 64 hex chars, token.service.ts:270-272); expiry = now + 1 hour (:1525-1526); `updateAccountLinkToken(userId, email, provider, tokenCode, expiry)` (:1527). Verification link = `buildUiLink(resolveSiteUrl(req,...), '/link-verify?token=<tokenCode>', ...)` (:1528-1529) sent via `config.email.sendVerificationEmail(email, tokenCode, link, emailLang)` or the `MailerService` fallback (:1530-1535) — it reuses the *verification email* sender. Pinned: tests/auth-flow-improvements.test.ts:402-427 (link contains `/auth/link-verify?token=`); custom-scheme siteUrl `myapp://auth/auth/link-verify?token=` (tests/auth.router.test.ts:648-685). If neither email transport is configured, no email is sent but the response is still success. [UNTESTED]
- **Success:** **200 `{ success: true }`** (:1536).
- **Bearer mode:** `X-Auth-Strategy` itself is irrelevant; `Authorization: Bearer` alone authenticates (pinned: tests/auth.router.test.ts:733-754). But see the CSRF caveat above.
- **Client cross-check:** auth.js `requestLinkingEmail` posts `{ email, provider }` (tests/auth-js.test.ts:628-636) — matches.

### POST /link-verify (:1544-1594)

- **Auth gate:** none (the user proves identity via the emailed token; pinned "no auth required" tests/auth.router.test.ts:714-717). **CSRF: none at all** — asymmetric with `/link-request`, despite being a state-changing POST.
- **Precondition:** `userStore.findByAccountLinkToken` and `updateAccountLinkToken` must exist, else **500 `{ error: 'UserStore does not implement account-link methods', code: 'NOT_IMPLEMENTED' }`** (:1546-1549). [UNTESTED]
- **Request body:** `{ token: string (required), loginAfterLinking?: boolean }`. Extra fields (e.g. the `provider` auth.js sends, tests/auth-js.test.ts:643-648) are ignored.
- **Errors** (all pinned in tests/auth-flow-improvements.test.ts:485-563):
  - Missing token → **400 `{ error: 'token is required', code: 'TOKEN_REQUIRED' }`** (:1551-1554).
  - Unknown token or `user.accountLinkToken !== token` → **400 `{ error: 'Invalid account-link token', code: 'INVALID_LINK_TOKEN' }`** (:1555-1559).
  - `accountLinkTokenExpiry` in the past → **400 `{ error: 'Account-link token has expired', code: 'LINK_TOKEN_EXPIRED' }`** (:1560-1563).
  - No `accountLinkPendingEmail` on the user → **400 `{ error: 'No pending email found for this link token', code: 'INVALID_STATE' }`** (:1564-1567). [UNTESTED]
- **Effect (:1568-1585):** `email = accountLinkPendingEmail`; `provider = accountLinkPendingProvider ?? 'email'`; `providerAccountId` defaults to the email, but if `pendingLinkStore.retrieve(email, provider)` returns a stashed entry, the stashed OAuth `providerAccountId` is used and `pendingLinkStore.remove(email, provider)` is called (failures swallowed). Then `linkedAccountsStore.linkAccount(user.id, { provider, providerAccountId, email, linkedAt: new Date() })` and the link token is cleared via `updateAccountLinkToken(user.id, null, null, null, null)`. Pinned: tests/auth-flow-improvements.test.ts:485-511; tests/auth.router.test.ts:687-731.
- **Success:**
  - Without `loginAfterLinking`: **200 `{ success: true }`**, no cookies, no token issuance (pinned tests/auth.router.test.ts:869-891).
  - With `loginAfterLinking: true` (:1586-1589): `issueTokens` without redirect → cookie mode: token cookies set + **200 `{ success: true }`** (pinned tests/auth.router.test.ts:834-867 incl. `updateRefreshToken` persistence); bearer mode (`X-Auth-Strategy: bearer`): **200 `{ success: true, accessToken, refreshToken }`**, no cookies (`sendTokens`, :399-406). [UNTESTED: the bearer variant of this specific route] A session is created when `sessionStore` is configured.
- **Client cross-check:** Flutter `verifyConflictLinkingToken` posts `{ token, loginAfterLinking: true }` (awesome-node-auth-flutter/lib/src/platform/base_auth_client.dart:541-549) — matches; auth.js `verifyConflictLinkingToken` same (tests/auth-js.test.ts:651-661) — matches.

### Pending-link stash — `IPendingLinkStore` (src/interfaces/pending-link-store.interface.ts:61-77)

`stash(email, provider, providerAccountId): Promise<void>`, `retrieve(email, provider): Promise<{ providerAccountId: string } | null>`, `remove(email, provider): Promise<void>`. Usage points: stash on conflict (auth.router.ts:1349-1351, 1395-1397, 1441-1443), retrieve for unauthenticated `/link-request` identity (:1517) and for the real `providerAccountId` in `/link-verify` (:1572-1577), remove after consumption (:1576). Reference in-memory implementation pinned in tests/auth.router.test.ts:894-924. Entries have no TTL enforcement in the contract.

### Provider strategy contract

`BaseOAuthStrategy<TUser>` (src/abstract/base-oauth-strategy.abstract.ts:5-16):

- `abstract name: string` — becomes the route segment and the `provider` value in linked accounts.
- `abstract getAuthorizationUrl(state?: string): string`
- `abstract handleCallback(code: string, state?: string): Promise<TUser>`
- `protected abstract exchangeCodeForTokens(code): Promise<{ accessToken: string; idToken?: string }>`
- `protected abstract getUserProfile(accessToken): Promise<{ id: string; email: string; emailVerified?: boolean; name?: string; picture?: string }>`
- `authenticate({code, state})` delegates to `handleCallback`.

The router additionally reads `user.providerAccountId` off the returned user for auto-linking (auth.router.ts:1336) — a strategy that wants auto-linking must set it on the user object.

**GoogleStrategy** (src/strategies/oauth/google.strategy.ts): `name = 'google'` (:7); requires `config.oauth.google` `{clientId, clientSecret, callbackUrl}` else throws `AuthError('Google OAuth not configured', 'OAUTH_NOT_CONFIGURED', 500)` at construction (:15-17). Authorization URL `https://accounts.google.com/o/oauth2/v2/auth` with `response_type=code`, `scope='openid email profile'`, `access_type=offline`, optional `state` (:23-33). Token exchange: POST form-encoded to `https://oauth2.googleapis.com/token`; failure → `AuthError('Google token exchange failed', 'OAUTH_TOKEN_EXCHANGE_FAILED', 401)` (:35-50). Profile: `https://www.googleapis.com/oauth2/v3/userinfo` with `Authorization: Bearer`; `id` = `sub`; failure → `AuthError('Failed to get Google user profile', 'OAUTH_PROFILE_FAILED', 401)` (:52-59). `findOrCreateUser(profile, state?)` is abstract (:67).

**GithubStrategy** (src/strategies/oauth/github.strategy.ts): `name = 'github'` (:7); requires `config.oauth.github` else `OAUTH_NOT_CONFIGURED` 500 (:15-17). Authorization `https://github.com/login/oauth/authorize`, `scope='user:email'` — note: no `response_type` param (:23-31). Token exchange: POST JSON to `https://github.com/login/oauth/access_token` with `Accept: application/json`; failure → `OAUTH_TOKEN_EXCHANGE_FAILED` 401 (:33-47). Profile: parallel `GET https://api.github.com/user` + `/user/emails` with `Authorization: token <at>`; email falls back to the primary verified entry, then the first entry, from `/user/emails` when the profile email is null; `id = String(user.id)`, `name = user.name ?? user.login`, `picture = avatar_url` (:49-70).

**GenericOAuthStrategy** (src/strategies/oauth/generic-oauth.strategy.ts:98-173) + **GenericOAuthProviderConfig** (:39-78):

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | provider id → route `/oauth/<name>` |
| `clientId` / `clientSecret` | string | yes | OAuth app credentials |
| `callbackUrl` | string | yes | full redirect URL sent as `redirect_uri` |
| `authorizationUrl` / `tokenUrl` / `userInfoUrl` | string | yes | provider endpoints |
| `scope` | string \| string[] | yes | arrays are joined with a space (:110-112; pinned tests/auth-flow-improvements.test.ts:332-342) |
| `additionalAuthParams` | Record<string,string> | no | extra authorize-URL query params (:63, spread before `state`, :118) |
| `mapProfile` | `(raw) => {id, email, emailVerified?, name?, picture?}` | no | default mapping: `id = raw.id ?? raw.sub` (stringified), `email`, `email_verified`, `name`, `picture` (:154-160) |

- `getAuthorizationUrl(state?)`: `authorizationUrl?client_id&redirect_uri&response_type=code&scope&<additional>&state?` (:109-122; pinned tests/auth-flow-improvements.test.ts:316-330, incl. omission of `state=` when absent).
- `exchangeCodeForTokens`: POST `application/x-www-form-urlencoded` with `code, client_id, client_secret, redirect_uri, grant_type=authorization_code`, `Accept: application/json`; non-OK → `AuthError('<name> token exchange failed', 'OAUTH_TOKEN_EXCHANGE_FAILED', 401)` (:124-141).
- `getUserProfile`: GET `userInfoUrl` with `Authorization: Bearer`; non-OK → `AuthError('Failed to get <name> user profile', 'OAUTH_PROFILE_FAILED', 401)` (:143-161).
- `handleCallback(code, state?)`: exchange → profile → `findOrCreateUser(profile, state)` (abstract, :163-172).

### Mismatch and gap summary

1. **[MISMATCH] Flutter `getLinkedAccounts` expects a bare JSON array**; the router returns `{ linkedAccounts: [...] }` (auth.router.ts:1461), so the Flutter helper always yields `[]` (awesome-node-auth-flutter/lib/src/platform/base_auth_client.dart:552-561). Angular and auth.js expect the wrapped object and match.
2. **[MISMATCH] `/link-request` CSRF check has no bearer exemption** (auth.router.ts:1489-1495) — native `X-Auth-Strategy: bearer` clients fail with 403 `CSRF_INVALID` when CSRF is enabled server-side, unlike every `authMiddleware`-gated route (auth.middleware.ts:35). [UNTESTED]
3. `/link-verify` performs **no CSRF check** despite being a state-changing POST (:1544-1594).
4. The state **nonce (`n`) is never verified**; the "CSRF protection" comment at auth.router.ts:288 is not implemented — only origin allowlisting exists. With an empty allowlist, any state-supplied origin is honored (:327).
5. OAuth callback errors other than `OAUTH_ACCOUNT_CONFLICT` return **JSON (401/500), not a redirect** (:1357), stranding browser flows. [UNTESTED]
6. The 2FA callback redirect bypasses `buildUiLink` (raw `${redirectTo}/auth/2fa?...`, :1312) while the account-conflict redirect uses it (`<prefix>/ui/account-conflict` with the built-in UI) — a front-end must serve `/auth/2fa` at its own origin.
7. Auth failures on `/linked-accounts` are **403 without a `code` field** (auth.middleware.ts:30, :63) — never 401 `SESSION_REVOKED`, because the router builds its middleware without a sessionStore (auth.router.ts:466).
8. Google/GitHub 404 stub bodies (`{ error: '<Provider> OAuth not configured' }`, no `code`) are [UNTESTED]; generic providers get Express's HTML 404 instead of a JSON stub.
9. Cookie Max-Age values are fixed (15m access / 7d refresh) regardless of configured JWT expiries (token.service.ts:195-202) — JWT lifetime and cookie lifetime can diverge.

---

## 5. Admin router (complete surface)

Scope: complete wire contract of `src/router/admin.router.ts` in awesome-node-auth (pinned cc01e997), covering all 50 route registrations (the recon inventory claimed 51 — see the count note below), the three guard modes (legacy `adminSecret`, `accessPolicy` policy guard, unprotected fallback), the self-contained admin login/logout with its `__Host-`-aware cookie, upload/settings/webhook/template/api-key/session/role/tenant endpoint groups, optional-store gating, and the Swagger endpoints. Every claim carries a `file:line` reference into the router or its interfaces; test pins cite `tests/new-features.test.ts` and `tests/swagger.test.ts`. Behaviors with no test are marked [UNTESTED]. All error bodies on this router use `{error: string}` — **no route on the admin router ever emits a `code` field** (relevant to the client-contract cross-check at the end).

### Route count note

`grep 'router.(get|post|put|patch|delete)('` over src/router/admin.router.ts yields exactly **50** registrations, first at src/router/admin.router.ts:543 (`POST /login`) and last at src/router/admin.router.ts:1517 (`GET /api/docs`). The recon inventory's "51 routes" is off by one — [MISMATCH] with recon, not with any client. (`router.use(expressJson())` at src/router/admin.router.ts:509 is middleware, not a route; it means the admin router parses JSON bodies itself even if the host app has no body parser.) **dev line (node-auth@e8af923):** **51** registrations — the same 50 plus `POST /users/:id/promote` (src/router/admin.router.ts:1030-1064; documented under "User ↔ role assignment" below). Still no `code` field on any admin error body.

### Guard selection (applies to every `guard`-protected route)

Priority: `accessPolicy` (new) > `adminSecret` (legacy) > open with a stderr warning (src/router/admin.router.ts:511-537).

**Legacy `adminSecret` guard** (`adminAuth`, src/router/admin.router.ts:189-203):
- No `Authorization: Bearer …` header → `401 {"error":"Unauthorized"}` (:192-195). Pinned: tests/new-features.test.ts:409-412.
- Bearer token !== `adminSecret` → `403 {"error":"Forbidden"}` (:196-200). Pinned: tests/new-features.test.ts:414-417.
- Match → next(). Pinned: tests/new-features.test.ts:419-426.

**Policy guard** (`buildPolicyGuard`, src/router/admin.router.ts:259-397):
- `'open'` → `next()` immediately, no token read at all (:269).
- Token extraction (only when `jwtSecret` set): `Authorization: Bearer` first, then cookie (:276-296). Cookie name: with `cookiePrefix` configured, only `${cookiePrefix}accessToken` (:291); otherwise priority `__Host-accessToken` > `__Secure-accessToken` > `accessToken` (:294). Falls back to raw `Cookie`-header parsing when cookie-parser is absent (:282-289); pinned by tests/new-features.test.ts:1379 (app deliberately has no cookie-parser) + :1437-1452.
- Invalid/missing token: if `Accept` includes `text/html` — `302` to `${loginPath}?redirect=<encodeURIComponent(req.baseUrl+req.path)>` when `loginPath` set (:312-315) [UNTESTED]; else GET requests pass through with `(req as any).adminNeedsAuth = true` so `GET /` serves the built-in login form (:318-325) [UNTESTED]; non-GET HTML → `401 {"error":"Unauthorized"}` (:328). Non-HTML → `401 {"error":"Unauthorized"}` (:330).
- Payload without `sub` → `401 {"error":"Unauthorized"}` (:336-340). [UNTESTED]
- **Root override**: payload `isRoot === true` → synthetic user `{id, email: payload.email || 'root@admin', isAdmin: true}` is attached and the policy check is **bypassed entirely** (:343-352). [UNTESTED]
- `userStore.findById(sub)` null/throws → `401 {"error":"Unauthorized"}` (:354-364). [UNTESTED]
- Policy evaluation (:366-385): `'is-admin-flag'` → `user.isAdmin === true` (:369-370); `'first-user'` → `listUsers(1,0)[0].id === user.id` (:371-374), and if `listUsers` is not implemented → `500 {"error":"accessPolicy: first-user requires IUserStore.listUsers to be implemented"}` (:375-379) [UNTESTED]; custom function → `await policy(user, rbacStore)` (:380-381) [UNTESTED]; any throw → denied (:383-385). Denied → `403 {"error":"Forbidden"}` (:387-390). [UNTESTED for is-admin-flag denial path]
- On success `(req as any).user = user` (:392-394).
- **dev line (node-auth@e8af923):** the root-override synthetic user gains `roles: ['admin']` (admin.router.ts:405-416; typed `AuthorizedAdminUser = BaseUser & { roles: string[] }`, :30, exported from src/index.ts:68); after `findById`, `roles = rbacStore ? await rbacStore.getRolesForUser(user.id).catch(() => []) : []` and `authorizedUser = { ...user, roles }` (:431-432) — one extra RBAC read per guarded request when `rbacStore` is configured, failures collapse to `[]`; the policy (`is-admin-flag`, `first-user`, custom fn now typed `(user: AuthorizedAdminUser, rbacStore?) => boolean | Promise<boolean>`, :52) evaluates `authorizedUser` (:436-450) and `(req as any).user = authorizedUser` (:462). Nothing changes on the wire — `req.user` is never serialized. Pinned: tests/dx-improvements.test.ts:76-112.

**Neither configured** → stderr warning `[awesome-node-auth] WARNING: createAdminRouter called without \`accessPolicy\` or \`adminSecret\`. …` and a pass-through guard (:530-537). [UNTESTED]

### Self-contained admin auth (only when `accessPolicy` set and !== `'open'` AND `jwtSecret` provided)

Registration is conditional: `if (sessionBased && secret)` (src/router/admin.router.ts:542), where `sessionBased = options.accessPolicy !== 'open'` (:526) and `secret = options.jwtSecret` (:539). With a legacy `adminSecret`-only setup, `POST /admin/login` and `POST /admin/logout` do **not exist** (Express default 404). [UNTESTED for the absent case]

**POST /login** (src/router/admin.router.ts:543) — no guard, no CSRF.
- Body: `{email?: string, password: string}`. Missing `password` → `400 {"error":"Password required"}` (:545-548). [UNTESTED]
- Credential check order:
  1. `rootUser`: `email === options.rootUser.email` and `bcrypt.compare(password, rootUser.passwordHash)` → `{id:'root', email, isRoot:true}` (:553-557). [UNTESTED]
  2. `adminSecret` bootstrap: when no match yet, `options.adminSecret` set, and (`email` empty OR `email === 'admin'`), plain equality `password === options.adminSecret` → `{id:'admin', email:'admin@bootstrap', isRoot:true}` (:560-564). [UNTESTED]
  3. `userStore.findByEmail(email)` + `bcrypt.compare(password, user.password)` (:567-574). Pinned: tests/new-features.test.ts:1396-1406.
- All fail → `401 {"error":"Invalid credentials"}` (:576-579). Pinned: tests/new-features.test.ts:1388-1394.
- **JWT**: `jwt.sign({sub, email, isRoot}, options.jwtSecret, {expiresIn: '24h'})` (:582-586). The 24h admin JWT is signed with **`AdminOptions.jwtSecret`** — the same secret documented to match `AuthConfig.accessTokenSecret` (:71-78) — never with `adminSecret`. Claims: `sub` (user id / `'root'` / `'admin'`), `email`, `isRoot` (undefined for regular users), plus standard `iat`/`exp`.
- **Cookie**: `isSecure = req.secure === true || req.headers['x-forwarded-proto'] === 'https'` (:591). Name via `resolveAdminCookieName` (:218-232): explicit `cookiePrefix` always wins → `${cookiePrefix}accessToken` (:224-227); HTTP → `accessToken` (:228); HTTPS + (path unset or `/`) + no domain → `__Host-accessToken` (:229-230); HTTPS otherwise → `__Secure-accessToken` (:231). Default attributes: `httpOnly: true, secure: isSecure, sameSite: 'lax', path: '/', maxAge: 24*60*60*1000` (86400000 ms = 24h, aligned with the JWT) (:603-611). An undeclared `(options as any).cookieOptions` overrides the whole attribute object (:596) — **not part of the public `AdminOptions` interface** (:44-186), a hidden option. `applyHostCookieRequirements` (:243-250) then forces `secure=true`, `path='/'` and deletes `domain` whenever the name starts with `__Host-`.
- Response: `200 {"success":true}` (:614).
- Test pins: HttpOnly set — tests/new-features.test.ts:1396-1406; plain `accessToken` name on HTTP — :1408-1420; Max-Age/Expires present (24h persistence) — :1422-1435; cookie readable by guard on next request — :1437-1452; `__Host-accessToken` + `Secure` + `Path=/` under `x-forwarded-proto: https` — :1478-1494. `SameSite=Lax` attribute itself is [UNTESTED].

**POST /logout** (src/router/admin.router.ts:618) — no guard, no CSRF, no body.
- Recomputes the identical cookie name from `isSecure`/`cookiePrefix`/explicit options (:619-626) and `res.clearCookie(name, opts)` with `{httpOnly:true, secure:isSecure, sameSite:'lax', path:'/'}` (no maxAge) (:627-633). Response `200 {"success":true}` (:634).
- Pinned: clears the same name set at login with `Max-Age=0`/1970 expiry — tests/new-features.test.ts:1454-1476; clears `__Host-accessToken` on HTTPS — :1496-1515.

### UI shell & public static assets (no store gating)

**dev line (node-auth@e8af923):** the built-in admin login form served to an unauthenticated HTML `GET /` gains `<p …>End-user login is at <code>/auth/ui/login</code>. This is the admin panel.</p>` (src/router/admin.router.ts:533) — a literal `/auth/…` path that ignores `apiPrefix`; cosmetic, body not pinned by any test.

| Route | Guard | Notes |
|---|---|---|
| `GET /assets/admin.css` (src/router/admin.router.ts:690) | **none** | 200 `Content-Type: text/css; charset=utf-8`, `Cache-Control: public, max-age=3600`; `404` plain-text `Not found` if the asset file was not found at startup (:691). [UNTESTED] |
| `GET /assets/admin.js` (:696) | **none** | same, `application/javascript; charset=utf-8`. [UNTESTED] |
| `GET /` (:738) | policy guard when `sessionBased`, otherwise **none** (:707-737) | 200 HTML shell. Headers: `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-store, no-cache, must-revalidate, max-age=0`, `Pragma: no-cache`, `Expires: 0`. Injects `window.__ADMIN_CONFIG__` JSON with keys `base, featSessions, featRoles, featTenants, featMetadata, feat2faPolicy, featControl, featLinkedAccounts, featApiKeys, featWebhooks, featTemplates, featUpload, uploadBaseUrl, sessionBased, authApiPrefix` (default `'/auth'`), `cookiePrefix` (:429-446). Pinned: tests/new-features.test.ts:402-407 (HTML served), :617-628 (`featLinkedAccounts` true/false), :1239-1243 (Control tab). |

### GET /api/ping (src/router/admin.router.ts:741) — guard

`200 {"ok":true,"features":{"sessions":b,"roles":b,"tenants":b,"metadata":b,"twoFAPolicy":b,"control":b,"linkedAccounts":b,"apiKeys":b,"webhooks":b,"templates":b,"upload":b}}` (:742). Feature flags computed at :645-656: each is presence of the corresponding optional store; `twoFAPolicy` requires **both** a `updateRequire2FA` function and `listUsers` on the user store (:649-650); `upload` = `!!options.uploadDir` (:656). Pinned: tests/new-features.test.ts:419-426, :578-582, :861-869, :1233-1237.

### Users (always registered; degrade via 501)

**GET /api/users?limit=&offset=&filter=** (src/router/admin.router.ts:748)
- `limit` default 20, capped at 100; `offset` default 0; `filter` lowercased substring match on `email` or `id` (:750-752, :774-775).
- `userStore.listUsers` missing → `501 {"error":"IUserStore.listUsers is not implemented","users":[],"total":0}` (:753-756). [UNTESTED]
- With `filter`: fetches up to 500 records from offset 0, filters in memory, `total` = filtered count, then slices `[offset, offset+limit)` (:760-780). Pinned: tests/new-features.test.ts:1325-1336.
- Projection per user: `{id, email, role, isEmailVerified, isTotpEnabled, require2FA, phoneNumber, createdAt}` (:764-773) — password/refreshToken stripped, pinned tests/new-features.test.ts:428-436.
- Without filter: `200 {"users":[…],"total": users.length + offset + (users.length === limit ? 1 : 0)}` (:782) — **`total` is a pagination heuristic, not a real count**; clients must not treat it as exact.
- Store throw → `500 {"error":"Internal server error"}` (:783-785). [UNTESTED]

**GET /api/users/:id** (:789) — not found → `404 {"error":"User not found"}` [UNTESTED]; `200 {id, email, role, isEmailVerified, isTotpEnabled}` (:793-796) — note the detail projection has **fewer fields** than the list projection (no `require2FA`/`phoneNumber`/`createdAt`). Pinned: tests/new-features.test.ts:438-442.

**DELETE /api/users/:id** (:803) — duck-typed `deleteUser`; implemented → `200 {"success":true}`; missing → `501 {"error":"IUserStore.deleteUser is not implemented"}` (:806-811). [UNTESTED]

### 2FA policy

**POST /api/2fa-policy** (src/router/admin.router.ts:820) — body `{required: boolean}` (required, strict boolean).
- Non-boolean → `400 {"error":"\"required\" must be a boolean"}` (:823-826). Pinned: tests/new-features.test.ts:835-841.
- `updateRequire2FA` missing → `501 {"error":"IUserStore.updateRequire2FA is not implemented"}` (:827-830). Pinned: :843-859. `listUsers` missing → `501 {"error":"IUserStore.listUsers is not implemented"}` (:831-834). [UNTESTED]
- Iterates all users in batches of 100 (:836-847), `200 {"success":true,"updated":<count>}` (:848). Pinned: :812-833.

### User metadata (gated: `userMetadataStore`; absent → `404 {"error":"User metadata store not configured"}`)

- **GET /api/users/:id/metadata** (src/router/admin.router.ts:855) → `200` with the **raw metadata object, unwrapped** (:859). Pinned: tests/new-features.test.ts:501-528 (empty `{}` default, round-trip).
- **PUT /api/users/:id/metadata** (:866) — body: arbitrary JSON object, replaces via `updateMetadata` → `200 {"success":true}` (:871). Pinned: :509-516.

### Linked accounts (gated: `linkedAccountsStore`; absent → `404 {"error":"Linked accounts store not configured"}`)

- **GET /api/users/:id/linked-accounts** (src/router/admin.router.ts:880) → `200 {"linkedAccounts":[…]}` (:884) — wrapped. Pinned: tests/new-features.test.ts:584-600 (incl. empty array), :602-605 (401 without auth), :607-615 (404 when store absent).
- Cross-check note: the client-contract divergence (Angular expects `{linkedAccounts:[…]}`, Flutter expects a bare array) concerns the **auth** router's `/linked-accounts`; the **admin** router unambiguously returns the wrapped `{linkedAccounts:[…]}` form.

### User ↔ role assignment (gated: `rbacStore`; absent → `404 {"error":"RBAC store not configured"}`)

- **GET /api/users/:id/roles** (src/router/admin.router.ts:893) → `200 {"roles":[…]}` (string array from `getRolesForUser`) (:897). Pinned: tests/new-features.test.ts:530-534.
- **POST /api/users/:id/roles** (:904) — body `{role: string (required), tenantId?: string}`; missing role → `400 {"error":"role is required"}` (:908) [UNTESTED]; → `200 {"success":true}`. Pinned: :536-543.
- **DELETE /api/users/:id/roles/:role** (:917) — `:role` is `decodeURIComponent`ed (:922) → `200 {"success":true}`. Pinned: :545-551.
- **dev line (node-auth@e8af923): POST /users/:id/promote** (src/router/admin.router.ts:1030-1064) — the only admin JSON route **not** under `/api/`; middleware order `...rateLimiter, guard` (`AdminOptions.rateLimiter`, :208-211, is prepended here and nowhere else — :577, :1030). Body `{ method?: 'flag' | 'role' }`, default `'role'` (:1032). `flag`: `userStore.update` absent → **`501 {"error":"IUserStore.update is required for method=flag"}`** (:1036-1039), else `update(userId, { isAdmin: true })` → **`200 {"success":true,"method":"flag"}`** (:1040-1045). `role`: no `rbacStore` → **`404 {"error":"RBAC store not configured"}`** (:1049-1052), else `createRole('admin')` then `addRoleToUser(userId, 'admin')` (no tenant) → **`200 {"success":true,"method":"role"}`** (:1053-1059). Any throw → `500 {"error":"Internal server error"}` (:1060-1062). Absent from `buildAdminOpenApiSpec` (src/router/openapi.ts) and from `admin.js`. Under `AuthConfigurator.buildAllRouters` the full path is `<apiPrefix>/admin/users/:id/promote` (src/auth-configurator.ts:63-78). Pinned: tests/dx-improvements.test.ts:145-178. The two `/api/users/:id/roles*` mutations above additionally publish `ROLE_ASSIGNED` / `ROLE_REVOKED` when a bus is set (§6 (8)); their responses are unchanged.

### User ↔ tenant view (gated: `tenantStore`)

- **GET /api/users/:id/tenants** (src/router/admin.router.ts:933) → `200 {"tenantIds":[…]}` — maps tenant objects to their `id`s (:936-937); absent store → `404 {"error":"Tenant store not configured"}`. Pinned: tests/new-features.test.ts:1269-1282 (incl. 404 case).

### Webhook actions metadata

- **GET /api/actions** (src/router/admin.router.ts:946) — guard, **not gated on any store** → `200 {"actions":[WebhookActionMeta…]}` from `ActionRegistry.getAllMeta()` (:947; src/tools/webhook-action.ts:81-83). Each item: `{id: string, label: string, category: string, description: string, dependsOn?: string[]}` minus the `fn` reference (src/tools/webhook-action.ts:34-49) — `description` is a **required** field of `WebhookActionMeta` (:42), only `dependsOn` is optional. [UNTESTED]
> CORRECTED(verify): `description` is required in `WebhookActionMeta`, not optional as previously stated.

### Settings (gated: `settingsStore`; absent → `404 {"error":"Settings store not configured"}`)

`AuthSettings` shape (src/interfaces/settings-store.interface.ts:45-92):
`requireEmailVerification?: boolean`; `emailVerificationMode?: 'none'|'lazy'|'strict'` (overrides the legacy flag); `lazyEmailVerificationGracePeriodDays?: number` (doc default 7); `require2FA?: boolean`; `enabledWebhookActions?: string[]` (global allowlist intersected with each webhook's `allowedActions`); `ui?: {primaryColor, secondaryColor, logoUrl, siteName, logoPath, bgColor, bgImage, cardBg}` — all strings (:79-91).

- **GET /api/settings** (src/router/admin.router.ts:951) → `200` with the **raw AuthSettings object, unwrapped** (:955). Pinned: tests/new-features.test.ts:1245-1249, 404-when-absent :1261-1266.
- **PUT /api/settings** (:962) — body `Partial<AuthSettings>` (shallow merge is the store's contract, src/interfaces/settings-store.interface.ts:36-39) → `200 {"success":true}` (:967). Pinned: tests/new-features.test.ts:1251-1258.
- **PATCH /api/settings/ui** (:974) — body: partial `ui` object only; router does GET-merge-PUT of `{...current.ui, ...patch}` to avoid the read-modify-write race (:979-981) → `200 {"success":true}`; on throw → `500 {"error": err.message}` (unlike most routes, the **actual error message** leaks) (:983-986). [UNTESTED]

### Uploads (entire group registered ONLY when `options.uploadDir` is set, src/router/admin.router.ts:991 — absent config → Express default 404, NOT a JSON error)

Multer config (:1002-1021): `multer.diskStorage` into `uploadDir` (created recursively at startup if missing, :994-1000); filename = `${sanitizedBase}_${Date.now()}.${ext}` where the base keeps `[a-zA-Z0-9_-]` (the sanitizer regex `/[^a-z0-9_-]/gi` is case-insensitive, so uppercase letters survive; others → `_`), max 40 chars, and the extension is lowercased then stripped to `[a-z0-9]` (:1005-1013);
> CORRECTED(verify): base sanitizer keeps uppercase letters too (`/gi` flag) — was stated as `[a-z0-9]` only; also noted the extension is lowercased before stripping. `limits: {fileSize: 5 * 1024 * 1024}` (5 MB) (:1015); `fileFilter` accepts only original names matching `/\.(png|jpg|jpeg|gif|svg|webp|ico)$/i`, otherwise `cb(new Error('Only image files are allowed'))` (:1016-1020). **The filter checks the file-name extension, not MIME type.** Filter/size errors are not caught by any router-level error handler — they propagate to Express's default error handler (HTML 500 unless the host app intercepts). [UNTESTED — no upload endpoint has any test]

- **POST /api/upload/logo** (:1024) — guard; multipart form, field name **`file`** (`upload.single('file')`). No file → `400 {"error":"No file uploaded"}` (:1025). Success → `200 {"success":true,"filename":"<stored name>","url":"<uploadBaseUrl>/<encodeURIComponent(filename)>"}`; when no base URL is resolvable, `url` is just the bare filename (:1027-1031). `effectiveUploadBaseUrl` = `options.uploadBaseUrl`, else `${apiPrefix (trailing / stripped)}/ui/assets/uploads` when both `apiPrefix` and `uploadDir` are set, else `''` (:639-643).
- **POST /api/upload/bg-image** (:1035) — identical contract (:1036-1041).
- **GET /api/upload/files** (:1047) → `200 {"files":[{"name":string,"size":number,"mtime":"<ISO 8601>"}…]}`, image extensions only, sorted newest-first (:1049-1056); fs errors → `500 {"error":"<message or 'Could not list files'>"}` (:1057-1060).
- **DELETE /api/upload/:filename** (:1066) — traversal guard: filename containing `/` or `\` or starting with `.` → `400 {"error":"Invalid filename"}` (:1069-1072); missing file → `404 {"error":"File not found"}` (:1074); success → `200 {"success":true}`; unlink error → `500 {"error":"<message or 'Could not delete file'>"}` (:1075-1081).

### Sessions (gated: `sessionStore`; absent → `404 {"error":"Session store not configured"}`)

- **GET /api/sessions?limit=&offset=&filter=** (src/router/admin.router.ts:1086) — `limit` default 20 cap 100, `offset` default 0, `filter` substring on `userId` or `ipAddress` (:1089-1091, :1100-1103). `getAllSessions` missing → `501 {"error":"ISessionStore.getAllSessions is not implemented","sessions":[],"total":0}` (:1092-1095) [UNTESTED]. Filter mode fetches 500 and slices like users (:1096-1107). `200 {"sessions":[…raw session records…],"total":<heuristic as for users>}` (:1108-1109). Pinned: tests/new-features.test.ts:444-448; filter — :1339-1345.
- **DELETE /api/sessions/:handle** (:1116) — `revokeSession(decodeURIComponent(handle))` → `200 {"success":true}` (:1119-1120). Pinned: tests/new-features.test.ts:450-454.

### Roles & permissions (gated: `rbacStore`; absent → `404 {"error":"RBAC store not configured"}`)

- **GET /api/roles** (src/router/admin.router.ts:1129) — `getAllRoles` missing → `501 {"error":"IRolesPermissionsStore.getAllRoles is not implemented","roles":[]}` (:1132-1135) [UNTESTED]. `200 {"roles":[{"name":string,"permissions":[string…]}…]}` (permissions resolved per role, :1136-1143). Pinned: tests/new-features.test.ts:456-462.
- **POST /api/roles** (:1150) — body `{name: string (required), permissions?: string[]}`; missing name → `400 {"error":"name is required"}` [UNTESTED]; → `200 {"success":true}` (:1153-1156). Pinned: :464-471.
- **DELETE /api/roles/:name** (:1163) — `decodeURIComponent`ed → `200 {"success":true}` (:1166-1167). Pinned: :473-477.

### Tenants (gated: `tenantStore`; absent → `404 {"error":"Tenant store not configured"}`)

- **GET /api/tenants** (src/router/admin.router.ts:1176) → `200 {"tenants":[…raw tenant objects…]}` (:1179-1180). Pinned: tests/new-features.test.ts:479-484.
- **POST /api/tenants** (:1187) — body `{name: string (required), isActive?: boolean (default true)}`; missing name → `400 {"error":"name is required"}` [UNTESTED]; → `200 {"tenant":<created tenant>}` (:1190-1193). Pinned: :486-493 (asserts `createTenant({name, isActive:true})`).
- **DELETE /api/tenants/:id** (:1200) → `200 {"success":true}` (:1203-1204). Pinned: :495-499.
- **GET /api/tenants/:id/users** (:1213) → `200 {"userIds":[string…]}` (:1216-1217). Pinned: :553-559.
- **POST /api/tenants/:id/users** (:1224) — body `{userId: string (required)}`; missing → `400 {"error":"userId is required"}` [UNTESTED]; → `200 {"success":true}` (:1227-1230). Pinned: :561-568.
- **DELETE /api/tenants/:id/users/:userId** (:1237) → `200 {"success":true}` (:1240-1244). Pinned: :570-576.

### API keys (gated: `apiKeyStore`; absent → `404 {"error":"API key store not configured"}`) — entire group [UNTESTED] at the HTTP level (tests/api-key.test.ts covers service/strategy only; no test hits `/admin/api/api-keys`)

- **GET /api/api-keys?limit=&offset=&filter=** (src/router/admin.router.ts:1253) — same limit/offset/filter mechanics as users; filter matches `name`, `serviceId`, or `keyPrefix` (:1256-1258, :1279-1283). `listAll` missing → `501 {"error":"IApiKeyStore.listAll is not implemented","keys":[],"total":0}` (:1259-1262). `200 {"keys":[{id, name, keyPrefix, serviceId, scopes, allowedIps, isActive, expiresAt, createdAt, lastUsedAt}…],"total":<heuristic>}` (:1266-1288) — `keyHash` is never returned.
- **POST /api/api-keys** (:1295) — body `{name: string (required), serviceId?: string, scopes?: string[], allowedIps?: string[], expiresAt?: string (parsed with new Date())}`; missing name → `400 {"error":"name is required"}` (:1305). Success `200`:
  `{"rawKey":"ak_<48 hex chars>", "record":{id, name, keyPrefix, serviceId, scopes, allowedIps, isActive, expiresAt, createdAt}}` (:1314-1327).
  **Yes — the plaintext key is returned exactly once** in `rawKey` and is never recoverable afterwards: only the bcrypt hash is persisted (src/services/api-key.service.ts:48-70; model doc src/models/api-key.model.ts:1-6). Format `ak_` + 48 hex chars = 24 random bytes = **192 bits** of entropy (the code comment at src/services/api-key.service.ts:91 says "~196 bits", which is arithmetically wrong; generator :89-92); `keyPrefix` = first 11 chars (`ak_` + 8 hex, :84-87). The creation `record` omits `keyHash` and `lastUsedAt`.
  > CORRECTED(verify): entropy is 192 bits (24 bytes), not ~196 — the spec had copied the source comment's incorrect figure.
- **DELETE /api/api-keys/:id/revoke** (:1334) — soft revoke (`isActive=false`) → `200 {"success":true}` (:1337-1338). Registered before the plain `:id` route, so it wins the match.
- **DELETE /api/api-keys/:id** (:1345) — hard delete when `store.delete` exists → `200 {"success":true}`; otherwise falls back to revoke → `200 {"success":true,"note":"IApiKeyStore.delete not implemented; key was revoked instead"}` (:1348-1354).

### Webhooks (gated: `webhookStore`; absent → `404 {"error":"Webhook store not configured"}`) — entire group [UNTESTED]

`WebhookConfig` shape (src/interfaces/webhook-store.interface.ts:4-73): `{id, url, events: string[] ('*' = all), secret? (HMAC SHA-256), isActive? (default true), tenantId?, maxRetries? (default 3), retryDelayMs? (default 1000), provider? (inbound), allowedActions? (intersected with AuthSettings.enabledWebhookActions), jsScript? (runs in the vm sandbox with `body` and `actions`, assigns `result`)}`.

- **GET /api/webhooks?limit=&offset=** (src/router/admin.router.ts:1363) — limit default 20 cap 100, offset; **no filter param**. `listAll` missing → `501 {"error":"IWebhookStore.listAll is not implemented","webhooks":[],"total":0}` (:1368-1371). `200 {"webhooks":[{id, url, events, isActive, tenantId, maxRetries, retryDelayMs, secret: "***"|undefined}…],"total":<heuristic>}` (:1373-1383). `secret` is masked as the literal string `"***"` when set, `undefined` otherwise. [MISMATCH-internal] The list projection **omits `provider`, `allowedActions`, and `jsScript`** even though `WebhookConfig` defines them and its doc comments say they are "Managed via the Admin UI's Webhooks → edit drawer" (src/interfaces/webhook-store.interface.ts:43-72) — an admin client cannot read these fields back through this API; it can only write them blindly via PATCH.
- **POST /api/webhooks** (:1390) — body `{url: string (required), events?: string[] (default ["*"]), secret?: string, tenantId?: string, isActive?: boolean (default true), maxRetries?: number, retryDelayMs?: number}`; missing url → `400 {"error":"url is required"}` (:1397); `add` missing → `501 {"error":"IWebhookStore.add is not implemented"}` (:1398-1401). Success `200 {"webhook":{…created record, secret masked "***"|undefined}}` (:1402-1406). Note: `provider`/`allowedActions`/`jsScript` are **not accepted on create** (only the destructured fields are forwarded, :1393-1405) — they must be set afterwards via PATCH.
- **PATCH /api/webhooks/:id** (:1413) — body: arbitrary partial object forwarded verbatim to `store.update(id, body)` (:1420), so `jsScript`, `allowedActions`, `provider`, `isActive` etc. can all be written here; `update` missing → `501 {"error":"IWebhookStore.update is not implemented"}` (:1416-1419); → `200 {"success":true}`.
- **DELETE /api/webhooks/:id** (:1428) — `remove` missing → `501 {"error":"IWebhookStore.remove is not implemented"}` (:1431-1434); → `200 {"success":true}` (:1435-1436).

### Email & UI templates (entire group registered ONLY when `templateStore` is provided, src/router/admin.router.ts:1444 — absent store → Express default 404, **not** a JSON `{error:…}` like other gated groups) — entire group [UNTESTED] (tests/template-store.test.ts covers the store, not these routes)

Shapes (src/interfaces/template-store.interface.ts:1-11): `MailTemplate {id, baseHtml, baseText, translations: Record<lang, Record<key,value>>}`; `UiTranslation {page, translations: Record<lang, Record<key,value>>}`.

- **GET /api/templates/mail** (:1448) → `200 {"templates":[MailTemplate…]}` (:1451).
- **POST /api/templates/mail** (:1458) — body `{id: string (required), baseHtml?, baseText?, translations?}`; missing id → `400 {"error":"id is required"}` (:1461); upserts via `updateMailTemplate` → `200 {"success":true}` (:1462-1463).
- **GET /api/templates/ui** (:1470) → `200 {"translations":[UiTranslation…]}` (:1473).
- **POST /api/templates/ui** (:1480) — body `{page: string (required), translations: object (required)}`; either missing → `400 {"error":"page and translations are required"}` (:1483); → `200 {"success":true}` (:1484-1485).

### Swagger / OpenAPI (registered only when enabled: `options.swagger === true`, or not `false` and `NODE_ENV !== 'production'`, src/router/admin.router.ts:1493-1495)

- **GET /api/openapi.json** (:1499) — **NO guard**: publicly readable whenever enabled. Builds `buildAdminOpenApiSpec` with feature flags for sessions/roles/tenants/metadata/settings/linkedAccounts/apiKeys/webhooks and `swaggerBasePath` (default `'/admin'`, :1498) (:1500-1514). Pinned: tests/swagger.test.ts:292-298 (serves when true), :307-311 (404 when false), :313-323 (auto = on in dev, off in production).
- **GET /api/docs** (:1517) — **NO guard**; `text/html; charset=utf-8` Swagger-UI shell pointing at `${swaggerBasePath}/api/openapi.json` (:1518-1519). Pinned: tests/swagger.test.ts:300-305.
- Spec content pins (unit level): core paths ping/users/users-{id}/2fa-policy always present, optional groups toggled by flags, `AdminAuth` security scheme — tests/swagger.test.ts:168-222.

### Cross-check against the client contract facts

- **CSRF**: the admin router implements **no CSRF protection whatsoever** — no `X-CSRF-Token` read, no CSRF cookie set or checked, on any of the 50 routes (whole file, src/router/admin.router.ts). State-changing routes rely on the `SameSite=Lax` HttpOnly admin cookie or Bearer auth. Also, the admin session cookie is `httpOnly: true` (:604) — unlike the auth-router CSRF cookie contract, nothing here is meant to be JS-readable. Not a client [MISMATCH] (browser admin UI is served same-origin), but a deliberate contract difference to document.
- **`{code:"SESSION_REVOKED"}` fast-logout**: never emitted here. All admin 401s are `{"error":"Unauthorized"}` / `{"error":"Invalid credentials"}` with **no `code` field** (:193, :328, :330, :338, :362, :577). A client applying the SESSION_REVOKED rule to admin responses will never match; it will fall back to its generic 401 handling.
- **`X-Auth-Strategy: bearer` / top-level tokens**: the header is never read by this router. `POST /admin/login` returns only `{"success":true}` and sets a cookie (:614) — it **never returns `accessToken`/`refreshToken` in the body**, and there is no `/admin/refresh`. [MISMATCH] for any native (Flutter-style) client expecting the auth-router bearer contract from admin login; cookie-less clients must instead present a JWT signed with the same secret via `Authorization: Bearer` (accepted by the guard, :276-278).
- **Angular no-retry substring list** (`/login /logout /refresh …`): `/admin/login` and `/admin/logout` contain the `/login` and `/logout` substrings, so an Angular interceptor using substring matching will correctly not retry them. Consistent, no mismatch.
- **`GET /me` unwrapped / `GET /sessions` wrapped / magic-link `mode`**: not applicable — those endpoints live on the auth router. The admin analogue `GET /api/sessions` returns `{"sessions":[…],"total":n}` (:1105, :1109), and admin `GET /api/settings` / `GET /api/users/:id/metadata` are the two admin endpoints that return **unwrapped** objects (:955, :859).
- **Cookie read priority**: the policy guard's cookie fallback order `__Host-accessToken` > `__Secure-accessToken` > `accessToken` (:294) mirrors the clients' CSRF-cookie priority convention (`__Host-` > `__Secure-` > bare) applied to the access-token cookie. Consistent.

---

## 6. Tools router, SSE, UI router

Scope: wire contract of `createToolsRouter` (src/router/tools.router.ts), the SSE protocol implemented by `SseManager` (src/tools/sse-manager.ts) plus its `ISseDistributor` contract, the inbound-webhook vm pipeline (`ActionRegistry`, src/tools/webhook-action.ts; `WebhookSender`, src/tools/webhook-sender.ts), the `AuthTools` facade (src/tools/auth-tools.ts), and `buildUiRouter` (src/router/ui.router.ts) including `GET /config`, SSR injection, headless mode, and static serving. All claims cite awesome-node-auth @ cc01e997; behavior pinned by tests cites tests/tools.test.ts (51 `it()` cases) and tests/auth-js.test.ts.
> CORRECTED(verify): tests/tools.test.ts contains 51 `it()` cases, not 52 (`grep -c "^\s*it(" tests/tools.test.ts` = 51). Paths below are relative to the tools router mount point (example mount `/tools`, src/router/tools.router.ts:114; the Angular demo mounts it at `<apiPrefix>/tools`, ng-awesome-node-auth/src/server/auth.routes.ts:98-104). The library core never auto-mounts the tools router — it is exported (`src/index.ts:88`) and mounted by the host app; the UI router IS auto-mounted at `<apiPrefix>/ui` when `config.ui.enabled` (src/router/auth.router.ts:1639-1649).

---

### 1. Tools router — option gating and auth model

`createToolsRouter(tools: AuthTools, options: ToolsRouterOptions)` (src/router/tools.router.ts:117).

| Option | Default | Effect |
|---|---|---|
| `telemetry` | `true` | mounts `POST /track/:eventName` (:140); with `telemetryStore.query` also `GET /telemetry` (:226) |
| `notify` | `true` | mounts `POST /notify/:target` (:165) |
| `stream` | `true` | mounts `GET /stream` (:184) |
| `webhook` | `true` | mounts `POST /webhook/:provider` only if `options.onWebhook` OR `options.webhookStore?.findByProvider` exists (:250) |
| `authMiddleware` | none | prepended to track/notify/stream/telemetry via `protect` array (:135). **Default is NO auth at all.** |
| `swagger` | `'auto'` | `true` → always; `false` → never; `'auto'` → enabled when `process.env['NODE_ENV'] !== 'production'` (:131-133) |
| `swaggerBasePath` | `'/tools'` | base path used in the OpenAPI paths and the docs spec URL (:127) |

- `protect` is applied to `/track`, `/notify`, `/stream`, `/telemetry` — but **NOT** to `/webhook/:provider` (:251), `/openapi.json` (:333) or `/docs` (:348). Those three are always unauthenticated.
- No CSRF middleware exists anywhere in this router; CSRF applicability: none (the auth router's CSRF stack is not attached here).
- The router mounts **no body parser**. `POST /track`, `/notify`, `/webhook` destructure `req.body` (:143, :168) — with Express 5 (`express@^5.2.1`, package.json:75) and no host-mounted `express.json()`, `req.body` is `undefined` and destructuring throws → Express default 500. All tests mount `express.json()` first (tests/tools.test.ts:490, :576). [UNTESTED] (no-parser case)

Bearer-mode note: these endpoints have no cookie/bearer branching of their own — auth semantics are entirely those of the injected `authMiddleware`. The only bearer-specific affordance is `?token=` promotion on `/stream` (§2.3).

### 2. Tools router routes

#### 2.1 POST /track/:eventName (src/router/tools.router.ts:141-159)

- Gate: `telemetry` flag; auth: `authMiddleware` if provided, else none.
- Path param: `eventName` (opaque string; convention `identity.<resource>.<action>`).
- Request body (all optional, no validation): `data: unknown`, `userId: string`, `tenantId: string`, `sessionId: string`, `correlationId: string` (:143).
- Server-derived metadata: `ip` = first comma-separated entry of `X-Forwarded-For` (trimmed) else `req.socket.remoteAddress` (:144); `userAgent` = `User-Agent` header (:145).
- userId resolution: **body `userId` wins over the authenticated principal**; fallback `req.user.id` then `req.user.sub` (:146-147). A caller can attribute events to arbitrary users. [UNTESTED]
- Awaits full `tools.track()` fan-out (§4.1), then responds `202` body `{"ok":true}` (:158). No error branch — a throwing telemetry/bus listener propagates to Express (telemetry-store errors themselves are swallowed inside `track`, src/tools/auth-tools.ts:218; pinned tests/tools.test.ts:274-280).

#### 2.2 POST /notify/:target (src/router/tools.router.ts:166-178)

- Gate: `notify` flag; auth: `authMiddleware` if provided, else none.
- Path param: `target` = SSE topic string (e.g. `user:123`, `tenant:acme`, `global`).
- Body (all optional): `data: unknown`, `type: string`, `tenantId: string`, `userId: string`, `metadata: object` (:168).
- Calls `tools.notify(target, data, {type,tenantId,userId,metadata})` **without await** (handler is synchronous; fire-and-forget) (:170-175). The HTTP surface can NOT select channels — `channels` is never passed, so it is always the default `['sse']` (src/tools/auth-tools.ts:293); email/SMS channels are reachable only via the programmatic facade. Responds `202` `{"ok":true}` (:177).

#### 2.3 GET /stream — SSE (src/router/tools.router.ts:185-220)

- Gate: `stream` flag. Middleware order: `extractSseToken` → `protect` → handler (:192).
- **`?token=` promotion** (:185-190): when `req.query['token']` is a string, the router sets `req.headers['authorization'] = 'Bearer ' + token` (overwriting any existing Authorization header) BEFORE `authMiddleware` runs. This exists because `EventSource` cannot set headers. Applied even when no `authMiddleware` is configured. [UNTESTED]
- If `tools.sseManager` is null (AuthTools built without `sse: true`): `503` `{"error":"SSE not enabled"}` (:193-196). [UNTESTED]
- Topic authorization (:198-216): server builds `authorisedTopics = ['global']` + `tenant:<req.user.tenantId>` + `user:<req.user.id ?? req.user.sub>`. `?topics=` is a comma-separated list (trimmed, empties dropped). If topics were requested, `finalTopics = requested ∩ authorised`; if none requested, `finalTopics = authorised` (all). Clients cannot self-declare channels. Edge: requesting only unauthorized topics yields `finalTopics = []` — the connection opens, gets the `connected` event with `topics: []`, and never receives anything. [UNTESTED]
- Hands off to `sseManager.connect(res, finalTopics, {userId, tenantId})` (:218); response is held open.

#### 2.4 GET /telemetry (src/router/tools.router.ts:227-244)

- Mount gate: `telemetry === true` **AND** `options.telemetryStore?.query` exists (:226). Auth: `protect`.
- The inner re-check returning `501` `{"error":"Telemetry query not supported by the configured store"}` (:229-231) is unreachable dead code given the mount gate. [UNTESTED]
- Query params (all optional strings): `event`, `userId`, `tenantId`, `from`, `to` (each passed through `new Date(...)` — an unparsable value becomes Invalid Date, no validation), `limit`, `offset` (`parseInt(x,10)`, `NaN` possible) (:233-242).
- Success: `200` `{"data": <store.query() result array>}` (:243). No error handling — a rejecting store propagates to Express. [UNTESTED]

#### 2.5 POST /webhook/:provider — inbound webhooks (src/router/tools.router.ts:251-325)

- Mount gate: `webhook && (options.onWebhook || options.webhookStore?.findByProvider)` (:250). **No auth middleware, ever** (`protect` deliberately not applied — external providers post here).
- **No signature verification.** `WebhookSender.verify()` (HMAC-SHA256 `sha256=<hex>`, constant-time compare; src/tools/webhook-sender.ts:65-74) exists and is unit-tested (tests/tools.test.ts:90-103) but is never invoked anywhere in `src/` — only `sign()` is used, for OUTGOING deliveries (src/tools/auth-tools.ts:266 → webhook-sender.ts:32). The OpenAPI spec even advertises an optional `X-Hub-Signature-256` header on this route (src/router/openapi.ts:1540-1546) that the router never reads. [MISMATCH] (spec/docs vs. code — inbound payloads are accepted unverified)

Execution pipeline (:253-324), inside one try/catch:

1. **vm sandbox branch** — only when `webhookStore.findByProvider` exists (:257): `config = await findByProvider(provider)`; runs only if `config?.jsScript` is set (:259).
   - Action set: `settings = settingsStore ? await settingsStore.getSettings().catch(() => ({})) : {}`; `enabledIds = settings.enabledWebhookActions ?? []`; `allowedIds = config.allowedActions ?? []`; `actions = ActionRegistry.buildContext(enabledIds, allowedIds)` (:261-266).
   - **Intersection logic** (src/tools/webhook-action.ts:108-117): effective set = `allowedIds ∩ enabledIds`; an action is injected only if (a) registered, (b) in the effective set, and (c) every `dependsOn` entry is also in the effective set. Pinned: tests/tools.test.ts:434-442 (intersection), :444-452 (unmet dependsOn excluded), :454-462 (met dependsOn included), :525-546 (allowed+enabled action callable from script), :548-570 (globally disabled action absent from sandbox).
   - Wrapper: `` const wrappedScript = `(async () => { ${config.jsScript} })()` `` (:269) — `await` is legal inside the script.
   - Sandbox context = `vm.createContext({ body: req.body, actions, result: null, console: sandboxConsole })` (:281-286). `sandboxConsole`: when `NODE_ENV !== 'production'`, `log/warn/error` write to stderr prefixed `[webhook:<provider>] `, `[webhook:<provider>] WARN `, `[webhook:<provider>] ERR  ` (note: `ERR` is followed by **two** spaces in the source) (:272-279); in production all three are no-ops.
   > CORRECTED(verify): the `error` prefix is `ERR ` + an extra space (`` `ERR  ${args}` `` at :277) — spec previously showed a single space.
   - `vm.runInContext(wrappedScript, sandbox, { timeout: 5_000 })` (:289) — the **5 s timeout bounds synchronous execution only**. If the return value is a Promise, it is awaited with **no timeout** (unbounded await); `.catch()` is attached synchronously before the await to avoid `unhandledRejection` (:290-298). Async rejections and sync errors (timeout, syntax) are logged via `console.error('[tools-router] vm script error for provider', provider, err)` (:296, :301) and swallowed — the request still succeeds. Pinned (sync-throw path → 200): tests/tools.test.ts:595-612.
   - Result extraction: the script's *return value* is ignored except for Promise detection; the script must **assign** `result = {...}` in the sandbox. Accepted only when `sandbox.result` is truthy and `typeof result.event === 'string'` (:304-306); shape `{event: string, data?: unknown, userId?: string, tenantId?: string}`.
2. **Fallback `onWebhook`** (:311-313): runs when `result === null` (no store, no config, no jsScript, script error, or script set an invalid/`null` result) and `options.onWebhook` is set: `result = await onWebhook(provider, req.body, req)`. Pinned: tests/tools.test.ts:572-593.
3. **Fan-out** (:315-320): when `result` is non-null → `await tools.track(result.event, result.data, {userId, tenantId})` — i.e. the full track pipeline including OUTGOING webhooks (§4.1), so an inbound webhook can trigger outbound ones.
4. **Responses**: success (including `result === null` "silently accepted", and swallowed script errors) → `200` `{"ok":true}` (:321; pinned tests/tools.test.ts:505-523). Any throw from `findByProvider`, `onWebhook`, or `tools.track` → `400` `{"error":"Webhook processing failed"}` (:322-324). [UNTESTED] (400 path)

#### 2.6 GET /openapi.json and GET /docs (src/router/tools.router.ts:333-351)

- Gate: resolved `swaggerEnabled` (§1 table); auth: none.
- `GET /openapi.json` → `200`, `Content-Type: application/json`, body = `buildOpenApiSpec({telemetry,notify,stream,webhook,telemetryStore}, swaggerBasePath)` (:333-346) — OpenAPI `3.0.3` document; disabled features are omitted from `paths`; declares `BearerAuth` (`http`/`bearer`/JWT) security scheme (src/router/openapi.ts:1366-1573). Pinned: tests/tools.test.ts:286-341 (spec content), :379-409 (route gating: 200 when `swagger=true`, 404 when `false`, 200 in dev + 404 in prod under `'auto'`).
- `GET /docs` → `200`, `Content-Type: text/html; charset=utf-8`, body = `buildSwaggerUiHtml('<swaggerBasePath>/openapi.json')` (:348-351): a self-contained HTML page loading `swagger-ui-dist@5` from unpkg CDN (src/router/openapi.ts:1646-1669). Pinned: tests/tools.test.ts:386-391.

---

### 3. SSE wire protocol — SseManager (src/tools/sse-manager.ts)

#### 3.1 Connect handshake (:125-172)

Headers written on `connect()` (:133-137):

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
X-Accel-Buffering: no
```

then `res.flushHeaders?.()`. HTTP status is the default `200`.

Initial event (:140-146): a `connected` frame is written immediately:

- `id:` fresh `randomUUID()` (distinct from the connection id)
- `event: connected`
- data JSON: `{"id": "<uuid>", "type": "connected", "timestamp": "<ISO 8601>", "topic": "meta", "rawData": {"connectionId": "<connId>", "topics": [<finalTopics>]}}` (via the re-keying writer, §3.3).

#### 3.2 Heartbeat (:156-164)

Every `heartbeatIntervalMs` (default `30_000`; `0` disables — :105, :51) the server writes the SSE comment frame `: heartbeat\n\n` (colon + space; the option JSDoc says `:heartbeat` without space — code wins, :159). A write failure disconnects the connection.

#### 3.3 Event wire format and rawData re-keying (:249-253)

```
id: <event.id>\n
event: <event.type>\n
data: <JSON.stringify({ ...event, data: undefined, rawData: event.data })>\n\n
```

The JSON payload therefore contains keys `id`, `type`, `timestamp`, `topic`, `rawData`, plus `userId`/`tenantId`/`metadata` when present — and **never a `data` key** (`data: undefined` is dropped by `JSON.stringify`; the payload lives under `rawData`). Every frame carries an explicit `event:` line; the server never emits an unnamed (default `message`) event. See mismatch §6.1.

#### 3.4 Broadcast, dedupe, tenant isolation (:179-221)

- `broadcast(topic, event)` (:179-198) fills `id` (`event.id ?? randomUUID()`) and `timestamp` (`?? new Date().toISOString()`), then spreads the caller's object LAST — so a caller-supplied key `id: undefined` would clobber the generated UUID (:183-188). [UNTESTED]
- **Distributor contract** (`ISseDistributor`, src/interfaces/sse-distributor.interface.ts:10-25): `publish(topic, event): Promise<void>` and `subscribe(cb: (topic, event) => void): Promise<void>`. When configured (constructor :109-113) the manager subscribes and re-broadcasts incoming events locally via `broadcastLocal`.
- **No local broadcast when a distributor exists** (:190-197): `broadcast()` publishes ONLY to the distributor; local delivery happens solely through the distributor's subscribe callback (so the distributor must echo to the publishing instance). Local fallback occurs only when `distributor.publish()` rejects. [UNTESTED]
- `broadcastLocal` (:204-221) per connection: skip if topic not in `conn.topics`; **tenant isolation** — skip when `event.tenantId && conn.tenantId && conn.tenantId !== event.tenantId` (an event with tenantId still reaches connections that have NO tenantId) (:211; pinned tests/tools.test.ts:151-158); **dedupe** — when `deduplicate` (default `true`, :106) skip if `event.id === conn.lastEventId`, else set `conn.lastEventId = event.id` and write (:214-216).
- **`lastEventId` is a server-side, per-connection, single-value cursor** comparing only against the immediately preceding delivered id (guards double delivery when one event is broadcast to several topics the connection subscribes to). The **`Last-Event-ID` request header is never read** anywhere in `src/` and there is no replay buffer: on `EventSource` reconnect no missed events are re-delivered. [UNTESTED]
- Disconnect (:226-236): clears heartbeat timer, removes connection, `res.end()`; also wired to the response `close` event (:169; pinned tests/tools.test.ts:160-167, :169-176). Topic-subscription filtering pinned at tests/tools.test.ts:134-149.

---

### 4. AuthTools facade (src/tools/auth-tools.ts)

Constructor (:170-189): `sseManager` created only when `options.sse === true` (else `null`); `WebhookSender` always instantiated; `webhookVersion` default `'1'` (:175); email/SMS `NotificationService` only when `emailConfig`/`smsConfig` provided; when SSE is on, the manager is registered in `SseNotifyRegistry` (:186-188, decorator plumbing in src/tools/sse-notify.decorator.ts:37-54 — not an HTTP surface). **dev line (node-auth@e8af923):** constructor now :178-197; new `AuthToolsOptions.sseDistributor?: ISseDistributor` (:47-51, "used instead of the internal SseManager broadcaster" for `notify()`) stored at :184; stderr WARN when both `sse: true` and `sseDistributor` are given (:187-191).

#### 4.1 track(eventName, data?, options) fan-out — exact order (:199-269)

1. **Telemetry store** — `store.save(telemetryEvent)` awaited, errors swallowed (:217-219; pinned tests/tools.test.ts:199-205, :274-280). `TelemetryEvent` = `{id: uuid, event, timestamp: ISO, data, userId, tenantId, sessionId, correlationId, ip, userAgent}` (:203-214).
2. **Event bus** — `eventBus.publish(eventName, payload)` (:222-231; pinned :207-213).
3. **SSE** — broadcast to topics `['global']` + `tenant:<tenantId>` + `user:<userId>` + `session:<sessionId>` as present (:234-247, resolveTopics :353-359); stream event reuses the SAME `id`/`timestamp` as the telemetry event, `type = eventName`, and **`data` = the whole `TelemetryEvent`** (so on the wire it appears as `rawData: {id, event, timestamp, data, ...}`) (:236-243; pinned :215-230).
4. **Outgoing webhooks** — `webhookStore.findByEvent(eventName, tenantId)` (errors → `[]`), payload `OutgoingWebhookEvent` = `{event, version: webhookVersion, timestamp, data: data ?? null, metadata: {userId, tenantId, sessionId, correlationId}}`, delivered fire-and-forget via `webhookSender.send()` (:250-268; pinned :253-272). Sender headers: `Content-Type: application/json`, `X-Webhook-Event`, `X-Webhook-Delivery` (uuid), `X-Webhook-Timestamp`, plus `X-Webhook-Signature: sha256=<hmac-hex>` when the config has a `secret`; retries `maxRetries` (default 3) with exponential backoff from `retryDelayMs` (default 1000 ms) (src/tools/webhook-sender.ts:17-47).

Note: the code order is telemetry → bus → SSE → webhooks (comments `// 1.`–`// 4.` at :216, :221, :233, :249). Any description ordering webhooks before bus/SSE is wrong.

#### 4.2 notify(target, data, options) channels (:292-342)

- `channels` default `['sse']` (:293).
- `'sse'`: `sseManager.broadcast(target, {type: options.type ?? 'notification', data, tenantId, userId, metadata})` (:296-304) — no-op without a manager (pinned tests/tools.test.ts:232-235, :237-251). **dev line (node-auth@e8af923):** the SSE branch (:310-323) tries `sseDistributor.publish(target, streamEvent).catch(() => {})` first (un-awaited, errors swallowed; the distributor receives the raw pre-envelope object — no `id`/`timestamp`/`topic`), then `sseManager.broadcast`, and is a no-op only when neither exists. `track()` (:248-259) is unchanged and still broadcasts through `sseManager` only — the distributor is honoured by `notify()` but not by `track()` (reference-issues.md N43). Pinned: tests/tools.test.ts "notify() prefers a custom SSE distributor when provided". HTTP surface (`POST /notify/:target` → 202) unchanged.
- `'email'` / `'sms'`: require `options.userId` AND `userStore` (:307); user looked up via `userStore.findById` (errors → skip). Email additionally needs `user.email` + `emailConfig`: subject = `emailSubject ?? (type ? String(type) : 'Notification')` (:322 — a falsy `type` falls back to `'Notification'`; the `??`-chain notation previously given would never reach the fallback), text = `data` if string else `JSON.stringify(data, null, 2)`, html = `<p>` with `\n`→`<br>` (:321-330).
> CORRECTED(verify): subject fallback is a ternary on `type`, not a nullish chain — `emailSubject ?? (options.type ? String(options.type) : 'Notification')`. SMS needs `user.phoneNumber` + `smsConfig`: message = `smsMessage ?? (string data or JSON.stringify(data))` (:333-339). All channel sends are `.catch()`-swallowed best-effort; a failing channel does not affect the others. [UNTESTED] (email/sms channels have no test in tests/tools.test.ts)

---

### 5. UI router — buildUiRouter (src/router/ui.router.ts)

Mounted by the auth router at `'/ui'` under the API prefix when `config.ui?.enabled` (src/router/auth.router.ts:1639-1649); `apiPrefix` resolves `options.apiPrefix || config.apiPrefix || '/auth'` (src/router/auth.router.ts:253-255). UI asset directory: `options.uiAssetsDir` or first existing of six candidates (dist `ui-assets`, src `ui/assets`, node_modules copies) (src/router/ui.router.ts:72-93).

#### 5.1 GET /config (:165-170)

Auth: none. CSRF: none. Success `200` JSON, exact shape (built by `getUiConfig` :95-162 plus the route-added `headless`):

```jsonc
{
  "apiPrefix": "<req.baseUrl minus trailing '/ui', else configured apiPrefix>", // :97-98
  "features": {                       // :114-123 — all booleans
    "register":       !!routerOptions.onRegister,   // dev line (node-auth@e8af923): true by default — routerOptions.onRegister is the resolved registerHandler (auth.router.ts:1793; ui.router.ts:121), false only in resource-server mode
    "magicLink":      !!email.sendMagicLink || !!email.mailer,
    "sms":            !!authConfig.sms,
    "google":         !!oauth.google,
    "github":         !!oauth.github,
    "forgotPassword": !!email.sendPasswordReset || !!email.mailer,
    "verifyEmail":    (!!email.sendVerificationEmail || !!email.mailer) && (emailVerificationMode !== 'none' || requireEmailVerification),
    "twoFactor":      !!authConfig.twoFactor
  },
  "ui": {                             // :125-134 — settingsStore value wins over authConfig.ui, then defaults
    "primaryColor":   "…default '#4a90d9'",
    "secondaryColor": "…default '#6c757d'",
    "logoUrl":        "settings.ui.logoUrl || authConfig.ui.customLogo || authConfig.ui.logoUrl (may be absent)",
    "siteName":       "…default 'Awesome Node Auth'",
    "customCss":      "authConfig.ui.customCss (may be absent)",
    "bgColor": "…", "bgImage": "…", "cardBg": "…"
  },
  "translations": { "<key>": "<string>" },  // templateStore.getUiTranslations(page)[lang] || ['en'] || {} — :106-112
  "lang": "req.query.lang || authConfig.email.mailer.defaultLang || 'en'",     // :102-103
  "headless": false                          // added ONLY by this route — :168
}
```

- Quirk: when fetched via `/config`, the translations `page` argument is `'config'` (`req.path.replace(/^\//,'') || 'login'` evaluated inside the `/config` handler, :107). [UNTESTED]
- Error fallback (:143-161): `features` collapses to only `{register:false, google:false, github:false}` — `magicLink`, `sms`, `forgotPassword`, `verifyEmail`, `twoFactor` become `undefined` for consumers; `ui` reverts to hardcoded defaults; `translations: {}`, `lang: 'en'`. [UNTESTED] **dev line (node-auth@e8af923):** fallback unchanged (`register:false`, ui.router.ts:153).
- Pinned: `headless:true`/`false` echoed from `authConfig.ui.headless` — tests/auth-js.test.ts:1398-1416.

#### 5.2 Headless-mode early return (:175-182)

When `authConfig.ui.headless` is truthy, after `/config` the router mounts ONLY `expressStatic(uiAssetsDir, {maxAge: 0, index: false})` and returns: no upload statics, no SSR, no catch-all. Result: HTML pages 404 (pinned tests/auth-js.test.ts:1418-1425), static assets like `auth.js` still served (pinned :1438-1445), `/config` still works.

#### 5.3 Uploaded-asset statics (:184-190)

When `uploadDir` is set: `expressStatic(uploadDir)` mounted at both `'/assets/logo'` (legacy) and `'/assets/uploads'`, default options (Cache-Control `public, max-age=0`). [UNTESTED]

#### 5.4 SSR injection — serveSsrHtml (:193-291)

For every SSR-rendered page:

- `<head>` gets, injected before `</head>` (:275): (1) a `<style>:root{...}</style>` with `--primary-color`, `--input-focus` (both = primaryColor), `--secondary-color`, `--bg-color`, `--card-bg`, `--bg-image: url("<quote-escaped>")` as configured (:201-213), plus a second `<style>` with raw `customCss` (:216); (2) splash-screen CSS (:232-253); (3) **`<script>window.__AUTH_CONFIG__ = <JSON.stringify(config)>;</script>`** (:272) where `config` is exactly the `getUiConfig` object — `{apiPrefix, features, ui, translations, lang}` — **WITHOUT the `headless` key** (only the `/config` route adds it, :168).
- `<title>` and `<h1 class="site-name">` contents replaced with HTML-escaped `siteName` (:217-225); the hidden logo `<img>` swapped for `logoUrl` (:227-229).
- After `<body>`: splash `<div id="global-splash">` (:278); before `</body>`: splash-removal script (:281).
- Response headers: `Content-Type: text/html; charset=utf-8`; `Cache-Control: no-store, no-cache, must-revalidate, max-age=0` (:283-284). On any SSR error: fallback `res.sendFile(htmlPath)` (:289).
- Client consumption pinned: auth.js uses `window.__AUTH_CONFIG__` when present and skips the `/ui/config` fetch, else fetches `${apiPrefix}/ui/config` (src/ui/assets/auth.js:225-233; tests/auth-js.test.ts:1121-1160).

#### 5.5 Catch-all page mapping (:295-326)

GET-only, extensionless paths only (paths with an extension fall through to static, :296-303). `page = req.path.replace(/^\//,'') || 'login'`; serve `<uiAssetsDir>/<page>.html` via SSR if it exists (:306-313); else the first existing of `['login.html','index.html','index.csr.html']` via SSR (:316-323); else `next()` → 404. Pinned (non-headless `/login` → 200 text/html): tests/auth-js.test.ts:1427-1436.

#### 5.6 Asset serving (:329-332)

Final mount: `expressStatic(uiAssetsDir, { maxAge: 0, index: false })` — assets are served with `Cache-Control: public, max-age=0` (ETag/Last-Modified revalidation, no long-lived caching). No immutable/hashed-asset caching exists.

---

### 6. Client cross-checks — mismatches and notes

1. **[MISMATCH] SSE clients never receive events.** The server writes an `event: <type>` line on EVERY frame (src/tools/sse-manager.ts:251) — including the initial `connected` frame — so no frame is dispatched as the default `message` event. Both clients listen exclusively via `onmessage`: Angular `es.onmessage = ...` (ng-awesome-node-auth/projects/ng-awesome-node-auth/src/lib/auth.service.ts:387-390) and Flutter web `es.onmessage = ...` (awesome-node-auth-flutter/lib/src/platform/web_auth_client.dart:65-71). As written, `getToolsStream()` in both clients yields nothing from this server (heartbeats are comments and are also invisible). Clients would need `addEventListener('<type>')` per event name, or the server would need to drop the `event:` line.
2. **[MISMATCH] Inbound webhook signature.** OpenAPI advertises `X-Hub-Signature-256` on `POST /webhook/:provider` (src/router/openapi.ts:1540-1546) and `WebhookSender.verify` implements constant-time HMAC verification (src/tools/webhook-sender.ts:65-74), but the route performs no verification of any kind (src/router/tools.router.ts:251-325). Unauthenticated callers can inject events into the full track fan-out (including outgoing webhooks) subject only to the vm/onWebhook mapping.
3. **[MISMATCH] SSR `__AUTH_CONFIG__` never carries `headless`.** auth.js honors `window.__AUTH_CONFIG__ = {headless:true}` (tests/auth-js.test.ts:1262-1277), but the router's SSR injection omits the key (src/router/ui.router.ts:272 vs :168) and headless mode serves no HTML at all (:175-182) — so the SSR headless path is only reachable when the hosting SPA sets `__AUTH_CONFIG__` itself. Cookie-mode headless SPAs relying on the router must use the `/config` fetch path (pinned tests/auth-js.test.ts:1279-1293).
4. **Fan-out order**: actual `track()` order is telemetry store → event bus → SSE → outgoing webhooks (src/tools/auth-tools.ts:216-268), not "telemetry, webhooks, bus, sse".
5. `/config` error fallback drops five `features` keys (§5.1) — clients feature-gating on `features.magicLink` etc. see `undefined` (falsy, so fails safe). [UNTESTED]
6. Clients connect to `${apiPrefix}/tools/stream` (Angular auth.service.ts:387; Flutter web_auth_client.dart:62) — this only works when the host mounts `createToolsRouter` under the same prefix (the library does not do it automatically; the Angular demo server does at ng-awesome-node-auth/src/server/auth.routes.ts:98-104). Angular sets `withCredentials: true` (cookie mode); Flutter web constructs `EventSource(url)` with no init — cross-origin cookie auth would fail there, same-origin works. Neither client sends `?topics=` or `?token=`.
7. Auth-router-specific contract facts (CSRF header/cookie priority, `SESSION_REVOKED`, `/refresh` body modes, `/me`//`sessions`//`linked-accounts` shapes, magic-link `mode`, Angular no-retry list) do not intersect this router: no tools/UI path appears in the Angular no-retry substring list, and no tools/UI endpoint sets or reads cookies or CSRF tokens.

### 7. Test coverage map (tests/tools.test.ts unless noted)

| Behavior | Test |
|---|---|
| SseManager connect/count, topic filtering, tenant isolation, close/disconnect | :126-176 |
| track(): telemetry persist, bus emit, SSE broadcast, outgoing webhook fetch, store-error swallow | :199-280 |
| notify(): no-op without SSE, broadcast with SSE | :232-251 |
| WebhookSender sign/verify (unit only — verify unused in prod code) | :90-103 |
| buildOpenApiSpec feature gating, basePath, BearerAuth | :286-341 |
| Swagger route gating (true/false/'auto'×NODE_ENV) | :364-409 |
| ActionRegistry register/getAllMeta/intersection/dependsOn, decorator | :415-476 |
| vm sandbox: script result → 200, action injection, globally-disabled exclusion, onWebhook fallback, sync-throw → 200 | :481-613 |
| UI /config headless flag, headless 404 for pages, non-headless SSR 200, static auth.js in headless | tests/auth-js.test.ts:1385-1446 |
| auth.js SSR fast-path vs /ui/config fetch | tests/auth-js.test.ts:1121-1160 |

Not covered by any test [UNTESTED]: `POST /track` HTTP handler (body precedence, ip/UA extraction, 202), `POST /notify` HTTP handler, `GET /stream` handler (503, `?token=` promotion, topic intersection), `GET /telemetry` (200/501/param parsing), webhook 400 path, vm 5 s sync timeout + unbounded await, heartbeat wire format, `Last-Event-ID` semantics, distributor pub/sub paths, notify email/SMS channels, `/config` error fallback, upload statics, catch-all fallback chain, SSR injection content.

### 8. Event emission map (dev line node-auth@e8af923)

Not present at v1.9.0 — at `cc01e997` no router, strategy or middleware publishes to the `AuthEventBus` (reference-issues.md N10). At the dev line the routers publish when, and only when, a bus is supplied (`RouterOptions.eventBus`, src/router/auth.router.ts:183-188; `AdminOptions.eventBus`, src/router/admin.router.ts:162-166 — config-schema.md §1.20); every site below is skipped silently otherwise. Nothing in this subsection is visible on HTTP; it is the direct input for the P7 event plane. All `file:line` references here resolve against `nik2208/node-auth` @ `e8af923`.

#### 8.1 Envelope and request context

`AuthEventBus.publish(name, payload)` (src/events/auth-event-bus.ts:57-65) fills `event` and `timestamp` (ISO 8601, unless supplied) and emits on `name` **and** on `'*'`. Full `AuthEventPayload` (src/events/auth-event-bus.ts:6-26): `event`, `timestamp`, `data?`, `userId?`, `tenantId?`, `sessionId?`, `correlationId?`, `ip?`, `userAgent?`.

`getRequestEventContext(req)` — identical in both routers (src/router/auth.router.ts:402-416, src/router/admin.router.ts:218-232):

| Field | Source |
|---|---|
| `correlationId` | `req.headers['x-correlation-id']` (first element when the header repeats); `undefined` when absent; copied verbatim — **unvalidated client input**, no length or format check |
| `ip` | `req.ip \|\| req.socket.remoteAddress` (honours Express `trust proxy` through `req.ip`) |
| `userAgent` | `req.headers['user-agent']` (first element if array) |

`publishRouterEvent` / `publishAdminEvent` (src/router/auth.router.ts:418-433, src/router/admin.router.ts:234-250) publish `{ ...context, ...payload }` — payload keys win. The three `AuthConfigurator` sites (§8.4) publish with **no** request context. `X-Correlation-Id` is thus the one new request header the dev line consumes; nothing is echoed back.

#### 8.2 `src/router/auth.router.ts` — 19 sites

| # | Line | Event | Trigger (route → outcome) | `userId` | `sessionId` | `data` |
|---|---|---|---|---|---|---|
| 1 | :649 | `AUTH_LOGIN_SUCCESS` | `POST /login` → 200 after `issueTokens` (no-2FA path only; the 2FA challenge responses emit nothing) | `user.id` | new `sid` | `{ method: 'local' }` |
| 2 | :656 | `AUTH_LOGIN_FAILED` | `POST /login` → `AuthError` with `statusCode === 401` only (`INVALID_CREDENTIALS`, local.strategy.ts:21/:24/:28); the 403 `EMAIL_NOT_VERIFIED` / `EMAIL_VERIFICATION_REQUIRED` paths emit nothing | — | — | `{ method: 'local', email: req.body?.email }` (the attempted e-mail — PII on the bus) |
| 3 | :692 | `AUTH_LOGOUT` | `POST /logout` → 200 (always, even with no/invalid cookie) | `req.user?.sub` (cookie-derived; bearer mode → `undefined`, §1 3.2 [MISMATCH] unchanged) | `req.user?.sid` | — |
| 4 | :733 | `SESSION_ROTATED` | `POST /refresh` → 200 | `user.id` | new `sid` | `{ previousSessionId: payload.sid }` |
| 5 | :813 | `USER_CREATED` | `POST /register` → 201 | `user.id` | — | `{ email: user.email, method: 'custom' \| 'default' }` (`'custom'` iff `options.onRegister` was supplied) |
| 6 | :943 | `USER_2FA_ENABLED` | `POST /2fa/verify-setup` → 200 | `req.user.sub` | — | — |
| 7 | :968 | `AUTH_LOGIN_SUCCESS` | `POST /2fa/verify` → 200 | `user.id` | new `sid` | `{ method: 'totp' }` |
| 8 | :997 | `USER_2FA_DISABLED` | `POST /2fa/disable` → 200 | `req.user.sub` | — | — |
| 9 | :1030 | `USER_PASSWORD_CHANGED` | `POST /change-password` → 200 (**not** `/reset-password`, which emits nothing) | `user.id` | — | — |
| 10 | :1096 | `USER_EMAIL_VERIFIED` | `GET /verify-email` → 200 (not from the silent first-magic-link verification, :1278-1280) | `user.id` | — | — |
| 11 | :1175 | `USER_EMAIL_CHANGED` | `POST /change-email/confirm` → 200 | `user.id` | — | `{ oldEmail, newEmail }` |
| 12 | :1267 | `AUTH_LOGIN_SUCCESS` | `POST /magic-link/verify` `mode='2fa'` → 200 | `user.id` | new `sid` | `{ method: 'magic-link' }` |
| 13 | :1282 | `AUTH_LOGIN_SUCCESS` | `POST /magic-link/verify` default (login) mode → 200 | `user.id` | new `sid` | `{ method: 'magic-link' }` |
| 14 | :1408 | `AUTH_LOGIN_SUCCESS` | `POST /sms/verify` → 200 | `user.id` | new `sid` | `{ method: 'sms' }` |
| 15 | :1444 | `AUTH_OAUTH_SUCCESS` | `GET /oauth/{google,github,<name>}/callback` → 302 (no-2FA path, after cookies set; the 2FA redirect path :1428-1440 returns first and emits nothing) | `user.id` | new `sid` | `{ provider: user.loginProvider ?? 'oauth', redirectTo }` |
| 16 | :1480 | `AUTH_OAUTH_CONFLICT` | `GET /oauth/google/callback` → `OAUTH_ACCOUNT_CONFLICT` catch (before the 302) | — | — | `{ provider: 'google', ...err.data }` (`email`/`providerAccountId` from `err.data` land on the bus) |
| 17 | :1530 | `AUTH_OAUTH_CONFLICT` | `GET /oauth/github/callback` → same | — | — | `{ provider: 'github', ...err.data }` |
| 18 | :1580 | `AUTH_OAUTH_CONFLICT` | `GET /oauth/<name>/callback` → same | — | — | `{ provider: s.name, ...err.data }` |
| 19 | :1776 | `USER_DELETED` | `DELETE /account` → 200 | `userId` (from token) | — | — |

`tenantId` is never set by the auth router. `issueTokens` now returns `{ sessionId: payload.sid }` (:463, :493) to feed the `sessionId` column; it is `undefined` without a `sessionStore`.

#### 8.3 `src/router/admin.router.ts` — 4 sites

| # | Line | Event | Trigger | `userId` | `tenantId` | `data` |
|---|---|---|---|---|---|---|
| A | :1002 | `ROLE_ASSIGNED` | `POST /api/users/:id/roles` → 200 | `:id` | `body.tenantId` | `{ role }` |
| B | :1020 | `ROLE_REVOKED` | `DELETE /api/users/:id/roles/:role` → 200 | `:id` | — | `{ role }` (decoded) |
| C | :1041 | `ROLE_ASSIGNED` | `POST /users/:id/promote` `{ method: 'flag' }` → 200 | `:id` | — | `{ role: 'admin', method: 'flag' }` |
| D | :1055 | `ROLE_ASSIGNED` | `POST /users/:id/promote` `{ method: 'role' }` → 200 | `:id` | — | `{ role: 'admin', method: 'role' }` |

Admin `POST /login` / `POST /logout` and every other admin route emit nothing.

#### 8.4 `src/auth-configurator.ts` — 3 sites (no request context)

| # | Line | Event | Trigger | `data` |
|---|---|---|---|---|
| a | :92 | `ROLE_ASSIGNED` | `promoteToAdmin(userId, { method: 'flag' })` | `{ role: 'admin', method: 'flag' }` |
| b | :104 | `ROLE_ASSIGNED` | `promoteToAdmin(userId, { method: 'role' })` | `{ role: 'admin', method: 'role' }` |
| c | :133 | `ROLE_REVOKED` | `revokeAdmin(userId, { method })` — always, even when `method: 'both'` skipped the flag step for lack of `userStore.update` (:115-125) | `{ role: 'admin', method }` |

#### 8.5 Full `AuthEventNames` (src/events/auth-event-names.ts:5-40) — 26 names, 15 with an emitter

v1.9.0 has 25 names; the dev line inserts `USER_EMAIL_CHANGED` (:9). The 26 publish sites (19 + 4 + 3) cover 15 names; 11 remain convention-only.

| Constant | String | Emitted at the dev line? |
|---|---|---|
| `USER_CREATED` | `identity.user.created` | yes (§8.2 #5) |
| `USER_DELETED` | `identity.user.deleted` | yes (#19) — **not** from admin `DELETE /api/users/:id` |
| `USER_EMAIL_CHANGED` | `identity.user.email.changed` | yes (#11) — **new name** |
| `USER_EMAIL_VERIFIED` | `identity.user.email.verified` | yes (#10) — not from the first magic-link login (:1278-1280 verifies silently) |
| `USER_PASSWORD_CHANGED` | `identity.user.password.changed` | yes (#9) — **not** from `/reset-password` |
| `USER_2FA_ENABLED` | `identity.user.2fa.enabled` | yes (#6) |
| `USER_2FA_DISABLED` | `identity.user.2fa.disabled` | yes (#8) |
| `USER_LINKED` | `identity.user.linked` | **no** (linked-accounts / link-verify routes emit nothing) |
| `USER_UNLINKED` | `identity.user.unlinked` | **no** |
| `SESSION_CREATED` | `identity.session.created` | **no** (login success emits only `AUTH_LOGIN_SUCCESS`) |
| `SESSION_REVOKED` | `identity.session.revoked` | **no** (`DELETE /sessions/:handle`, admin `DELETE /api/sessions/:handle`, logout's `revokeSession` all silent) |
| `SESSION_EXPIRED` | `identity.session.expired` | **no** |
| `SESSION_ROTATED` | `identity.session.rotated` | yes (#4) |
| `AUTH_LOGIN_SUCCESS` | `identity.auth.login.success` | yes (#1, #7, #12, #13, #14) |
| `AUTH_LOGIN_FAILED` | `identity.auth.login.failed` | yes (#2) — local 401 only; no failure events for TOTP/SMS/magic-link/OAuth |
| `AUTH_LOGOUT` | `identity.auth.logout` | yes (#3) |
| `AUTH_OAUTH_SUCCESS` | `identity.auth.oauth.success` | yes (#15) |
| `AUTH_OAUTH_CONFLICT` | `identity.auth.oauth.conflict` | yes (#16–18) |
| `TENANT_CREATED` | `identity.tenant.created` | **no** |
| `TENANT_DELETED` | `identity.tenant.deleted` | **no** |
| `TENANT_USER_ADDED` | `identity.tenant.user.added` | **no** |
| `TENANT_USER_REMOVED` | `identity.tenant.user.removed` | **no** |
| `ROLE_ASSIGNED` | `identity.role.assigned` | yes (§8.3 A, C, D; §8.4 a, b) |
| `ROLE_REVOKED` | `identity.role.revoked` | yes (§8.3 B; §8.4 c) |
| `PERMISSION_GRANTED` | `identity.permission.granted` | **no** |
| `PERMISSION_REVOKED` | `identity.permission.revoked` | **no** |

Coverage holes a port must not paper over by inventing emissions the reference lacks: `/reset-password`, session revocation (user and admin), linked accounts, admin user delete / tenant / role CRUD, admin login. Retention note for the telemetry store: `AUTH_LOGIN_FAILED.data.email` (:657) and `AUTH_OAUTH_CONFLICT.data` (spreads `err.data`, :1481) carry PII.

---

## 7. Token claim sets, cookie serialization matrix, JWKS, error catalog

Scope: exact JWT payloads (HS256 access/refresh, 2FA tempToken, admin JWT, RS256 IdP pair), the full cookie name/attribute matrix produced by `TokenService`, the JWKS document/endpoint/client behaviour, and the complete error catalog (every `new AuthError(` site plus every plain-object error emission carrying a `code`). All claims are grounded in awesome-node-auth @ cc01e997; file:line references are relative to that repo root. Where README/JSDoc prose disagrees with code, the code is documented and the disagreement flagged.

---

### 1. JWT claim sets

#### 1.1 HS256 access token (cookie/bearer session token)

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
| `loginProvider` | string | always (`?? 'local'`, src/router/auth.router.ts:379). **dev line (node-auth@e8af923):** `buildPayload` unchanged (:387), but the OAuth callbacks pre-fill `user.loginProvider ?? '<google\|github\|s.name>'` before signing (:1476, :1526, :1576), so the callback-issued pair carries the provider name for strategy users that lack the field; not persisted — `/me` and every later `/refresh` pair still say what the DB user says (claim drift, reference-issues.md N42) |
| `isEmailVerified` | boolean | always (`?? false`) |
| `isTotpEnabled` | boolean | always (`?? false`) |
| `sid` | string | only when `options.sessionStore` configured (src/router/auth.router.ts:425-433) |
| `iat`, `exp` | number | always (jwt-managed; stripped from input at token.service.ts:19/:73) |
| `iss` | string | **never** in HS256 router-issued tokens (only IdP mode, §1.5) |
| custom | unknown | whatever `buildTokenPayload` returns (index signature, src/models/token.model.ts:22) |

Type declarations: `AccessTokenPayload`, src/models/token.model.ts:6-23. `kid` is intentionally absent from the payload — it is a JOSE **header** parameter set via `keyid` (comment src/models/token.model.ts:19-20; consistent with code at token.service.ts:73, :84).

Tests: round-trip of `sub`/`email`/`role` — tests/token.service.test.ts:26-32; custom claims in access token — tests/token.service.test.ts:171-179; `sid` embedded on login — tests/auth.router.test.ts:1142-1151.

#### 1.2 HS256 refresh token

`src/services/token.service.ts:25-29`: **identical claim set** (same `claims` object as the access token, including `sid` and custom claims), signed with `config.refreshTokenSecret`, `expiresIn: config.refreshTokenExpiresIn ?? '7d'`. Algorithm HS256 (default, unpinned).

Tests: custom claims survive in refresh token — tests/token.service.test.ts:181-188; refresh verification — tests/token.service.test.ts:34-38.

`parseExpiryMs` (src/router/auth.router.ts:357-372) converts `refreshTokenExpiresIn` to ms for the session `expiresAt` and the stored refresh-token expiry (defaults to `7d` = 604 800 000 ms when unparseable, :360); it does **not** drive cookie Max-Age (see §2.3).

#### 1.3 2FA tempToken

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

#### 1.4 Admin JWT (`src/router/admin.router.ts`)

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

#### 1.5 RS256 IdP-mode pair (`src/services/token.service.ts:40-96`)

Activation: `config.idProvider.privateKey` present **or** `idProvider.enabled === true` (:42); otherwise `AuthError('IdP mode is not enabled', 'IDP_NOT_ENABLED', 500)` (:44). Missing privateKey → ephemeral RSA-2048 keypair auto-generated with a **once-per-process** console warning (:50-66; warning text "auto-generating an ephemeral RSA keypair… All tokens will be invalidated on restart"); missing publicKey → derived from privateKey (:67-69). Tests: tests/jwks.service.test.ts:153-171, :211-232, :234-273.

Payload: `{ iat, exp, kid: _kid, ...claims }` destructured out (:73), then `iss: idp.issuer` added **only when configured** (:74-77; no issuer → no `iss` claim, pinned by tests/jwks.service.test.ts:228-231).

Header: `algorithm: 'RS256'`, `keyid: 'provisioner-key-1'` — the kid is a **hardcoded constant** (:78) used for both tokens (:81-85, :89-93). Pinned by tests/jwks.service.test.ts:147-150.

Expiries:
- Access token: `idp.tokenExpiry ?? '30d'` (:80).
- Refresh token: **also RS256-signed with the same private key** (:89-93), `expiresIn: idp.refreshTokenExpiry ?? config.refreshTokenExpiresIn ?? '90d'` (:91). The code comment (:87-88) states the intent: refresh is RS256 with a longer expiry — in IdP mode there is no shared HS256 secret with downstream verifiers, so both halves must verify against the JWKS. [UNTESTED — no test asserts refresh-token alg or the 30d/90d defaults.]

**[MISMATCH] The auth router never calls `generateIdProviderTokenPair`.** Grep over `src/` finds no caller — `/login`, `/refresh`, etc. always issue HS256 pairs via `generateTokenPair` (src/router/auth.router.ts:441). Enabling `idProvider` registers the JWKS endpoint (§3) but does **not** switch router-issued session tokens to RS256; RS256 issuance is a host-app-level API only. README.detailed.md implies IdP mode signs "JWTs" generally — code wins.

#### 1.6 `jwt.verify` options — the missing algorithms allow-list

| Verifier | Call | `algorithms` pinned? |
|---|---|---|
| `verifyAccessToken` | `jwt.verify(token, config.accessTokenSecret)` — src/services/token.service.ts:145 | **NO** |
| `verifyRefreshToken` | `jwt.verify(token, config.refreshTokenSecret)` — src/services/token.service.ts:154 | **NO** |
| `_verifyRsaToken` (JWKS path) | `jwt.verify(token, publicKeyPem, { algorithms: ['RS256'] })` — src/services/token.service.ts:136 | yes, `['RS256']`; manual `iss` equality check at :137-138 |
| Admin policy guard | `jwt.verify(rawToken, jwtSecret)` — src/router/admin.router.ts:300 | **NO** |

Dependency is `jsonwebtoken ^9.0.3` (package.json:61); v9 limits a string secret to the HMAC family by key type, so RS→HS key-confusion is mitigated by the library, but HS384/HS512 tokens signed with the same secret string would still verify on the HS256 paths. [UNTESTED]

Failure mapping: `verifyAccessToken` catch → `AuthError('Invalid or expired access token', 'INVALID_ACCESS_TOKEN', 401)` (:148); `verifyRefreshToken` catch → `AuthError('Invalid or expired refresh token', 'INVALID_REFRESH_TOKEN', 401)` (:157). Note the route handlers and middleware usually catch these and emit their own bodies (§4.2, §4.4).

#### 1.7 Bearer-mode delivery (cross-check)

`sendTokens` (src/router/auth.router.ts:399-406): when `req.headers['x-auth-strategy'] === 'bearer'` (:390-392) the response is `{ success: true, accessToken, refreshToken }` **top-level** and **no cookies are set**; otherwise cookies are set and the body is `{ success: true }`. Pinned by tests/auth.router.test.ts:534-545 (login) and :566-577 (refresh; `set-cookie` asserted undefined). `POST /refresh` accepts `refreshToken` from the body first, cookie fallback (src/router/auth.router.ts:625-626), so cookie-mode refresh with an empty body works — matches the client contract. ✓ no mismatch.

---

### 2. Cookie serialization matrix (`src/services/token.service.ts:161-302`)

#### 2.1 Name-prefix resolution — `getCookieName` (:161-172)

| Condition (from `config.cookieOptions`) | Resulting name |
|---|---|
| `secure` falsy (incl. unset) | `<name>` (plain) — :162 |
| `secure: true` AND (`path` unset or `'/'`) AND no `domain` | `__Host-<name>` — :166-169 |
| `secure: true` otherwise (custom path or domain set) | `__Secure-<name>` — :171 |

Tests: `__Host-` — tests/token.service.test.ts:191-200; `__Secure-` via path — :227-233; `__Secure-` via domain — :235-242; no prefix when insecure — :244-251.

#### 2.2 `setCookie` enforcement (:182-193)

Common options (:175-180): `httpOnly: true`, `secure: cookieOptions?.secure ?? false`, `sameSite: cookieOptions?.sameSite ?? 'lax'`, `path: cookieOptions?.path ?? '/'`.

For a finalised `__Host-` name (:185-188): `domain` deleted, `path` forced to `'/'`, `secure` forced `true` — this **overrides even the refresh cookie's restricted path** (pinned with rationale by tests/token.service.test.ts:202-214). Otherwise `domain = config.cookieOptions?.domain` (:190).

#### 2.3 The matrix

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

#### 2.4 `clearTokenCookies` (:232-268)

Clears **all name variants defensively**: `possibleNames = new Set([primaryName, '__Host-<name>', '__Secure-<name>', '<name>'])` (:243) — up to 3 distinct `clearCookie` calls per logical cookie (4 entries, Set-deduped). Per variant: `__Host-` cleared with `path: '/'`, `secure: true`, no domain (:247-250); others get `domain: config?.cookieOptions?.domain` (:252). Cleared cookies and options:

- `accessToken` (:258) — path `cookieOptions.path ?? '/'`.
- `refreshToken` (:261-263) — path mirrors the set-time refresh-path resolution (`refreshTokenPath ?? apiPrefix/refresh ?? '/auth/refresh'`), because clearing requires exact name+path+domain match (comments :241, :260).
- `csrf-token` (:265-267) — **only when `config?.csrf?.enabled`**.

Config is optional (`config?`): calling with no config clears plain+prefixed `accessToken`/`refreshToken` with defaults but **not** csrf-token. Tests: all variants cleared — tests/token.service.test.ts:269-282; `__Host-refreshToken` cleared with `path=/` — :216-225; refresh-path parity — :96-114; csrf variants — :335-343.

#### 2.5 `extractTokenFromCookie` (:274-302)

Read priority: **`__Host-<name>` → `__Secure-<name>` → `<name>`** (:276-280). Sources: `req.cookies` (cookie-parser) first (:282-287); fallback manual parse of the raw `Cookie` header, splitting on `;` / first `=`, `decodeURIComponent` on values (:289-296), then the same priority order again (:298-300); returns `null` when absent (:301). Matches the client contract's cookie read priority exactly. Tests: priority — tests/token.service.test.ts:253-267; header fallback — :139-143; `req.cookies` — :145-149; null — :151-155.

---

### 3. JWKS

#### 3.1 Document shape (`src/services/jwks.service.ts`)

`JWK` interface (:5-12) and `publicKeyToJwk` (:168-179) produce exactly:

```json
{ "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "<kid>", "n": "<base64url>", "e": "<base64url>" }
```

`buildJwksDocument(publicKeyPem, kid = 'provisioner-key-1')` → `{ "keys": [ <single JWK> ] }` (:184-186). Default kid pinned by tests/jwks.service.test.ts:67-71; field shape by :42-50; PEM↔JWK round-trip by :80-89.

#### 3.2 Endpoint registration (`src/router/auth.router.ts:471-505`)

- Registered only when `config.idProvider?.privateKey || config.idProvider?.enabled === true` (:473), **before any auth middleware — always public** (comment :472; it is the first route registered).
- Path: `idp.jwksPath ?? '/.well-known/jwks.json'` (:475). Custom path honored (pinned tests/jwks.service.test.ts:318-338).
- Keypair initialised at router-creation time (:480-486) and the JWKS document is **built once** (:488) — key rotation requires recreating the router.
- Handler (:490-504):
  - CORS: `idp.jwksCorsOrigins ?? '*'` → `Access-Control-Allow-Origin: *` (:492-494); when a list/string is configured, the request `Origin` is echoed back only if it matches (:496-500), otherwise **no ACAO header at all**. [UNTESTED — no test asserts CORS headers]
  - `Cache-Control: public, max-age=3600` (:502). [UNTESTED]
  - Body: the prebuilt JWKS document as JSON (:503). Pinned (status 200, `keys[0].kty === 'RSA'`, `alg === 'RS256'`, `kid === 'provisioner-key-1'`) by tests/jwks.service.test.ts:293-316.
- **There is NO `/.well-known/openid-configuration`.** A repo-wide grep for `openid-configuration` returns zero hits in `src/` and `tests/`; the only `.well-known` path anywhere is the JWKS one. Confirmed.

#### 3.3 JwksClient — SWR caching (`src/services/jwks.service.ts:29-141`)

- Defaults: `cacheTtl = 3_600_000` ms (:40), `fetchTimeout = 5000` ms (:41).
- `getJwks()` (:49-92): fresh cache (now < expiry) returned directly (:51-53); in-flight fetch deduped via `fetchPromise` (:56-58); **stale-while-revalidate**: with a stale cache, returns the stale doc immediately and refreshes in background, a failed background refresh silently keeps the stale doc (:62-76); no cache → awaits the initial fetch (:79-91).
- `getKey(kid)` → `doc.keys.find(k => k.kid === kid) ?? null` (:95-98). `invalidateCache()` nulls doc/expiry/fetchPromise (:101-105).
- `_fetch` rejects on non-200, timeout, or a body without a `keys` array (:107-140).

#### 3.4 Unknown-kid invalidation retry (`src/services/token.service.ts:102-133`)

`verifyWithJwks`: decode unverified to read header `kid` (:105-113; missing/garbled → `INVALID_TOKEN` 401). If `getKey(kid)` is null → `invalidateCache()` and retry **once** (:117-124, supports key rotation); still null → `AuthError('Unknown signing key', 'INVALID_TOKEN', 401)` (:121). Verification pins `['RS256']` and checks `iss` equality when `expectedIssuer` given (:135-141). Any non-AuthError failure is normalized to `INVALID_TOKEN` 401 (:129-132). Tests: unknown kid → 401 — tests/jwks-auth.middleware.test.ts:152-173; wrong issuer → 401 — :107-125; expired → 401 — :127-150.

Resource-server middleware keeps one module-level `JwksClient` per `jwksUrl`, shared across middleware instances (src/middleware/jwks-auth.middleware.ts:10-23).

---

### 4. Error catalog

#### 4.1 Error body shape

`AuthError` (src/models/errors.ts:1-11): `message`, `code: string`, `statusCode: number = 401`, optional `data?: Record<string, unknown>`. **`data` is never serialized into any HTTP response.**

Emitters that translate AuthError → HTTP:
- `handleError` (src/router/auth.router.ts:189-196): `res.status(err.statusCode).json({ error: err.message, code: err.code })`; non-AuthError → `500 { "error": "Internal server error" }` (no `code`).
- Router-level catch-all error middleware (src/router/auth.router.ts:1682-1689): identical mapping.
- API-key middleware (src/middleware/api-key.middleware.ts:48-54): identical mapping.

So the canonical error body is `{ "error": "<message>", "code": "<CODE>" }`; unexpected errors are `{ "error": "Internal server error" }` **without** `code`.

#### 4.2 Complete `new AuthError(` table (all 38 sites in `src/` at v1.9.0 — **39 at the dev line node-auth@e8af923**, last row)

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
| `INVALID_INPUT` | Email and password are required | 400 | **dev line (node-auth@e8af923) only** — src/router/auth.router.ts:519, built-in `/register` handler (§1 3.7); absent at v1.9.0 |

(Counts per file: auth.router.ts 5, token.service.ts 8, local 5, magic-link 5, api-key 6, google 3, github 3, generic-oauth 2, sms 1 = 38 — matches the grep count. **dev line (node-auth@e8af923):** auth.router.ts 6 with `INVALID_INPUT` = **39**, matches the grep count at `e8af923`.)

#### 4.3 Coded errors emitted as plain objects (not AuthError)

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

#### 4.4 Code-less error bodies clients must not pattern-match on `code`

- `createAuthMiddleware`: `403 { error: 'No access token provided' }` (src/middleware/auth.middleware.ts:30) and `403 { error: 'Invalid or expired access token' }` (:63) — **no `code`**, and note both are **403**, not 401.
- `POST /refresh`: `401 { error: 'No refresh token provided' }` (src/router/auth.router.ts:628) and `401 { error: 'Invalid refresh token' }` (:645) — **no `code`**. `SESSION_REVOKED` (:638) is the **only** coded 401 on the refresh path; clients distinguishing revocation from ordinary refresh failure by `code` are compatible. ✓
- `jwks-auth.middleware`: `403 { error: 'No access token provided' }` (src/middleware/jwks-auth.middleware.ts:57) — no code.
- The entire admin router emits plain `{ error: '<msg>' }` bodies without `code` (e.g. src/router/admin.router.ts:193, :198, :328, :388, :784), and admin `/login` failure is `401 { error: 'Invalid credentials' }` (:577).

#### 4.5 Cross-checks against the client contract (this section's scope)

- CSRF header `X-CSRF-Token` (read as `req.headers['x-csrf-token']`, src/middleware/auth.middleware.ts:37) ✓; cookie priority `__Host-csrf-token` > `__Secure-csrf-token` > `csrf-token` (token.service.ts:276-280) ✓; JS-readable (`httpOnly: false`, :206/:216) ✓; no `/csrf` endpoint (auto-init middleware instead, auth.router.ts:530-538) ✓.
- `SESSION_REVOKED` 401 body shape ✓ (§4.3).
- Bearer login/refresh return top-level `accessToken`/`refreshToken` ✓; cookie-mode refresh works with an empty body ✓ (§1.7).
- CSRF cookie Max-Age is 15 min; if it expires, protected state-changing calls fail `CSRF_INVALID` until any auth-router request re-initializes the cookie (auth.router.ts:530-538). Clients that hit `/refresh` first (an auth-router route) recover automatically. [UNTESTED]
