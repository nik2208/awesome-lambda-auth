## Core auth, profile, sessions, account deletion, auth middleware

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
- **dev line (node-auth@e8af923):** mounted by default — `registerHandler = options.onRegister ?? <built-in userStore.create + bcrypt handler>` (auth.router.ts:515-525, gate :801; `400 INVALID_INPUT` on missing email/password, :519); see wire-contract.md §1 3.7.

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
