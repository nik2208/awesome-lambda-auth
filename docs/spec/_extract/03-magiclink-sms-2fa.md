## Magic link, SMS OTP, TOTP 2FA

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
