# (extract) OAuth and account linking

## OAuth and account linking

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
     - **No-2FA path:** `updateLastLogin(user.id)`; `issueTokens(..., redirectTo || '/')` → sets `accessToken`/`refreshToken` (+ `csrf-token` if enabled) cookies and **302 redirects to `redirectTo`** with no query params appended (:1315-1316, :445-447). Pinned: redirect to custom mobile scheme `myapp://auth` (tests/auth-flow-improvements.test.ts:688-706), redirect to state-embedded origin (:901-920).
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
