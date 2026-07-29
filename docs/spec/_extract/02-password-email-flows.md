## Password management, email verification, email change

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
