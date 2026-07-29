## Admin router (complete surface)

Scope: complete wire contract of `src/router/admin.router.ts` in awesome-node-auth (pinned cc01e997), covering all 50 route registrations (the recon inventory claimed 51 — see the count note below), the three guard modes (legacy `adminSecret`, `accessPolicy` policy guard, unprotected fallback), the self-contained admin login/logout with its `__Host-`-aware cookie, upload/settings/webhook/template/api-key/session/role/tenant endpoint groups, optional-store gating, and the Swagger endpoints. Every claim carries a `file:line` reference into the router or its interfaces; test pins cite `tests/new-features.test.ts` and `tests/swagger.test.ts`. Behaviors with no test are marked [UNTESTED]. All error bodies on this router use `{error: string}` — **no route on the admin router ever emits a `code` field** (relevant to the client-contract cross-check at the end).

### Route count note

`grep 'router.(get|post|put|patch|delete)('` over src/router/admin.router.ts yields exactly **50** registrations, first at src/router/admin.router.ts:543 (`POST /login`) and last at src/router/admin.router.ts:1517 (`GET /api/docs`). The recon inventory's "51 routes" is off by one — [MISMATCH] with recon, not with any client. (`router.use(expressJson())` at src/router/admin.router.ts:509 is middleware, not a route; it means the admin router parses JSON bodies itself even if the host app has no body parser.)

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
