## Tools router, SSE, UI router

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

Constructor (:170-189): `sseManager` created only when `options.sse === true` (else `null`); `WebhookSender` always instantiated; `webhookVersion` default `'1'` (:175); email/SMS `NotificationService` only when `emailConfig`/`smsConfig` provided; when SSE is on, the manager is registered in `SseNotifyRegistry` (:186-188, decorator plumbing in src/tools/sse-notify.decorator.ts:37-54 — not an HTTP surface).

#### 4.1 track(eventName, data?, options) fan-out — exact order (:199-269)

1. **Telemetry store** — `store.save(telemetryEvent)` awaited, errors swallowed (:217-219; pinned tests/tools.test.ts:199-205, :274-280). `TelemetryEvent` = `{id: uuid, event, timestamp: ISO, data, userId, tenantId, sessionId, correlationId, ip, userAgent}` (:203-214).
2. **Event bus** — `eventBus.publish(eventName, payload)` (:222-231; pinned :207-213).
3. **SSE** — broadcast to topics `['global']` + `tenant:<tenantId>` + `user:<userId>` + `session:<sessionId>` as present (:234-247, resolveTopics :353-359); stream event reuses the SAME `id`/`timestamp` as the telemetry event, `type = eventName`, and **`data` = the whole `TelemetryEvent`** (so on the wire it appears as `rawData: {id, event, timestamp, data, ...}`) (:236-243; pinned :215-230).
4. **Outgoing webhooks** — `webhookStore.findByEvent(eventName, tenantId)` (errors → `[]`), payload `OutgoingWebhookEvent` = `{event, version: webhookVersion, timestamp, data: data ?? null, metadata: {userId, tenantId, sessionId, correlationId}}`, delivered fire-and-forget via `webhookSender.send()` (:250-268; pinned :253-272). Sender headers: `Content-Type: application/json`, `X-Webhook-Event`, `X-Webhook-Delivery` (uuid), `X-Webhook-Timestamp`, plus `X-Webhook-Signature: sha256=<hmac-hex>` when the config has a `secret`; retries `maxRetries` (default 3) with exponential backoff from `retryDelayMs` (default 1000 ms) (src/tools/webhook-sender.ts:17-47).

Note: the code order is telemetry → bus → SSE → webhooks (comments `// 1.`–`// 4.` at :216, :221, :233, :249). Any description ordering webhooks before bus/SSE is wrong.

#### 4.2 notify(target, data, options) channels (:292-342)

- `channels` default `['sse']` (:293).
- `'sse'`: `sseManager.broadcast(target, {type: options.type ?? 'notification', data, tenantId, userId, metadata})` (:296-304) — no-op without a manager (pinned tests/tools.test.ts:232-235, :237-251).
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
    "register":       !!routerOptions.onRegister,   // dev line (node-auth@e8af923): = resolved registerHandler (auth.router.ts:1793; ui.router.ts:121) → true unless resource-server mode
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
- Error fallback (:143-161): `features` collapses to only `{register:false, google:false, github:false}` — `magicLink`, `sms`, `forgotPassword`, `verifyEmail`, `twoFactor` become `undefined` for consumers; `ui` reverts to hardcoded defaults; `translations: {}`, `lang: 'en'`. [UNTESTED]
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
