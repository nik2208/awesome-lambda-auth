package main

import (
	"log/slog"

	auth "github.com/nik2208/awesome-go-auth"
)

// WireDeviation is one place this product knowingly answers differently from
// the reference at the configuration layer: a default, a refusal or a policy
// that no store and no core route owns, and that a client can observe.
//
// The other two registers live where their behaviour lives — the imported core
// publishes auth.CompatibilityNotes() and the DynamoDB store publishes
// (*Store).CompatibilityNotes() — and docs/deviations.md indexes all three.
// deviations_test.go fails when an entry of any register is missing from that
// index, so a deviation cannot quietly stop being documented.
//
// One kind of entry sits outside that division and is here because nowhere else
// can carry it: a divergence that belongs to a core route, that this product
// cannot fix without forking the core, and that a deployment only becomes able
// to reach because this product wired the block it lives in. The rule that a
// deviation has to be announced at cold start does not stop applying because
// the code that causes it is imported, and the core's own register is not ours
// to write. Such an entry says so in Why, and names the test that will fail the
// day upstream closes it.
type WireDeviation struct {
	// ID is the stable handle. It never changes once published.
	ID string
	// Surface is the knob or route affected.
	Surface string
	// Behaviour is what this product does.
	Behaviour string
	// Reference is what awesome-node-auth does instead.
	Reference string
	// Why is the reason the reproduce-the-reference rule was set aside.
	Why string
	// Spec names the document and section that argues the decision.
	Spec string
}

// WireDeviations returns the product-level register, freshly built on every
// call.
func WireDeviations() []WireDeviation {
	return []WireDeviation{
		{
			ID:      "csrf-enabled-by-default",
			Surface: "security.csrf.enabled, every cookie-authenticated unsafe request",
			Behaviour: "Double-submit CSRF is enforced unless the operator turns it off, " +
				"and turning it off in production is refused (RS-3).",
			Reference: "csrf.enabled defaults to false (src/middleware/auth.middleware.ts:35), " +
				"so a deployment that never mentions CSRF runs without it.",
			Why: "A deployable product has to be safe with an empty configuration; a " +
				"library can leave the choice to the integrator.",
			Spec: "docs/spec/config-schema.md §1.3 and §2 RS-3",
		},
		{
			ID:      "production-by-default",
			Surface: "deployment.environment",
			Behaviour: "The environment defaults to production, which is the strict side of " +
				"every rule that distinguishes the two: memory stores are refused, " +
				"env-sourced secrets are warned about, swagger is off.",
			Reference: "There is no environment knob; behaviour that depends on one reads " +
				"NODE_ENV, which is unset in a fresh process and therefore not production.",
			Why: "A stack deployed by someone who forgot to say which environment it is " +
				"should get the stricter rules, not the looser ones.",
			Spec: "docs/spec/config-schema.md §1 (deployment) and §2",
		},
		{
			ID:      "refresh-token-families",
			Surface: "POST <prefix>/refresh",
			Behaviour: "Refresh tokens form a family per session: a replayed refresh token " +
				"revokes the whole session, and every later refresh on it answers 401 " +
				"SESSION_REVOKED.",
			Reference: "Rotation replaces the token; a replay fails as an invalid token and " +
				"the session stays alive.",
			Why: "A replay is the signature of a stolen refresh token, and on a serverless " +
				"stack the store is the only place the theft can be acted on.",
			Spec: "docs/spec/data-model.md §4.3; docs/spec/decisions.md D-7 (signed off 2026-09-11)",
		},
		{
			ID:      "idp-kid-derived-from-key-material",
			Surface: "the kid header of every RS256 token the IdP signs, and the kid of every key in GET <prefix>/.well-known/jwks.json",
			Behaviour: "The kid is base64url(sha256(SPKI DER))[:16] of the key that signed — derived from the " +
				"key material, so it is stable for a key, different for a different key, and identical " +
				"whether the key is held in KMS or supplied as a PEM.",
			Reference: "The kid is the constant \"provisioner-key-1\" for every deployment and every key " +
				"(src/services/token.service.ts:78, src/services/jwks.service.ts:184).",
			Why: "A rotation has to be additive. With a derived kid the old and new keys are published " +
				"together under different kids and a token minted before the rotation still selects the " +
				"key that signed it; with one constant kid the JWKS document can only ever describe one " +
				"key, so every rotation invalidates every token in flight. A relying party reads the kid " +
				"out of the token and looks it up in the document, so nothing that follows the protocol " +
				"can tell the difference — only something that hardcoded the reference's constant could.",
			Spec: "docs/oidc.md; docs/spec/config-schema.md §1.10 addendum; docs/spec/decisions.md D-3",
		},
		{
			ID:      "templates-dir-only-seeds-absent-ids",
			Surface: "email.templatesDir, and the body and subject of every mail rendered from a stored template",
			Behaviour: "The directory is read once, at cold start, and writes only the template ids " +
				"and UI pages the template store does not already hold; a template saved " +
				"through the store wins over the file of the same id, on every cold start.",
			Reference: "There is no templates directory: config.templateStore is the only " +
				"override source and its contents come from whoever writes to it " +
				"(src/interfaces/template-store.interface.ts:13-43, memory-template.store.ts).",
			Why: "A Lambda has no writable filesystem and no deploy step that runs code, so " +
				"the artifact is the only place a shipped template can live and cold start " +
				"the only moment it can be read; and a runtime edit must survive the next " +
				"redeploy, or the admin API would be undone by every cold start.",
			Spec: "docs/spec/config-schema.md §1.5, §3.8 and §3.10; docs/spec/decisions.md D-17",
		},
		{
			ID:      "runtime-settings-seed-only-fills-absent-keys",
			Surface: "runtimeSettings.*, and every route that reads the settings store — today POST <prefix>/2fa/disable",
			Behaviour: "The runtimeSettings block is a cold-start seed, applied key by key and only to the keys the " +
				"settings store does not already hold; a key an administrator has set at run time wins over the " +
				"document, on every cold start, for good. A key the document leaves at its schema default is not " +
				"seeded at all.",
			Reference: "There is no seed. routerOptions.settingsStore is whatever the host app passes and its " +
				"contents come from whoever writes to it (src/interfaces/settings-store.interface.ts:28-40); the " +
				"reference ships no implementation of the interface and no configuration path into one.",
			Why: "A Lambda has no deploy step that runs code, so cold start is the only moment a declared seed can be " +
				"applied — the same position email.templatesDir is in, and templates-dir-only-seeds-absent-ids is the " +
				"same decision. Two things make it sharper here. Cold start recurs: a Lambda cold-starts on every " +
				"scale-out and after every idle period, so a seed that overwrote would revert an administrator's " +
				"toggle not at the next deployment but at an unpredictable moment in between. And the unit is a key " +
				"rather than an item: the settings are one document, so seeding it whole on the first cold start " +
				"would freeze every key at once, including the ones no block has a knob for yet — AuthSettings' " +
				"nil-means-absent gives the right granularity for free. Seeding only declared keys follows from the " +
				"same argument: writing a schema default into a runtime-mutable store is not starting from a declared " +
				"state but inventing one, and it would make a seed added to the document later inert on arrival.",
			Spec: "docs/spec/config-schema.md §1.19; docs/config-reference.md §11; docs/spec/decisions.md D-17 (the templates sibling)",
		},
		{
			ID:      "docs-page-carries-a-content-security-policy",
			Surface: "the response headers of GET <prefix>/docs and GET <prefix>/openapi.json",
			Behaviour: "Both documentation responses carry a Content-Security-Policy, X-Content-Type-Options: nosniff " +
				"and Referrer-Policy: no-referrer. The page's policy pins the one CDN origin the reference's HTML " +
				"loads from and denies everything else -- no fetch or XHR off this origin, no image beacon, no form " +
				"action, no nested frame, no framing of the page itself, no rewritten base URL. The document's policy " +
				"is default-src 'none' with the same framing and base-URI denial. The routes, their bodies and their " +
				"status codes are untouched.",
			Reference: "Neither route sets any header beyond Content-Type (auth.router.ts:1658-1677), so the Swagger " +
				"page runs swagger-ui-dist@5 from the unpkg CDN, unpinned and without subresource integrity, with " +
				"no policy of any kind (openapi.ts:1646-1669).",
			Why: "That script runs same-origin with this deployment's auth cookies, and the CSRF cookie is readable " +
				"from JavaScript by design, because the double-submit pattern requires the client to read it -- so a " +
				"bad day at the CDN is a credential-reading script on the auth origin. The honest fix is not ours to " +
				"make: the core mounts the page and the machine-readable document under one bool, this binary may add " +
				"no route under the api prefix, and the core is not forked, so the product can neither serve the " +
				"document without the page nor replace the page's HTML. A header middleware adds no route and is what " +
				"is left. It is narrowing, not closure, and the entry says so: a compromised bundle can still read a " +
				"cookie and still leak it through a top-level navigation, which no CSP directive in any shipping " +
				"browser prevents. What it removes are the silent channels. cmd/auth/docs_test.go " +
				"TestDocsPolicyCoversEveryOriginTheCorePageLoads fails the day the core's page loads from anywhere " +
				"else, which is when this policy would otherwise break the page instead of protecting it.",
			Spec: "docs/spec/config-schema.md §1.18; docs/config-reference.md §12; upstream deviation docs-routes-are-opt-in",
		},
		{
			ID:      "oauth-callback-skips-the-second-factor",
			Surface: "GET <prefix>/oauth/{provider}/callback, for an account with a second factor enabled",
			Behaviour: "The callback issues a session and redirects, for every account it resolves. " +
				"An account whose POST /login answers the second-factor challenge is signed in " +
				"through a provider without presenting one.",
			Reference: "The callback is 2FA-aware: such an account is redirected to " +
				"${redirectTo}/auth/2fa?tempToken=<jwt>&methods=<list> with no session issued " +
				"(src/router/auth.router.ts:1298-1313).",
			Why: "Not a decision this product made: the imported core's OAuthComplete has no " +
				"second-factor branch, and the rule against forking the core stands. It is " +
				"registered rather than left in a comment because wiring oauth.providers is what " +
				"makes it reachable at all -- before P4 the route answered the not-configured stub -- " +
				"and an operator who requires 2FA has to learn this from the cold-start log rather " +
				"than from an incident. cmd/auth/oauth_test.go " +
				"TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount fails the day upstream " +
				"grows the branch, which is when this entry is retired.",
			Spec: "docs/spec/wire-contract.md §3 (the tempToken) and §4; docs/config-reference.md §8.4",
		},
		{
			ID: "rate-limited-routes-answer-429",
			Surface: "every route named in rateLimit.scope -- by default POST <prefix>/login, POST <prefix>/forgot-password, " +
				"POST <prefix>/magic-link/send, POST <prefix>/magic-link/verify, POST <prefix>/sms/send, " +
				"POST <prefix>/sms/verify and POST <prefix>/2fa/verify",
			Behaviour: "A deployment that configures nothing is rate limited. Over budget, the route answers, byte for byte, " +
				"429 Too Many Requests with Retry-After: <integer seconds, at least 1>, Content-Type: application/json, " +
				"Cache-Control: no-store and the body {\"error\":\"Too many requests\",\"code\":\"RATE_LIMITED\"} -- and no " +
				"Set-Cookie, not even the CSRF auto-init one, because the limiter is outermost and nothing that sets a cookie " +
				"has run. No RateLimit-Limit, RateLimit-Remaining or RateLimit-Reset header is sent, on this response or on a " +
				"successful one. The default budget is 10 requests per 60-second fixed window per subject per scope, and the " +
				"default subject is the normalised email in the request body, falling back to the sha256 of a presented " +
				"tempToken and then to the client address the event reported.",
			Reference: "There is no rate limiting anywhere. RouterOptions.rateLimiter (src/router/auth.router.ts:46) is an " +
				"empty slot for a host-supplied Express handler; absent, the router collapses it to an empty middleware list " +
				"(rl = [], :468) and the package ships no algorithm, no default, no status and no body. Every one of these " +
				"routes answers its ordinary 200, 400 or 401 however often it is called.",
			Why: "This is net-new surface rather than a divergence from something: there is no upstream behaviour to reproduce, so " +
				"the question was never whether to match the reference but what a deployable product should do when nobody says. " +
				"The answer is this product's house rule, the one csrf-enabled-by-default and production-by-default already state: " +
				"a library may leave the choice to its integrator, a product has to be safe with an empty configuration. An auth " +
				"stack that ships unlimited is one that gets credential-stuffed, and the scope is exactly the flows where a guess " +
				"costs an attacker nothing -- login, the three credential-minting sends, and the two six-digit codes. An operator " +
				"who wants the reference's behaviour sets rateLimit.enabled to false and gets it exactly.\n\n" +
				"Four properties of the refusal are decisions in their own right. **The budget is per account, not per address.** " +
				"keyBy defaults to email because the threat is account-shaped and because an address-keyed default would put a " +
				"corporate NAT's whole office in one bucket and one DynamoDB partition, making the limiter the outage for the " +
				"people it is not aimed at (data-model.md §2.3, whose own conclusion is that the account-scoped limiter must be the " +
				"primary control); volumetric defence by source address belongs at the edge. **No RateLimit-* headers.** The usual " +
				"objection, that they hand an attacker the limit, is weak -- anyone willing to spend requests finds it by reaching " +
				"it. The decisive one is that RateLimit-Remaining on a successful response would be an oracle about somebody else's " +
				"traffic under an account-keyed counter: whoever can name victim@example.com could read from a 200 whether that " +
				"person has been logging in. Retry-After stays, because it tells a caller only what the refusal already told them " +
				"and a client that backs off is better for everyone. **The window is fixed**, so the worst case over any sliding " +
				"window of the same length is twice the budget; closing that seam means a read-modify-write on the login path " +
				"forever, and a factor of two does not change what a limit does to a stuffing run. **It fails open.** The counter " +
				"lives in the same DynamoDB table as the user store, so on this product a limiter that cannot count and a route " +
				"that cannot serve are one event: refusing would convert a partial degradation into a total outage and would " +
				"replace a 500 naming the store with a 429 blaming the caller. During such a window the remaining bound is the " +
				"in-process pre-filter, which is per execution environment and is stated as such rather than sold as a limit.\n\n" +
				"One 429 in this surface is not ours and is deliberately not restated here. GET <prefix>/oauth/{provider} and its " +
				"callback, for a provider nobody configured, are bare 404 stubs registered outside the limiter slot in the " +
				"reference (:1361-1362, :1407-1408) and one always-guarded handler here, so behind a limiter at its limit they " +
				"answer 429 where the reference answers 404. That belongs to the imported core, whose HTTPConfig.RateLimiter " +
				"comment names it and whose register carries it; duplicating it as a product entry would give one divergence two " +
				"owners and two places to retire it from. It is also unreachable without an operator naming an OAuth route in " +
				"rateLimit.scope, which the vocabulary does not offer. " +
				"cmd/auth/ratelimit_test.go TestRateLimitResponseIsExactlyThis and " +
				"TestTheShippedDefaultsAreTheOnesTheRegisterClaims fail the day this entry stops describing the product.",
			Spec: "docs/spec/config-schema.md §1.16; docs/spec/data-model.md §1.5 row #61 and §2.3; docs/config-reference.md §13",
		},
		{
			ID:      "ui-uploaded-assets-are-not-served",
			Surface: "GET <prefix>/ui/assets/logo/* and GET <prefix>/ui/assets/uploads/*, and the ui.uploadDir knob behind them",
			Behaviour: "Both paths answer 404, in every configuration. ui.uploadDir is accepted by the schema, reported at cold " +
				"start as a knob this build does not honour, and reaches nothing: HTTPConfig.UI.Uploads is left nil, which is the " +
				"core's own unconfigured state, so the two mounts do not exist rather than failing. Everything else the hosted UI " +
				"serves is unaffected, and a deployment that wants a logo sets ui.branding.logoUrl to a URL it hosts elsewhere, " +
				"which this build does honour and which the SSR injection writes into every page.",
			Reference: "config.ui.uploadDir is a directory the admin router writes uploads into (admin.router.ts:656) and two " +
				"express.static mounts read them back out of, under both the legacy /assets/logo path and the unified " +
				"/assets/uploads one (ui.router.ts:185-191). With the option set, an uploaded logo is served from the auth origin.",
			Why: "Three reasons, and the first is decisive on its own: there is no writer. The upload route is an admin route, this " +
				"build mounts no admin router, and the `admin` domain is still refused by internal/config/phases.go -- so a read " +
				"path built now would read an empty location on every deployment until the admin surface lands. The imported core " +
				"made the same call for the same reason and says so: UIOptions.Uploads is read-only \"on purpose\", because the " +
				"port has no UploadStore to write through yet.\n\n" +
				"The second is that a directory is the wrong noun in this runtime. The knob names a filesystem path and a Lambda " +
				"has none that survives a request: /var/task is read-only and /tmp is per execution environment, so a logo " +
				"uploaded during one cold start would be invisible to the next and gone by the one after. The serverless shape is " +
				"an S3 location, which config-schema.md §1.12 already records -- and that is a different thing behind the same " +
				"knob, so what the value means has to be decided together with the writer rather than guessed at here.\n\n" +
				"The third is cost, and it is why the seam was not filled speculatively. fs.FS has one operation, Open, so every " +
				"request for an uploaded asset is a GetObject -- misses included, and misses are the common case, because the logo " +
				"is requested by every page of the hosted UI whether or not anyone has ever uploaded one. Caching it per execution " +
				"environment would trade that for an upload that does not appear until the next cold start, which is worse than " +
				"not having the feature. The read path belongs beside the write path, where one design pays for both.\n\n" +
				"The entry is registered rather than left as a comment because wiring the `ui` block is what makes the two paths " +
				"reachable at all: before it, the whole subtree answered 404 and there was nothing to be surprised by. " +
				"cmd/auth/ui_test.go TestUIOptionsCarryTheWholeBlock fails the day Uploads is filled, which is the day this entry " +
				"is retired.",
			Spec: "docs/spec/config-schema.md §1.12; docs/config-reference.md §15.4; upstream UIOptions.Uploads (awesome-go-auth ui_config.go)",
		},
		{
			ID:      "tools-stream-is-not-mounted-on-api-gateway",
			Surface: "GET <tools>/stream, and the tools.stream.enabled and tools.sse.distributor knobs behind it",
			Behaviour: "The stream route is not mounted, in every configuration: HTTPConfig.Tools.DisableStream is set " +
				"unconditionally, so GET <tools>/stream answers 404 whatever tools.stream.enabled says, and the knob is " +
				"reported at cold start as one this runtime cannot honour. A tools.sse.distributor of any type but none is " +
				"refused at cold start (RS-14). tools.sse.enabled is honoured as far as it goes -- the in-process manager " +
				"is built and Track and Notify broadcast into it -- and the cold start says that nothing is listening. The " +
				"tools OpenAPI document describes the routes that are mounted and not this one.",
			Reference: "GET /stream is registered whenever the stream feature is on (tools.router.ts:184-221), which is the " +
				"default, and serves text/event-stream through SseManager.connect for as long as the client holds the " +
				"socket; the distributor is an object the host constructs and passes (sse-manager.ts:110-112).",
			Why: "API Gateway -- the REST API and the HTTP API alike -- buffers the integration response and enforces a " +
				"29-second integration timeout, so behind it the route would be a response that ends every 29 seconds with " +
				"whatever had been buffered. EventSource, the client the reference wrote the route for, reconnects on a " +
				"dropped connection automatically and forever, so the steady state would be a reconnect loop delivering " +
				"frames late and in batches while billing a held-open invocation per client per 29 seconds " +
				"(docs/cost-model.md §3.1: USD 0.024 per connection-hour at 512 MB). That is not SSE and not a degraded SSE; " +
				"it is a spinner that bills. 404 is the reference's own answer for a route the host did not mount, and it is " +
				"the one status EventSource treats as terminal -- the specification fails the connection on anything but " +
				"200 and does not reconnect -- so a client learns the absence at once. The distributor is refused rather " +
				"than ignored because on Lambda it is the whole feature and not an optimisation: every concurrent " +
				"invocation is its own process, so a manager without one reaches only the environment that happened to " +
				"serve the tracking request, silently. The transport that makes the route real is a Lambda Function URL " +
				"with response streaming and a distributor, mandatory there, which is D9c's; that block clears " +
				"DisableStream, adds WithSseDistributor, retires RS-14 and retires this entry. " +
				"cmd/auth/tools_test.go TestToolsRoutesComeFromTheAdapter fails the day the route answers.",
			Spec: "docs/spec/config-schema.md §1.14; docs/config-reference.md §17.3; docs/cost-model.md §3.1; docs/spec/serverless-gap-analysis.md §1.5",
		},
		{
			ID:      "library-events-are-bridged-into-the-tools-fan-out",
			Surface: "every identity.* event the auth core raises; the telemetry store, GET <tools>/telemetry and every outgoing webhook subscribed to one of those names",
			Behaviour: "With tools.enabled, every event the core publishes -- a login, a failed login, a logout, a rotation, an " +
				"account created or deleted, and the rest of the twenty-three -- is fanned out exactly as a tracked event is: " +
				"persisted to the telemetry store when one is enabled, broadcast to the SSE manager when one is built, and " +
				"delivered to every matching outgoing webhook with the same envelope, headers and signature a tracked " +
				"event gets. One login is one telemetry row and one delivery per matching subscription. A tracked event is " +
				"fanned out once as well.",
			Reference: "AuthTools is fed by the host calling track and by nothing else: the routers publish onto the event " +
				"bus and stop, and no part of the package subscribes the bus back into the telemetry store, the stream or " +
				"the webhooks (src/tools/auth-tools.ts:199-269 against the development line's auth.router.ts:418-433). " +
				"The published reference publishes no identity events at all. The imported core reproduces that default " +
				"-- silence -- and exposes AuthTools.Bridge as the opt-in.",
			Why: "This is a deployment and not a library. An operator who configures an outgoing webhook on " +
				"identity.auth.login.success expects logins to reach it, and one who enables the telemetry store expects " +
				"GET <tools>/telemetry to show them; the core names the alternative the monitoring gap -- a deployment can " +
				"believe it is receiving login failures and not be -- and a product whose documented remedy is one line " +
				"in the source is not a product. The core's own Bridge is deliberately not used, and the reason is the " +
				"hazard the core documents on the type, verified here rather than assumed: Bridge is a wildcard " +
				"subscription on the facade's own bus, the one Track publishes on at step 2, so it hears Track's own " +
				"publication and records every tracked event twice with two ids -- not merely events tracked under an " +
				"identity.* name, every event POST <tools>/track ever tracks. The product therefore keeps two buses: the " +
				"core is handed one, the facade is built on a private one nothing subscribes to, and a single wildcard " +
				"subscription on the core's bus calls Track with the event's own name, payload and six identifiers. A " +
				"bridged event and a tracked one are then one kind of thing to every sink, no loop is possible because " +
				"the only bus with a subscriber is the one Track never publishes on, and nothing is doubled because the " +
				"only path to the sinks is that subscription. What it gives up is stated: App.Events carries the " +
				"library's events and App.Tools.Events carries everything fanned out, and the record's timestamp is " +
				"the fan-out instant rather than the publication instant, microseconds apart on one synchronous chain. " +
				"cmd/auth/tools_test.go TestBridgeDeliversEachLoginOnce fails the day a login is delivered zero times or " +
				"twice.",
			Spec: "docs/config-reference.md §17.2; docs/cost-model.md §2.6; upstream auth_tools.go (the AuthTools type comment)",
		},
		{
			ID:      "outgoing-webhook-delivery-races-the-response",
			Surface: "every outgoing webhook delivery, whether the event was tracked or bridged",
			Behaviour: "Deliveries are made in process by the core's HTTP deliverer, on a goroutine detached from the request, " +
				"and the response is written without waiting for them. On Lambda the execution environment is frozen the " +
				"moment the response is written, so a delivery that has not completed by then completes -- if the same " +
				"environment is ever thawed -- during some later invocation, and the retry schedule of one, two and four " +
				"seconds between attempts is almost never honoured. A delivery is therefore best-effort: an endpoint that " +
				"answers within the request's own lifetime receives it, one that does not may receive it late, once, or " +
				"not at all, and no record of the outcome is kept anywhere.",
			Reference: "The same code shape on a long-lived process: send is not awaited (src/tools/auth-tools.ts:280) and " +
				"retries with exponential back-off (src/tools/webhook-sender.ts:18-46), and a Node process that stays up " +
				"finishes them all.",
			Why: "Not a decision this product made: the core's WebhookEmitter reproduces the reference's fire-and-forget " +
				"exactly and its comment says a process that exits drops whatever is in flight; a Lambda freezes rather " +
				"than exits, which is the same thing on a shorter clock. It is registered rather than left in a comment " +
				"because wiring the tools block is what makes a delivery happen at all, and an operator reading a " +
				"receiver's log must be able to learn from the cold-start line why a delivery arrived a minute late or " +
				"never. The seam the core built for this is WebhookDeliverer, which receives a fully built, signed, numbered " +
				"attempt with no secret in it; D9b implements it as an SQS enqueue with a dead-letter queue and a worker " +
				"that reproduces the schedule from Retries() and RetryDelay(), which is when this entry is retired. " +
				"Delivering synchronously on the request goroutine instead was considered and rejected: it would make a " +
				"slow receiver a slow login, times the retry schedule, and would still lose the deliveries of the " +
				"invocation that hit the function timeout.",
			Spec: "docs/config-reference.md §17.4; docs/cost-model.md §2.6; upstream webhook_sender.go (WebhookEmitter.Emit, WebhookDeliverer)",
		},
		{
			ID:      "inbound-webhooks-are-refused-without-a-runner",
			Surface: "POST <tools>/webhook/{provider}, and the tools.inboundWebhooks.enabled knob behind it",
			Behaviour: "A tools block with tools.inboundWebhooks.enabled left at its default of true is refused at cold start " +
				"(RS-15), and the document has to write tools.inboundWebhooks.enabled: false to load. With it off the " +
				"route is not mounted and answers 404. tools.inboundWebhooks.scriptTimeoutMs is mapped onto the core's " +
				"ScriptTimeout regardless, so the day the runner lands the knob is already live.",
			Reference: "The route is mounted by default whenever a webhook store answering findByProvider or an onWebhook " +
				"callback exists (tools.router.ts:250), and a row's jsScript runs in an in-process vm with a five-second " +
				"timeout on its synchronous prefix (:269-292).",
			Why: "The core runs no script in process -- inbound-webhook-script-runs-out-of-process -- and fails closed " +
				"without an InboundScriptRunner: 400, nothing tracked. That is right for the core and wrong as a deployed " +
				"outcome, because every webhook provider treats a non-2xx as undelivered and redelivers, for hours and " +
				"some for days, so a deployment that came up with the route mounted and no runner would answer a retry " +
				"storm from the first event onwards. A row with no script is no better served: the alternative handler, " +
				"OnWebhook, is a host callback this product has no configuration path into, so it would be acknowledged " +
				"and dropped. The runner is D9d's, a Lambda of its own whose IAM role is the sandbox, and until it lands " +
				"the honest answer is a refusal that names the line to write. The default is not silently overridden to " +
				"false because a document that says one thing and deploys another is the failure the phase mechanism " +
				"this rule descends from exists to prevent. internal/config/rules_test.go pins the refusal; D9d retires " +
				"RS-15 and this entry together.",
			Spec: "docs/spec/config-schema.md §1.15; docs/config-reference.md §17.5; upstream tools_webhook.go",
		},
	}
}

// logDeviations writes every register to the cold-start log, so a deployment
// announces the ways it differs from the reference instead of leaving them to
// be discovered from a client's bug report. storeNotes is nil for a driver
// that publishes none.
func logDeviations(log *slog.Logger, storeNotes []string) {
	for _, d := range WireDeviations() {
		log.Info("wire deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, d := range auth.CompatibilityNotes().KnownDeviations {
		log.Info("core deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, note := range storeNotes {
		log.Info("store compatibility note", slog.String("note", note))
	}
}
