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
			ID: "docs-page-carries-a-content-security-policy",
			Surface: "the response headers of GET <prefix>/docs and GET <prefix>/openapi.json, and -- with the admin console mounted -- " +
				"of the console's own pair, GET <admin>/api/docs and GET <admin>/api/openapi.json",
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
				"else, which is when this policy would otherwise break the page instead of protecting it. The admin " +
				"console's pair joined the surface with the admin block for the same reason and with the same two " +
				"policies: the core serves the console's page with SwaggerUIHandler unchanged -- the same HTML, the " +
				"same CDN -- and its document describes the most privileged surface in the deployment; both follow " +
				"docs.swagger, so one switch turns both pairs and both policies on.",
			Spec: "docs/spec/config-schema.md §1.18; docs/config-reference.md §12 and §16; upstream deviation docs-routes-are-opt-in",
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
				"POST <prefix>/sms/verify and POST <prefix>/2fa/verify -- and, with the admin console mounted, " +
				"POST <admin>/users/{id}/promote, the one route the console's own limiter slot covers",
			Behaviour: "A deployment that configures nothing is rate limited. Over budget, the route answers, byte for byte, " +
				"429 Too Many Requests with Retry-After: <integer seconds, at least 1>, Content-Type: application/json, " +
				"Cache-Control: no-store and the body {\"error\":\"Too many requests\",\"code\":\"RATE_LIMITED\"} -- and no " +
				"Set-Cookie, not even the CSRF auto-init one, because the limiter is outermost and nothing that sets a cookie " +
				"has run. No RateLimit-Limit, RateLimit-Remaining or RateLimit-Reset header is sent, on this response or on a " +
				"successful one. The default budget is 10 requests per 60-second fixed window per subject per scope, and the " +
				"default subject is the normalised email in the request body, falling back to the sha256 of a presented " +
				"tempToken and then to the client address the event reported. The promote route shares the budget, the window " +
				"and the switch, runs its limiter ahead of the admin guard, and is keyed by the client address under either " +
				"keyBy: its body names how to promote and its path names the person being promoted, and neither is a subject " +
				"a caller should be able to mint budgets with. The admin login is deliberately not limited, on either line.",
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
			Spec: "docs/spec/config-schema.md §1.16; docs/spec/data-model.md §1.5 row #61 and §2.3; docs/config-reference.md §14 and §16",
		},
		{
			ID:      "admin-first-user-policy-is-refused",
			Surface: "admin.accessPolicy: first-user, and therefore who the console admits",
			Behaviour: "The policy is refused at start on every store driver (RS-18). The spelling stays in the schema so a " +
				"document written for another port parses and meets the refusal, which names the way in: admin.rootUser " +
				"or admin.bootstrapSecret, then POST <admin>/users/{id}/promote {\"method\":\"flag\"} under is-admin-flag.",
			Reference: "accessPolicy: 'first-user' grants whoever listUsers(1, 0) returns first, documented as \"the first " +
				"registered user\" (src/router/admin.router.ts:372-374), and the core reproduces the evaluation as written " +
				"(admin.go evaluate).",
			Why: "The policy's premise is monotonic ids, and this product does not have them. The core's newID is prefix + " +
				"\"_\" + hex(16 random bytes) (security.go), the DynamoDB lister orders by its <tenant>#<id> sort key and the " +
				"memory lister by id, so \"first\" is whoever holds the lowest random id today -- and every registration " +
				"redraws: with one existing account a single POST <prefix>/register takes the console with probability one " +
				"half, and the incumbent is locked out in the same moment. The register route is public and the guard " +
				"accepts the newcomer's ordinary access token, so no operator setting compensates. Repairing it would mean " +
				"a creation-ordered listing, which is a store seam the core would have to grow (the lister's order is a " +
				"contract, AdminUserStore) -- an upstream change, and one to file. Until then the honest answer is to refuse " +
				"the policy and say why, rather than ship a knob whose documented meaning is not what it does. " +
				"internal/config/rules_test.go TestRefuseToStartRules (the RS-18 case) pins the refusal; it retires the day " +
				"the pinned core lists by creation time or mints monotonic ids.",
			Spec: "docs/config-reference.md §16.1; docs/spec/config-schema.md §2 RS-18",
		},
		// ui-uploaded-assets-are-not-served was registered by the hosted-UI
		// block and retired by the admin surface. Its three reasons -- no
		// writer, a directory is the wrong noun, an fs.FS over S3 costs a
		// GetObject per page -- are each answered in cmd/auth/ui.go
		// (uiUploadsFollowTheUploadStore) and cmd/auth/admin.go; the retired
		// entry is kept in docs/deviations.md under "Retired" so the id keeps
		// resolving, and nothing replaces it here because a deployment with no
		// S3 location behaves exactly as the reference does with uploadDir
		// unset.
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
