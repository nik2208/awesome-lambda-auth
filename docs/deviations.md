# Deviations from the reference

The standing rule is to reproduce `awesome-node-auth` including its quirks, because the family's shipped clients (`ng-awesome-node-auth`, `awesome-node-auth-flutter`, the served `auth.js`) are pinned to it. Every place the rule is set aside is recorded in one of three executable registers, each living where its behaviour lives, and this page indexes all three. `cmd/auth/deviations_test.go` fails when an entry of any register is missing from this page, and every register is written to the cold-start log.

| Register | Where | Scope |
|---|---|---|
| Product | `cmd/auth/deviations.go` `WireDeviations()` | configuration defaults, refusals and policies no store or core route owns — plus any divergence a core route causes that this product cannot fix without forking the core, since the core's own register is not ours to write |
| Store | `internal/store/dynamodb/store.go` `(*Store).CompatibilityNotes()` | what the DynamoDB single-table design answers differently |
| Core | `awesome-go-auth` `auth.CompatibilityNotes()` | the imported core's own register, mirrored into its README |

## 1. Product register

| ID | Surface | This product | The reference | Why | Argued in |
|---|---|---|---|---|---|
| `csrf-enabled-by-default` | `security.csrf.enabled` | double-submit CSRF enforced unless turned off; off in production is refused (RS-3) | `csrf.enabled` defaults to false (`src/middleware/auth.middleware.ts:35`) | a product must be safe with an empty configuration | `docs/spec/config-schema.md` §1.3, §2 RS-3 |
| `production-by-default` | `deployment.environment` | defaults to production, the strict side of every environment-dependent rule | no environment knob; `NODE_ENV` unset means not production | forgetting to name the environment should tighten, not loosen | `docs/spec/config-schema.md` §1, §2 |
| `refresh-token-families` | `POST <prefix>/refresh` | a replayed refresh token revokes the whole session; later refreshes answer `401 SESSION_REVOKED` | rotation replaces the token; a replay fails alone and the session lives on | a replay is the signature of a stolen token | `docs/spec/data-model.md` §4.3; `docs/spec/decisions.md` D-7 |
| `idp-kid-derived-from-key-material` | the `kid` of every RS256 token the IdP signs and of every key in `GET <prefix>/.well-known/jwks.json` | `base64url(sha256(SPKI DER))[:16]` of the key that signed, identical whether the key is held in KMS or supplied as a PEM | the constant `provisioner-key-1` for every deployment and every key (`src/services/token.service.ts:78`, `src/services/jwks.service.ts:184`) | a rotation has to be additive: with a derived `kid` the old and new keys are published together and a token minted before the rotation still selects the key that signed it, where one constant `kid` makes every rotation invalidate every token in flight | `docs/oidc.md`; `docs/spec/config-schema.md` §1.10 addendum; `docs/spec/decisions.md` D-3 |
| `templates-dir-only-seeds-absent-ids` | `email.templatesDir`, and the body and subject of every mail rendered from a stored template | the directory is read once, at cold start, and writes only the ids and UI pages the template store does not already hold; a template saved through the store wins over the file of the same id, on every cold start | there is no templates directory: `config.templateStore` is the only override source and its contents come from whoever writes to it (`src/interfaces/template-store.interface.ts:13-43`) | a Lambda has no writable filesystem and no deploy step that runs code, so the artifact is the only place a shipped template can live and cold start the only moment it can be read; and a runtime edit must survive the next redeploy | `docs/spec/config-schema.md` §1.5, §3.8, §3.10; `docs/spec/decisions.md` D-17 |
| `runtime-settings-seed-only-fills-absent-keys` | `runtimeSettings.*`, and every route that reads the settings store — today `POST <prefix>/2fa/disable` | the block is a cold-start seed applied key by key, and only to keys the settings store does not already hold; a key an administrator set at run time wins over the document on every cold start, and a key left at its schema default is not seeded at all | there is no seed: `routerOptions.settingsStore` is whatever the host app passes and its contents come from whoever writes to it (`src/interfaces/settings-store.interface.ts:28-40`), with no implementation and no configuration path into one shipped | a Lambda has no deploy step that runs code, so cold start is the only moment a declared seed can be applied — the `templates-dir-only-seeds-absent-ids` argument — and here it is sharper: cold start recurs on every scale-out, so overwriting would revert an admin toggle at an unpredictable moment rather than at a redeploy; the unit is a key rather than an item because the settings are one document and seeding it whole would freeze every key at once; and seeding a schema default would not be a declared state but an invented one, which would also make a seed added later inert on arrival | `docs/spec/config-schema.md` §1.19; `docs/config-reference.md` §11; `docs/spec/decisions.md` D-17 |
| `docs-page-carries-a-content-security-policy` | the response headers of `GET <prefix>/docs` and `GET <prefix>/openapi.json` | both carry a `Content-Security-Policy`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`: the page's policy pins the one CDN origin its HTML loads from and denies every other channel — no off-origin fetch or XHR, no image beacon, no form action, no nested frame, no framing of the page itself, no rewritten base URI — and the document's is `default-src 'none'` with the same two denials; routes, bodies and status codes are untouched | neither route sets a header beyond `Content-Type` (`src/router/auth.router.ts:1658-1677`), so the page runs `swagger-ui-dist@5` from the unpkg CDN, unpinned and without subresource integrity (`src/router/openapi.ts:1646-1669`) | that script runs same-origin with the auth cookies, and the CSRF cookie is JavaScript-readable by design, so a bad day at the CDN is a credential-reading script on the auth origin. The honest fix is upstream's: the core mounts the page and the machine-readable document under one bool, this binary may add no route under the api prefix, and the core is not forked — so the product can neither serve the document without the page nor rewrite the page's HTML. A header middleware adds no route and is what is left. Narrowing, not closure: a compromised bundle can still read a cookie and still leak it through a top-level navigation, which no CSP directive in any shipping browser prevents; what goes are the silent channels. `cmd/auth/docs_test.go` `TestDocsPolicyCoversEveryOriginTheCorePageLoads` fails the day the core's page loads from anywhere else | `docs/spec/config-schema.md` §1.18; `docs/config-reference.md` §12; upstream `docs-routes-are-opt-in` |
| `oauth-callback-skips-the-second-factor` | `GET <prefix>/oauth/{provider}/callback`, for an account with a second factor enabled | issues a session and redirects for every account it resolves, so an account whose `POST /login` answers the 2FA challenge is signed in through a provider without presenting one | redirects to `${redirectTo}/auth/2fa?tempToken=<jwt>&methods=<list>` with no session issued (`src/router/auth.router.ts:1298-1313`) | not a choice: the imported core's `OAuthComplete` has no second-factor branch and the core is not forked. Registered because wiring `oauth.providers` is what makes it reachable, and an operator who requires 2FA must read it in the cold-start log rather than in an incident. `cmd/auth/oauth_test.go` `TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount` fails the day upstream closes it | `docs/spec/wire-contract.md` §3, §4; `docs/config-reference.md` §8.4 |

## 2. Store register

Quoted verbatim from `CompatibilityNotes()`; the test compares these strings byte for byte.

Unconditional:

- POST /sessions/cleanup always reports deleted:0 — expiry is DynamoDB TTL, which produces no count (data-model.md §4.5).
- GET /sessions returns sessions oldest-first by creation time; the reference returns them in unspecified map order (data-model.md §5).
- Revoking an already-revoked session keeps the first revocation's timestamp and reason instead of overwriting them (data-model.md §4.4).
- POST /change-email/confirm fails rather than applying an empty address when no email change is pending; the reference would overwrite the address (data-model.md §4.1).
- POST /change-email/confirm fails if the pending address changed between reading the token and applying it, instead of applying the address it read (data-model.md §1.3 #22).
- GET /linked-accounts returns bindings ordered by provider then provider account id; the reference returns them in insertion order (data-model.md §1.5 #54).
- Re-linking a provider account that is already linked moves the binding and deletes the previous link id; the reference leaves the old id resolvable and still listed under its old owner (upstream nik2208/awesome-go-auth#37).
- POST /link-verify answers INVALID_LINK_TOKEN for an expired account-link token, where the reference answers LINK_TOKEN_EXPIRED: the store refuses to return an entry past its deadline, so the route's own expiry branch is never reached (data-model.md §4.5).
- Mail templates list sorted by id and UI translations sorted by page, which GET /admin/api/templates/mail and /ui will expose once the admin surface is mounted; the reference lists both in first-insertion order (data-model.md §1.6).
- Listing users without naming a tenant orders them by tenant then id, which GET /admin/api/users and the first-user access policy will expose once the admin surface is mounted; the reference's normative order is id alone (data-model.md §1.4 #47).
- Webhook subscriptions are listed, matched and looked up by provider in id order rather than in first-insertion order, so a deployment holding two inbound webhooks for one provider gets whichever has the lower id (data-model.md §1.5 #72).
- Telemetry queries treat an absent tenant as the untenanted tenant rather than as every tenant, and refuse outright in multi-tenant mode; the reference reads an absent tenant as no filter at all (data-model.md §1.5 #60).

With single-use consumption on read (the default):

- Single-use tokens and SMS codes are consumed by the lookup itself, so a failure in the step that follows burns them and the user must request a new one (data-model.md §4.1). A code that does not match burns nothing.
- A replayed refresh token revokes the whole session, not just that token (data-model.md §4.3).
- An OAuth state nonce and an account-link token are consumed by PendingLinkStore.Get, so two callers racing on one link produce exactly one winner and the loser sees an invalid token (data-model.md §1.5 #57).

The `deleted:0` entry and the refresh-family design were signed off on 2026-09-11 (`docs/spec/decisions.md` D-7).

## 3. Core register (awesome-go-auth)

The ids below are `auth.CompatibilityNotes().KnownDeviations`; the full text of each entry is generated into the upstream README section "Deliberate deviations from the reference".

- `forgot-password-succeeds-on-delivery-failure` — `POST /forgot-password` answers 200 even when the configured sender fails or none is configured.
- `temp-token-is-typed-not-an-access-token` — the 2FA step-up `tempToken` carries `typ: "temp"` and is refused as a session credential.
- `link-request-exempts-bearer-from-csrf` — `POST /link-request` is CSRF-checked for cookie callers only.
- `password-policy-on-reset-and-change` — reset and change apply the password policy (`400 WEAK_PASSWORD`); the reference applies it on register only.
- `totp-setup-omits-qrcode` — `POST /2fa/setup` returns `secret` and `otpauthUrl` without a `qrCode` data URL. The contract suite fails when this stops being true so the entry can be retired.
- `one-time-tokens-are-base64url` — minted one-time tokens are base64url rather than hex.
- `advertised-2fa-methods-require-store-support` — `available2faMethods` lists only the factors the mounted stores can complete.
- `csrf-cookie-not-reissued-with-tokens` — the CSRF cookie is distributed by the middleware, not re-set by every token-issuing response.
- `cookie-max-age-follows-configured-ttl` — cookie `Max-Age` derives from the configured token TTLs instead of fixed values.
- `totp-issuer-defaults-to-config-issuer` — the TOTP issuer label defaults to `Config.Issuer` (the reference falls back to the literal `awesome-node-auth`); `WithTwoFactorAppName` matches the reference exactly.
- `totp-accepts-one-step-of-skew` — a TOTP code from the previous or next 30-second step is accepted; the reference (otplib `epochTolerance` 0) accepts the current step only. No knob exists to match it.
- `config-require2fa-is-a-system-policy-term` — `Config.Require2FA` counts as a system policy alongside the settings store's `require2FA`, so `/2fa/disable` refuses on either; the reference reads the store alone.
- `oauth-provisioning-is-a-policy-not-a-function` — provisioning is declared (`OAuthProvisioning`) rather than supplied as the reference's abstract `findOrCreateUser`, so the library decides create, link, refuse or conflict instead of delegating the whole question to the host.
- `jwks-cors-wildcard-string-form` — `JWKSCORSOrigins` of exactly `[]string{"*"}` is the wildcard, where the reference treats any array as an allowlist and only the bare string `'*'` as the wildcard. The empty slice spells the reference's `['*']`.
- `resource-server-gates-all-credential-routes` — resource-server mode unmounts the whole credential surface; the reference unmounts two routes and leaves the rest mounted to fail at runtime (`reference-issues.md` N26).
- `jwks-unknown-kid-refetch-is-rate-limited` — an unknown `kid` triggers at most one JWKS refetch per `MinRefreshInterval`, so a token flood cannot turn the verifier into a client of its own issuer; the reference refetches on every unknown `kid`.
- `register-issues-a-session` — `POST /register` mints a token pair with the `201` and creates a refresh session, so the account is logged in as soon as it exists; the reference creates the account and issues nothing. Kept deliberately (2026-09-12): the family's clients treat the `201` as a sign-in, and the entry carries the second difference on that surface, that the route is mounted at all.
- `ui-config-verify-email-follows-the-effective-mode` — `GET /ui/config` reports `features.verifyEmail: true` only when a sender is wired *and* the effective verification mode is `lazy` or `strict`; the reference's `undefined !== 'none'` makes an unset mode report `true`.
- `register-route-is-always-mounted` — every adapter mounts `POST /register` and `features.register` is `true` to match; the reference mounts it only when the host supplies `onRegister`.
- `docs-routes-are-opt-in` — `GET /openapi.json` and `GET /docs` are off until `HTTPConfig.Docs.Enabled` is set; the reference serves both anywhere `NODE_ENV` is not exactly `production`. The served document also describes those two paths, which the reference's generator never does.

## Recording a new deviation

1. Add it to the register that owns the behaviour, with the reference citation and the reason.
2. Add it here, in the matching section.
3. Run `./scripts/toolchain.sh go test ./cmd/auth/...`; `TestDeviationsIndexIsComplete` is the tripwire.
