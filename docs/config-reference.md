# Configuration reference

What the deployed binary reads, in the order it reads it, and what every knob of
the `email` and `oauth` domains does once it is read.

This page is operator-facing. The schema's provenance — every default traced to
the line of `awesome-node-auth` that sets it, and the refuse-to-start rules —
is [`docs/spec/config-schema.md`](spec/config-schema.md); where the two differ,
the spec is the contract and this page is the deployment. Behaviour that
deliberately departs from the reference is registered in
[`docs/deviations.md`](deviations.md).

## 1. The two sources

Configuration comes from a JSON **document** and from `AWESOME_AUTH_*`
**environment variables**, layered at cold start in this order
(`internal/config/load.go`):

1. **Defaults** — `config.Defaults()`. A deployment that sets nothing still
   starts, in the product's safe posture: `deployment.environment: production`,
   CSRF on, secure cookies.
2. **The document**, over the defaults.
3. **The environment**, over the document. One variable per knob; the variable
   always wins, which is what lets a stack template override a baked document
   without rebuilding the artifact.
4. **Derived values** that depend on the layered result.
5. **Secrets**, resolved from their stores (§3). After both override layers,
   because a rule such as RS-1 needs the value's length and not its reference.
6. **Validation**: types, ranges and enums, then the §2 refuse-to-start rules,
   then the phase gate (§4). All three run to completion — an operator fixing a
   broken deploy gets the whole list, not the first line of it.

A failure at step 6 aborts the cold start. The Lambda service reports an init
failure the deployment can see, rather than a 500 per request that looks like an
outage.

### Where the document comes from

| Variable | Meaning |
|---|---|
| `AWESOME_AUTH_CONFIG_FILE` | path to a JSON document inside the artifact, normally `/var/task/awesome-auth.json` |
| `AWESOME_AUTH_CONFIG_JSON` | the JSON document inline |

Setting both refuses to start: picking one silently would make the deployment
depend on which variable a template happened to set last. Setting neither means
defaults plus the environment, which is how a minimal development stack runs.

Every document needs `"schemaVersion": 1` at its root. It is checked before
anything else is trusted, because a document written for another major version
may mean something different by the very keys this build is about to read.

### Environment variable conventions

- One variable per knob, named in the tables below and in the spec.
- A list knob takes a comma-separated value; entries are trimmed and empties
  dropped (`AWESOME_AUTH_EMAIL_SITE_URLS=https://a.example.com,https://b.example.com`).
- A boolean takes `true` or `false`.
- `stores.enable.<store>` is generated from the store list:
  `AWESOME_AUTH_STORES_ENABLE_TEMPLATES`, `..._LINKED_ACCOUNTS`, and so on.
- Some knobs are **file-only** by design, `email.templatesDir` among them: a
  directory baked into the artifact is not something an environment variable
  should be able to move. Those knobs have no variable and the tables say so
  with a dash.

## 2. What a cold start tells you

Three kinds of line, all JSON, all on the deployment's log group:

- `configuration warning` — the document loaded, and something in it deserves
  saying out loud (a production secret in a plain environment variable, for
  one).
- `configured knob is not wired to the auth core` — a knob inside a wired domain
  that the imported core cannot honour, reported with its path and a remedy
  (`unwiredKnobs`, `cmd/auth/app.go`). It is never silently ignored.
- `credential delivery wired`, `email flows wired` and `oauth wiring` — one line
  each an operator can read the whole delivery, email and federated-login
  posture off: which transport each seam uses, the canonical site URL, how many
  origins are allowlisted, what the templates directory seeded, and which
  providers, provisioning policy and linking stores the OAuth block came up
  with.

## 3. Secrets

A secret-valued knob never holds a value in the document. It holds a reference:

```json
{
  "email": {
    "deliveryWebhook": {
      "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}
    }
  }
}
```

The three forms, highest priority first:

| Form | Resolved from |
|---|---|
| `{"secretsManager": "<id-or-arn>[#<jsonKey>]"}` | Secrets Manager; `#<jsonKey>` selects one key of a JSON secret document |
| `{"ssmParameter": "<name>"}` | SSM Parameter Store, `SecureString` |
| `{"envVar": "<NAME>"}` | that environment variable — development only |

Without a document, the environment can name a store too: the knob's documented
variable with `_SECRETSMANAGER` or `_SSM_PARAMETER` appended carries a reference
rather than a value (`AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET_SECRETSMANAGER`).
The bare variable carries the value itself and is development-grade: in
production it loads and warns, because a Lambda environment variable is visible
to anyone who can describe the function.

A plaintext secret written straight into the document refuses to start, with the
knob's dotted path.

## 4. Domains this build does not act on yet

A domain the schema accepts but the binary does not wire is **refused at start**
(rule `PHASE`), never silently ignored: a document that configures it would
otherwise describe behaviour the deployment does not have. The live list is
`unwiredDomains()` in `internal/config/phases.go`.

The whole `email` domain now loads, and so does the whole `oauth` domain.
`email.siteUrls`, `email.templatesDir` and `email.deliveryWebhook` were the last
three of the former to leave that list; `oauth.providers` and
`oauth.provisioning` (§8) are the latest to go, secret prefix included — a
provider's `clientSecret` supplied through its documented environment variable
no longer trips the gate, because it is read.

So do `twoFactor`, `security.jwt.extraClaims` and `security.jwt.claimsWebhook`
(§6, §7). Nothing under `security.` is refused any more either.

`idProvider` and `resourceServer` left it too (§9 and §10). Configuring either is
now a deployment that behaves differently rather than one that refuses: the first
mounts the OIDC surface and publishes a JWKS document, the second unmounts the
credential surface and verifies another issuer's tokens.

`runtimeSettings` left the list before it (§11). Configuring it now seeds the
runtime-mutable layer instead of refusing the deployment, and
`runtimeSettings.require2fa` reaches a route: `POST <prefix>/2fa/disable` answers
`403` `2FA_REQUIRED` on it.

`docs` left it in the round before (§12). `docs.swagger` now decides whether the
imported adapter mounts `GET <prefix>/openapi.json` and `GET <prefix>/docs`, and
`auto` — the default — is resolved against `deployment.environment`, so an
unconfigured deployment answers 404 on both. `docs.basePath` reaches the core
unchanged and moves what the document describes, never where it is served.

`rateLimit` is the latest to go (§13), and it is the first domain to leave this
list whose behaviour has no counterpart upstream at all: the reference ships no
limiter, so there was nothing to inherit and every default is this product's.
Configuring the block now changes what a deployment does instead of refusing it —
and, because `rateLimit.enabled` defaults to `true`, so does configuring nothing.

`ui` is the latest to go (§15), and it is the first domain to leave this list
that adds a *surface* rather than changing one: with `ui.enabled` set, the
imported adapter mounts the reference's whole UI router at `<prefix>/ui` — the
config document, the server-rendered pages and the vendored assets — and the
same flag re-points every emailed link at a hosted page. It is also the first
whose surface reads the settings store on every request rather than once at cold
start; §15.1 says what that costs and what a store failure looks like from
outside. **The two left on the list are `admin` and `tools`.**

`stores.migration` (§13) never appeared on that list and never will: it is new in
this release and is wired by the same change that declared it, so there was never
a build that validated it and did nothing.

`email.templatesDir` needs a template store and `runtimeSettings` needs a
settings store, and both drivers now back both: the DynamoDB store keeps mail
templates and UI translations on its `TEMPLATES` partition and the settings on
its `SETTINGS` one, the memory driver holds both per execution environment (§5.3,
§11). A driver that backs neither is still refused by `checkStoreSupport` at cold
start, by name — a store gap rather than a phase gap.


### 4.1 Six `stores.enable.*` flags the DynamoDB driver can now back, and still refuses

`stores.enable.metadata`, `.rbac`, `.tenants`, `.apiKeys`, `.webhooks` and
`.telemetry` are still refused by `checkStoreSupport` on both drivers, and that
is deliberate rather than pending.

The DynamoDB store *implements* all six as of the admin-store block — metadata
entries, role definitions and assignments, the tenant directory, API keys with
their id pointers, the webhook directory and telemetry events all have item
types, key schemas and tests. What has not happened is the other half: the auth
core takes every one of those six **by name** rather than discovering it by type
assertion, so none of them reaches a route until the composition root hands it
over, and that lands with the admin surface.

`driverStores` therefore answers a narrower question than "can the driver store
this": it answers "does turning the flag on change what the deployment does".
Listing the six today would let an operator enable a knob that validates, starts
cleanly, and does nothing — which is the exact misconfiguration §1.17 exists to
refuse, and the reason the refusal names the driver rather than shrugging.

Nothing else about these six is waiting on a decision. When the admin surface
mounts, each flag becomes a real switch and the refusal disappears for it alone.

The three admin listers that arrived with the same block — the user, session and
role enumerations the admin tables page through — need no flag at all and have
none: the core finds them by type-asserting the user, session and RBAC stores it
was already given, so they are live wherever those are.

## 5. `email.*`, knob by knob

| Path | Type | Default | Env var |
|---|---|---|---|
| `email.siteUrls` | string[] | none; `deployment.publicUrl` stands in | `AWESOME_AUTH_EMAIL_SITE_URLS` |
| `email.mailer.endpoint` | string | none | `AWESOME_AUTH_MAILER_ENDPOINT` |
| `email.mailer.apiKey` | secret | none | `AWESOME_AUTH_MAILER_API_KEY` |
| `email.mailer.from` | string | none | `AWESOME_AUTH_MAILER_FROM` |
| `email.mailer.fromName` | string | none | `AWESOME_AUTH_MAILER_FROM_NAME` |
| `email.mailer.provider` | string | none | `AWESOME_AUTH_MAILER_PROVIDER` |
| `email.mailer.defaultLang` | `en`\|`it` | `en` | `AWESOME_AUTH_MAILER_DEFAULT_LANG` |
| `email.verification.mode` | `none`\|`lazy`\|`strict` | `none` | `AWESOME_AUTH_EMAIL_VERIFICATION_MODE` |
| `email.templatesDir` | string (directory) | none | — (file-only) |
| `email.deliveryWebhook.url` | string (https) | none | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL` |
| `email.deliveryWebhook.timeoutMs` | integer 1–10000 | `5000` | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_TIMEOUT_MS` |
| `email.deliveryWebhook.secret` | secret | none; **required** with a url | `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET` |

### 5.1 `email.siteUrls` — where an emailed link points

Two things at once, and they are the reference's two
(`src/router/auth.router.ts:202-246`):

- **The canonical site.** The first entry is the base every emailed link is
  built on: `<siteUrl><apiPrefix><route>?token=…`. With no entry at all the
  canonical site is `deployment.publicUrl` — a product addition, because a
  relative link is dead in a mailbox and this deployment always knows the origin
  it is reached at.
- **The allowlist.** Every entry, followed by every `http.cors.origins` entry,
  deduplicated with the first occurrence's position kept. A request's `Origin`
  (else its `Referer`) is matched against that list exactly; a match becomes the
  base of the link in *that* mail, and anything else falls back to the canonical
  site.

That fallback is the security property. A password-reset link is a credential:
if any `Origin` a caller cared to send steered where the link points, anyone
could have a victim's reset link built against a host they control.

The same two values are what OAuth redirects resolve against, so an emailed link
and an OAuth redirect can never disagree about a request's origin.

```json
{"email": {"siteUrls": ["https://app.example.com", "https://admin.example.com"]},
 "http": {"cors": {"origins": ["https://console.example.com"]}}}
```

Canonical site `https://app.example.com`; a request from any of the three gets
its links built on its own origin.

### 5.2 `email.mailer.*` — the mail transport

`email.mailer.from` is the switch: a `from` address means mail delivery is
wanted, and the four mail seams go through Amazon SES. The schema also requires
`email.mailer.endpoint`, which describes the reference's HTTP gateway; SES is
reached through the AWS API and authorised by the execution role, so the
endpoint and `apiKey` address and authenticate nothing here. Both are reported
at cold start as knobs this build cannot honour rather than quietly dropped.

`email.mailer.defaultLang` is the default only: a request that carries an
`emailLang` body field of `en` or `it` renders in that language instead.

### 5.3 `email.templatesDir` — shipped templates

A directory of JSON files baked into the artifact, read once at cold start and
written into the template store. It requires `stores.enable.templates`: a
directory that seeds a store nobody enabled would be read and discarded, which
the loader treats as a misconfiguration rather than a no-op.

> **Both drivers back this.** On `dynamodb` the templates live on the table's
> `TEMPLATES` partition, so a template seeded from the artifact outlives the
> execution environment and an edit made through the store survives the next
> redeploy — which is the whole point of seeding absent ids only. On `memory`
> each execution environment holds its own copy and loses it on every cold
> start, which is what the development driver is for (§1.17). A driver that
> backs no template store is refused at cold start by name, so nothing is
> silently ignored.

Layout — one file per template at the top level, nothing recursive:

| File | Contents |
|---|---|
| `<id>.json` | a mail template: `{"baseHtml": …, "baseText": …, "translations": {…}}` |
| `<page>.ui.json` | one UI page's translations: `{"translations": {"<lang>": {"<key>": …}}}` |

Anything that is not a `.json` file is ignored, so a README can sit beside them.
The ids the mail routes render are the reference's six: `password-reset`,
`magic-link`, `welcome`, `verify-email`, `email-changed`, `invitation`. A
template stored under any other id is seeded and then rendered by nothing, which
the cold-start log says.

Inside a stored body, `{{T.key}}` is looked up in the translations for the
rendering language and `{{key}}` in the data the route supplies (`link`,
`token`, `newEmail`, …). `translations.<lang>.subject` is the subject.

Two rules, both of which fail the deployment rather than ship something inert:

- `baseHtml` and `baseText` must both be non-empty, or the core keeps rendering
  its built-in template and the seed does nothing.
- an `id` or `page` field, when present, must agree with the file name.

**The store wins.** A file whose id the store already holds is skipped, on this
and on every later cold start, so a template edited at runtime survives the next
redeploy. That precedence is the registered deviation
`templates-dir-only-seeds-absent-ids`.

A directory that is missing or unreadable **refuses to start in production** —
the artifact is supposed to contain what the document names — and **warns in
development**, where a stack may come up and render the built-ins.

The template store itself has to exist on the selected driver, and today exactly
one does — see the note above. With `stores.enable.templates` on and a driver
whose store does not provide one, the cold start refuses and names the driver,
rather than advertising admin routes whose every write goes nowhere:

```json
{"level":"ERROR","msg":"cold start failed, refusing to serve",
 "error":"config: refusing to start: 1 problem(s) in stores.enable\nstores.enable.templates is on but the dynamodb driver does not implement that store, so the feature would return NOT_IMPLEMENTED on the wire -- turn it off until the driver grows it"}
```

### 5.4 `email.deliveryWebhook.*` — delivering credentials yourself

Set `email.deliveryWebhook.url` and it becomes **the** sender for all five
credential seams: magic link, password reset, email verification, email change
and SMS code. Each one is POSTed to that receiver and nothing goes through SES
or SNS for those routes, even when the mailer and sms blocks are also
configured. It is what a deployment whose transport is neither mail nor SMS — or
is not reachable from a Lambda — wires, and it replaces the reference's
in-process send-callback functions, which a configuration document cannot
express.

The request:

```
POST <url>
Content-Type:        application/json
X-Webhook-Event:     delivery.<kind>
X-Webhook-Delivery:  <a fresh UUID per request>
X-Webhook-Timestamp: <ISO 8601 UTC, milliseconds>
X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the exact body>

{"kind": "<kind>", "delivery": { … }}
```

`<kind>` is one of `magic-link`, `password-reset`, `email-verification`,
`email-change`, `sms-code`. `delivery` carries the recipient, the token or code,
its expiry, and `linkBase` — the base this request resolved (§5.1), which the
receiver should build the link on. Any 2xx is a delivery; anything else, a
transport failure or the timeout is an error, which each route handles under its
existing contract (`/forgot-password` still answers 200 whatever happens).

**`email.deliveryWebhook.secret` is required when the url is set.** The body of
every request is a credential, so a receiver that cannot verify
`X-Webhook-Signature` cannot tell a replayed or forged delivery from a real one
— it would mint sessions for whoever posts to it. A url without a secret is
refused; a secret without a url is refused as the dead configuration it is, and
when the secret arrives through its plain environment variable with no url to
switch it on, the cold-start log reports it. The secret is never sent, only
proof of it.

`email.deliveryWebhook.timeoutMs` bounds one request, connect to last byte. The
route that minted the credential is waiting on the answer inside a Lambda
invocation, so this is what keeps a slow receiver from turning every password
reset into a function timeout. It is capped at 10000, the same ceiling
`security.jwt.claimsWebhook.timeoutMs` has and for the same reason: a deadline
longer than the invocation bounds nothing, because the function times out first
and the route then answers nothing at all rather than the 500 the deadline
exists to produce.

Two mails stay with the mailer, and are sent only when one is configured: the
notice `POST /change-email/confirm` sends to the address an account just moved
away from, and the OAuth account-linking mail of `POST /link-request`. The
reason is the seam, not the payload: `auth.DeliveryWebhook` posts the five
credential kinds above and has no method for either of these. The notice indeed
carries nothing worth signing — the link-token mail does, a single-use account
link token, and it still goes out by mail, so a deployment that moved to a
webhook to keep credentials off SES should know this one did not move with it.

```json
{"email": {"deliveryWebhook": {
  "url": "https://hooks.example.com/auth-delivery",
  "timeoutMs": 2000,
  "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}}}}
```

## 6. `security.jwt.extraClaims` and `security.jwt.claimsWebhook` — what a token carries

| Path | Type | Default | Env var |
|---|---|---|---|
| `security.jwt.extraClaims` | map of `{fromUserField}` \| `{const}` | none | — (file-only) |
| `security.jwt.claimsWebhook.url` | string (https) | none | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL` |
| `security.jwt.claimsWebhook.timeoutMs` | integer 1–10000 | `2000` | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS` |
| `security.jwt.claimsWebhook.secret` | secret | none; **required** with a url | `AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET` |

Every token this deployment mints carries six base claims — `sub`, `email`,
`role`, `loginProvider`, `isEmailVerified`, `isTotpEnabled` — and seven session
claims: `sid`, `tid`, `jti`, `typ`, `iss`, `iat`, `exp`. These two knobs add to
that set. They replace the reference's `buildTokenPayload(user)` callback, which
is in-process code a configuration document cannot carry: the table covers
"copy a field" and "write a constant", the webhook covers everything that has to
be computed.

### 6.1 `security.jwt.extraClaims` — the mapping table

A map from claim name to exactly one of two forms:

```json
{"security": {"jwt": {"extraClaims": {
  "tenant":  {"fromUserField": "tenantId"},
  "plan":    {"const": "enterprise"},
  "seats":   {"const": 25}
}}}}
```

It is file-only: a map of objects has no sensible environment form, so it
arrives in the configuration document (`AWESOME_AUTH_CONFIG_FILE`).

`fromUserField` reads one field of the user, spelled as `GET /me` spells it:
`id`, `email`, `role`, `tenantId`, `firstName`, `lastName`, `phoneNumber`,
`isEmailVerified`, `isTotpEnabled`, `loginProvider`. Anything else is refused at
start with the claim's dotted path. The credential columns are deliberately not
on that list, and neither are the enriched collections — a mint sees the stored
row, and a collection is not a claim value.

A mapped claim is emitted on every token with whatever the field holds: an empty
`firstName` becomes an empty-string claim, not an absent one. A mapping declares
that a claim exists, and a consumer must be able to tell "not configured" from
"empty". `const` lands verbatim, keeping its JSON type.

**Three classes of name are refused at start, each naming the knob to edit:**

| Refused | Why |
|---|---|
| the six base claims | the family's clients read them off every token; redefining one changes what every client in the family sees |
| the seven session claims | the library writes them *after* the merge, so the entry could never reach a token — a claim that is silently discarded on every mint is worse than one that does not exist |
| a `fromUserField` outside the list above | a mapping is configuration, and a typo in configuration must fail at startup rather than turn every login into a 500 |

### 6.2 `security.jwt.claimsWebhook.*` — claims that are computed

With a url set, every mint — login, refresh, the 2FA step-up token — and every
`GET /me` POSTs one request:

```
POST <url>
Content-Type:        application/json
X-Webhook-Event:     claims.build
X-Webhook-Delivery:  <a fresh UUID per request>
X-Webhook-Timestamp: <ISO 8601 UTC, milliseconds>
X-Webhook-Signature: sha256=<hex HMAC-SHA256 of the exact body>

{"user": { …the profile exactly as GET /me renders it… }}
```

and expects `200 {"claims": {…}}`. The claims object is merged last, so it wins
over the table on a shared name — the table says the same thing for everybody,
the receiver computed its answer for this user.

**A session is two tokens and the builder runs per token, so one login is two
requests.** A `GET /me` is one. An authenticated request to any other route is
**zero**: the middleware verifies the token and never runs the hook, because
what the hook computed is already inside the token the request carried.

**`security.jwt.claimsWebhook.secret` is required when the url is set.** The
request body is the user's profile and the answer decides what the token
authorises, so an unsigned receiver can neither tell this deployment's question
from anybody else's nor be told apart from a receiver that is not it. A url
without a secret is refused; a secret without a url is refused as the dead
configuration it is. The secret is never sent, only proof of it.

`timeoutMs` bounds one request, connect to last byte. A login is waiting on the
answer inside a Lambda invocation, so this is what turns a slow receiver into a
fast 500 rather than a function timeout. It must be between 1 and 10000: the
loader refuses anything above that ceiling however the value arrives, because a
deadline longer than the invocation bounds nothing — the function times out
first and the route answers nothing at all. The `ClaimsWebhookTimeoutMs` CFN
parameter carries the same `MaxValue`, and the loader enforces it for the two
routes CloudFormation cannot see: the environment variable set some other way,
and `timeoutMs` written into the configuration document.

**It fails closed (decision D-10), and the core already does it.** A non-2xx
answer, a transport failure, the timeout, a body over 64 KiB, a body that is not
JSON, a missing or non-object `claims` member: each aborts the mint, and login,
refresh and 2FA step-up answer `500 {"error":"Internal server error"}` — the
generic envelope, deliberately code-less, deliberately describing nothing. A
token minted without the claims the deployment configured would authorise less,
or more, than the deployment decided.

`GET /me` is the one deliberate exception: a builder failure there is logged and
leaves `customClaims` out of the body rather than failing the read. So a
receiver outage costs logins and refreshes and leaves the profile answering.

That log line names the receiver's **origin only**, never its path or query, and
so does the cold-start line and every refusal the loader writes about either
webhook url. A receiver behind a gateway that cannot verify an HMAC is commonly
given a capability token in its path instead; an outage must not then copy that
token into CloudWatch once per `/me` for as long as it lasts. The same holds for
`email.deliveryWebhook.url`, whose failures `POST /forgot-password` can only
report to the log.

**The receiver cannot retype a token or rebind its session.** `sid`, `tid`,
`jti`, `typ`, `iss`, `iat` and `exp` are written after the merge and a returned
value under those names is discarded. It *can* override the six base claims, as
the reference's callback can — so point this only at a receiver you own.

```json
{"security": {"jwt": {"claimsWebhook": {
  "url": "https://claims.example.com/token",
  "timeoutMs": 2000,
  "secret": {"secretsManager": "awesome-auth/prod/claims-webhook"}}}}}
```

## 7. `twoFactor.appName` — the TOTP issuer

| Path | Type | Default | Env var |
|---|---|---|---|
| `twoFactor.appName` | string, non-empty | `awesome-node-auth` | `AWESOME_AUTH_2FA_APP_NAME` |

The name an authenticator app prints above the six digits. It is the issuer in
the `otpauth://` URI `POST /2fa/setup` returns, in both places the URI carries
one — the label prefix and the `issuer` parameter — and it is the only part of
TOTP a user ever reads. Set it to the product name they know; an empty value is
refused at start, because it produces a URI no app can label.

It is passed unconditionally, so the core's fallback to its own issuer never
applies and a deployment that configures nothing gets the reference's own
default. The `iss` claim is a different thing and is not this knob: it is not
configurable in this build, and it becomes one with the identity-provider block.

## 8. `oauth.*`, knob by knob

| Path | Type | Default | Env var |
|---|---|---|---|
| `oauth.providers.<name>.clientId` | string | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CLIENT_ID` (google, github) |
| `oauth.providers.<name>.clientSecret` | secret | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CLIENT_SECRET` |
| `oauth.providers.<name>.callbackUrl` | string (absolute URL) | none; **required** per provider | `AWESOME_AUTH_OAUTH_<NAME>_CALLBACK_URL` (google, github) |
| `oauth.providers.<name>.authorizationUrl` | string (https, or http on loopback) | none; required for a generic provider, refused on a built-in one | — (file-only) |
| `oauth.providers.<name>.tokenUrl` | string (https, or http on loopback) | as above | — (file-only) |
| `oauth.providers.<name>.userInfoUrl` | string (https, or http on loopback) | as above | — (file-only) |
| `oauth.providers.<name>.scope` | string (space-separated) | the preset's, for a built-in provider | — (file-only) |
| `oauth.providers.<name>.additionalAuthParams` | map | none; layered over the preset's | — (file-only) |
| `oauth.providers.<name>.profileMap` | map | none; the default mapping | — (file-only) |
| `oauth.providers.<name>.projectId` | string | none | `AWESOME_AUTH_OAUTH_<NAME>_PROJECT_ID` (google, github) |
| `oauth.provisioning.autoCreate` | boolean | `true` | `AWESOME_AUTH_OAUTH_PROVISIONING_AUTO_CREATE` |
| `oauth.provisioning.onEmailMatch` | `link`\|`conflict`\|`reject` | `link` | `AWESOME_AUTH_OAUTH_PROVISIONING_ON_EMAIL_MATCH` |
| `oauth.provisioning.requireVerifiedEmail` | boolean | `false` | `AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL` |
| `oauth.provisioning.allowedEmailDomains` | string[] | none — every domain | `AWESOME_AUTH_OAUTH_PROVISIONING_ALLOWED_EMAIL_DOMAINS` |
| `oauth.provisioning.fieldMap` | map | none | — (file-only) |

### 8.1 Providers

A provider entry under its own name is the whole switch: configure one and
`GET <apiPrefix>/oauth/<name>` starts a flow, configure none and every provider
answers the reference's `404 {"error":"<Provider> OAuth not configured"}`.

**`google` and `github` are the reference's two hard-coded strategies** and
arrive as presets: the endpoints, the scopes and Google's `access_type=offline`
come from the imported core, and a document that tries to point either of them
at another authorization server is refused by name. Three fields are still
yours, because none of them is an endpoint: `scope` (a deployment that needs one
more consent scope should not have to fork a provider), `additionalAuthParams`
(layered over the preset, so an entry replaces the preset's key of the same
name) and `profileMap`.

**Any other name is a generic OIDC/OAuth2 provider** and must bring
`authorizationUrl`, `tokenUrl` and `userInfoUrl`. They must be `https`, with one
carve-out: **outside production**, a loopback host (`127.0.0.1`, `::1`,
`localhost`) may use plain `http`, because such a request never leaves the
machine and an identity provider running beside the process has no name to hold
a certificate for. That is the carve-out RFC 8252 §8.3 makes for the same
reason. It stops at `deployment.environment: production`, where the premise
fails: nothing can run beside a Lambda, and `127.0.0.1` there is the runtime
API — so a production document pointing `tokenUrl` at loopback would POST the
client secret to the execution environment's own control plane, and is refused.

`clientSecret` is a secret-tagged knob like the signing secrets: a
`{"secretsManager": …}` / `{"ssmParameter": …}` reference in the document, or
`AWESOME_AUTH_OAUTH_<NAME>_CLIENT_SECRET` (development) — never a value in the
document.

`callbackUrl` is what the provider redirects back to, and it must be the URL you
registered with that provider. The SAM template derives it —
`<PublicUrl><ApiPrefix>/oauth/<provider>/callback` — and refuses a provider with
no `PublicUrl` to derive it from.

**A provider needs `stores.enable.linkedAccounts`, and it is not on by default.**
The linked-accounts store is where a provider identity is bound to an account,
and the core's callback refuses before it does anything without it: the
authorization redirect still goes out, the person still consents, and the
callback answers `501 {"error":"Feature not supported by the configured stores",
"code":"NOT_IMPLEMENTED"}`. A half-wired login nobody is told about is exactly
what `RS-11` exists to prevent, so **a configured provider with the store off
refuses to start**, naming `stores.enable.linkedAccounts`. The SAM template sets
`AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS=true` whenever a provider parameter
is set, so a stack deployed from it never meets this; a document-configured
deployment has to say so itself:

```json
{"stores": {"enable": {"linkedAccounts": true, "pendingLinks": true}}}
```

`pendingLinks` in that snippet is the second store and a separate decision:
§8.2 covers what `onEmailMatch: conflict` needs it for, and §8.3 what the state
nonce uses it for.

`projectId` is accepted because the reference carries it and nothing reads it;
it is reported at cold start as a knob this build cannot honour, the same way
the mailer's endpoint is.

**`profileMap`** replaces the reference's `mapProfile` function with
expressions, and is what makes a provider whose userinfo document is not
OIDC-shaped configurable rather than code. The keys are `id` (required),
`email`, `emailVerified`, `name` and `picture`; a value is a `??` chain of
`$.path` segments with an optional quoted literal last, evaluated like
JavaScript's `??` — the first alternative that resolves to something other than
missing or null wins:

```json
{"oauth": {"providers": {"contoso": {
  "clientId": "…",
  "clientSecret": {"secretsManager": "awesome-auth/prod/contoso"},
  "callbackUrl": "https://auth.example.com/auth/oauth/contoso/callback",
  "authorizationUrl": "https://login.contoso.example/oauth2/v2.0/authorize",
  "tokenUrl": "https://login.contoso.example/oauth2/v2.0/token",
  "userInfoUrl": "https://graph.contoso.example/v1.0/me",
  "scope": "openid email profile",
  "profileMap": {
    "id": "$.id",
    "email": "$.mail ?? $.userPrincipalName",
    "name": "$.displayName"
  }}}}}
```

An expression that does not compile **refuses the cold start**, naming the
provider and the field, rather than producing a provider that 500s on its first
callback.

### 8.2 The provisioning policy

The reference has no policy: `findOrCreateUser` is abstract and every integrator
writes the function (`generic-oauth.strategy.ts:169-172`). A deployable product
cannot ask for a function, so the policy is declared. The defaults reproduce
what a permissive `findOrCreateUser` does — create missing accounts, link a
matching address — so a deployment that configures only a provider behaves the
way the family's demos do.

| Knob | What it decides |
|---|---|
| `autoCreate` | May the callback create an account for a provider identity nothing here knows yet? With `false`, the answer is `403 OAUTH_USER_NOT_PROVISIONED` and accounts come from `/register`, an invitation or an admin. |
| `onEmailMatch` | The provider account is unknown, but some account already holds the address it asserts. `link` signs that account in and records the binding; `conflict` raises the reference's `OAUTH_ACCOUNT_CONFLICT` — a 302 to `/account-conflict` where the front end drives `/link-request` and `/link-verify`, so the link is made only after an emailed token proves the address; `reject` refuses outright. **`conflict` needs `stores.enable.pendingLinks`** — see below. |
| `requireVerifiedEmail` | Refuse a profile whose `emailVerified` is not positively true (`403 OAUTH_EMAIL_NOT_VERIFIED`). Most providers send no claim at all, so turning this on for one of them refuses every login through it. |
| `allowedEmailDomains` | Bare domains, matched case-insensitively on the part after the last `@`, with no subdomain matching. Empty admits every address; non-empty refuses a profile with no address at all. |
| `fieldMap` | Fills `firstName`, `lastName`, `phoneNumber` and `role` on an account the callback **creates**, with `profileMap` expressions over the same userinfo document. A key outside that list, or a value that does not compile, refuses the cold start. |

**`onEmailMatch` is a knob rather than a constant on purpose.** Linking by
address is the account-takeover shape the reference's own store interface warns
about — two providers can assert one address without representing one person —
and the imported core's default is to link. Hardcoding either answer would put a
security posture in a binary where no operator can see it;
[`docs/spec/decisions.md`](spec/decisions.md) D-20 argues the default.

**`conflict` is the one mode with a store dependency.** Its entire answer to a
conflict is to *stash* it — address, provider, provider account id — so that the
`/link-request` the front end makes next can resolve who is being linked to
what. That stash lives in `stores.enable.pendingLinks`, which is off by default
(only `users`, `sessions` and `tokens` are on). With the store off the core
skips the stash silently: the browser is still sent to
`/account-conflict?provider=…&code=OAUTH_ACCOUNT_CONFLICT&email=…`, and
`/link-request` then has nothing to identify. So **`onEmailMatch: conflict` with
`stores.enable.pendingLinks` off refuses to start** (`RS-11`), naming the mode
and pointing at the store. `link` and `reject` have no such dependency — but see
§8.3 for the other thing that store buys.

### 8.3 Redirects, and the one rule that refuses to start

Where the callback sends the browser is decided by the same two values every
emailed link is built from (§5.1): the canonical site, and the allowlist
`email.siteUrls` ∪ `http.cors.origins`. The flow carries the origin it started
from inside a signed `state`, and the callback honours it only if it is still
allowlisted; anything else falls back to the canonical site.

**A configured provider with an empty allowlist refuses to start** (rule
`RS-11`). The callback answers with a fresh session in a `Set-Cookie`, so where
it sends the browser is a credential-bearing redirect, and with nothing
allowlisted the reference honours whatever origin the state names
(`docs/spec/reference-issues.md` N1). The core signs its states, which is why it
can reproduce that behaviour safely for an embedder; a deployment also has to
survive the day the signing secret is what went wrong, and an allowlist is the
defence that does not depend on the signature holding.

**The state's other defence is a store key.** `stores.enable.pendingLinks` is
also where the flow records the state's nonce on the way out and consumes it on
the way back, which is what makes a state single-use rather than replayable for
the whole of its TTL. With the key off — the default — the core skips both
halves and falls back to the reference's behaviour: signed and time-bounded,
replayable in between. That is not refused, because it is not a broken
deployment; it is reported at every cold start on the `configured knob is not
wired to the auth core` line (§2), with the path and the remedy. Turn it on and
the nonce becomes single-use.

### 8.4 What the callback does not do yet

The reference's callback is 2FA-aware: an account with a second factor is
redirected to `${redirectTo}/auth/2fa?tempToken=…&methods=…` instead of being
handed a session (`auth.router.ts:1298-1313`). The imported core has no such
branch — it issues a session for every account it resolves — and this product
does not fork the core, so **a federated login skips the second factor a
password login demands**. A deployment that requires 2FA and also configures an
OAuth provider should know that before it turns one on.

It is not silent. It is registered as the product deviation
`oauth-callback-skips-the-second-factor`, so every cold start announces it
([`docs/deviations.md`](deviations.md)), and `cmd/auth/oauth_test.go` pins both
halves — that `POST /login` on such an account does answer the challenge, and
that the callback does not — so the test fails the day upstream grows the
branch, which is the signal to delete this paragraph and the register entry.

## 9. `idProvider.*`, knob by knob

Identity-provider mode makes the deployment an OIDC issuer. The full surface —
what it serves, what it deliberately does not do, and how a key is rotated — is
[docs/oidc.md](oidc.md); this section is the knobs.

| Path | Type | Default | Env var |
|---|---|---|---|
| `idProvider.enabled` | boolean | `false` | `AWESOME_AUTH_IDP_ENABLED` |
| `idProvider.kmsKeyId` | string | none | `AWESOME_AUTH_IDP_KMS_KEY_ID` |
| `idProvider.kmsPreviousKeyIds` | string[] | none | `AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS` |
| `idProvider.privateKey` | secret (PEM) | none | `AWESOME_AUTH_IDP_PRIVATE_KEY` |
| `idProvider.issuer` | string (https) | `deployment.publicUrl` + `http.apiPrefix` | `AWESOME_AUTH_IDP_ISSUER` |
| `idProvider.jwksPath` | absolute path | `/.well-known/jwks.json` | `AWESOME_AUTH_IDP_JWKS_PATH` |
| `idProvider.jwksCorsOrigins` | string \| string[] | `"*"` | `AWESOME_AUTH_IDP_JWKS_CORS_ORIGINS` |
| `idProvider.clients[]` | object[] | none | — (file-only) |
| `idProvider.accessTokenTtl` | ms-syntax | `30d` | reported as unwired, see below |
| `idProvider.refreshTokenTtl` | ms-syntax | `90d` | reported as unwired, see below |
| `idProvider.publicKey` | PEM | none | reported as unwired, see below |

**The switch is the same one the reference uses.** Mode is on when `enabled` is
true *or* key material is present, so a document that names a key and forgets the
flag does not come up with the IdP silently off. `kmsKeyId` counts as key
material for the same reason `privateKey` does.

### 9.1 The signing key: `kmsKeyId` or `privateKey`, never both

Rule RS-4 refuses a deployment that sets both, in every environment — nothing
would decide which key signs, and the `kid` in a token, the key in the JWKS
document and the key that actually signed could all disagree. In production it
refuses a deployment that sets neither; in development the core generates an
ephemeral key and the cold-start log says what that costs (every token becomes
unverifiable at the next cold start).

`kmsKeyId` is the production path, and the reason is not ceremony: a PEM is a
value the function reads and holds, so anything that can make it emit a string
takes the issuer's identity with it. A KMS key cannot be exported — the function
holds `kms:Sign` on one ARN, `kms:GetPublicKey` on that one and on the keys being
retired (§9.2), and nothing else at all. The SAM template creates one and
scopes the policy to it; the key costs **USD 1.00 per month**, plus about USD
3.00 per million tokens signed.

Identity-provider mode and `resourceServer.enabled` are mutually exclusive (§10).

### 9.2 `kmsPreviousKeyIds` — rotating without a flag day

Keys listed here sign nothing and are published in the JWKS document after the
current one, so a token minted before a rotation keeps verifying until it
expires. The `kid` is derived from the key material rather than being the
reference's fixed constant, which is what makes the whole rotation additive; the
procedure is [oidc.md](oidc.md) §3, and the divergence is registered as
`idp-kid-derived-from-key-material`.

Each id here is read with `kms:GetPublicKey` at cold start, so the function's
policy has to cover it: an ARN listed but not granted fails the init naming
`idProvider.kmsPreviousKeyIds`, rather than serving an incomplete document. On
the SAM stack, one parameter does both halves (`IdpPreviousKmsKeyArns`).

### 9.3 `idProvider.clients[]` — the relying parties

File-only: a client is an array of objects and no environment variable expresses
one.

```json
{"idProvider": {
  "enabled": true,
  "kmsKeyId": "arn:aws:kms:eu-west-1:000000000000:key/11111111-2222-3333-4444-555555555555",
  "clients": [{
    "clientId": "console",
    "name": "Ops console",
    "clientSecret": {"secretsManager": "awesome-auth/prod/idp-console"},
    "redirectUris": ["https://console.example.com/callback"]
  }]
}}
```

Each client's secret is an ordinary secret knob keyed by **client id**, not by
position: `AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET`, or its `_SECRETSMANAGER`
form. Inserting a client at the top of the list therefore does not move any other
client's variable.

Refused at start: a client with no secret, a client with no redirect URI, a
duplicate client id, and a redirect URI that is neither https nor http on a
loopback host. [oidc.md](oidc.md) §5 says what each of those would otherwise
break. No clients at all is a **warning**, not a refusal — publishing a signing
key and nothing else is exactly what the reference's `idProvider` block is for.

### 9.4 The three knobs that are reported rather than honoured

`idProvider.accessTokenTtl` and `idProvider.refreshTokenTtl` govern the RS256
token pair `auth.IssueIdPTokenPair` mints, and no mounted route calls it — the
OIDC token endpoint returns the HS256 session pair, which is decision D-3 and the
reference's own posture. Set `security.jwt.accessTokenTtl` instead; that is the
lifetime `/token` reports as `expires_in` and the one the token really has.
`idProvider.publicKey` is never read because the JWKS document is built from the
signing key's own public half. All three are named, with their paths, in the
cold-start log.

## 10. `resourceServer.*`, knob by knob

The mirror image: this deployment mints nothing and verifies tokens another
issuer signed.

| Path | Type | Default | Env var |
|---|---|---|---|
| `resourceServer.enabled` | boolean | `false` | `AWESOME_AUTH_RS_ENABLED` |
| `resourceServer.jwksUrl` | string (https) | none; **required** when enabled (RS-8) | `AWESOME_AUTH_RS_JWKS_URL` |
| `resourceServer.issuer` | string | none; unset means `iss` is not checked | `AWESOME_AUTH_RS_ISSUER` |
| `resourceServer.jwksCacheTtlMs` | integer > 0 | `3600000` | `AWESOME_AUTH_RS_JWKS_CACHE_TTL_MS` |
| `resourceServer.jwksFetchTimeoutMs` | integer > 0 | `5000` | `AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS` |

**Turning it on unmounts the credential surface.** All nineteen routes that
create, prove, deliver or change a credential — `/register` and `/login` among
them — answer 404. Do not turn it on for a stack that is supposed to log people
in.

**Not together with identity-provider mode.** Both on is refused at cold start by
rule `IDENTITY`, naming `resourceServer.enabled` and the three knobs that make
the IdP active. The identity provider mounts `POST <prefix>/authorize`, which
takes an email and a password, so the combination would serve a credential route
from a deployment whose configuration says it has none. To publish a signing key
without logging anyone in, run the identity provider with no clients (§9.3).

**The verifier guards your routes, not these** — and in this artifact, nothing.
It is built at cold start with the cache and timeout above and exposed as
`App.ResourceServerGuard`, and the auth routes that remain keep verifying this
instance's own HS256 session, because the commonest resource-server deployment is
the hybrid that needs exactly that. `cmd/auth` mounts the guard on nothing: every
route it serves is the imported adapter's, and there is no second binary and no
SAM wiring that consults it. So on a deployed stack this knob removes nineteen
routes and adds no verification; the export is for a host that embeds this
package, and the cold-start log line says exactly that. [oidc.md](oidc.md) §4 has
the reasoning.

**`security.jwt.accessTokenSecret` is still required**, even though RS-1 exempts
it here: the auth core needs one to build, and the verifier's cookie path reads
it. The cold start refuses by name rather than letting the core complain about a
knob you were told to leave out.

## 11. `runtimeSettings.*`, knob by knob

The one block of this document that an administrator changes without a
deployment. Everything else here is fixed at cold start; these three keys are
seeds for a store the admin surface patches at run time.

| Path | Type | Default | Env var |
|---|---|---|---|
| `runtimeSettings.require2fa` | boolean | `false` | `AWESOME_AUTH_RUNTIME_SETTINGS_REQUIRE_2FA` |
| `runtimeSettings.enabledWebhookActions` | string[] | none (absent, which is not the same as `[]`) | `AWESOME_AUTH_RUNTIME_SETTINGS_ENABLED_WEBHOOK_ACTIONS` |
| `runtimeSettings.lazyEmailVerificationGracePeriodDays` | integer | `7` | `AWESOME_AUTH_RUNTIME_SETTINGS_LAZY_EMAIL_VERIFICATION_GRACE_PERIOD_DAYS` |

Any of them needs `stores.enable.settings`, and a document that declares one
without it is refused by name (rule `STORE_REQUIRED`). Both drivers back the
store: the DynamoDB one keeps it as a single item on its own `SETTINGS`
partition ([data-model.md](spec/data-model.md) §1.8), the memory driver holds it
per execution environment — which for this block is worse than for the others,
since an administrator's toggle is then invisible to every other environment and
gone on the next cold start. RS-12 already refuses the memory driver in
production.

The store may also be switched on with no `runtimeSettings` block at all. That
is a normal deployment: the settings start empty and the admin surface fills
them.

### 11.1 The seed is a seed, and the store wins forever after

The document is applied **once per key, and only to keys the store does not
already hold**. A value an administrator saves through the admin surface is
never overwritten by a redeploy — not on the next cold start, and not on any
later one. Registered as the deviation
`runtime-settings-seed-only-fills-absent-keys` ([deviations.md](deviations.md)),
the sibling of `templates-dir-only-seeds-absent-ids`.

Two consequences worth knowing before you write the block.

**Changing a seeded value in the document does nothing.** Once the key is in the
store, the document has no further say. Change it through the admin surface, or
delete the key from the store.

**A key left at its default is not seeded**, and that is what keeps the block
usable over time: adding `require2fa: true` to a document months from now is
applied on the next cold start, because nothing ever wrote that key. Had the
schema's own `false` been seeded on day one, the later declaration would have
arrived inert. "Declared" therefore means *moved off the default*, which is the
same test that decides whether the block requires the store.

A corollary for `enabledWebhookActions`: **absent and `[]` are different
declarations.** Absent says nothing and seeds nothing; `[]` is the administrator
switching every inbound-webhook action off, and it is seeded, stored and served
as an explicit empty list. The core carries a custom encoder to keep that
difference alive, and so does the store.

### 11.2 What this build actually reads

One key, on one route. `require2fa` is consulted by
`POST <prefix>/2fa/disable`, which answers `403` `2FA_REQUIRED` when it is true —
the reference's behaviour at `auth.router.ts:890-896`. It is a *system policy*
term, so it refuses the disable regardless of whether that account has a second
factor enabled.

The other two are stored and handed back, and nothing in this build acts on
them. Both are named, with their paths, in the cold-start log:

- `enabledWebhookActions` is the global allowlist the inbound-webhook sandbox
  intersects with each webhook's own `allowedActions`. No tools router is
  mounted here yet (P7), so the list is stored and read by nothing.
- `lazyEmailVerificationGracePeriodDays` is read by nothing **here or in the
  reference**: the reference's admin UI displays it and its server never computes
  a verification deadline from it ([config-schema.md](spec/config-schema.md)
  §1.19 `[MISMATCH]`), and the imported core stores it and hands it back
  unchanged. Seed it if you want the admin surface to show a declared value; do
  not expect a login to be refused on it.

Leave both set if the same document is deployed to another port in the family —
nothing in this build reads them, and both become live here without the document
changing.

**Two keys the reference's settings store has and this block does not.**
`requireEmailVerification` and `emailVerificationMode` are storable through the
admin surface and are §1.19's other `[MISMATCH]` row: no login path reads them,
in the reference or here. The knob that does decide a login on this deployment is
`email.verification.mode` (§5), and it is deliberately not copied into the
settings store — a second place for the same non-effect to be discovered from is
worse than none. The branding keys under `ui.*` belong to the settings store too
and arrive with the hosted UI.

## 12. `docs.*`, knob by knob

The two documentation routes: `GET <prefix>/openapi.json`, the generated OpenAPI
document, and `GET <prefix>/docs`, the Swagger UI page that reads it. Both come
from the imported adapter — nothing in this binary mounts a route under the api
prefix — and both are unguarded, exactly as the reference registers them
(`src/router/auth.router.ts:1651-1677`).

| Path | Type | Default | Env var |
|---|---|---|---|
| `docs.swagger` | `true` \| `false` \| `auto` | `auto` | `AWESOME_AUTH_DOCS_SWAGGER` |
| `docs.basePath` | absolute path | `http.apiPrefix` (so `/auth` unless you moved it) | `AWESOME_AUTH_DOCS_BASE_PATH` |

### 12.1 What `auto` resolves to

`auto` is **on outside production and off in it**, resolved against
`deployment.environment`:

| `docs.swagger` | `deployment.environment` | Both routes |
|---|---|---|
| `true` | anything | mounted |
| `false` | anything | 404 |
| `auto` | `development` | mounted |
| `auto` | `production` | 404 |

That reproduces the reference's `swagger === true || (swagger !== false &&
NODE_ENV !== 'production')` (`src/router/auth.router.ts:1652-1654`) with one
substitution: a configuration knob in place of a process variable. The
substitution is not this product's idea — the imported core takes a plain
boolean and says why, that a library whose routes appear and disappear with a
variable it never sees configured is one nobody can reason about from its own
configuration — so resolving `auto` is the host's job, and `cmd/auth/docs.go` is
where it happens.

**The consequence is that a deployment which says nothing gets neither route.**
`auto` is the default here and `production` is the default environment, so
silence is 404 on both; the reference reads an unset `NODE_ENV` as "not
production" and serves both. That is the `production-by-default` deviation
([deviations.md](deviations.md)), whose text names swagger as one of the three
things the default tightens. Say `deployment.environment: development` and the
routes appear.

The cold-start log says which way it went, on every start: `documentation routes
mounted` with both paths, or `documentation routes not mounted` with the knob and
the environment that decided it.

### 12.2 `docs.basePath` moves the description, never the mount

It is the reference's `swaggerBasePath` (`src/router/auth.router.ts:133-139`,
read at `:1657`) and the core's `DocsOptions.BasePath`, and all three mean one
thing: the base the served document writes its path items under, and the base of
the spec URL the Swagger page fetches. **The two routes are always served under
`http.apiPrefix`.** The reference's own doc comment — "Base path where the auth
router is mounted" — is the misleading one; nothing mounts anything from this
value, there or here.

Unset, it is the resolved `http.apiPrefix`, so the document describes the paths
this deployment actually answers and no one has to think about it. Set it only
when a reverse proxy makes this stack reachable from outside under some other
path, so that a reader who fetches what the document names gets a real response.
Set it to anything else and the deployment publishes a document describing paths
it does not serve — which is why a base path that differs from the mount is
called out by name in the cold-start log rather than quietly honoured.

### 12.3 The page puts a third-party script on the auth origin

The Swagger page is the reference's, reproduced byte for byte by the core, and
it loads `swagger-ui-dist@5` from the **unpkg CDN with no subresource
integrity** (`src/router/openapi.ts:1646-1669`). Whatever unpkg serves then
executes same-origin with this deployment's cookies — the CSRF cookie included,
which is readable from JavaScript by design, because the double-submit pattern
requires the client to read it. A bad day at that CDN is a credential-reading
script on your auth origin.

**This is not a refuse-to-start rule, and that is a decision.** The core's
`DocsOptions.Enabled` is one switch for the page *and* for the machine-readable
document; every adapter mounts both under it; this binary may add no route under
the api prefix and does not fork the core. So a refusal aimed at the page would
take the document with it and refuse a production deployment for wanting the one
artefact in the pair that carries no script at all — leaving one move, turning
both off, which is the state the operator was trying to leave. The house rule
that "forgetting to name the environment should tighten, not loosen" is already
satisfied by §12.1: reaching this takes two deliberate statements,
`docs.swagger: "true"` and `deployment.environment: "production"`, in one
document. The fix that would let the product be stricter is upstream's — a
spec-only mode, or a page served from assets the library vendors — and it is
recorded as an upstream ask rather than worked around here.

**What the deployment does instead**, in three parts:

- **It warns at deploy time.** `docs.swagger: true` in production raises a
  configuration warning naming the CDN and the cookie it can read. It is a
  warning and not a log line so that the deployment tooling, which reads
  `Config.Warnings()` before an upload, shows it before the stack has it.
- **It sends a `Content-Security-Policy`** on both documentation responses,
  together with `X-Content-Type-Options: nosniff` and `Referrer-Policy:
  no-referrer`. The page's policy allows the one CDN origin its own HTML names
  and denies everything else: no `fetch` or XHR off this origin, no image
  beacon, no form action, no nested frame, no rewritten `<base>`, and no framing
  of the page itself. The document's is `default-src 'none'` with the same two
  denials. Registered as the deviation
  `docs-page-carries-a-content-security-policy` ([deviations.md](deviations.md)),
  since the reference sends no header of the kind.
- **It keeps the two routes together.** The served document describes both paths,
  so a deployment answering one and 404ing the other would publish a document
  that lies about its own surface.

**Be clear about what the policy buys.** It narrows the hazard; it does not
close it. A compromised bundle still executes same-origin, can still read
`document.cookie`, and can still put what it read into a top-level navigation,
which no CSP directive in any shipping browser prevents. What goes are the quiet
channels. If that is not good enough for your deployment — and on anything
facing the internet it should not be — the answer is `docs.swagger: false`, or
`auto` with `deployment.environment: production`, and reading the document from
a checkout instead.
## 13. `stores.migration.*` — where your users are coming from

The one block in this schema with no counterpart anywhere in the reference: the
reference is a library mounted in front of a store somebody already populated,
and a deployable product has to answer the question of how the users got there.
With the block unset — the default — nothing here is constructed and every route
answers exactly what it answered before the block existed.

| Path | Type | Default | Env var |
|---|---|---|---|
| `stores.migration.source` | `cognito` | none — **empty is the off switch** | `AWESOME_AUTH_STORES_MIGRATION_SOURCE` |
| `stores.migration.userPoolId` | string | none; **required** with a source (RS-13) | `AWESOME_AUTH_STORES_MIGRATION_USER_POOL_ID` |
| `stores.migration.region` | string | none; **required** with a pool id (RS-13) | `AWESOME_AUTH_STORES_MIGRATION_REGION` |
| `stores.migration.clientId` | string | none — no client id, no login-path dependency | `AWESOME_AUTH_STORES_MIGRATION_CLIENT_ID` |
| `stores.migration.mode` | `import-only`\|`dual-read` | `import-only` | `AWESOME_AUTH_STORES_MIGRATION_MODE` |

**`source` is the switch, and nothing else is.** A pool id, an app client or a
mode written without one is refused (`RS-13`), because a block that reads as
configured and does nothing is the shape of an operator who turned the migration
off by deleting the wrong line.

**`region` is not inherited** from `stores.connection.region`. The commonest
migration is out of a pool in another region or another account, and a pool
addressed in the wrong region answers "no such user" for every single person —
indistinguishable from an empty pool. It is demanded rather than guessed.

**`clientId` is the second switch, and the one you clear first.** It names an
app client in the pool, and it is what makes just-in-time password migration
possible: `AdminInitiateAuth` is a client-scoped call. The app client must allow
`ADMIN_USER_PASSWORD_AUTH` and must have **no client secret** — one with a secret
needs a `SECRET_HASH` this product does not compute, and the failure is reported
by name in the log rather than as "wrong password" on every login. With the
client id empty the deployment still imports and still dual-reads; it simply
never calls the pool from a login. That is the posture of a stack whose bulk
import has finished.

**`mode: dual-read` costs one `AdminGetUser` per lookup miss**, on
unauthenticated routes, and is bounded per address and globally by a token
bucket per execution environment. Use it while the bulk import is incomplete and
turn it back to `import-only` afterwards.
[cognito-migration.md](cognito-migration.md) §4 has the numbers and the
reasoning.

**Only the `dynamodb` driver.** The migration marker is a profile attribute, and
there is nowhere else in this build it survives a cold start; `RS-13` refuses any
other driver rather than letting a memory-backed stack re-provision the same
person from Cognito on every execution environment, forever, on an
unauthenticated route.

**Nothing about the migration reaches the wire.** The marker is store-private: it
never enters `auth.User`, so `GET <prefix>/me` cannot disclose it, and no
deviation is registered for it. The one thing a migrated account does carry in
its `metadata` is `imported` — the source attributes the import mapped there,
which is your data and is opt-out per attribute in the map (§3 of the runbook).
[cognito-comparison.md](cognito-comparison.md) §5 has the detail.

The bulk import is `cmd/migrate`, an operator command and not part of the
deployed artifact. The whole procedure, including what happens on a user that
already exists, a paging failure halfway through and a record with no email, is
[cognito-migration.md](cognito-migration.md).

```json
{
  "stores": {
    "driver": "dynamodb",
    "connection": {"tableName": "awesome-auth", "region": "eu-west-1"},
    "enable": {"users": true, "sessions": true, "tokens": true},
    "migration": {
      "source": "cognito",
      "userPoolId": "<region>_XXXXXXXXX",
      "region": "<pool region>",
      "clientId": "<an app client with no secret>",
      "mode": "dual-read"
    }
  }
}
```

## 14. `rateLimit.*`, knob by knob

The built-in rate limiter. It is **net-new to this product**: the reference has
no rate limiting at all — `RouterOptions.rateLimiter`
(`src/router/auth.router.ts:46`) is an empty slot for a host-supplied Express
middleware, and absent it the router collapses the slot to an empty list
(`rl = []`, `:468`) and ships no algorithm. So there is no upstream default to
inherit, every value below is a product decision, and this section is where each
one is argued rather than merely stated.

| Path | Type | Default | Env var |
|---|---|---|---|
| `rateLimit.enabled` | boolean | `true` | `AWESOME_AUTH_RATE_LIMIT_ENABLED` |
| `rateLimit.windowSeconds` | integer > 0 | `60` | `AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS` |
| `rateLimit.max` | integer > 0 | `10` | `AWESOME_AUTH_RATE_LIMIT_MAX` |
| `rateLimit.keyBy` | `ip` \| `email` | `email` | `AWESOME_AUTH_RATE_LIMIT_KEY_BY` |
| `rateLimit.scope` | endpoint names | `login, forgot-password, magic-link, sms-code, 2fa-verify` | `AWESOME_AUTH_RATE_LIMIT_SCOPE` (comma-separated) |

**A deployment that says nothing is rate limited**, and that is the whole point
of the default. It is the same house rule `csrf-enabled-by-default` and
`production-by-default` state: a library can leave the choice to whoever embeds
it, a product has to be safe with an empty configuration, and an auth stack that
ships with unlimited login attempts is one that gets credential-stuffed. The
`429` that follows is the registered wire deviation
`rate-limited-routes-answer-429` ([deviations.md](deviations.md)), because it is
a refusal the reference never makes. Set `rateLimit.enabled: false` and you have
the reference's behaviour exactly.

### 14.1 What `scope` names, and which routes each name covers

A scope name is a flow, not a path, because several flows are two routes and an
operator who wants one almost never wants only one half. `internal/config`
validates the vocabulary; `cmd/auth/ratelimit.go` holds the table below, and
`TestEveryScopeNameMapsToRoutes` fails if the two ever disagree.

| Name | Routes | Subject under `keyBy: email` |
|---|---|---|
| `login` | `POST <prefix>/login` | body `email` |
| `register` | `POST <prefix>/register` | body `email` |
| `forgot-password` | `POST <prefix>/forgot-password` | body `email` |
| `magic-link` | `POST <prefix>/magic-link/send`, `POST <prefix>/magic-link/verify` | body `email`, else `sha256(tempToken)`, else the client address |
| `sms-code` | `POST <prefix>/sms/send`, `POST <prefix>/sms/verify` | body `email` or `userId`, else `sha256(tempToken)`, else the client address |
| `2fa-verify` | `POST <prefix>/2fa/verify` | `sha256(tempToken)`, else the client address |
| `refresh` | `POST <prefix>/refresh` | the client address |
| `reset-password` | `POST <prefix>/reset-password` | the client address |
| `verify-email` | `GET <prefix>/verify-email` | the client address |
| `resend-verification` | `POST <prefix>/send-verification-email` | the client address |

The default scope is the five flows `docs/spec/data-model.md` §1.5 row #61 names
— the ones where a guess costs an attacker nothing and where there is no session
to lose. The other five are nameable and deliberately off: `refresh` and
`verify-email` are spent by a client holding a token it was given, and limiting
them by default would throttle ordinary use of a working deployment to defend
against guessing a 256-bit value.

**Nothing here mounts a route.** The limiter is a middleware over the whole mux
that matches on the resolved `http.apiPrefix` plus a path suffix, so moving the
prefix moves the limiter with it and the adapter still owns every path under it.

### 14.2 `keyBy`, and why the default is not `ip`

`keyBy: email` makes the budget **per account**. `keyBy: ip` makes it **per
source address**, on every route.

The default is `email`, and the argument is about who gets hurt when the limiter
fires:

* The threat these routes face is credential stuffing and password spraying
  against accounts. That is account-shaped, and an account-keyed counter hits it
  exactly: ten attempts a minute against one address is invisible to a real
  person and is six seconds per guess to an attacker.
* An address-keyed default punishes the wrong people. A corporate NAT or a mobile
  carrier's egress is one address for thousands of users, so one abuser behind it
  spends everybody's budget — and, because the counter is one DynamoDB partition
  key capped at 1 000 WCU, it also concentrates the writes
  (`docs/spec/data-model.md` §2.3, whose own conclusion is that per-IP windows
  must be short and the account-scoped limiter must be the primary control).
* Volumetric defence by source address is a real need and belongs at the edge,
  where a WAF or CloudFront can do it with the whole request rate in view. Doing
  it here would be a worse copy of it, one DynamoDB write at a time.

What `keyBy: email` does **not** do is bound an attacker who names a million
different addresses; each gets its own budget. That is the known limit of
account-keyed limiting, it is the layer above's job, and it is the reason
`keyBy: ip` exists as a choice rather than being removed.

**The subject never comes from a header.** It is the source address the Lambda
event reported, not `X-Forwarded-For`, which the client writes: a limiter whose
subject the caller chooses hands out a fresh budget with every request and is not
a limiter at all.

#### When `keyBy: email` meets a route with no email

Three of the ten scopes carry no address in the body, and `POST /2fa/verify`
carries no identity at all. Each route declares an ordered chain (the table in
§14.1) and every chain ends at the client address. Two alternatives were
rejected: one shared sentinel subject would put every such request in the
deployment into a single budget and a single partition — a self-inflicted outage
an attacker triggers by sending an empty body — and skipping the limiter would
leave a six-digit TOTP code unlimited, which is the single route a limiter is
most obviously for.

Where a `tempToken` is present it is preferred over the address, because it names
the challenge: an attacker brute-forcing the six digits holds one token and
presents it with every guess, so the counter is exactly per challenge, and one
who rotates tokens has to log in again for each, which `login` limits. It is
hashed because it is a bearer credential and must not become a partition key in
the clear. Nothing in the chain verifies anything or reads a store — a hash is
not a check — so a refusal still costs nothing downstream.

### 14.3 What a refused request looks like

Byte for byte:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 43
Content-Type: application/json
Cache-Control: no-store

{"error":"Too many requests","code":"RATE_LIMITED"}
```

`Retry-After` is delta-seconds (RFC 9110 §10.2.3), rounded up and never below 1,
and is the time left in the current window.

**No `Set-Cookie`, not even the CSRF one.** The limiter is the outermost
middleware — `RateLimiter`, then CSRF, then the auth middleware, which is the
order the reference uses and the core's adapters reproduce — so a refused request
reaches nothing that verifies a token, reads a store, compares a CSRF value or
distributes the auto-init cookie. A client whose very first request is refused
therefore has no `csrf-token` cookie yet. That is correct rather than an
oversight: a refused request is one the deployment did no work for.

**No `RateLimit-Limit`, `RateLimit-Remaining` or `RateLimit-Reset`**, on the
refusal or on a successful response. The obvious objection to those headers — that
they tell an attacker the limit — is weak on its own, since anyone willing to
spend requests finds the limit by reaching it. The decisive one is
`RateLimit-Remaining` on a **successful** response under an account-keyed
counter: it would be an oracle about somebody else's traffic, letting anyone who
can name `victim@example.com` read from a `200` whether that person has been
logging in. The headers would add a side channel the `429` does not have, in
exchange for something `Retry-After` already gives.

### 14.4 The window is fixed, and what that costs

The counter is a fixed window: the window index is part of the item's key, so
each window is a new item that starts at zero and there is nothing to reset.
Windows are aligned to the Unix epoch, not to a subject's first request.

**The boundary is a seam.** A subject can spend its whole budget in the last
instant of one window and its whole budget again in the first instant of the
next, so the true worst case over any sliding window of the same length is
**twice `max`** — 20 per minute on the defaults, not 10. This is accepted, not
overlooked. Closing it means a sliding window or a token bucket, which needs the
request history or a timestamp plus a fractional balance, which means a
read-modify-write on the login path forever; and a factor of two does not change
what a 10-per-minute limit does to a credential stuffing run. Size `max` for the
bound you want doubled.

The other consequence of a fixed window is the ceiling on a false positive: a
legitimate user who trips the limiter waits at most `windowSeconds`. That is why
60 is the default — long enough to be a real bound, short enough that being wrong
about someone costs them a minute.

### 14.5 What it costs per request, and what happens when the store is down

The limit lives in DynamoDB, in the same table as everything else
(`docs/spec/data-model.md` §1.5 row #61). One limited request is **one
conditional `UpdateItem`, so 1 WCU** — and that is true of a refused request too,
because DynamoDB bills a conditional write whose condition fails. Unlimited
routes cost nothing at all; the limiter does not look at them beyond a map
lookup.

Two things reduce that. A refused request does not increment the counter, so the
stored number is bounded by `max` however long a flood lasts. And each execution
environment keeps a small in-process pre-filter holding the same budget over the
same window, so once an environment has watched a subject exhaust its budget it
refuses locally and writes nothing — under a sustained flood only the first `max`
requests per environment per window cost a write.

**The in-process tier is a pre-filter, never the limit.** A Lambda execution
environment serves one request at a time and AWS runs as many as the arrival rate
demands, so an in-process counter alone would limit each environment separately
and the real ceiling would be `max` times a concurrency nobody chose. The shared
counter is the limit; the local tier only ever refuses what the shared counter
would have refused, because both hold the same budget over the same
epoch-aligned window.

**When the shared counter is unreachable, the limiter allows the request.** It
fails open, deliberately. The counter is in the same table as the user store, so
on this product "the limiter cannot count" and "the route cannot serve" are the
same event: every route in the default scope reads or writes that table
immediately after the limiter. Failing closed would refuse requests that were
going to fail anyway, turn a partial DynamoDB degradation into a total outage on
exactly the routes people need during one, and replace a `500` naming the store
with a `429` blaming the caller.

The cost of that choice is stated rather than hidden: during such a window the
only remaining bound is the in-process pre-filter, which is **per execution
environment**, so the effective ceiling is `max` per subject per window
multiplied by however many environments AWS is running. It is a floor, not the
limit. The degradation is logged once per cold start at `WARN` — once, not per
request, because a limiter that logged every failed write during a DynamoDB
incident would add its own load to the incident.

With `stores.driver: memory` there is no shared counter at all and the in-process
tier is the whole limiter. The cold-start log says so in as many words. That
driver is refused in production (RS-12), so this is a development posture and
never a deployed one.

### 14.6 Reading it from outside

You cannot see a limiter without tripping it, which is why the cold-start log is
where its resolved shape is written: `rate limiting is on` with `keyBy`, `max`,
`windowSeconds` and the full list of watched `METHOD /path` patterns, or `rate
limiting is off` with what that means. Two warnings are worth knowing: `rate
limiting is on but its scope is empty`, which is a document that enabled the
block and pointed it at nothing, and `rate limiting has no shared counter`, which
is the memory driver above.

The contract suite's `rate-limit` capability is **opt-in and off by default**,
for the reason a probe cannot be written any other way: discovering a limiter
costs the budget it protects, and a suite that exhausted a live one would flake
and would leave the deployment throttled for whoever called next. See
[test/contract/README.md](../test/contract/README.md).

## 15. `ui.*`, knob by knob

The hosted UI: everything under `GET <prefix>/ui` — the config document the
pages boot from, the server-rendered pages themselves, and the static assets
under them. It is the whole of the reference's `ui` router
(`src/router/ui.router.ts`), mounted where the reference mounts it
(`src/router/auth.router.ts:1640`), and it comes from the imported adapter:
nothing in this binary mounts a route under the api prefix.

The pages are the reference's own fourteen browser assets, vendored byte for
byte by `awesome-go-auth` and compiled into the binary. There is no bucket to
deploy them to, no second origin and no build step — which is the point of §15.3
below.

| Path | Type | Default | Env var |
|---|---|---|---|
| `ui.enabled` | boolean | `false` | `AWESOME_AUTH_UI_ENABLED` |
| `ui.headless` | boolean | `false` | `AWESOME_AUTH_UI_HEADLESS` |
| `ui.customCss` | string | none | — (file-only) |
| `ui.assetsDir` | string (directory) | none; the vendored assets | — (file-only) |
| `ui.uploadDir` | string (directory) | none; **accepted and not honoured**, see §15.4 | `AWESOME_AUTH_UI_UPLOAD_DIR` |
| `ui.branding.siteName` | string | `Awesome Node Auth` | `AWESOME_AUTH_UI_SITE_NAME` |
| `ui.branding.primaryColor` | string | `#4a90d9` | `AWESOME_AUTH_UI_PRIMARY_COLOR` |
| `ui.branding.secondaryColor` | string | `#6c757d` | `AWESOME_AUTH_UI_SECONDARY_COLOR` |
| `ui.branding.logoUrl` | string | none | `AWESOME_AUTH_UI_LOGO_URL` |
| `ui.branding.bgColor` / `.bgImage` / `.cardBg` | string | none | `AWESOME_AUTH_UI_BG_COLOR`, `…_BG_IMAGE`, `…_CARD_BG` |

`ui.enabled` is one switch for two things, and the second is easy to miss: it
also changes the shape of **every emailed link**. With it on, a password-reset
mail points at `<siteUrl><prefix>/ui/reset-password?token=…`, the hosted page for
it; with it off, at `<siteUrl><prefix>/reset-password?token=…`, the API route
itself (`HTTPConfig.UILink`, the reference's `buildUiLink`,
`auth.router.ts:261-271`). Turning the UI off on a deployment whose users have
unspent reset links in their inbox invalidates the *destination* of those links,
not the tokens.

There is no `features` knob and there will not be one. The eight flags in the
config document — `register`, `magicLink`, `sms`, `google`, `github`,
`forgotPassword`, `verifyEmail`, `twoFactor` — are derived from what this
deployment is actually wired to do, so they cannot claim a flow it cannot
perform. `config-schema.md` §1.12 records that as a rule rather than an omission.

### 15.1 What the cold start tells you, and what the settings store now costs

`hosted UI mounted` names the mount, the asset source, the language, the site
name and whether the settings store is behind the branding. `hosted UI not
mounted` — the default — says that the whole subtree answers 404 and that
emailed links therefore point at the API routes.

The line worth reading twice is `the settings store is on the UI render path`.
**This is the first block whose surface reads the settings store per request.**
The core builds the config document by reading that store first (the reference's
own order, `ui.router.ts:99`) and then the template store for the `config` page's
translations — so with the UI on and both stores enabled, **every SSR page render
and every `GET <prefix>/ui/config` is two DynamoDB reads**. Before this, the
settings store was read once at cold start by the seed (§11) and once per
`POST <prefix>/2fa/disable`.

And a settings store that fails does not fail the request. The core catches it
and serves the reference's fallback document — default branding, English, no
translations, and a **shorter** `features` object carrying three of the eight
flags, which is upstream's bug reproduced rather than fixed. A client cannot tell
that from success. So an unreachable store degrades every page of the hosted UI
to the reference's default look, silently; the cold-start line is the notice you
get in advance.

One thing that interaction does *not* change: what §11's seed writes.
`runtimeSettings` has no `ui` member, so the stored branding an administrator
will eventually save is written by the admin surface and by nothing in this
build. Until then the store's `ui` block is absent on every read and the branding
falls straight through to `ui.branding.*`.

### 15.2 `ui.headless` serves no HTML at all

Headless is a different product, not a degraded one. With it on, the router
serves the config document and the static assets and **no page** — every page
path 404s (`ui.router.ts:172-183`; the return is the behaviour, and the uploaded
asset mounts are on the far side of it, so they are not mounted either).

That is the posture for a hosting SPA: your application provides its own login
UI, loads `<prefix>/ui/auth.js` from this origin, and reads `headless: true` out
of the config document to stop redirecting to a login page that is not there. It
is the right answer when you already have a design system and the wrong one if
you wanted the built-in pages, and the two are indistinguishable from a status
code — which is why the cold start says which it is.

### 15.3 What a hosting page has to allow, and what the pages load

There is no `Content-Security-Policy` on these responses, and that is not an
oversight — the reference sets none, and a header this port invented would be a
deviation on a surface whose whole purpose is to be the family's page. What
matters instead is what the pages *do*, because that is what a hosting
application's own policy has to permit:

- **An inline `<script>`, always.** The SSR injection writes
  `window.__AUTH_CONFIG__ = {…}` into the document (`ui.router.ts:273`) so the
  page boots without waiting for a fetch. A policy with no `script-src
  'unsafe-inline'`, and no nonce, breaks every page.
- **An inline `<style>`, always, twice.** The branding variables go into a
  `:root` block ahead of any stylesheet, which is what prevents a flash of
  unstyled content, and the readiness splash brings its own.
- **`ui.customCss` is injected unescaped**, in a `<style>` of its own
  (`ui.router.ts:216`). It is stylesheet source and there is nothing to escape it
  into; a `</style>` inside it closes the block, here exactly as there. It is
  readable only from the static configuration — no settings store can reach it —
  so the string is always your own code.
- **`ui.branding.logoUrl` is written into `src="…"` unescaped**, which is the
  reference's sink reproduced. A value containing a double quote escapes the
  attribute. Today that value can only come from this document or from a settings
  store nothing in this build writes; the core names it explicitly so that the
  admin surface has to decide about it rather than inherit it.
- **Everything else is same-origin.** The assets are served from
  `<prefix>/ui/…` by this deployment. No CDN, no external font, nothing to
  allowlist — which is the opposite of the documentation surface (§12.3) and
  worth the contrast.

The injected object itself is serialised with Go's default escaping, so `<`, `>`
and `&` leave as `<`, `>` and `&`. The bytes differ from
`JSON.stringify`'s and the parsed value does not; it is the upstream deviation
`ui-ssr-config-json-is-html-escaped` ([deviations.md](deviations.md)), and it is
the one place the port is *stricter* than the reference — a `</script>` inside a
branding string cannot end the block.

**Headless and a hosting SPA.** If your application serves its own pages, none of
the above applies to it: it loads `auth.js` from this origin and writes its own
markup, so its CSP is its own. What it does need from this origin is the config
document, which is a plain `GET` with no credential, and the cookies the auth
routes set — which means the SPA and this deployment want to be the same origin,
or the cookies want a shared parent domain and `cookies.sameSite` set
accordingly. `infra/sam/template.yaml`'s `EnableCloudFront` exists for exactly
that: one hostname in front of both.

### 15.4 `ui.assetsDir`, and `ui.uploadDir` which is not honoured

**`ui.assetsDir`** replaces the built-in pages with your own. It is file-only —
a path inside the deployment artifact, the same position `email.templatesDir` is
in — because a Lambda's only readable filesystem is the package it was deployed
with.

It is all-or-nothing. The core takes a supplied asset set at its word and never
falls back to the vendored one, on the grounds that a half-replaced UI is worse
than a missing one, so a page your directory lacks is a 404 rather than the
built-in page. A directory that is not there, or that holds none of the three
pages the handler falls back to — `login.html`, `index.html`, `index.csr.html`,
tried in that order — **refuses the deployment at cold start**, naming the three.
That refusal exists because the alternative is a stack that 404s every page while
every health check passes.

**`ui.uploadDir` is accepted by the schema and honoured by nothing.**
`GET <prefix>/ui/assets/logo/*` and `GET <prefix>/ui/assets/uploads/*` answer 404
in every configuration, which is the core's own unconfigured behaviour — the two
mounts do not exist, rather than failing on a store that is not there. Setting
the knob is reported at cold start as a knob this build does not act on.

Three reasons, and the first is decisive on its own. **There is no writer:** the
upload route is an admin route, this build mounts none, so a read path would read
an empty location on every deployment. **A directory is the wrong noun here:**
`/var/task` is read-only and `/tmp` is per execution environment, so a logo
uploaded during one cold start would be invisible to the next request and gone by
the one after — the serverless shape is an S3 location, which `config-schema.md`
§1.12 already records, and that is a different thing behind the same knob.
**And an `fs.FS` over S3 costs a `GetObject` per `Open`,** misses included, on a
path every page of the hosted UI requests whether or not anyone ever uploaded
anything. Registered as `ui-uploaded-assets-are-not-served`
([deviations.md](deviations.md)).

Until the upload store lands, set `ui.branding.logoUrl` to a URL you host
elsewhere. This build honours it and writes it into every rendered page.

### 15.5 The caveat that matters right now

**Leave `ui.enabled` off on a deployed stack until the admin surface lands, and
know why.**

The vendored assets are the reference's, complete — which means they include
`admin.js` and `admin.css`, and the pages reference `/admin/*` and `/tools/*`
routes that **this build does not mount**. The `admin` and `tools` domains are
still refused by the phase gate. So a deployment that turns the UI on today gets
working login, registration, password-reset, magic-link, verification and 2FA
pages, and an admin dashboard that loads and then fails against routes that
answer 404.

Nothing about that is a bug in this block: the UI is servable, configurable and
tested, and the login half genuinely works. It is a gap between a complete asset
set and an incomplete route surface, and it closes when the admin and tools
surfaces land. Until then the stack template's own configuration leaves the UI
off, deliberately, and this paragraph is here so that turning it on is a decision
rather than a discovery.

## 16. Two worked postures

**Mail through SES, templates from the artifact.** Every key that is not
`email.*` here is load-bearing: `stores.enable.templates` needs a driver that
backs a template store (§5.3), and the `stores` block has to name that driver,
because the default is `memory` and rule RS-12 refuses it in production.

```json
{
  "schemaVersion": 1,
  "deployment": {"environment": "development", "publicUrl": "https://auth.example.com"},
  "email": {
    "siteUrls": ["https://app.example.com"],
    "mailer": {"endpoint": "https://unused.invalid", "from": "no-reply@example.com", "fromName": "Example"},
    "templatesDir": "/var/task/templates"
  },
  "stores": {"driver": "memory", "enable": {"users": true, "sessions": true, "tokens": true, "templates": true}}
}
```

For production today, drop `templatesDir` and `stores.enable.templates`, keep
`stores.driver: dynamodb`, and the built-in `en`/`it` templates render.

**Every credential posted to a receiver you own.** A production document: no
mailer block at all, so nothing is sent through SES or SNS, and the
email-changed notice and the account-linking mail are not sent either. The
`stores` block is what makes it a production document rather than a refusal —
the default driver is `memory`, which RS-12 forbids in production.

```json
{
  "schemaVersion": 1,
  "deployment": {"environment": "production", "publicUrl": "https://auth.example.com"},
  "email": {
    "siteUrls": ["https://app.example.com"],
    "deliveryWebhook": {
      "url": "https://hooks.example.com/auth-delivery",
      "timeoutMs": 2000,
      "secret": {"secretsManager": "awesome-auth/prod/delivery-webhook"}
    }
  },
  "stores": {
    "driver": "dynamodb",
    "connection": {"tableName": "awesome-auth", "region": "eu-west-1"},
    "enable": {"users": true, "sessions": true, "tokens": true}
  }
}
```
