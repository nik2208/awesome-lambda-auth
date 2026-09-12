# Configuration reference

What the deployed binary reads, in the order it reads it, and what every knob of
the `email` domain does once it is read.

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
- `credential delivery wired` and `email flows wired` — one line each an
  operator can read the whole delivery and email posture off: which transport
  each seam uses, the canonical site URL, how many origins are allowlisted, and
  what the templates directory seeded.

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

The whole `email` domain now loads. `email.siteUrls`, `email.templatesDir` and
`email.deliveryWebhook` were the last three to leave that list; nothing under
`email.` is refused by the phase gate any more.

So do `twoFactor`, `security.jwt.extraClaims` and `security.jwt.claimsWebhook`
(§6, §7). Nothing under `security.` is refused any more either.

`email.templatesDir` needs a template store, and both drivers now back one: the
DynamoDB store keeps mail templates and UI translations on its `TEMPLATES`
partition, the memory driver holds them per execution environment (§5.3). A
driver that backs none is still refused by `checkStoreSupport` at cold start,
by name — a store gap rather than a phase gap.

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

## 8. Two worked postures

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
