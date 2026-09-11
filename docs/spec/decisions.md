# Decisions register

Every entry records a fork in the road that the reference source does not settle, the option taken, and what it would cost to reverse it. The rule during the 2026-09 build-out is: decide, record here, continue. A later reversal by the project owner is a new block of work, never a stop.

## D-0 — Rules of the non-stop run (2026-09-11)

- The owner asked for the whole programme, Go port and Lambda product, to be completed in one autonomous run. The former "stop at each phase boundary" rule is replaced by "write the phase summary in `docs/PROGRESS.md` and continue".
- Pull requests on both repositories are merged by the author account after CI is green (squash, one concern each); milestone tags are cut without a separate review.
- Deployments target only the CloudFormation stack `awesome-lambda-auth` in `eu-west-1`, always through the AWS CLI profile named `lambda-auth`. The profile name is the invariant: a pre-flight check refuses to run when that profile resolves to the same account as `default`, or when the stack is missing or in a rollback state. Nothing is ever deleted.
- On-demand resources may be created without asking (KMS keys, S3 buckets, SQS queues, EventBridge buses, Function URLs, CloudFront distributions, additional Lambda functions, CloudWatch alarms). Provisioned capacity, WAF, NAT, VPC attachments, real domains and anything in the demo account beyond reading are `blocked-owner` items.
- Reversal cost: none; this is process.

## D-1 — Configuration format

The document is JSON, baked into the artifact (`AWESOME_AUTH_CONFIG_FILE=/var/task/awesome-auth.json`) or supplied inline (`AWESOME_AUTH_CONFIG_JSON`), with the `AWESOME_AUTH_*` environment layer on top and the runtime settings store above that. No SSM parameter tree. YAML is a front-end for later. `cookies.allowInsecureCookieMode` is honoured in every environment and warned about in production. Reversal cost: low, the loader already takes a `Document`.

## D-2 — Rate-limit wire shape

There is nothing to inherit: the reference ships no limiter. Every limited outcome is `429` with the family error shape, `{"error":"Too many requests","code":"RATE_LIMITED"|"TOO_MANY_FAILURES"|"ACCOUNT_LOCKED","retryAfter":<seconds>}`, plus `Retry-After` and the IETF draft `RateLimit-*` headers. No server-side sleep; a progressive delay is expressed through `Retry-After`. Reversal cost: trivial before the first release.

## D-3 — What identity-provider mode signs

Only the OIDC surface: `id_token` and the OIDC `access_token` from `/oidc/token`, RS256 through KMS or an injected PEM key. Session tokens from `/login` and `/refresh` stay HS256, exactly as in the reference (`reference-issues.md` N35). Version 1 issues no OIDC `refresh_token`; clients are configured, not registered dynamically. Reversal cost: medium, but the reference points the same way.

## D-4 — Temporary 2FA token

Kept as the upstream registered deviation `temp-token-is-typed-not-an-access-token`: a five-minute HS256 JWT with `typ: "temp"`, refused as a session credential by every protected route, `INVALID_TEMP_TOKEN` everywhere. Reversal cost: low.

## D-5 — Offset pagination on DynamoDB

Admin list endpoints emulate `limit`/`offset` by walking query pages and discarding `offset` items, capped at `offset + limit ≤ 1000` (`400 OFFSET_TOO_LARGE` beyond); `total` reproduces the reference's heuristic; an additive `nextCursor` is returned for clients that can use it. Reversal cost: low.

## D-6 — Hosted UI

The reference's UI assets are vendored byte for byte upstream and pinned by a SHA test, served embedded under `<apiPrefix>/ui/*`. CloudFront in front of the stack is the production front door (same origin for `/auth`, static assets from S3, the SSE Function URL), enabled on the development stack. Reversal cost: medium.

## D-7 — `deleted:0` and refresh-token families

Both signed off as registered deviations: `POST /sessions/cleanup` answers `{deleted:0}` because expiry is DynamoDB TTL; a replayed refresh token revokes its whole session. Reversal cost: high for the count (needs an index and a scan), and the family design is security-positive, so it stays.

## D-8 — Server-sent events on Lambda

`/tools/stream` is served by its own function behind a Function URL with response streaming. The DynamoDB event log (`SSE#<topic>` / `E#<ulid>`) is the distributor: publishers append, the streaming handler long-polls with an adaptive interval. `Last-Event-ID` replays from the log within a 24-hour window, which the reference never offered. Reversal cost: medium.

## D-9 — Swagger UI

Upstream serves the reference HTML verbatim (swagger-ui-dist from unpkg). In the product, docs are off in production unless `docs.swagger: true`. Reversal cost: trivial.

## D-10 — Claims webhook failure

Fails closed: a webhook error or timeout fails token issuance with `500 CLAIMS_WEBHOOK_FAILED`. The auth middleware uses a verification path that never calls the claims builder, so the webhook fires on token issuance only. Reversal cost: trivial.

## D-11 — Delivery webhook

Synchronous within the request, bounded by `timeoutMs`. Moves to the SQS queue once the P7 event plane exists. Reversal cost: trivial.

Amended when it was wired (P2): the failure contract is each seam's own rather than "never fails the route", because the seams do not agree and the webhook must not make them. `POST /forgot-password` answers 200 whatever the receiver does, as it does with every other sender; the other four surface the reference's generic 500 and leave the minted token stored. The webhook also takes *all five* credential seams when its url is set — SES and SNS are not called for those routes at all — and `email.deliveryWebhook.secret` is required alongside the url (config-schema.md §1.5 addendum).

## D-12 — `first-user` admin policy

An atomic election item (`SETTINGS` / `adminFirstUser`, `attribute_not_exists`) written on the first admin login, instead of "position 0 of an unordered list". Reversal cost: low.

## D-13 — Runtime settings at login

As the reference: the settings store's `require2FA` is read where the reference reads it (`/2fa/disable` and the two-factor policy), and `emailVerificationMode` from the store is not consulted at login (`reference-issues.md` N36, documented rather than fixed). Reversal cost: low.

## D-14 — Rate limiter design

Fixed window counter per `RL#<scope>#<subject>#<window>` with one conditional `UpdateItem`; lockout and progressive delay on the credential-guessable scopes; `keyBy` in `ip|email|tenant`; fail-open on store errors with a metric; scope vocabulary is the eleven names in `internal/config/validate.go`. Reversal cost: low.

## D-15 — Backup codes

Out of scope: absent from the reference, the specs and the clients. Reversal cost: none.

## D-16 — Event plane

The core `Service` publishes to the in-process bus; the tools facade subscribes to `*` and performs the reference's fan-out order (telemetry → bus → SSE → webhooks). The product plugs EventBridge or SNS as the transport and SQS as the webhook deliverer. Reversal cost: low.

## D-17 — Templates from the artifact (2026-09-11)

`email.templatesDir` is read once, at cold start, and seeds only the ids and UI pages the template store does not already hold; a template saved through the store wins over the file of the same id, on this and on every later cold start. A Lambda has no writable filesystem and no deploy step that runs code, so the artifact is the only place a shipped template can live and cold start the only moment it can be read — and a runtime edit has to survive the next redeploy, or the admin API would be undone by every cold start. A directory that is missing or unreadable refuses to start in production, where the artifact is supposed to contain what the document names, and warns in development. Registered as the product deviation `templates-dir-only-seeds-absent-ids`. Reversal cost: low — "the directory always wins" is one branch in `seedTemplates`, but it would make a runtime edit unstable, which is why it is not the default.

## D-18 — The delivery webhook requires a secret

`email.deliveryWebhook` is a transport, not a notification: the core's `auth.NewDeliveryWebhook(url, secret)` (v0.4.0) is handed the magic link, the reset token, the verification token, the email-change token and the SMS code, and POSTs them to the operator's endpoint so a transport the product does not ship (Postmark, a queue, an on-premises relay) can carry them. The body therefore carries the credential itself, and the receiver has to be able to tell the product's POST from anyone else's — the core signs each request with `X-Webhook-Signature` only when a secret is set, and leaves the choice to the integrator. The product does not: a `deliveryWebhook.url` with no secret refuses to start, in every environment, as a refuse-to-start rule beside RS-1…RS-12. The secret is a secret-tagged knob like the JWT secrets (`{"secretsManager": …}`, `{"ssmParameter": …}`, or `AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET`), never a value in the document. Not a wire deviation — the reference has no webhook to compare against; it replaces the reference's five send-callback functions (`config-schema.md` §3.8) — so it is recorded here rather than in a register. D-11's "synchronous, bounded by `timeoutMs`, never fails the route" still applies to the call. Reversal cost: trivial in code (drop one validation rule), but it would ship a product that mails credentials to an endpoint nothing authenticates, so it is not expected to be reversed.

