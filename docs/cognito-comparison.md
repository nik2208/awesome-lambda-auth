# awesome-lambda-auth and Amazon Cognito

This page exists because the question is asked before every migration and
answering it honestly is cheaper than answering it twice. It is a comparison,
not a pitch: several rows below say Cognito does something this product does
not, and one of them — rate limiting — says Cognito does something neither this
product nor the reference it ports does yet.

For *how* to migrate, see [cognito-migration.md](cognito-migration.md). For the
knobs, [config-reference.md](config-reference.md) §11.

## 1. The shape of the difference

A Cognito user pool is a managed directory: AWS holds the users, AWS holds the
password hashes, AWS decides what a token looks like, and the surface you
integrate against is the AWS SDK or the Hosted UI.

`awesome-lambda-auth` is the opposite trade. The users are rows in **your**
DynamoDB table, in a schema documented in `docs/spec/data-model.md`; the routes
are HTTP endpoints under a prefix you choose, with a wire contract that is a
port of a reference implementation you can read; and every behaviour that is
not the reference's is written down, with its reason, in
[deviations.md](deviations.md).

Neither is better in the abstract. What follows is what actually differs.

## 2. Feature by feature

| | Cognito user pool | awesome-lambda-auth |
|---|---|---|
| Where users live | AWS-managed directory | your DynamoDB table, one documented schema |
| Password hashing | AWS-managed, algorithm unpublished, hashes never exported | bcrypt at `security.password.bcryptSaltRounds` (default 12), in your table |
| Export a user's password | never, by design | it is your table; the hash is a column |
| Sign-in API | SDK (`InitiateAuth`, SRP or `USER_PASSWORD_AUTH`) or Hosted UI | `POST <prefix>/login`, a JSON route |
| Token format | Cognito's own access/id/refresh JWTs, claims fixed by the service | HS256 access + refresh pair by default; RS256 with a published JWKS in identity-provider mode |
| Custom claims | pre-token-generation Lambda trigger | `security.jwt.extraClaims` (declarative) or `security.jwt.claimsWebhook` (computed) — §6 |
| Refresh-token theft | rotation optional; a replay is not acted on | a replayed refresh token revokes the whole session (`refresh-token-families`) |
| Second factor | SMS and TOTP, plus adaptive/risk-based MFA | SMS and TOTP. **No adaptive or risk-based MFA**, and none planned |
| Social sign-in | Google, Facebook, Apple, Amazon, generic OIDC/SAML | Google and GitHub as presets, plus any generic OAuth2 provider — §8. **No SAML** |
| Hosted sign-in pages | Hosted UI, customisable within limits | not yet (`ui.*` is a later phase); today you build the pages |
| Rate limiting | per-account lockout and per-API throttles, on by default | **none yet**, on any route — see §4 |
| Multi-tenancy | one pool per tenant, or an attribute you manage | tenant id in the partition key; one table, isolated by construction |
| Admin surface | AWS console and the admin APIs | not yet (`admin.*` is a later phase) |
| Audit trail | CloudTrail | your CloudWatch logs; no per-event audit store yet |
| Cost | per monthly active user | DynamoDB + Lambda; no per-user charge |
| Compliance posture | inherits AWS's certifications for the directory itself | yours, because the data is yours |
| Lock-in | leaving means a migration like the one this page documents | leaving means copying your own table |

## 3. What you give up that is easy to underestimate

**Adaptive authentication.** Cognito's advanced security scores a sign-in
attempt against the account's history and can demand a second factor for an
unusual one. There is no equivalent here and no plan for one. If you rely on it,
that reliance has to be replaced before the migration, not after.

**SAML and the enterprise identity providers.** The OAuth block speaks OAuth2
and OIDC. A pool federating to Okta over SAML has no counterpart here.

**The Hosted UI.** Until the hosted-UI phase lands, every screen — sign-in,
sign-up, forgot-password, the 2FA prompt — is yours to build against the JSON
routes. The family's shipped clients (`ng-awesome-node-auth`,
`awesome-node-auth-flutter`) are one way to shorten that.

**Password-policy enforcement at the pool.** Cognito enforces a configured
complexity policy on every password. This product enforces a minimum length,
applied on register, reset and change.

## 4. Rate limiting: state it plainly

**The reference implementation has no rate limiting at all.** `awesome-node-auth`
leaves it to whatever Express middleware the integrator mounts
(`src/router/auth.router.ts:46,468`), and this product inherits that: as of this
release, no route is rate-limited, `rateLimit.*` is validated but not wired, and
a deployment that turns it on is refused with the phase that will wire it.

So a stack migrating off Cognito **loses per-account lockout and per-API
throttling on the day of the cutover**, and gets nothing back until the limiter
lands. When it lands it is net-new: a product decision, with no reference
behaviour to be compatible with, which is why its defaults are marked TBD in the
spec rather than copied from anywhere.

Two exceptions exist today, and they are both about protecting *Cognito* rather
than this deployment:

- the just-in-time password verifier bounds how often one account, and all
  accounts together, may be asked about at the pool;
- the dual-read fall-through bounds the same thing for lookups.

Both are per execution environment, both are described in §4 of
[cognito-migration.md](cognito-migration.md), and neither is a general limiter.
Do not read them as one.

In the meantime, the honest mitigations are outside this product: an AWS WAF
rate-based rule in front of the HTTP API, and a throttle on the API Gateway
stage. Both are one console setting, both are the right shape for the problem,
and neither is something this template configures for you today.

## 5. What a migrated account looks like from a client

**Like an ordinary one.** That is deliberate and it is tested rather than
intended, and it is why this block registers nothing in
[deviations.md](deviations.md).

**The migration marker is not on the wire at all.** Every imported row carries
one — it is what the login path keys on before it is willing to send a password
to your old pool — but it never becomes a field on the user record. The profile
read hands it to the password verifier on the request context and it stops
there, so `GET <prefix>/me`, the only route that serialises the user object,
cannot disclose it. Nobody can read which directory an account came from, or the
id of the pool that held them, by asking this service.

That was not free: the obvious design puts the marker in `metadata`, where the
verifier can read it, and the upstream seam's own example does exactly that. It
would have meant every not-yet-migrated account disclosing its source and your
pool id to whoever held a session on it. The context carrier is what buys the
alternative.

**What a migrated account does carry is `imported`**, and only if you asked for
it:

```json
"metadata": {
  "imported": {"department": "analytics"}
}
```

That is whatever the attribute map placed there — by default every `custom:*`
attribute the pool held. It is your data about your person, in the field the
reference defines for exactly that purpose, and it is permanent. If you do not
want it on the wire, map those attributes to `-` in the attribute map (§3 of the
runbook) and they are never written in the first place. The same projection is
what is POSTed to `security.jwt.claimsWebhook`, if you have one, which is a
receiver you own.

Everything else about a migrated account is indistinguishable from a registered
one: the id has the same shape, the token has the same claims, and
`POST /login` answers the same statuses, codes and bodies whether a verifier is
configured or not. Both halves are pinned in `cmd/auth/migration_test.go`, by
`TestLoginIsByteIdenticalWithAVerifierConfigured` and
`TestMigrationDisclosesNothingOnTheWire`.

## 6. When not to migrate

- You rely on adaptive authentication or SAML federation. Neither has a
  counterpart here.
- You need the Hosted UI and cannot build sign-in screens.
- You need per-account lockout on day one and cannot put a WAF rule in front of
  the API.
- Your pool's users sign in mostly through federated providers rather than with
  a password. The just-in-time half of this migration carries passwords; a
  federated identity is re-established by the person signing in through the
  provider again, which is fine but is not a migration this tooling performs.
