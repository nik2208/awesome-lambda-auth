# Contract suite

Black-box checks of the wire contract in `docs/spec/wire-contract.md`, run over
HTTP against a *running* stack.

The port's correctness claim is that the family's shipped clients
(`ng-awesome-node-auth`, `awesome-node-auth-flutter`, the served `auth.js`) work
against it with only a base-URL change. Everything else that supports that claim
is a unit test somewhere inside a library — the auth core's `adapter/internal/wiretest`
is Go-`internal` to `adapter/`, so this repository cannot even import it — or a
one-off curl. Neither runs against a deployment, and a deployment is where the
claim is actually made: cookie prefixes depend on `cookies.secure`, the CSRF
double-submit depends on `security.csrf.enabled`, and half the routes depend on
which stores the operator switched on.

So this suite is parametrised on a base URL, and the identical assertions run
against a deployed stack and against the reference Express app.

## Running it

```sh
# a deployed stack
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.<region>.amazonaws.com \
  ./scripts/toolchain.sh go test ./test/contract/... -v

# the reference implementation, for a side-by-side (see below)
AWESOME_AUTH_CONTRACT_BASE_URL=http://localhost:3000 \
  ./scripts/toolchain.sh go test ./test/contract/... -v
```

| Variable | Meaning |
|---|---|
| `AWESOME_AUTH_CONTRACT_BASE_URL` | Origin of the stack under test — scheme and host, no path, no trailing slash. **Unset means skip**: `go test ./...` in a plain checkout stays green and CI needs no deployment. Under `-v` the skip prints a `[contract] SKIPPED:` banner; unset *while* `…_REQUIRE` is set is a failure, not a skip (see below). |
| `AWESOME_AUTH_CONTRACT_API_PREFIX` | Router mount point. Default `/auth`, the same default the reference uses. |
| `AWESOME_AUTH_CONTRACT_REQUIRE` | Capabilities this deployment claims to offer: comma-separated (`register,csrf,secure-cookies,sessions,totp,linked-accounts`) or `all`. A listed capability the probe cannot find is a **failure**, not a skip. |

All three are passed through `scripts/toolchain.sh` into the container.

**Set `AWESOME_AUTH_CONTRACT_REQUIRE` for anything that is supposed to be
complete.** Absence is unfalsifiable from outside: a session store the operator
never wired and a session store that regressed into answering `NOT_IMPLEMENTED`
are the same three bytes on the wire, and the skip that is right for the first
is a silent green run for the second. Only the operator knows which deployment
they pointed the suite at, so the operator says. For the current stack:

```sh
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.eu-west-1.amazonaws.com \
AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp \
  ./scripts/toolchain.sh go test ./test/contract/... -v
```

(`linked-accounts` is left out because it really is switched off there.)

`…_REQUIRE` doubles as the guard on the suite's own plumbing: setting it while
`…_BASE_URL` is empty is a **failure**, because a caller who named the
capabilities to verify meant to run against something, and a CI job whose base
URL arrived empty must not report success for checks that never happened. This
is the only such guard the exit code can carry — `cmd/go` buffers a passing
package's stdout *and* stderr and prints neither, so no banner a green test
binary writes survives a non-verbose `go test`.

Against a named API Gateway stage the base URL includes the stage segment
(`https://<id>.execute-api.<region>.amazonaws.com/<stage>`); the quickstart
template deploys to `$default`, which serves at the domain root.

## Pointing it at the reference Express app

```sh
cd ../awesome-node-auth/demo/express-vanilla
npm install && npm start          # listens on :3000, mounts the router at /auth
```

then run the suite with `AWESOME_AUTH_CONTRACT_BASE_URL=http://localhost:3000`.
That demo passes `onRegister`, so the suite can provision accounts; it runs with
`cookieOptions.secure` off and CSRF disabled, so the cookies come back
unprefixed and the CSRF cases skip themselves. Both are deployment differences,
not contract differences, and the suite reports them as such — see below.

## What it will not do

**It imports nothing.** No `awesome-go-auth`, no `internal/…` from this
repository, nothing beyond the standard library. Every header name, error code,
cookie name and message is written out as a literal at the point it is asserted,
because the failure this suite exists to catch is *a change in that literal* —
importing the constant would make the test agree with the change and stay green.
For the same reason it never reads DynamoDB and never calls AWS: a client cannot,
so neither can the thing that claims to speak for clients.

**It provisions itself.** It cannot seed a store it is not allowed to reach, so
it registers the accounts it needs through `POST <prefix>/register` and throws
them away. Addresses are random under `@contract.invalid` — a reserved TLD
(RFC 2606) — so a stack with a live mailer cannot be made to send real mail by
running this. If registration is not mounted, the whole suite skips with that
reason rather than failing.

**It reads the deployment instead of assuming one.** A probe runs once at the
start and reports what this stack offers:

```
deployment under test: https://… (router mounted at /auth)
  AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp
  csrf             on      auto-init cookie "__Host-csrf-token" observed
  linked-accounts  absent  …/auth/linked-accounts answered 501 NOT_IMPLEMENTED — the store is switched off
  register         on      POST /auth/register answered 201
  secure-cookies   on      csrf cookie Secure=true
  sessions         on      …/auth/sessions answered 200
  totp             on      …/auth/2fa/setup answered 200
```

**`off` is two different things, and the probe keeps them apart.** A capability
is `absent` only when the deployment declares it in one of the two documented
ways — the reference's Express 404 fall-through for an unmounted route, or this
port's 5xx with `code:"NOT_IMPLEMENTED"`. Anything else (a 500, a 403, a 501
without that code) is `BROKEN`, and a broken capability **fails** the cases that
need it instead of skipping them, and fails the probe besides. A fault must
never be able to switch a case off; that is how a contract suite goes green
against a broken deployment.

The same rule guards the suite's own footing: `POST /register` answering
anything but 2xx or 404 aborts the run. It used to skip, which meant a stack
answering 500 to every request produced the same green `ok` as a healthy one.

Cases declare what they need and are skipped, with that reason, when it is
genuinely absent — and every skip is listed on stdout at the end of the run, so
a suite that quietly stopped checking half the contract does not read like one
that checked all of it. Where a route's answer is *legitimately*
configuration-dependent — `/magic-link/send` is 200 with a mailer and 500
`EMAIL_NOT_CONFIGURED` without one, `/linked-accounts` is the
`{linkedAccounts:[…]}` wrapper with a store and a declared `NOT_IMPLEMENTED`
without one — the case accepts either and then **asserts the full shape of
whichever branch it took**, absence branches included: an absence must not carry
the payload it says it hasn't got, must not smuggle a bare array, and must not
contradict what the probe saw on that same route seconds earlier. A branch that
only logs is a corruption's way in. A suite that fails because the operator has
not configured mail is a broken suite; a suite that stops asserting because of
it is a useless one.

The one thing deliberately asserted *without* consulting configuration is the
cookie name-prefix rule, restated so it needs no configuration: a cookie that is
`Secure` with `Path=/` and no `Domain` must be named `__Host-…`, one that is
`Secure` otherwise must be `__Secure-…`, and one that is not `Secure` must be
bare. That is the same rule on every deployment, which is why the identical
assertion holds on a hardened stack and on the demo over plain http.

**The email flows need no mailer, and `…_REQUIRE` has no capability for one.**
`cases_email_test.go` covers what a suite with no mailbox can see: the gates and
shapes decided before a message would leave. They are deployment-dependent in
the sense above — the answers hold whether or not the operator wired mail — but
not forked: the reference's three token routes (`/forgot-password`,
`/send-verification-email`, `/change-email/request`) check nothing about
delivery and answer `200 {"success":true}` with or without a sender (§2, "Mailer
dispatch order"), so there is no mailer branch to accept and nothing a mailer's
absence could switch off. A `500` on those routes is a transport that failed
after the token was stored — a fault, and the suite reports it as one. Only
`/magic-link/send` and `/sms/send` refuse up front, and they keep their coded
`…_NOT_CONFIGURED` branches in `cases_deployment_dependent_test.go`.

| Case | Pins | Needs |
|---|---|---|
| `verify-email/get-always-json` | `GET /verify-email?token=<never issued>` is `400 {"error":"Invalid verification token"}` with no `code`, as JSON for `Accept: application/json` *and* `Accept: text/html`; never a redirect, never markup (the static UI page fetches this route and renders the JSON) | — |
| `change-email/request-requires-auth-and-csrf` | bare request → `403 {"error":"No access token provided"}` (no `code`); cookie session without `X-CSRF-Token` → `403 CSRF_INVALID`; both → `200 {"success":true}`, against a fresh address so the route's deliberate `409` oracle cannot fire | `csrf` |
| `send-verification-email/requires-auth` | bare, body-less request → `403 {"error":"No access token provided"}` (no `code`), the way the Flutter client and the served `auth.js` call it | — |
| `forgot-password/unknown-address-is-a-plain-success` | (extended) the optional `emailLang` body field is accepted: `{"email":…,"emailLang":"it"}` is the same plain `200 {"success":true}` | — |

`me/known-gaps-against-the-reference` changed with awesome-go-auth v0.4.0: the
profile now carries `loginProvider` unconditionally (`"local"` for a password
account, the reference's `?? 'local'`), and the case that used to record its
absence now fails on its absence. `role` stays presence-optional, as it is in
the reference.

## Adding a case

Adding a route to the covered surface is adding a `Case`, never editing the
harness:

```go
// cases_whatever_test.go
func init() {
	register(Case{
		Name:  "area/what-it-pins",
		Doc:   "§n — the clause of docs/spec/wire-contract.md this pins",
		Needs: []Capability{CapSessions},        // optional
		Run: func(t *testing.T, e *Env) {
			c, acct := e.LoginCookie(t)
			c.POST(t, "/route", body{"field": acct.Email}, CSRF()).
				mustError(t, 400, "SOME_CODE", "Some message")
		},
	})
}
```

`Doc` is logged before the case runs, so a failure names the clause that broke
without anyone opening the spec.

The pieces: `harness_test.go` (env, probe, runner), `client_test.go` (client,
request options, response assertions, provisioning), `cookies_test.go` (cookie
parsing and the prefix rule), `totp_test.go` (RFC 6238, so the suite can mint its
own second factor rather than shell out).

Everything lives in `_test.go` files: nothing here compiles into the deployable,
and nothing here can be imported by it.

## Scope

Covered: the contract hard points — cookie vs bearer mode, cookie names and
attributes, CSRF double-submit, unwrapped `/me` (with `loginProvider`),
empty-body refresh, the `{sessions:[…]}` and `{linkedAccounts:[…]}` wrappers,
`SESSION_REVOKED`, the TOTP round trip end to end, the documented error shapes
including the paths that carry no `code`, and the mailbox-free half of the email
flows: the auth and CSRF gates on `/change-email/request` and
`/send-verification-email`, `GET /verify-email` answering JSON and never
redirecting, `/forgot-password` accepting `emailLang`.

Not covered: OAuth provider flows (they need a provider), the admin router, the
tools/SSE router, and the email/SMS token round trips — a token minted by one
route and spent by another — because the suite has no mailbox to read it from.
Nothing stops a case being added for them the day the deployment has what they
need.
