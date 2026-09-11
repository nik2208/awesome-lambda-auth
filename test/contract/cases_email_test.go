package contract

import (
	"strings"
	"testing"
)

// The email flows, as far as a suite with no mailbox can see them: every gate
// and every shape that is decided before a message would leave, and nothing
// that depends on one arriving. The round trips — a token minted by one route
// and spent by another — stay uncovered until a deployment offers a way to
// read its outbox.
//
// None of these needs a mailer, and that is the reference's own design rather
// than a concession by the suite: /forgot-password, /send-verification-email
// and /change-email/request check nothing about delivery, and with no sender
// configured they send nothing and still answer 200 (§2, "Mailer dispatch
// order" — "if neither exists, no email is sent and the route still
// succeeds"). Only /magic-link/send and /sms/send refuse up front, and those
// two are pinned in cases_deployment_dependent_test.go. So the answers here do
// not fork on configuration, and there is no branch that only logs.

// neverMintedToken is a well-formed token nobody issued: 64 hex characters,
// the width the reference mints (§2, "Token generation"). Well-formed on
// purpose — a token that fails a format check before the lookup would not
// prove the lookup answers what the contract says.
const neverMintedToken = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"

// assertJSONNeverHTML pins what GET /verify-email exists to be checked for:
// the answer is JSON whatever the caller asked for, and it is never a redirect.
// The reference performs no content negotiation and no redirect on this route;
// the HTML experience belongs to the optional static UI page, which fetches
// this endpoint client-side and renders the JSON it gets back (§2, "HTML vs
// JSON — exact behavior"). A port that redirected a browser to a pretty page
// would break exactly that page.
func assertJSONNeverHTML(t *testing.T, r *Resp) {
	t.Helper()
	if r.Status >= 300 && r.Status < 400 {
		t.Errorf("answered %d; the reference never redirects here, whatever Accept says\n  %s", r.Status, r.where())
	}
	if loc := r.Header.Get("Location"); loc != "" {
		t.Errorf("carries Location: %q; this route never redirects, the static UI page fetches it and renders the JSON\n  %s", loc, r.where())
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json regardless of Accept\n  %s", ct, r.where())
	}
	if strings.HasPrefix(strings.TrimSpace(string(r.Body)), "<") {
		t.Errorf("body is markup; this route answers JSON only\n  %s", r.where())
	}
}

func init() {
	register(
		Case{
			Name: "verify-email/get-always-json",
			Doc:  "§2 (GET /verify-email) — a token nobody issued is 400 {\"error\":\"Invalid verification token\"} with no `code`, as JSON whatever Accept says: the route performs no content negotiation and no redirect; the HTML page is the static UI's, and it fetches this",
			Run: func(t *testing.T, e *Env) {
				// Twice, because the property is "regardless of Accept": once
				// as a fetch() from the static page would ask, once as a
				// browser following the emailed link with the UI disabled
				// would. A port that negotiated would pass the first and fail
				// the second.
				for _, accept := range []string{"application/json", "text/html"} {
					r := e.NewClient().GET(t, "/verify-email?token="+neverMintedToken, Header("Accept", accept))
					assertJSONNeverHTML(t, r)
					r.mustCodelessError(t, 400, "Invalid verification token")
				}
			},
		},

		Case{
			Name:  "change-email/request-requires-auth-and-csrf",
			Doc:   "§2 (POST /change-email/request) — behind authMiddleware: no credential is 403 {\"error\":\"No access token provided\"} with no `code`; a cookie session without X-CSRF-Token is 403 CSRF_INVALID; both together are 200 {\"success\":true}, mailer or no mailer, because with no sender the reference sends nothing and still succeeds",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				// The address is fresh every time so the route's deliberate
				// oracle — 409 "Email address is already in use" for an
				// authenticated caller naming a taken address — cannot fire
				// and turn a gate check into an availability check.
				fresh := func() body { return body{"newEmail": randomAccount().Email} }

				// No credential at all. The reference extracts the access
				// token before it looks at CSRF (auth.middleware.ts:29-32,
				// then :33-42), so a bare request is told it has no token, not
				// that its double-submit is missing. Sent bare on purpose:
				// giving it a CSRF pair would hide the ordering this pins.
				e.NewClient().POST(t, "/change-email/request", fresh()).
					mustCodelessError(t, 403, "No access token provided")

				// A cookie session and no header: the forgery shape. The
				// session is real, so the auth gate passes and the
				// double-submit is what refuses it.
				c, _ := e.LoginCookie(t)
				c.POST(t, "/change-email/request", fresh()).
					mustError(t, 403, "CSRF_INVALID", "CSRF token validation failed")

				// Both. There is no mailer branch to take here: the reference
				// mints and stores the token, mails it if it can, and answers
				// the same {"success":true} either way (§2, "Mailer dispatch
				// order"). A 500 would be a transport that failed after the
				// token was stored — a fault, not a configuration — and this
				// suite does not let a fault look like an absent mailer.
				c.POST(t, "/change-email/request", fresh(), CSRF()).
					mustSuccessOnly(t)
			},
		},

		Case{
			Name: "send-verification-email/requires-auth",
			Doc:  "§2 (POST /send-verification-email) — behind authMiddleware: without a credential 403 {\"error\":\"No access token provided\"} with no `code` (403, not 401), before any store or sender is consulted",
			Run: func(t *testing.T, e *Env) {
				// No body, the way the Flutter client and the served auth.js
				// call it (§2 cross-checks); the gate answers before the body
				// would be read, so an empty one must not turn this into 400.
				e.NewClient().POST(t, "/send-verification-email", nil).
					mustCodelessError(t, 403, "No access token provided")
			},
		},
	)
}
