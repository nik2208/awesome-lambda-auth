package contract

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

// jsonObject decodes a body that may or may not be JSON, returning nil when it
// is not. Resp.obj fails the test instead, which is the right default
// everywhere the contract fixes the content type; here two documented answers
// meet and one of them is Express's HTML fall-through.
func jsonObject(r *Resp) map[string]any {
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		return nil
	}
	return m
}

// The OAuth entry points (wire-contract.md §4). Both routes are deployment
// dependent in the same way the credential-delivery routes are: whether a
// provider is configured is the operator's business, and the suite asserts the
// full shape of whichever documented answer it gets — never "302 or 404, fine
// either way".
//
// What is NOT asserted here is as deliberate as what is. The signed `state` and
// the PKCE challenge are this port's fixes for reference-issues N1 and for the
// reference's missing PKCE; the reference sends an unsigned state and no
// challenge at all, and this suite runs against both. So the contract is "a
// state is present", and cmd/auth/oauth_test.go is where the signature and the
// challenge are pinned.

// oauthAbsent is the reference's stub for a provider the host app never passed a
// strategy for (auth.router.ts:1361). It is a JSON body, not an unmounted
// route's fall-through, so there is a shape to pin.
func assertGoogleNotConfigured(t *testing.T, r *Resp) {
	t.Helper()
	r.mustCodelessError(t, 404, "Google OAuth not configured")
}

func init() {
	register(
		Case{
			Name: "oauth/google/redirects-to-the-provider-or-declares-itself-unconfigured",
			Doc:  "§4 (oauth/{provider}) — with a Google provider: 302 to accounts.google.com carrying client_id, redirect_uri, response_type=code, scope and state. Without one: 404 {\"error\":\"Google OAuth not configured\"}",
			Run: func(t *testing.T, e *Env) {
				// No credential: the route has no auth gate and reads no token
				// (§4, "Auth gate: none"), and a deployment that started reading
				// one would be linking a provider identity to whoever happened
				// to be signed in.
				r := e.NewClient().GET(t, "/oauth/google")

				switch r.Status {
				case 302:
					loc := r.Header.Get("Location")
					if loc == "" {
						t.Fatalf("302 with no Location\n  %s", r.where())
					}
					u, err := url.Parse(loc)
					if err != nil {
						t.Fatalf("Location %q does not parse: %v\n  %s", loc, err, r.where())
					}
					// Google's endpoint is hard-coded in the reference's strategy
					// (google.strategy.ts:25) and is a preset here, so a
					// deployment that sends the browser anywhere else is sending
					// credentials to somebody else's authorization server.
					if got := u.Scheme + "://" + u.Host + u.Path; got != "https://accounts.google.com/o/oauth2/v2/auth" {
						t.Errorf("the browser is sent to %q, want Google's fixed authorization endpoint\n  %s", got, r.where())
					}
					q := u.Query()
					if q.Get("response_type") != "code" {
						t.Errorf("response_type = %q, want \"code\"\n  %s", q.Get("response_type"), r.where())
					}
					if q.Get("client_id") == "" {
						t.Errorf("the authorization request carries no client_id\n  %s", r.where())
					}
					if q.Get("state") == "" {
						t.Errorf("the authorization request carries no state, so the callback has nothing to verify\n  %s", r.where())
					}
					if !strings.Contains(q.Get("scope"), "email") {
						t.Errorf("scope = %q, want it to include email — the callback resolves the identity by address\n  %s",
							q.Get("scope"), r.where())
					}
					redirect := q.Get("redirect_uri")
					if redirect == "" {
						t.Errorf("the authorization request carries no redirect_uri\n  %s", r.where())
					} else if !strings.HasSuffix(redirect, e.Prefix+"/oauth/google/callback") {
						// The callback URL is configuration — typed into the
						// document, or derived by the SAM template from
						// PublicUrl + ApiPrefix — so this is the one place a
						// mismatch shows up on the wire: the provider would send
						// the browser somewhere this deployment does not serve.
						t.Errorf("redirect_uri = %q, want it to end at %s/oauth/google/callback\n  %s",
							redirect, e.Prefix, r.where())
					}
					// A front-channel URL the browser, its history and every
					// proxy on the way can read.
					for _, leaked := range []string{"client_secret", "code_verifier"} {
						if q.Get(leaked) != "" {
							t.Errorf("the authorization request carries %q, which is a credential in a URL\n  %s", leaked, r.where())
						}
					}
					if len(r.SetCookie) > 0 {
						for _, c := range r.SetCookie {
							if strings.HasPrefix(c, "access_token=") || strings.HasPrefix(c, "refresh_token=") {
								t.Errorf("starting the flow issued a session cookie: %q\n  %s", c, r.where())
							}
						}
					}
					t.Logf("a Google provider is configured in this deployment\n  %s", r.where())

				case 404:
					assertGoogleNotConfigured(t, r)
					if e.can(CapOAuthGoogle) {
						t.Errorf(`the probe found %q on this deployment and this case then found it unconfigured, on the same route within the same run.
  probe: %s
  now:   %s`, CapOAuthGoogle, e.Caps[CapOAuthGoogle].why, r.where())
					}
					t.Logf("no Google provider is configured in this deployment\n  %s", r.where())

				default:
					t.Fatalf("want a 302 to the provider or the 404 stub\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "oauth/unknown-provider-404",
			Doc:  "§4 — a provider name the deployment does not know is a 404, never a redirect: the entry point must not be a relay to an arbitrary authorization server",
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/oauth/not-a-configured-provider")

				if r.Status != 404 {
					t.Fatalf("want 404 for an unknown provider, got %d\n  %s", r.Status, r.where())
				}
				if loc := r.Header.Get("Location"); loc != "" {
					t.Errorf("an unknown provider answered with a redirect to %q\n  %s", loc, r.where())
				}
				// Two documented 404s meet here: this port answers the same
				// per-provider JSON stub the reference uses for a strategy it
				// has no configuration for, and the reference itself never
				// mounts a route for an unknown name, so Express's HTML
				// fall-through is what comes back. A JSON body is therefore
				// pinned to the stub's shape — a message and no code (§4.4) —
				// and an HTML one only has to be a 404.
				if m := jsonObject(r); m != nil {
					if _, coded := m["code"]; coded {
						t.Errorf("the stub carries a `code`; the reference's 404 has none\n  %s", r.where())
					}
					msg, _ := m["error"].(string)
					if msg == "" {
						t.Errorf("a JSON 404 with no \"error\" message\n  %s", r.where())
					} else if !strings.Contains(msg, "not configured") {
						t.Errorf("error = %q, want the \"<provider> OAuth not configured\" stub\n  %s", msg, r.where())
					}
					mustErrorKeys(t, r, m, "error")
				}
			},
		},

		Case{
			Name: "oauth/callback/failure-is-json-not-a-redirect",
			Doc:  "§4 (oauth/{provider}/callback), reference-issues N29 — every callback failure except the account conflict answers with a JSON error body rather than a redirect, which strands a browser mid-flow. Reproduced, because three shipped clients are built against it",
			Run: func(t *testing.T, e *Env) {
				// A callback with no code and no state: whatever the deployment
				// makes of that, it is a failure, and the property under test is
				// what a failure looks like.
				r := e.NewClient().GET(t, "/oauth/google/callback")

				if r.Status == 404 && !e.can(CapOAuthGoogle) {
					assertGoogleNotConfigured(t, r)
					t.Logf("no Google provider is configured in this deployment\n  %s", r.where())
					return
				}
				if r.Status < 400 {
					t.Fatalf("a callback with no code and no state answered %d; it cannot have completed a flow\n  %s", r.Status, r.where())
				}
				if loc := r.Header.Get("Location"); loc != "" {
					t.Errorf(`the failed callback redirected to %q.

N29 is that the reference answers these with JSON (auth.router.ts:1357) — the
account conflict is the one redirect, and this is not it. A client that learned
to follow a redirect here would break against the reference.
  %s`, loc, r.where())
				}
				m := jsonObject(r)
				if m == nil {
					t.Fatalf("the failed callback answered a non-JSON body, which no client can read\n  %s", r.where())
				}
				if msg, _ := m["error"].(string); msg == "" {
					t.Errorf("the error body carries no \"error\" message\n  %s", r.where())
				}
				for _, c := range r.SetCookie {
					if strings.HasPrefix(c, "access_token=") || strings.HasPrefix(c, "refresh_token=") {
						t.Errorf("a failed callback issued a session cookie: %q\n  %s", c, r.where())
					}
				}
			},
		},
	)
}
