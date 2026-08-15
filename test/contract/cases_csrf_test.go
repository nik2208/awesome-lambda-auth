package contract

import "testing"

// The unsafe, authenticated request these cases drive is POST /change-password
// with the account's real password: it is mounted unconditionally (§2), it goes
// through authMiddleware, and it is state-changing, which is exactly the
// combination the double-submit guards. Its success body is {"success":true},
// so "refused" and "succeeded" are both unambiguous.
func changePassword(t *testing.T, c *Client, from, to string, opts ...reqOpt) *Resp {
	t.Helper()
	return c.POST(t, "/change-password", body{"currentPassword": from, "newPassword": to}, opts...)
}

func init() {
	register(
		Case{
			Name:  "csrf/unsafe-cookie-request-without-the-header-is-refused",
			Doc:   "hard point 1, §1.2 — a cookie-authenticated non-GET without X-CSRF-Token is 403 {\"error\":\"CSRF token validation failed\",\"code\":\"CSRF_INVALID\"}",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				c, acct := e.LoginCookie(t)
				changePassword(t, c, acct.Password, acct.Password+"-next").
					mustError(t, 403, "CSRF_INVALID", "CSRF token validation failed")
			},
		},

		Case{
			Name:  "csrf/unsafe-cookie-request-with-a-mismatched-header-is-refused",
			Doc:   "hard point 1, §1.2 — the header must equal the cookie; a well-formed but wrong value is refused the same way a missing one is",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				c, acct := e.LoginCookie(t)
				changePassword(t, c, acct.Password, acct.Password+"-next",
					RawCSRF("00000000000000000000000000000000")).
					mustError(t, 403, "CSRF_INVALID", "CSRF token validation failed")
			},
		},

		Case{
			Name:  "csrf/unsafe-cookie-request-with-the-matching-header-succeeds",
			Doc:   "hard point 1, §1.2 — double-submit: the JS-readable cookie echoed in X-CSRF-Token lets the request through",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				c, acct := e.LoginCookie(t)
				changePassword(t, c, acct.Password, acct.Password+"-next", CSRF()).
					mustSuccessOnly(t)
			},
		},

		Case{
			Name:  "csrf/safe-cookie-request-needs-no-header",
			Doc:   "§1.2 — GET/HEAD/OPTIONS are exempt: a cookie-authenticated GET with no X-CSRF-Token must not be refused",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				c.GET(t, "/me").mustStatus(t, 200)
			},
		},

		Case{
			Name:  "csrf/bearer-authenticated-request-is-exempt",
			Doc:   "hard point 1, §1.2 — a request authenticated by Authorization: Bearer skips the CSRF check entirely; native clients hold no cookie jar and could never satisfy it",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				login.mustStatus(t, 200)

				changePassword(t, c, acct.Password, acct.Password+"-next",
					Bearer(login.str(t, "accessToken"))).
					mustSuccessOnly(t)
			},
		},

		Case{
			Name:  "csrf/cookie-is-auto-initialised-and-there-is-no-csrf-endpoint",
			Doc:   "hard point 1, §0.6 — the cookie is distributed solely by the router's auto-init middleware; there is no GET /csrf anywhere in the reference, and clients do not call one",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				// Any request through the router, authenticated or not, hands a
				// fresh cookie to a client that has none.
				anon := e.NewClient()
				r := anon.GET(t, "/me")
				if c := r.cookie(cookieCSRF); c == nil {
					t.Errorf("an unauthenticated request through the router did not auto-initialise a csrf-token cookie (Set-Cookie: %v)\n  %s",
						r.SetCookie, r.where())
				}

				for _, path := range []string{"/csrf", "/csrf-token"} {
					got := e.NewClient().GET(t, path)
					if got.Status != 404 {
						t.Errorf("GET %s%s answered %d; the reference has no CSRF endpoint at all and no shipped client calls one\n  %s",
							e.Prefix, path, got.Status, got.where())
					}
				}
			},
		},
	)
}
