package contract

import "testing"

func init() {
	register(
		Case{
			Name: "refresh/cookie-mode/empty-body",
			Doc:  "hard point 3, §3.3 — POST /refresh with no body at all works in cookie mode: the refresh cookie is the credential, and no X-CSRF-Token is required (the route has no auth middleware)",
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)

				// No body, no Content-Type, no CSRF header. This is the exact
				// call every browser client makes on a 401.
				r := c.POST(t, "/refresh", nil)
				r.mustSuccessOnly(t)

				if r.cookie(cookieAccess) == nil {
					t.Errorf("refresh must issue a fresh accessToken cookie (Set-Cookie: %v)\n  %s", r.SetCookie, r.where())
				}
				if r.cookie(cookieRefresh) == nil {
					t.Errorf("refresh must issue a fresh refreshToken cookie (Set-Cookie: %v)\n  %s", r.SetCookie, r.where())
				}

				// The rotated session still opens a protected route.
				c.GET(t, "/me").mustStatus(t, 200)
			},
		},

		Case{
			Name: "refresh/bearer-mode/top-level-tokens-and-zero-cookies",
			Doc:  "hard point 8, §3.3 — a native client posts {refreshToken} with X-Auth-Strategy: bearer and gets both tokens back in the body, with no Set-Cookie",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				login.mustStatus(t, 200)

				r := c.POST(t, "/refresh", body{"refreshToken": login.str(t, "refreshToken")}, BearerStrategy())
				r.mustStatus(t, 200)
				if r.str(t, "accessToken") == "" || r.str(t, "refreshToken") == "" {
					t.Errorf("bearer refresh must return both tokens at the top level\n  %s", r.where())
				}
				r.mustNoCookies(t)
			},
		},

		Case{
			Name: "refresh/no-token-anywhere-is-a-code-less-401",
			Doc:  "§3.3, §4.4 — with no refresh token in body or cookie: 401 {\"error\":\"No refresh token provided\"} and no `code`",
			Run: func(t *testing.T, e *Env) {
				e.NewClient().POST(t, "/refresh", body{}).
					mustCodelessError(t, 401, "No refresh token provided")
			},
		},

		Case{
			Name: "refresh/unusable-token-is-INVALID_REFRESH_TOKEN",
			Doc:  "§3.3, §4.2 — a token that does not verify is 401 {\"error\":\"Invalid or expired refresh token\",\"code\":\"INVALID_REFRESH_TOKEN\"}",
			Run: func(t *testing.T, e *Env) {
				e.NewClient().POST(t, "/refresh", body{"refreshToken": "not.a.valid.token"}).
					mustError(t, 401, "INVALID_REFRESH_TOKEN", "Invalid or expired refresh token")
			},
		},

		Case{
			Name: "refresh/replayed-token-is-refused",
			Doc:  "§3.3 — one stored refresh token per user: after a refresh rotates it, the previous token no longer works (the literal body is [UNTESTED] upstream, so only the refusal is pinned)",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				login.mustStatus(t, 200)
				old := login.str(t, "refreshToken")

				c.POST(t, "/refresh", body{"refreshToken": old}, BearerStrategy()).mustStatus(t, 200)

				replay := c.POST(t, "/refresh", body{"refreshToken": old}, BearerStrategy())
				if replay.Status == 200 {
					t.Errorf("a rotated-out refresh token was accepted a second time; the reference stores exactly one refresh token per user\n  %s",
						replay.where())
				}
				replay.mustStatus(t, 401)
			},
		},
	)
}
