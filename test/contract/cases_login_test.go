package contract

import "testing"

func init() {
	register(
		Case{
			Name: "login/cookie-mode/body-and-cookie-set",
			Doc:  "§2, §3.1 — cookie mode answers 200 {\"success\":true} and sets accessToken, refreshToken and (when enabled) csrf-token, and nothing else",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				c := e.NewClient()
				r := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})

				r.mustSuccessOnly(t)

				want := []string{cookieAccess, cookieRefresh}
				wantCount := 2
				if e.can(CapCSRF) {
					want = append(want, cookieCSRF)
					wantCount = 3
				}
				if len(r.SetCookie) != wantCount {
					t.Errorf("want exactly %d Set-Cookie headers, got %d: %v\n  %s",
						wantCount, len(r.SetCookie), r.SetCookie, r.where())
				}
				got := r.cookieBaseNames()
				if !sameSet(got, want) {
					t.Errorf("want the cookie set %v, got %v\n  %s", want, got, r.where())
				}
			},
		},

		Case{
			Name: "login/cookie-mode/access-token-cookie-attributes",
			Doc:  "§0.4, §2.3 — accessToken is HttpOnly with a positive Max-Age, and its name prefix agrees with its attributes (hard point 9)",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				c := r.mustCookie(t, cookieAccess)

				if !c.HttpOnly {
					t.Errorf("cookie %q must be HttpOnly — it carries the access token\n  %s", c.Name, r.where())
				}
				if c.MaxAge <= 0 {
					t.Errorf("cookie %q must carry a positive Max-Age, got %d\n  %s", c.Name, c.MaxAge, r.where())
				}
				assertPrefixRule(t, r, c)
			},
		},

		Case{
			Name: "login/cookie-mode/refresh-token-cookie-attributes",
			Doc:  "§0.4, §2.3 — refreshToken is HttpOnly, outlives the access cookie, and is path-scoped to <apiPrefix>/refresh unless the __Host- prefix forces Path=/",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				access := r.mustCookie(t, cookieAccess)
				refresh := r.mustCookie(t, cookieRefresh)

				if !refresh.HttpOnly {
					t.Errorf("cookie %q must be HttpOnly\n  %s", refresh.Name, r.where())
				}
				if refresh.MaxAge <= access.MaxAge {
					t.Errorf("the refresh cookie must outlive the access cookie: Max-Age %d vs %d\n  %s",
						refresh.MaxAge, access.MaxAge, r.where())
				}
				assertPrefixRule(t, r, refresh)

				wantPath := e.Prefix + "/refresh"
				if isHostPrefixed(refresh.Name) {
					// §0.2: for a __Host- name the write path forces Path=/, and
					// the refresh scoping is deliberately lost.
					wantPath = "/"
				}
				if refresh.Path != wantPath {
					t.Errorf("cookie %q must carry Path=%q, got %q\n  %s", refresh.Name, wantPath, refresh.Path, r.where())
				}
			},
		},

		Case{
			Name:  "login/cookie-mode/csrf-cookie-is-js-readable",
			Doc:   "hard point 1, §0.4 — the csrf-token cookie is httpOnly:false so client JS can perform the double-submit, and its value is 32 hex chars",
			Needs: []Capability{CapCSRF},
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				c := r.mustCookie(t, cookieCSRF)

				if c.HttpOnly {
					t.Errorf("cookie %q must NOT be HttpOnly: every shipped client reads it from document.cookie to fill X-CSRF-Token\n  %s",
						c.Name, r.where())
				}
				if !hex32.MatchString(c.Value) {
					t.Errorf("cookie %q must be 32 hex characters (16 random bytes), got %q (%d chars)\n  %s",
						c.Name, c.Value, len(c.Value), r.where())
				}
				if c.MaxAge <= 0 {
					t.Errorf("cookie %q must carry a positive Max-Age, got %d\n  %s", c.Name, c.MaxAge, r.where())
				}
				assertPrefixRule(t, r, c)
			},
		},

		Case{
			Name: "login/bearer-mode/top-level-tokens-and-zero-cookies",
			Doc:  "hard point 8, §2 — X-Auth-Strategy: bearer answers 200 {\"success\":true,\"accessToken\",\"refreshToken\"} with no Set-Cookie at all",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/login",
					body{"email": acct.Email, "password": acct.Password}, BearerStrategy())

				r.mustStatus(t, 200)
				if m := r.obj(t); m["success"] != true {
					t.Errorf(`want "success":true, got %v\n  %s`, m["success"], r.where())
				}
				if tok := r.str(t, "accessToken"); tok == "" {
					t.Errorf("accessToken must be a non-empty token\n  %s", r.where())
				}
				if tok := r.str(t, "refreshToken"); tok == "" {
					t.Errorf("refreshToken must be a non-empty token\n  %s", r.where())
				}
				r.mustNoCookies(t)
			},
		},

		Case{
			Name: "login/bearer-mode/strategy-header-value-is-case-sensitive",
			Doc:  "hard point 8 — the value match is exact: anything other than the literal \"bearer\" leaves the request in cookie mode",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/login",
					body{"email": acct.Email, "password": acct.Password}, Header("X-Auth-Strategy", "Bearer"))

				r.mustStatus(t, 200)
				if r.hasKey(t, "accessToken") {
					t.Errorf(`X-Auth-Strategy: "Bearer" switched the response into bearer mode; the reference matches the literal "bearer" exactly, so a client sending the capitalised value must still get cookies`+"\n  %s", r.where())
				}
				if r.cookie(cookieAccess) == nil {
					t.Errorf("no accessToken cookie: the request should have stayed in cookie mode\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "login/invalid-credentials",
			Doc:  "§3.1, §4.2 — a wrong password is 401 {\"error\":\"Invalid credentials\",\"code\":\"INVALID_CREDENTIALS\"}, the same answer an unknown address gets",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				e.NewClient().
					POST(t, "/login", body{"email": acct.Email, "password": acct.Password + "-wrong"}).
					mustError(t, 401, "INVALID_CREDENTIALS", "Invalid credentials")

				unknown := randomAccount()
				e.NewClient().
					POST(t, "/login", body{"email": unknown.Email, "password": unknown.Password}).
					mustError(t, 401, "INVALID_CREDENTIALS", "Invalid credentials")
			},
		},

		Case{
			Name: "logout/clears-every-cookie-variant",
			Doc:  "§0.5, §3.2 — logout answers 200 {\"success\":true} and clears the resolved, __Host-, __Secure- and bare variants of each cookie it manages",
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				r := c.POST(t, "/logout", nil)
				r.mustSuccessOnly(t)

				cleared := map[string]bool{}
				for _, ck := range r.cookies {
					if ck.Value == "" {
						cleared[baseCookieName(ck.Name)] = true
					}
				}
				for _, base := range []string{cookieAccess, cookieRefresh} {
					if !cleared[base] {
						t.Errorf("logout did not clear the %q cookie (Set-Cookie: %v)\n  %s", base, r.SetCookie, r.where())
					}
				}
				if e.can(CapCSRF) && !cleared[cookieCSRF] {
					t.Errorf("logout did not clear the %q cookie (Set-Cookie: %v)\n  %s", cookieCSRF, r.SetCookie, r.where())
				}
			},
		},
	)
}

func isHostPrefixed(name string) bool { return len(name) > 7 && name[:7] == "__Host-" }

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}
