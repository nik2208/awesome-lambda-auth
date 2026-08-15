package contract

import (
	"reflect"
	"strings"
	"testing"
)

func init() {
	register(
		Case{
			Name: "me/unwrapped-and-carries-no-credential-material",
			Doc:  "hard point 4, §3.4 — the profile object is the top-level body, with no envelope, and it never carries a token, a hash or a session id",
			Run: func(t *testing.T, e *Env) {
				c, acct := e.LoginCookie(t)
				r := c.GET(t, "/me")
				r.mustStatus(t, 200)
				m := r.obj(t)

				// Unwrapped: the profile fields are the body. An envelope would
				// show up as a single object-valued key.
				for _, envelope := range []string{"user", "profile", "data", "result"} {
					if _, ok := m[envelope]; ok {
						t.Errorf("body is wrapped in a %q key; every shipped client reads the profile unwrapped\n  %s",
							envelope, r.where())
					}
				}
				if got, _ := m["email"].(string); got != acct.Email {
					t.Errorf("want the logged-in address %q at the top level, got %v\n  %s", acct.Email, m["email"], r.where())
				}

				// Credential material, recursively. The reference rebuilds this
				// body from the stored user and hands back claims only.
				for _, path := range scanForSecrets(m, "") {
					t.Errorf("profile carries %s, which must never reach a client\n  %s", path, r.where())
				}
				// The body is rebuilt, never a decoded token, so the JWT
				// bookkeeping claims are absent (§3.4).
				for _, claim := range []string{"sid", "iat", "exp", "jti", "typ"} {
					if _, ok := m[claim]; ok {
						t.Errorf("profile carries the token claim %q; the reference rebuilds the body from the stored user and never signs it\n  %s",
							claim, r.where())
					}
				}
			},
		},

		Case{
			Name: "me/fields-the-clients-require",
			Doc:  "§3.4 — of the documented profile {sub, email, role, loginProvider, isEmailVerified, isTotpEnabled}, the shipped clients cast `sub` and `email` non-nullably; the rest they read optionally",
			Run: func(t *testing.T, e *Env) {
				c, acct := e.LoginCookie(t)
				r := c.GET(t, "/me")
				r.mustStatus(t, 200)
				m := r.obj(t)

				// These two are the hard requirement, and the reason is not
				// tidiness: awesome-node-auth-flutter does `json['sub'] as
				// String` and `json['email'] as String` (auth_user.dart:76-77),
				// non-nullable casts that throw a Dart TypeError on null, and
				// ng-awesome-node-auth declares both as required
				// (auth.service.ts:9-11). Omitting one does not degrade a
				// client, it terminates inside it — which is exactly what a live
				// stack did until awesome-go-auth#46.
				for _, field := range []string{"sub", "email"} {
					v, ok := m[field]
					if !ok {
						t.Errorf("profile has no %q; both shipped clients cast it non-nullably and throw when it is absent, got %v\n  %s",
							field, keysOf(m), r.where())
						continue
					}
					if s, _ := v.(string); s == "" {
						t.Errorf("profile %q is %#v, want a non-empty string\n  %s", field, v, r.where())
					}
				}
				if got, _ := m["email"].(string); got != acct.Email {
					t.Errorf("profile email = %q, want the logged-in address %q\n  %s", got, acct.Email, r.where())
				}
			},
		},

		Case{
			Name: "me/known-gaps-against-the-reference",
			Doc:  "§3.4 — two documented profile fields this port does not send; asserted as they are so the gap cannot widen unnoticed, and so closing one fails here and prompts updating the register",
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				r := c.GET(t, "/me")
				r.mustStatus(t, 200)
				m := r.obj(t)

				// `role` is carried when set (awesome-go-auth models.go,
				// json:"role,omitempty"), and nothing in the port writes one
				// yet, so a fresh account legitimately has none. Assert the
				// shape rather than the presence: a non-string role would be a
				// real defect, an absent one is today's truth.
				if v, ok := m["role"]; ok {
					if _, isString := v.(string); !isString {
						t.Errorf("profile role = %#v, want a string\n  %s", v, r.where())
					}
				}

				// `loginProvider` has no counterpart in the core's User model,
				// so it is never sent. Both clients read it as `String?`, so
				// this costs them nothing — but it is a real gap against the
				// reference and stays visible here until a model field exists.
				if _, ok := m["loginProvider"]; ok {
					t.Errorf("profile now carries loginProvider — the gap this case records is closed, so update it and the deviation register\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "me/cookie-and-bearer-return-the-same-profile",
			Doc:  "§3.4 — bearer mode changes only the credential transport, never the body",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)

				cookieClient := e.NewClient()
				cookieClient.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}).mustStatus(t, 200)
				viaCookie := cookieClient.GET(t, "/me")
				viaCookie.mustStatus(t, 200)

				bearerClient := e.NewClient()
				lr := bearerClient.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				lr.mustStatus(t, 200)
				viaBearer := bearerClient.GET(t, "/me", Bearer(lr.str(t, "accessToken")))
				viaBearer.mustStatus(t, 200)

				if !reflect.DeepEqual(viaCookie.obj(t), viaBearer.obj(t)) {
					t.Errorf("cookie and bearer profiles differ:\n  cookie: %s\n  bearer: %s", viaCookie.snippet(), viaBearer.snippet())
				}
			},
		},

		Case{
			Name: "me/no-token-is-a-code-less-403",
			Doc:  "§1.1, §4.4 — a protected route without a credential is 403 {\"error\":\"No access token provided\"} with no `code` (note: 403, not 401)",
			Run: func(t *testing.T, e *Env) {
				e.NewClient().GET(t, "/me").mustCodelessError(t, 403, "No access token provided")
			},
		},

		Case{
			Name: "me/invalid-token-is-a-code-less-403",
			Doc:  "§1.3, §4.4 — an unusable access token is 403 {\"error\":\"Invalid or expired access token\"} with no `code`",
			Run: func(t *testing.T, e *Env) {
				e.NewClient().GET(t, "/me", Bearer("not.a.valid.token")).
					mustCodelessError(t, 403, "Invalid or expired access token")
			},
		},
	)
}

// scanForSecrets walks a decoded body and reports any field whose name says it
// holds a credential. A name-based scan rather than a fixed list, because the
// failure being guarded against is a store field reaching the wire — and the
// field that does it will be one nobody thought to enumerate.
func scanForSecrets(v any, path string) []string {
	var found []string
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if looksSecret(k) {
				found = append(found, "field "+p)
				continue
			}
			found = append(found, scanForSecrets(sub, p)...)
		}
	case []any:
		for i, sub := range t {
			_ = i
			found = append(found, scanForSecrets(sub, path+"[]")...)
		}
	}
	return found
}

func looksSecret(name string) bool {
	n := strings.ToLower(name)
	for _, needle := range []string{"password", "secret", "hash", "token"} {
		if strings.Contains(n, needle) {
			return true
		}
	}
	return false
}
