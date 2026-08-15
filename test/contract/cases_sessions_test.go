package contract

import "testing"

func init() {
	register(
		Case{
			Name:  "sessions/list-is-wrapped",
			Doc:   "hard point 5, §3.9 — GET /sessions answers {\"sessions\":[…]}, wrapped in a sessions key, never a bare array",
			Needs: []Capability{CapSessions},
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				r := c.GET(t, "/sessions")
				r.mustStatus(t, 200)

				m := r.obj(t)
				raw, ok := m["sessions"]
				if !ok {
					t.Fatalf("body has no \"sessions\" key (a bare array would break every shipped client), got %v\n  %s",
						keysOf(m), r.where())
				}
				list, ok := raw.([]any)
				if !ok {
					t.Fatalf("\"sessions\" is %T, want an array\n  %s", raw, r.where())
				}
				if len(list) == 0 {
					t.Fatalf("the caller's own session is missing from its session list\n  %s", r.where())
				}
				first, ok := list[0].(map[string]any)
				if !ok {
					t.Fatalf("session entries must be objects, got %T\n  %s", list[0], r.where())
				}
				for _, field := range []string{"sessionHandle", "userId", "createdAt", "expiresAt"} {
					if _, ok := first[field]; !ok {
						t.Errorf("session entry has no %q field, got %v\n  %s", field, keysOf(first), r.where())
					}
				}
				for _, path := range scanForSecrets(m, "") {
					t.Errorf("session listing carries %s\n  %s", path, r.where())
				}
			},
		},

		Case{
			Name:  "sessions/revoked-session-refresh-is-SESSION_REVOKED",
			Doc:   "hard point 2, §1.4, §3.3 — once a session is revoked, POST /refresh answers 401 {\"error\":\"Session has been revoked\",\"code\":\"SESSION_REVOKED\"}: the fast-logout signal every client keys on",
			Needs: []Capability{CapSessions},
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)

				// Revoke every session this freshly provisioned account owns, so
				// the assertion does not depend on the listing's order.
				handles := sessionHandles(t, c)
				for _, h := range handles {
					c.DELETE(t, "/sessions/"+h, CSRF()).mustSuccessOnly(t)
				}

				r := c.POST(t, "/refresh", nil)
				if r.Status == 200 {
					t.Fatalf("refresh succeeded after every session of this user was revoked; a deployment that sets session.checkOn=none disables this signal, and clients relying on it to log out immediately will keep refreshing a dead session\n  %s",
						r.where())
				}
				r.mustError(t, 401, "SESSION_REVOKED", "Session has been revoked")
			},
		},

		Case{
			Name:  "sessions/unknown-or-foreign-handle-is-a-code-less-404",
			Doc:   "§3.10 — a handle that does not exist and a handle owned by someone else answer identically: 404 {\"error\":\"Session not found\"}, no `code`, no information leak",
			Needs: []Capability{CapSessions},
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				c.DELETE(t, "/sessions/ses_0000000000000000000000000000000000", CSRF()).
					mustCodelessError(t, 404, "Session not found")

				other, _ := e.LoginCookie(t)
				foreign := sessionHandles(t, other)[0]
				c.DELETE(t, "/sessions/"+foreign, CSRF()).
					mustCodelessError(t, 404, "Session not found")
			},
		},
	)
}

// sessionHandles lists the handles the client's own account owns.
func sessionHandles(t *testing.T, c *Client) []string {
	t.Helper()
	r := c.GET(t, "/sessions")
	r.mustStatus(t, 200)
	list, ok := r.obj(t)["sessions"].([]any)
	if !ok || len(list) == 0 {
		t.Fatalf("cannot read the caller's own session handles\n  %s", r.where())
	}
	out := make([]string, 0, len(list))
	for _, raw := range list {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("session entry is %T, want an object\n  %s", raw, r.where())
		}
		handle, ok := entry["sessionHandle"].(string)
		if !ok || handle == "" {
			t.Fatalf("session entry has no usable sessionHandle: %v\n  %s", entry, r.where())
		}
		out = append(out, handle)
	}
	return out
}
