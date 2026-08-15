package contract

import (
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The three cookie base names are contract (hard point 9). Written as literals:
// catching a change in the literal is the whole point.
const (
	cookieAccess  = "accessToken"
	cookieRefresh = "refreshToken"
	cookieCSRF    = "csrf-token"
)

// baseCookieName strips the security prefix a deployment's cookie settings
// select. Read priority elsewhere is __Host- > __Secure- > bare (§0.3); here we
// only need to know which logical cookie a name denotes.
func baseCookieName(n string) string {
	if s, ok := strings.CutPrefix(n, "__Host-"); ok {
		return s
	}
	if s, ok := strings.CutPrefix(n, "__Secure-"); ok {
		return s
	}
	return n
}

// setCookies returns the cookies this response actually sets, dropping the
// clears (Max-Age=0 with an empty value) that logout emits.
func (r *Resp) setCookies() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(r.cookies))
	for _, c := range r.cookies {
		if c.Value == "" || c.MaxAge < 0 {
			continue
		}
		out = append(out, c)
	}
	return out
}

// cookie returns the cookie set for a base name, or nil.
func (r *Resp) cookie(base string) *http.Cookie {
	for _, c := range r.setCookies() {
		if baseCookieName(c.Name) == base {
			return c
		}
	}
	return nil
}

func (r *Resp) mustCookie(t *testing.T, base string) *http.Cookie {
	t.Helper()
	c := r.cookie(base)
	if c == nil {
		t.Fatalf("no %q cookie was set (Set-Cookie: %v)\n  %s", base, r.SetCookie, r.where())
	}
	return c
}

// cookieBaseNames is the sorted set of logical cookies the response sets.
func (r *Resp) cookieBaseNames() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range r.setCookies() {
		b := baseCookieName(c.Name)
		if !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	sort.Strings(out)
	return out
}

func (r *Resp) mustNoCookies(t *testing.T) {
	t.Helper()
	if len(r.SetCookie) != 0 {
		t.Errorf("want zero Set-Cookie headers, got %d: %v\n  %s", len(r.SetCookie), r.SetCookie, r.where())
	}
}

// assertPrefixRule checks the write-side name resolution of hard point 9
// (§0.2 / §2.1) in the only form a black-box client can check it: the prefix a
// cookie carries must agree with the attributes it carries.
//
//	Secure and Path=/ and no Domain  ->  __Host-<name>
//	Secure otherwise                 ->  __Secure-<name>
//	not Secure                       ->  <name>
//
// Stated this way the rule needs no knowledge of the deployment's cookie
// settings, which is what lets the identical assertion run against a hardened
// stack and against the reference app on plain http.
func assertPrefixRule(t *testing.T, r *Resp, c *http.Cookie) {
	t.Helper()
	base := baseCookieName(c.Name)
	var want string
	switch {
	case c.Secure && c.Path == "/" && c.Domain == "":
		want = "__Host-" + base
	case c.Secure:
		want = "__Secure-" + base
	default:
		want = base
	}
	if c.Name != want {
		t.Errorf("cookie %q carries Secure=%v Path=%q Domain=%q, which by the name-resolution rule must be named %q\n  %s",
			c.Name, c.Secure, c.Path, c.Domain, want, r.where())
	}
	if strings.HasPrefix(c.Name, "__Host-") {
		// The write path force-overrides these for a __Host- name (§0.2).
		if !c.Secure || c.Path != "/" || c.Domain != "" {
			t.Errorf("__Host- cookie %q must be Secure with Path=/ and no Domain, got Secure=%v Path=%q Domain=%q\n  %s",
				c.Name, c.Secure, c.Path, c.Domain, r.where())
		}
	}
}

var hex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
