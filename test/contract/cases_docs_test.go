package contract

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The documentation surface, black-box: GET <prefix>/openapi.json and
// GET <prefix>/docs.
//
// The reference registers both at the very end of its auth router, under one
// option and with no guard on either (auth.router.ts:1651-1677); its own pins
// are tests/swagger.test.ts:228-260. Neither route is outside the router-level
// CSRF auto-init, which is a router.use eleven hundred lines earlier (:529-538)
// and which Express runs for everything registered after it — so a bare GET
// answers with a fresh csrf-token cookie where csrf is enabled, and rejects
// nothing, because the double-submit check passes every non-mutating method
// through.
//
// Every case here fetches with no credential of any kind. That is not
// convenience: it is the assertion. Both routes are public by construction, and
// a suite that reached them with a session would report a deployment that had
// quietly put them behind one as perfectly healthy.
//
// What is deliberately *not* here is the product's own Content-Security-Policy
// on these two responses. It is a registered deviation
// (docs-page-carries-a-content-security-policy) and therefore not part of the
// contract this suite holds the deployment to — the identical assertions run
// against the reference Express app, which sets no such header. It is pinned in
// cmd/auth/docs_test.go, where the middleware that sends it lives.

// swaggerSpecURL extracts the url the page hands SwaggerUIBundle. Written as a
// literal pattern over the rendered HTML because that is what a browser sees:
// the page is a string the server produced, and the failure worth catching is a
// page pointing at a document this deployment does not serve.
var swaggerSpecURL = regexp.MustCompile(`url:\s*"([^"]+)"`)

func init() {
	register(
		Case{
			Name:  "docs/openapi-document-is-served-anonymously",
			Doc:   "reference auth.router.ts:1656-1671, pinned at tests/swagger.test.ts:229-236 — GET <prefix>/openapi.json is 200 application/json with an OpenAPI 3.0.3 document, served with no credential of any kind, whose path items all sit under one base and include the login route",
			Needs: []Capability{CapDocs},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/openapi.json")
				r.mustStatus(t, 200)

				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json\n  %s", ct, r.where())
				}

				var document struct {
					OpenAPI string                     `json:"openapi"`
					Paths   map[string]json.RawMessage `json:"paths"`
				}
				if err := json.Unmarshal(r.Body, &document); err != nil {
					t.Fatalf("the served document is not JSON (%v)\n  %s", err, r.where())
				}
				if document.OpenAPI != "3.0.3" {
					t.Errorf("openapi = %q, want %q\n  %s", document.OpenAPI, "3.0.3", r.where())
				}
				if len(document.Paths) == 0 {
					t.Fatalf("the document describes no paths, so it documents nothing\n  %s", r.where())
				}

				// The base the document writes its paths under. It is the
				// reference's swaggerBasePath and defaults to the mount prefix,
				// but a deployment behind a proxy may legitimately move it — so
				// it is read off the document rather than assumed to be
				// e.Prefix, and then every other path item is held to it. A
				// document mixing two bases describes a server that does not
				// exist.
				base := ""
				for path := range document.Paths {
					if strings.HasSuffix(path, "/login") {
						base = strings.TrimSuffix(path, "/login")
					}
				}
				if base == "" {
					t.Fatalf("no path item ends in /login, so the document does not describe the auth router: %v\n  %s",
						sortedPaths(document.Paths), r.where())
				}
				if !strings.HasPrefix(base, "/") {
					t.Errorf("the documented base %q is not an absolute path\n  %s", base, r.where())
				}
				for _, path := range sortedPaths(document.Paths) {
					if !strings.HasPrefix(path, base+"/") {
						t.Errorf("path item %q is not under the documented base %q\n  %s", path, base, r.where())
					}
				}

				// The route is behind the CSRF auto-init and behind nothing
				// else, so the only cookie it may ever set is that one. An
				// access or refresh cookie here would mean a public, cacheable
				// document handing out a session.
				for _, name := range r.cookieBaseNames() {
					if name != cookieCSRF {
						t.Errorf("the document response sets a %q cookie; the only cookie this route may set is the csrf auto-init one\n  %s",
							name, r.where())
					}
				}
			},
		},

		Case{
			Name:  "docs/swagger-page-points-at-the-document-beside-it",
			Doc:   "reference auth.router.ts:1674-1677, pinned at tests/swagger.test.ts:237-243 — GET <prefix>/docs is 200 text/html; charset=utf-8 carrying the Swagger UI page, served with no credential, and the spec url it hands SwaggerUIBundle is a document this same deployment serves",
			Needs: []Capability{CapDocs},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/docs")
				// Not a skip and not a tolerated 404: one option mounts both
				// routes, and the probe has already seen the document answer.
				r.mustStatus(t, 200)

				if ct := r.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
					t.Errorf("Content-Type = %q, want %q\n  %s", ct, "text/html; charset=utf-8", r.where())
				}
				page := string(r.Body)
				if !strings.Contains(page, "swagger-ui") {
					t.Fatalf("the page does not look like a Swagger UI shell\n  %s", r.where())
				}

				// The half of this route that can be wrong while the status code
				// is right: a page whose spec url points at a path this
				// deployment does not serve renders an empty, broken UI and
				// nothing about the response says so.
				match := swaggerSpecURL.FindStringSubmatch(page)
				if match == nil {
					t.Fatalf("the page names no spec url, so it has nothing to render\n  %s", r.where())
				}
				spec := e.NewClient().GET(t, "!"+specPathOf(t, e, match[1]))
				spec.mustStatus(t, 200)
				if !spec.hasKey(t, "openapi") {
					t.Errorf("the url the page fetches does not serve an OpenAPI document\n  %s", spec.where())
				}
			},
		},

		Case{
			Name:  "docs/documentation-routes-carry-no-guard",
			Doc:   "reference auth.router.ts:1656-1677 — neither documentation route has a guard of its own: no auth middleware, no session, and the router-level CSRF middleware they do sit behind rejects nothing on a GET (csrfEnforced passes every non-mutating method through). So both answer identically to a bare caller, to one presenting a token that is not a token, and to one presenting a CSRF header that matches no cookie",
			Needs: []Capability{CapDocs},
			Run: func(t *testing.T, e *Env) {
				for _, path := range []string{"/openapi.json", "/docs"} {
					bare := e.NewClient().GET(t, path)
					bare.mustStatus(t, 200)

					// A credential that is not one. A route with an auth gate
					// answers 403 {"error":"Invalid or expired access token"}
					// here; a route without one never looks.
					forged := e.NewClient().GET(t, path,
						Bearer("not.a.token.at.all"), BearerStrategy(), RawCSRF("00000000000000000000000000000000"))
					if forged.Status != 200 {
						t.Errorf(`%s answered %d to a caller presenting a bogus bearer token and a bogus CSRF header, and 200 to a bare one.

Both documentation routes are public by construction, and the CSRF middleware
in front of them rejects nothing on a GET. A refusal here means this deployment
put a guard on a route the reference leaves open, which is a surface difference
its clients and its readers cannot see any other way.
  %s`, path, forged.Status, forged.where())
					}
				}
			},
		},
	)
}

// sortedPaths gives a stable order for a failure message about a document.
func sortedPaths(paths map[string]json.RawMessage) []string {
	out := make([]string, 0, len(paths))
	for p := range paths {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// specPathOf reduces the url the page names to a path this suite's own client
// can ask the deployment under test for.
//
// Three shapes are legal and all three appear in the family: an absolute URL
// (take its path), an absolute path (take it as is), and the reference's own
// default of "./openapi.json" when no base was configured (openapi.ts:1646),
// which resolves against the page's own directory — the mount prefix.
func specPathOf(t *testing.T, e *Env, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("the page's spec url %q is not a URL: %v", raw, err)
	}
	if u.Path == "" {
		t.Fatalf("the page's spec url %q names no path", raw)
	}
	if strings.HasPrefix(u.Path, "/") {
		return u.Path
	}
	return e.Prefix + "/" + strings.TrimPrefix(u.Path, "./")
}
