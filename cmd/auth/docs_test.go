package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// TestDocsSwaggerResolvesAgainstTheDeploymentEnvironment pins the one place the
// reference's three-valued option becomes the core's bool.
//
// The table is built on config.Defaults() rather than through config.Load on
// purpose: this is a pure function of two knobs, and asserting it here means the
// resolution is pinned independently of which of the two knobs a document is
// allowed to carry on any given day.
//
// The row that matters most is the last one. `auto` is the schema default and
// `production` is the default environment, so a document that says nothing about
// either serves neither documentation route — where the reference, reading an
// unset NODE_ENV, serves both. That is the production-by-default deviation, and
// it is the whole of the difference from auth.router.ts:1652-1654.
func TestDocsSwaggerResolvesAgainstTheDeploymentEnvironment(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		swagger     string
		environment string
		want        bool
	}{
		{config.SwaggerTrue, config.EnvironmentDevelopment, true},
		{config.SwaggerTrue, config.EnvironmentProduction, true},
		{config.SwaggerFalse, config.EnvironmentDevelopment, false},
		{config.SwaggerFalse, config.EnvironmentProduction, false},
		{config.SwaggerAuto, config.EnvironmentDevelopment, true},
		{config.SwaggerAuto, config.EnvironmentProduction, false},
	} {
		t.Run(tc.swagger+"/"+tc.environment, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Docs.Swagger = tc.swagger
			cfg.Deployment.Environment = tc.environment

			if got := docsEnabled(cfg); got != tc.want {
				t.Errorf("docsEnabled(swagger=%q, environment=%q) = %v, want %v",
					tc.swagger, tc.environment, got, tc.want)
			}
			if got := httpConfig(cfg).Docs.Enabled; got != tc.want {
				t.Errorf("httpConfig().Docs.Enabled = %v, want %v — the resolution has to reach the adapter, not just the helper", got, tc.want)
			}
		})
	}

	t.Run("the defaults of an unconfigured deployment mount neither route", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		if cfg.Docs.Swagger != config.SwaggerAuto {
			t.Fatalf("test setup: docs.swagger defaults to %q, not auto", cfg.Docs.Swagger)
		}
		if !cfg.IsProduction() {
			t.Fatalf("test setup: deployment.environment no longer defaults to production")
		}
		if docsEnabled(cfg) {
			t.Errorf("the schema defaults serve the documentation routes; production-by-default says they must not")
		}
	})
}

// TestDocsBasePathReachesTheCoreUnchanged: docs.basePath and
// DocsOptions.BasePath are the reference's one swaggerBasePath, so the wiring is
// a pass-through and the defaults have to agree.
//
// Both halves are asserted because only together do they say the knob is
// honestly mapped: an unset base path must arrive as the api prefix (which
// internal/config derives, so the core's own empty-means-the-mount fallback is
// never reached), and a set one must arrive verbatim.
func TestDocsBasePathReachesTheCoreUnchanged(t *testing.T) {
	t.Parallel()

	t.Run("unset, it is the resolved api prefix", func(t *testing.T) {
		t.Parallel()
		cfg, err := config.Load(context.Background(), config.Options{
			Getenv: envFunc(with(baseEnv(), "AWESOME_AUTH_HTTP_API_PREFIX", "/identity")),
		})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		hc := httpConfig(cfg)
		if hc.Docs.BasePath != "/identity" {
			t.Errorf("Docs.BasePath = %q, want the resolved api prefix", hc.Docs.BasePath)
		}
		if hc.DocsBasePath() != hc.Prefix() {
			t.Errorf("the described base %q and the mount %q disagree on a deployment that configured only the prefix",
				hc.DocsBasePath(), hc.Prefix())
		}
	})

	t.Run("set, it moves the description and not the mount", func(t *testing.T) {
		t.Parallel()
		cfg := config.Defaults()
		cfg.Deployment.Environment = config.EnvironmentDevelopment
		cfg.Docs.BasePath = "/public/api/auth"

		hc := httpConfig(cfg)
		if hc.Docs.BasePath != "/public/api/auth" {
			t.Errorf("Docs.BasePath = %q, want the configured value passed through", hc.Docs.BasePath)
		}
		if hc.DocsBasePath() != "/public/api/auth" {
			t.Errorf("DocsBasePath() = %q, want the configured value", hc.DocsBasePath())
		}
		// The knob describes; it never mounts. If this ever stops holding, the
		// two routes move and every client that followed the api prefix breaks.
		if hc.Prefix() != config.Defaults().HTTP.APIPrefix {
			t.Errorf("docs.basePath moved the mount to %q; it may only move the description", hc.Prefix())
		}
	})
}

// TestDocumentationRoutesComeFromTheAdapter drives the whole cold start: with
// the environment declared development and nothing said about docs, `auto`
// resolves on and the adapter mounts both routes.
//
// It asserts the routes through the real event path, so what is checked is the
// deployed surface and not a helper's opinion of it. Both are fetched with no
// credential of any kind — that is how the reference registers them
// (auth.router.ts:1656-1677, no guard on either) and a deployment that had put
// them behind a session would answer 403 here.
func TestDocumentationRoutesComeFromTheAdapter(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	spec := invoke(t, app, http.MethodGet, "/auth/openapi.json", nil, nil, "")
	if spec.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/openapi.json answered %d; the adapter mounts it when docs are on", spec.StatusCode)
	}
	if ct := spec.Headers["Content-Type"]; !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var document struct {
		OpenAPI string                    `json:"openapi"`
		Paths   map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal([]byte(spec.Body), &document); err != nil {
		t.Fatalf("the served document is not JSON: %v", err)
	}
	if document.OpenAPI != "3.0.3" {
		t.Errorf("openapi = %q, want 3.0.3 (tests/swagger.test.ts:229-236)", document.OpenAPI)
	}
	for _, path := range []string{"/auth/login", "/auth/openapi.json", "/auth/docs"} {
		if _, ok := document.Paths[path]; !ok {
			t.Errorf("the document does not describe %q; it has %d path items", path, len(document.Paths))
		}
	}

	page := invoke(t, app, http.MethodGet, "/auth/docs", nil, nil, "")
	if page.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/docs answered %d; it shares one switch with the document next door", page.StatusCode)
	}
	if ct := page.Headers["Content-Type"]; ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	// The page has to point at the document this deployment really serves. A
	// page whose url is right in the reference and wrong here is the failure
	// docs.basePath exists to prevent, and it is invisible from a status code.
	if want := `url: "/auth/openapi.json"`; !strings.Contains(page.Body, want) {
		t.Errorf("the Swagger page does not name the document next door (%s)", want)
	}
}

// TestDocumentationRoutesAreOffInProduction is the other half of `auto`, driven
// the same way. A production deployment that says nothing about docs must answer
// 404 on both, and must not decorate a 404 with a policy that claims a surface
// it does not have.
//
// The driver is switched because RS-12 refuses the memory one in production; the
// store factory is still the in-memory bundle, so no AWS call is made.
func TestDocumentationRoutesAreOffInProduction(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, with(baseEnv(),
		"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT", "production",
		"AWESOME_AUTH_STORES_DRIVER", "dynamodb",
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", "awesome-auth-docs-test"))

	for _, path := range []string{"/auth/openapi.json", "/auth/docs"} {
		resp := invoke(t, app, http.MethodGet, path, nil, nil, "")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s answered %d in production under docs.swagger: auto, want 404", path, resp.StatusCode)
		}
		if policy := resp.Headers["Content-Security-Policy"]; policy != "" {
			t.Errorf("GET %s carries a Content-Security-Policy on a 404: %q", path, policy)
		}
	}
}

// TestDocumentationResponsesCarryTheSecurityHeaders pins the product deviation
// docs-page-carries-a-content-security-policy on the wire.
//
// The two policies differ, and the difference is the point: the document
// executes nothing and gets default-src 'none', while the page has to be allowed
// to load the one CDN bundle its own HTML names. What both must deny is the
// quiet exfiltration channel — connect-src anywhere but this origin, a form
// action, a nested frame — and being framed.
func TestDocumentationResponsesCarryTheSecurityHeaders(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, baseEnv())

	t.Run("the document", func(t *testing.T) {
		resp := invoke(t, app, http.MethodGet, "/auth/openapi.json", nil, nil, "")
		policy := resp.Headers["Content-Security-Policy"]
		if policy != docsSpecCSP {
			t.Fatalf("Content-Security-Policy = %q, want %q", policy, docsSpecCSP)
		}
		assertDocsCompanionHeaders(t, resp.Headers)
	})

	t.Run("the page", func(t *testing.T) {
		resp := invoke(t, app, http.MethodGet, "/auth/docs", nil, nil, "")
		policy := resp.Headers["Content-Security-Policy"]
		if policy != docsPageCSP {
			t.Fatalf("Content-Security-Policy = %q, want %q", policy, docsPageCSP)
		}
		for _, directive := range []string{
			"default-src 'none'",
			"connect-src 'self'",
			"form-action 'none'",
			"frame-src 'none'",
			"frame-ancestors 'none'",
			"base-uri 'none'",
		} {
			if !strings.Contains(policy, directive) {
				t.Errorf("the page policy dropped %q, which is one of the channels it exists to close", directive)
			}
		}
		assertDocsCompanionHeaders(t, resp.Headers)
	})

	t.Run("no other route is decorated", func(t *testing.T) {
		// The middleware acts on two paths. A policy leaking onto the API would
		// be a behaviour change to every route in the family contract, which is
		// exactly what a mux-wide middleware makes easy to do by accident.
		for _, path := range []string{"/auth/me", "/healthz"} {
			resp := invoke(t, app, http.MethodGet, path, nil, nil, "")
			if policy := resp.Headers["Content-Security-Policy"]; policy != "" {
				t.Errorf("GET %s carries a Content-Security-Policy (%q); the docs middleware must touch two paths and no others", path, policy)
			}
		}
	})
}

func assertDocsCompanionHeaders(t *testing.T, headers map[string]string) {
	t.Helper()
	for name, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := headers[name]; got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

// TestDocsSecurityHeadersFollowTheConfiguredPrefix: the middleware matches on
// the resolved mount, so moving http.apiPrefix moves the policy with the routes
// instead of leaving it decorating two paths nobody serves.
func TestDocsSecurityHeadersFollowTheConfiguredPrefix(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_HTTP_API_PREFIX", "/identity"))

	moved := invoke(t, app, http.MethodGet, "/identity/docs", nil, nil, "")
	if moved.StatusCode != http.StatusOK {
		t.Fatalf("GET /identity/docs answered %d; the routes follow the api prefix", moved.StatusCode)
	}
	if moved.Headers["Content-Security-Policy"] != docsPageCSP {
		t.Errorf("the moved page carries %q, want the page policy", moved.Headers["Content-Security-Policy"])
	}

	old := invoke(t, app, http.MethodGet, "/auth/docs", nil, nil, "")
	if old.StatusCode != http.StatusNotFound {
		t.Errorf("GET /auth/docs answered %d once the prefix moved, want 404", old.StatusCode)
	}
	if policy := old.Headers["Content-Security-Policy"]; policy != "" {
		t.Errorf("the old path still carries a policy (%q); the middleware is matching the wrong prefix", policy)
	}
}

// absoluteOrigin finds every scheme-and-host this page fetches from.
var absoluteOrigin = regexp.MustCompile(`https?://[A-Za-z0-9.\-]+`)

// TestDocsPolicyCoversEveryOriginTheCorePageLoads is the tripwire for the one
// way docsPageCSP can rot silently.
//
// The policy names a CDN origin that is a literal inside the core's HTML, not a
// knob of either layer: the page is the reference's byte for byte, and this port
// neither writes it nor may rewrite it. If upstream ever re-points that HTML at
// another host — a vendored bundle, a different CDN, an SRI-pinned copy — the
// policy would go on allowing only the old one and the page would break in a
// browser while every test that only checks status codes stayed green.
//
// So the page is rendered from the core's own handler and every absolute origin
// in it is held to the policy. This test is named in the deviation register as
// the thing that fails on that day.
func TestDocsPolicyCoversEveryOriginTheCorePageLoads(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	auth.SwaggerUIHandler("/auth"+auth.DocsSpecPath).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth"+auth.DocsUIPath, nil))
	page := rec.Body.String()
	if !strings.Contains(page, "swagger-ui") {
		t.Fatalf("the core no longer renders a Swagger page; this tripwire is reading the wrong thing:\n%s", page)
	}

	found := map[string]bool{}
	for _, origin := range absoluteOrigin.FindAllString(page, -1) {
		found[origin] = true
	}
	if len(found) == 0 {
		t.Fatalf("the core's page loads nothing from an absolute origin any more, so docsPageCSP is allowing %q for no reason", docsCDNOrigin)
	}
	for origin := range found {
		if !strings.Contains(docsPageCSP, origin) {
			t.Errorf(`the core's Swagger page loads from %q, which docsPageCSP does not allow.

The policy would block it and the page would render empty. Either add the origin
to docsPageCSP, or -- better -- check whether upstream has stopped needing a CDN
at all, in which case the whole allowance goes and so does the deviation entry
docs-page-carries-a-content-security-policy.`, origin)
		}
	}
	if !found[docsCDNOrigin] {
		t.Errorf("docsCDNOrigin is %q and the page loads from %v; the constant is stale", docsCDNOrigin, keysOfSet(found))
	}
}

func keysOfSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
