package config

import (
	"strings"
	"testing"
)

// TestRefuseToStartRules is one case per rule in spec §2, each asserting the
// specific rule identifier and the specific knob it fired on. Asserting only
// "Load returned an error" would pass even if the rule under test never ran,
// because these configurations are broken in a way that something else might
// also notice.
func TestRefuseToStartRules(t *testing.T) {
	cases := []struct {
		name string

		// mutate breaks exactly one thing in the base document.
		mutate func(Document)

		// env replaces the base environment when non-nil.
		env map[string]string

		// allowUnimplemented is set for the cases whose knob belongs to a domain
		// P1 does not wire yet, so the phase-gap check does not mask the rule.
		allowUnimplemented bool

		capabilities func(string) StoreCapabilities

		wantRule string
		wantPath string

		// wantMessage is a fragment the diagnostic must contain, to pin that the
		// operator is told what actually goes wrong rather than just which knob.
		wantMessage string
	}{
		{
			name:        "RS-1 access secret missing",
			env:         map[string]string{"AWESOME_AUTH_JWT_REFRESH_SECRET": strings.Repeat("b", 40)},
			wantRule:    RuleSecrets,
			wantPath:    "security.jwt.accessTokenSecret",
			wantMessage: "missing",
		},
		{
			name: "RS-1 secret too short",
			env: map[string]string{
				"AWESOME_AUTH_JWT_ACCESS_SECRET":  "too-short",
				"AWESOME_AUTH_JWT_REFRESH_SECRET": strings.Repeat("b", 40),
			},
			wantRule:    RuleSecrets,
			wantPath:    "security.jwt.accessTokenSecret",
			wantMessage: "below the 32-character minimum",
		},
		{
			name: "RS-1 access and refresh secrets identical",
			env: map[string]string{
				"AWESOME_AUTH_JWT_ACCESS_SECRET":  strings.Repeat("a", 40),
				"AWESOME_AUTH_JWT_REFRESH_SECRET": strings.Repeat("a", 40),
			},
			wantRule:    RuleSecrets,
			wantPath:    "security.jwt.refreshTokenSecret",
			wantMessage: "identical",
		},
		{
			name: "RS-2 cookie mode on an execute-api stage URL",
			mutate: func(doc Document) {
				set(doc, "deployment.publicUrl", "https://abc123.execute-api.eu-west-1.amazonaws.com/prod")
			},
			wantRule:    RuleInsecureCookieMode,
			wantPath:    "deployment.publicUrl",
			wantMessage: "shared AWS domain",
		},
		{
			name: "RS-2 cookie mode on a Function URL",
			mutate: func(doc Document) {
				set(doc, "deployment.publicUrl", "https://abc123.lambda-url.eu-west-1.on.aws/")
			},
			wantRule: RuleInsecureCookieMode,
			wantPath: "deployment.publicUrl",
		},
		{
			name: "RS-3 CSRF disabled in cookie mode",
			mutate: func(doc Document) {
				set(doc, "security.csrf.enabled", false)
			},
			wantRule:    RuleCSRFDisabled,
			wantPath:    "security.csrf.enabled",
			wantMessage: "cross-site forgeable",
		},
		{
			name: "RS-4 identity provider enabled with no key material in production",
			mutate: func(doc Document) {
				set(doc, "deployment.environment", "production")
				set(doc, "idProvider.enabled", true)
			},
			allowUnimplemented: true,
			wantRule:           RuleIDProviderKeys,
			wantPath:           "idProvider.privateKey",
			wantMessage:        "cold start",
		},
		{
			name: "RS-5 sameSite none without secure",
			mutate: func(doc Document) {
				set(doc, "cookies.sameSite", "none")
			},
			wantRule:    RuleSameSiteNone,
			wantPath:    "cookies.sameSite",
			wantMessage: "browser",
		},
		{
			name: "RS-6 admin surface with no guard",
			mutate: func(doc Document) {
				set(doc, "admin.enabled", true)
			},
			allowUnimplemented: true,
			wantRule:           RuleAdminUnguarded,
			wantPath:           "admin.accessPolicy",
			wantMessage:        "open to anyone",
		},
		{
			name: "RS-8 resource server without a JWKS URL",
			mutate: func(doc Document) {
				set(doc, "resourceServer.enabled", true)
			},
			allowUnimplemented: true,
			wantRule:           RuleResourceServerJWKS,
			wantPath:           "resourceServer.jwksUrl",
			wantMessage:        "no JWKS URL",
		},
		{
			name: "RS-8 resource server with a non-https JWKS URL",
			mutate: func(doc Document) {
				set(doc, "resourceServer.enabled", true)
				set(doc, "resourceServer.jwksUrl", "http://idp.example.com/jwks.json")
			},
			allowUnimplemented: true,
			wantRule:           RuleResourceServerJWKS,
			wantPath:           "resourceServer.jwksUrl",
		},
		{
			name: "RS-9 unparseable access token TTL",
			mutate: func(doc Document) {
				set(doc, "security.jwt.accessTokenTtl", "1h30m")
			},
			wantRule:    RuleTTLSyntax,
			wantPath:    "security.jwt.accessTokenTtl",
			wantMessage: "ms-syntax",
		},
		{
			name: "RS-9 unparseable refresh token TTL",
			mutate: func(doc Document) {
				set(doc, "security.jwt.refreshTokenTtl", "one week")
			},
			wantRule: RuleTTLSyntax,
			wantPath: "security.jwt.refreshTokenTtl",
		},
		{
			name: "RS-10 first-user policy on a driver that cannot list users",
			mutate: func(doc Document) {
				set(doc, "admin.enabled", true)
				set(doc, "admin.accessPolicy", "first-user")
			},
			allowUnimplemented: true,
			capabilities:       func(string) StoreCapabilities { return StoreCapabilities{ListUsers: false} },
			wantRule:           RuleFirstUserListUsers,
			wantPath:           "admin.accessPolicy",
			wantMessage:        "enumerate users",
		},
		{
			name: "RS-11 incomplete oauth provider block",
			mutate: func(doc Document) {
				set(doc, "email.siteUrls", []any{"https://app.example.com"})
				set(doc, "stores.enable.linkedAccounts", true)
				set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
			},
			wantRule:    RuleOAuthIncomplete,
			wantPath:    "oauth.providers.google",
			wantMessage: "clientSecret, callbackUrl",
		},
		{
			// reference-issues N1: with nothing to allowlist, the callback
			// honours whatever origin the state names — and the callback is the
			// route that answers with a fresh session in a Set-Cookie.
			//
			// Reported under the provider, because that is the block the
			// operator was writing when they triggered it; email.siteUrls and
			// http.cors.origins are named in the remedy, where they are the
			// answer rather than a place to go looking.
			name: "RS-11 a configured provider with an empty redirect allowlist",
			mutate: func(doc Document) {
				set(doc, "stores.enable.linkedAccounts", true)
				set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
				set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
			},
			env: map[string]string{
				"AWESOME_AUTH_JWT_ACCESS_SECRET":          strings.Repeat("a", 40),
				"AWESOME_AUTH_JWT_REFRESH_SECRET":         strings.Repeat("b", 40),
				"AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET": "google-client-secret",
			},
			wantRule:    RuleOAuthIncomplete,
			wantPath:    "oauth.providers.google",
			wantMessage: "redirect allowlist is empty",
		},
		{
			// The store defaults to off, and without it the core's callback
			// answers 501 NOT_IMPLEMENTED — after the browser has been sent to
			// the provider and the person has consented. A login nobody can
			// complete is a refusal, not a runtime surprise.
			name: "RS-11 a configured provider with the linked-accounts store disabled",
			mutate: func(doc Document) {
				set(doc, "email.siteUrls", []any{"https://app.example.com"})
				set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
				set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
			},
			env: map[string]string{
				"AWESOME_AUTH_JWT_ACCESS_SECRET":          strings.Repeat("a", 40),
				"AWESOME_AUTH_JWT_REFRESH_SECRET":         strings.Repeat("b", 40),
				"AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET": "google-client-secret",
			},
			wantRule:    RuleOAuthIncomplete,
			wantPath:    "stores.enable.linkedAccounts",
			wantMessage: "501",
		},
		{
			// onEmailMatch: conflict stashes the conflict for /link-request to
			// pick up, and the stash lives in the pending-links store. Without
			// it the 302 to /account-conflict still goes out and resolves
			// nothing.
			name: "RS-11 onEmailMatch conflict with the pending-links store disabled",
			mutate: func(doc Document) {
				set(doc, "email.siteUrls", []any{"https://app.example.com"})
				set(doc, "stores.enable.linkedAccounts", true)
				set(doc, "oauth.provisioning.onEmailMatch", "conflict")
				set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
				set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
			},
			env: map[string]string{
				"AWESOME_AUTH_JWT_ACCESS_SECRET":          strings.Repeat("a", 40),
				"AWESOME_AUTH_JWT_REFRESH_SECRET":         strings.Repeat("b", 40),
				"AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET": "google-client-secret",
			},
			wantRule:    RuleOAuthIncomplete,
			wantPath:    "oauth.provisioning.onEmailMatch",
			wantMessage: "stores.enable.pendingLinks",
		},
		{
			name: "an unknown oauth provisioning email-match mode",
			mutate: func(doc Document) {
				set(doc, "oauth.provisioning.onEmailMatch", "merge")
			},
			wantRule:    "",
			wantPath:    "oauth.provisioning.onEmailMatch",
			wantMessage: "not a valid value",
		},
		{
			name: "RS-12 memory store in production",
			mutate: func(doc Document) {
				set(doc, "deployment.environment", "production")
				set(doc, "stores.driver", "memory")
			},
			wantRule:    RuleMemoryStore,
			wantPath:    "stores.driver",
			wantMessage: "own disconnected copy",
		},
		{
			name: "schemaVersion of an unknown major",
			mutate: func(doc Document) {
				doc["schemaVersion"] = 2
			},
			wantRule:    RuleSchemaVersion,
			wantPath:    "schemaVersion",
			wantMessage: "not understood by this build",
		},
		{
			name: "schemaVersion absent",
			mutate: func(doc Document) {
				delete(doc, "schemaVersion")
			},
			wantRule:    RuleSchemaVersion,
			wantPath:    "schemaVersion",
			wantMessage: "no schemaVersion",
		},
		{
			name: "session checking with the sessions store disabled",
			mutate: func(doc Document) {
				set(doc, "sessions.checkOn", "allcalls")
				set(doc, "stores.enable.sessions", false)
			},
			wantRule:    RuleStoreRequired,
			wantPath:    "stores.enable.sessions",
			wantMessage: "allcalls",
		},
		{
			name: "rbac access policy with the rbac store disabled",
			mutate: func(doc Document) {
				set(doc, "admin.enabled", true)
				set(doc, "admin.accessPolicy", "rbac:superadmin")
			},
			allowUnimplemented: true,
			wantRule:           RuleStoreRequired,
			wantPath:           "stores.enable.rbac",
		},
		{
			name: "a plaintext secret in the document",
			mutate: func(doc Document) {
				set(doc, "security.jwt.accessTokenSecret", strings.Repeat("a", 40))
			},
			wantRule:    RulePlaintextSecret,
			wantPath:    "security.jwt.accessTokenSecret",
			wantMessage: "literal value",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			if tc.mutate != nil {
				tc.mutate(doc)
			}
			env := tc.env
			if env == nil {
				env = baseEnv()
			}

			cfg, err := Load(t.Context(), Options{
				Document:           doc,
				Getenv:             getenvFrom(env),
				Capabilities:       tc.capabilities,
				AllowUnimplemented: tc.allowUnimplemented,
			})
			if cfg != nil {
				t.Fatalf("a refused configuration must not be returned, got %v", cfg)
			}
			d := requireRule(t, err, tc.wantRule, tc.wantPath)
			if tc.wantMessage != "" && !strings.Contains(d.Error(), tc.wantMessage) {
				t.Errorf("diagnostic does not mention %q:\n%s", tc.wantMessage, d.Error())
			}
		})
	}
}

// TestBaseConfigurationLoads is the control for the table above: if the base
// document did not load cleanly, every case in it could be passing for the wrong
// reason.
func TestBaseConfigurationLoads(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("the base configuration must load cleanly:\n%v", err)
	}
	if cfg.AccessTokenSecret() != strings.Repeat("a", 40) {
		t.Errorf("access secret did not resolve from its documented environment variable")
	}
	if cfg.SecretSource("security.jwt.accessTokenSecret") != ResolverEnv {
		t.Errorf("secret source = %q, want %q", cfg.SecretSource("security.jwt.accessTokenSecret"), ResolverEnv)
	}
	// cookies.refreshTokenPath is derived from http.apiPrefix, fixing the
	// reference's TokenService-level '/auth/refresh' fallback.
	if cfg.Cookies.RefreshTokenPath != "/auth/refresh" {
		t.Errorf("cookies.refreshTokenPath = %q, want /auth/refresh", cfg.Cookies.RefreshTokenPath)
	}
}

// TestRefreshPathFollowsAPIPrefix pins the derivation, because a refresh cookie
// scoped to the wrong path is silently never sent and every refresh then 401s.
func TestRefreshPathFollowsAPIPrefix(t *testing.T) {
	doc := baseDoc()
	set(doc, "http.apiPrefix", "/identity")

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Cookies.RefreshTokenPath != "/identity/refresh" {
		t.Errorf("cookies.refreshTokenPath = %q, want /identity/refresh", cfg.Cookies.RefreshTokenPath)
	}
	if cfg.Docs.BasePath != "/identity" {
		t.Errorf("docs.basePath = %q, want the resolved api prefix", cfg.Docs.BasePath)
	}
}

// TestAllowInsecureCookieModeSuppressesRS2 pins the documented escape hatch, so
// that a dev stage on an execute-api URL can be deployed on purpose.
func TestAllowInsecureCookieModeSuppressesRS2(t *testing.T) {
	doc := baseDoc()
	set(doc, "deployment.environment", "development")
	set(doc, "deployment.publicUrl", "https://abc123.execute-api.eu-west-1.amazonaws.com/dev")
	set(doc, "cookies.allowInsecureCookieMode", true)

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("the escape hatch should allow this configuration:\n%v", err)
	}
	if !cfg.Cookies.AllowInsecureCookieMode {
		t.Error("allowInsecureCookieMode did not survive layering")
	}
}

// TestResourceServerModeExemptsSigningSecrets: a resource server validates tokens
// minted elsewhere, so RS-1 must not demand local signing secrets from it.
func TestResourceServerModeExemptsSigningSecrets(t *testing.T) {
	doc := baseDoc()
	set(doc, "resourceServer.enabled", true)
	set(doc, "resourceServer.jwksUrl", "https://idp.example.com/.well-known/jwks.json")

	_, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(map[string]string{}),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("resource-server mode must not require HS256 secrets:\n%v", err)
	}
}

// resourceServerWithAdmin is the combination the three tests below turn on: a
// stack that only validates tokens minted elsewhere, and also deploys the admin
// surface. Resource-server mode switches the auth-flow cookies off, but the admin
// login sets a session cookie of its own, so the cookie rules still apply to it.
func resourceServerWithAdmin() Document {
	doc := baseDoc()
	set(doc, "resourceServer.enabled", true)
	set(doc, "resourceServer.jwksUrl", "https://idp.example.com/.well-known/jwks.json")
	set(doc, "admin.enabled", true)
	set(doc, "admin.accessPolicy", "is-admin-flag")
	return doc
}

// TestAdminSurfaceKeepsTheCookieRulesInResourceServerMode: RS-3 protects the
// cookie-authenticated surfaces, and the admin one is the most privileged in the
// deployment. Exempting it because the auth-flow routes are absent would accept
// exactly the configuration the rule exists to refuse.
func TestAdminSurfaceKeepsTheCookieRulesInResourceServerMode(t *testing.T) {
	doc := resourceServerWithAdmin()
	set(doc, "security.csrf.enabled", false)

	_, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(baseEnv()),
		AllowUnimplemented: true,
	})
	requireRule(t, err, RuleCSRFDisabled, "security.csrf.enabled")
}

// TestAdminSurfaceKeepsRS2InResourceServerMode is the same argument for RS-2: an
// admin session cookie on a raw execute-api stage URL has the same broken scoping
// as any other.
func TestAdminSurfaceKeepsRS2InResourceServerMode(t *testing.T) {
	doc := resourceServerWithAdmin()
	set(doc, "deployment.publicUrl", "https://abc123.execute-api.eu-west-1.amazonaws.com/prod")

	_, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(baseEnv()),
		AllowUnimplemented: true,
	})
	requireRule(t, err, RuleInsecureCookieMode, "deployment.publicUrl")
}

// TestAdminGuardRequiresTheAccessSecret is RS-7, which the spec folds into RS-1
// because the admin guard verifies the access token with
// security.jwt.accessTokenSecret. Resource-server mode needs no signing secret of
// its own, so the fold has to survive the exemption or the admin surface comes up
// authenticating nobody — the silent failure §2 records against the reference.
func TestAdminGuardRequiresTheAccessSecret(t *testing.T) {
	_, err := Load(t.Context(), Options{
		Document:           resourceServerWithAdmin(),
		Getenv:             getenvFrom(map[string]string{}),
		AllowUnimplemented: true,
	})
	requireRule(t, err, RuleSecrets, "security.jwt.accessTokenSecret")

	// Only the access secret: nothing here mints or verifies a refresh token.
	ve := validationError(t, err)
	for _, d := range ve.Diagnostics {
		if d.Path == "security.jwt.refreshTokenSecret" {
			t.Errorf("resource-server mode must not demand a refresh secret: %s", d.Error())
		}
	}

	// An open policy verifies nothing, so it stays exempt.
	doc := resourceServerWithAdmin()
	set(doc, "admin.accessPolicy", "open")
	if _, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(map[string]string{}),
		AllowUnimplemented: true,
	}); err != nil {
		t.Fatalf("an open admin policy verifies no token and needs no secret:\n%v", err)
	}
}

// TestRS2SeesThroughHostSpellings: the suffix match decides whether a deployment
// controls its own host, so anything that is the same host written differently has
// to reach it in the same shape. A root-label trailing dot is legal DNS, is
// accepted by API Gateway and by every browser, and left in place it turned RS-2
// off completely.
func TestRS2SeesThroughHostSpellings(t *testing.T) {
	for _, publicURL := range []string{
		"https://abc123.execute-api.eu-west-1.amazonaws.com/prod",
		"https://abc123.execute-api.eu-west-1.amazonaws.com./prod",
		"https://abc123.EXECUTE-API.eu-west-1.AmazonAWS.CoM/prod",
		"https://abc123.execute-api.eu-west-1.amazonaws.com:443/prod",
		"https://abc123.lambda-url.eu-west-1.on.aws./",
	} {
		t.Run(publicURL, func(t *testing.T) {
			doc := baseDoc()
			set(doc, "deployment.publicUrl", publicURL)
			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			requireRule(t, err, RuleInsecureCookieMode, "deployment.publicUrl")
		})
	}

	// The control: a host the deployment does own must still pass, including one
	// that merely ends in something similar.
	for _, publicURL := range []string{
		"https://auth.example.com",
		"https://auth.example.com.",
		"https://not-amazonaws.com",
	} {
		t.Run("allowed/"+publicURL, func(t *testing.T) {
			doc := baseDoc()
			set(doc, "deployment.publicUrl", publicURL)
			if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())}); err != nil {
				t.Fatalf("a custom domain must not trip RS-2:\n%v", err)
			}
		})
	}
}

// TestAllRulesAreReportedTogether: an operator fixing a broken deployment gets the
// whole list, not one problem per deploy cycle.
// TestOAuthRedirectAllowlistAcceptsEitherSource: RS-11 asks for an allowlist,
// not for one particular knob. The reference builds it from both
// (buildAllowedOrigins, auth.router.ts:213-219), so a deployment that lists its
// front-end origins under http.cors.origins has already answered the question.
func TestOAuthRedirectAllowlistAcceptsEitherSource(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET"] = "google-client-secret"

	for _, tc := range []struct {
		name   string
		mutate func(Document)
	}{
		{"email.siteUrls", func(doc Document) {
			set(doc, "email.siteUrls", []any{"https://app.example.com"})
		}},
		{"http.cors.origins", func(doc Document) {
			set(doc, "http.cors.origins", []any{"https://app.example.com"})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			set(doc, "stores.enable.linkedAccounts", true)
			set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
			set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("%s supplies the redirect allowlist, so this must load:\n%v", tc.name, err)
			}
			if got := cfg.RedirectOrigins(); len(got) != 1 || got[0] != "https://app.example.com" {
				t.Errorf("RedirectOrigins() = %v, want the one configured origin", got)
			}
		})
	}
}

// TestGenericProviderEndpointsAllowLoopbackOverHTTP: the https requirement
// protects a client secret in flight, and a request to a loopback address is
// never in flight. A dev identity provider beside the process has no
// certificate to present, and refusing it would make the only local OAuth
// deployment impossible — while plain http to anywhere else stays refused.
//
// The carve-out is scoped to a non-production deployment, which is the only
// place its premise holds. Under Lambda nothing runs beside the function and
// loopback is where the runtime API listens, so a production document pointing
// tokenUrl at 127.0.0.1 is a client secret POSTed to the execution
// environment's own control plane — the last subtest pins that it is refused.
func TestGenericProviderEndpointsAllowLoopbackOverHTTP(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_OAUTH_ACME_CLIENT_SECRET"] = "acme-client-secret"

	provider := func(doc Document, endpointBase string) {
		set(doc, "email.siteUrls", []any{"https://app.example.com"})
		set(doc, "stores.enable.linkedAccounts", true)
		set(doc, "oauth.providers.acme.clientId", "acme-client")
		set(doc, "oauth.providers.acme.callbackUrl", "https://auth.example.com/auth/oauth/acme/callback")
		set(doc, "oauth.providers.acme.authorizationUrl", endpointBase+"/authorize")
		set(doc, "oauth.providers.acme.tokenUrl", endpointBase+"/token")
		set(doc, "oauth.providers.acme.userInfoUrl", endpointBase+"/userinfo")
	}

	for _, base := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		t.Run(base, func(t *testing.T) {
			doc := baseDoc()
			// deployment.environment defaults to production, and the carve-out
			// does not apply there: a local identity provider is a development
			// arrangement, so the document says so.
			set(doc, "deployment.environment", "development")
			provider(doc, base)
			if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)}); err != nil {
				t.Fatalf("a loopback provider endpoint must load outside production:\n%v", err)
			}
		})
	}

	t.Run("http elsewhere is still refused", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "deployment.environment", "development")
		provider(doc, "http://idp.example.com")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		d := requireRule(t, err, "", "oauth.providers.acme.tokenUrl")
		if !strings.Contains(d.Problem, "https") {
			t.Errorf("the diagnostic does not say what is wrong with the scheme:\n%s", d.Problem)
		}
	})

	t.Run("loopback in production is refused", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "deployment.environment", "production")
		provider(doc, "http://127.0.0.1:8080")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		d := requireRule(t, err, "", "oauth.providers.acme.tokenUrl")
		if !strings.Contains(d.Problem, "https") {
			t.Errorf("the diagnostic does not say what is wrong with the scheme:\n%s", d.Problem)
		}
	})
}

func TestAllRulesAreReportedTogether(t *testing.T) {
	doc := baseDoc()
	set(doc, "security.csrf.enabled", false)
	set(doc, "cookies.sameSite", "none")
	set(doc, "stores.driver", "memory")

	_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	ve := validationError(t, err)
	for _, rule := range []string{RuleCSRFDisabled, RuleSameSiteNone, RuleMemoryStore} {
		if !ve.HasRule(rule) {
			t.Errorf("expected %s among the reported problems, got:\n%v", rule, ve)
		}
	}
}
