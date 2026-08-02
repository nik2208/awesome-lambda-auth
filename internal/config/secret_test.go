package config

import (
	"strings"
	"testing"
)

// TestSecretResolutionOrder pins the order of spec §1: Secrets Manager, then SSM
// SecureString, then a plain environment variable, with a store that has no entry
// falling through to the next.
func TestSecretResolutionOrder(t *testing.T) {
	const (
		fromSM  = "secrets-manager-value-padded-to-32-chars"
		fromSSM = "ssm-secure-string-value-padded-to-32ch"
	)

	cases := []struct {
		name       string
		ref        map[string]any
		resolvers  Resolvers
		wantValue  string
		wantSource string
	}{
		{
			name: "secrets manager wins",
			ref:  map[string]any{"secretsManager": "auth/access", "ssmParameter": "/auth/access"},
			resolvers: Resolvers{
				SecretsManager: fakeResolver{ResolverSecretsManager, map[string]string{"auth/access": fromSM}},
				SSM:            fakeResolver{ResolverSSM, map[string]string{"/auth/access": fromSSM}},
			},
			wantValue:  fromSM,
			wantSource: ResolverSecretsManager,
		},
		{
			name: "falls through to ssm when secrets manager has no entry",
			ref:  map[string]any{"secretsManager": "auth/access", "ssmParameter": "/auth/access"},
			resolvers: Resolvers{
				SecretsManager: fakeResolver{ResolverSecretsManager, nil},
				SSM:            fakeResolver{ResolverSSM, map[string]string{"/auth/access": fromSSM}},
			},
			wantValue:  fromSSM,
			wantSource: ResolverSSM,
		},
		{
			name: "falls through to the environment when neither store has an entry",
			ref:  map[string]any{"secretsManager": "auth/access"},
			resolvers: Resolvers{
				SecretsManager: fakeResolver{ResolverSecretsManager, nil},
			},
			wantValue:  strings.Repeat("a", 40),
			wantSource: ResolverEnv,
		},
		{
			name:       "no reference at all uses the documented variable",
			ref:        nil,
			wantValue:  strings.Repeat("a", 40),
			wantSource: ResolverEnv,
		},
		{
			name:       "envVar renames the variable",
			ref:        map[string]any{"envVar": "MY_OWN_ACCESS_SECRET"},
			wantValue:  strings.Repeat("z", 40),
			wantSource: ResolverEnv,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			if tc.ref != nil {
				set(doc, "security.jwt.accessTokenSecret", tc.ref)
			}
			env := baseEnv()
			env["MY_OWN_ACCESS_SECRET"] = strings.Repeat("z", 40)

			cfg, err := Load(t.Context(), Options{
				Document: doc,
				Getenv:   getenvFrom(env),
				Secrets:  tc.resolvers,
			})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got := cfg.AccessTokenSecret(); got != tc.wantValue {
				t.Errorf("resolved value = %q, want %q", got, tc.wantValue)
			}
			if got := cfg.SecretSource("security.jwt.accessTokenSecret"); got != tc.wantSource {
				t.Errorf("source = %q, want %q", got, tc.wantSource)
			}
		})
	}
}

// TestUnreachableSecretStoreIsReported: P1 ships no AWS resolvers, so a document
// that references Secrets Manager must fail with an actionable message naming the
// knob. Falling back to an empty secret would let the stack come up and 500 on the
// first login.
func TestUnreachableSecretStoreIsReported(t *testing.T) {
	doc := baseDoc()
	set(doc, "security.jwt.accessTokenSecret", map[string]any{"secretsManager": "auth/access"})

	_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	ve := validationError(t, err)

	var found *Diagnostic
	for i := range ve.Diagnostics {
		if ve.Diagnostics[i].Path == "security.jwt.accessTokenSecret" {
			found = &ve.Diagnostics[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected a diagnostic naming the knob, got:\n%v", ve)
	}
	if !strings.Contains(found.Error(), ResolverSecretsManager) {
		t.Errorf("diagnostic does not name the unreachable store:\n%s", found.Error())
	}
}

// TestDeniedSecretReadDoesNotFallThrough: a permission failure is not a miss.
// Falling through would turn "the execution role cannot read this" into "the
// secret is empty", and the deployment would sign tokens with nothing.
func TestDeniedSecretReadDoesNotFallThrough(t *testing.T) {
	doc := baseDoc()
	set(doc, "security.jwt.accessTokenSecret", map[string]any{"secretsManager": "auth/access"})

	_, err := Load(t.Context(), Options{
		Document: doc,
		Getenv:   getenvFrom(baseEnv()),
		Secrets:  Resolvers{SecretsManager: deniedResolver{ResolverSecretsManager}},
	})
	ve := validationError(t, err)
	if !ve.HasRule(RulePlaintextSecret) {
		t.Fatalf("expected the read failure to be reported, got:\n%v", ve)
	}
	if ve.HasRule(RuleSecrets) {
		// RS-1 would mean the loader silently accepted an empty secret and then
		// complained that it was empty, hiding the real cause.
		t.Errorf("the denied read was masked as a missing secret:\n%v", ve)
	}
}

// TestPlaintextSecretInDocumentIsRejected pins the §1 secrets rule: secrets never
// appear as plaintext in the document, and the error has to name the path and
// offer both the store form and the development variable.
func TestPlaintextSecretInDocumentIsRejected(t *testing.T) {
	doc := baseDoc()
	set(doc, "admin.bootstrapSecret", strings.Repeat("s", 40))

	_, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(baseEnv()),
		AllowUnimplemented: true,
	})
	d := requireRule(t, err, RulePlaintextSecret, "admin.bootstrapSecret")
	if !strings.Contains(d.Error(), "secretsManager") {
		t.Errorf("the remedy does not show the store form:\n%s", d.Error())
	}
	if !strings.Contains(d.Error(), "AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET") {
		t.Errorf("the remedy does not name the development variable:\n%s", d.Error())
	}
}

// TestSecretIsNotReachableThroughTheConfigTree: printing or marshalling a Config
// must not be able to leak a signing key, which is why resolved values live
// outside the tree.
func TestSecretIsNotReachableThroughTheConfigTree(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	secret := strings.Repeat("a", 40)
	if cfg.AccessTokenSecret() != secret {
		t.Fatalf("test setup: the secret did not resolve")
	}
	for name, rendered := range map[string]string{
		"Config.String":          cfg.String(),
		"Secret.String":          cfg.Security.JWT.AccessTokenSecret.String(),
		"formatted whole struct": sprint(cfg.Security),
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s leaked the secret: %s", name, rendered)
		}
	}
}

// TestProductionEnvSecretWarns: reading a production secret from a plain
// environment variable works, but the operator hears about it.
func TestProductionEnvSecretWarns(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, w := range cfg.Warnings() {
		if w.Path == "security.jwt.accessTokenSecret" && strings.Contains(w.Problem, "environment variable") {
			return
		}
	}
	t.Errorf("expected a warning about the env-sourced production secret; got %v", cfg.Warnings())
}

// TestSecretDiagnosticNamesItsOrigin: the most common RS-1 report is "this secret
// is too short", and it is only actionable if it says which of the three possible
// places the value came from.
func TestSecretDiagnosticNamesItsOrigin(t *testing.T) {
	cases := []struct {
		name       string
		ref        map[string]any
		resolvers  Resolvers
		env        map[string]string
		wantOrigin string
	}{
		{
			name:       "documented environment variable",
			env:        map[string]string{"AWESOME_AUTH_JWT_ACCESS_SECRET": "short"},
			wantOrigin: "AWESOME_AUTH_JWT_ACCESS_SECRET",
		},
		{
			name:       "renamed environment variable",
			ref:        map[string]any{"envVar": "MY_OWN_ACCESS_SECRET"},
			env:        map[string]string{"MY_OWN_ACCESS_SECRET": "short"},
			wantOrigin: "MY_OWN_ACCESS_SECRET",
		},
		{
			name:      "secrets manager reference",
			ref:       map[string]any{"secretsManager": "auth/access"},
			resolvers: Resolvers{SecretsManager: fakeResolver{ResolverSecretsManager, map[string]string{"auth/access": "short"}}},
			// The reference is named; the value never is.
			wantOrigin: "auth/access",
		},
		{
			name:       "ssm parameter",
			ref:        map[string]any{"ssmParameter": "/auth/access"},
			resolvers:  Resolvers{SSM: fakeResolver{ResolverSSM, map[string]string{"/auth/access": "short"}}},
			wantOrigin: "/auth/access",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			if tc.ref != nil {
				set(doc, "security.jwt.accessTokenSecret", tc.ref)
			}
			env := tc.env
			if env == nil {
				env = map[string]string{}
			}
			env["AWESOME_AUTH_JWT_REFRESH_SECRET"] = strings.Repeat("b", 40)

			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env), Secrets: tc.resolvers})
			d := requireRule(t, err, RuleSecrets, "security.jwt.accessTokenSecret")
			if !strings.Contains(d.Error(), tc.wantOrigin) {
				t.Errorf("diagnostic does not name the origin %q:\n%s", tc.wantOrigin, d.Error())
			}
			if strings.Contains(d.Error(), "short") && !strings.Contains(d.Error(), "5 characters") {
				t.Errorf("the diagnostic echoed the secret value:\n%s", d.Error())
			}
		})
	}
}

// TestSecretRefFromTheEnvironment: the deployment that most needs Secrets
// Manager is a CloudFormation stack with no configuration document, and a
// template can only reach a knob through the environment. The reference
// variables are what let it pass an ARN where it used to have to pass the
// secret itself.
func TestSecretRefFromTheEnvironment(t *testing.T) {
	const fromSM, fromSSM = "secrets-manager-value-padded-to-32-chars", "ssm-secure-string-value-padded-to-32ch"

	cases := []struct {
		name       string
		env        map[string]string
		doc        map[string]any
		wantValue  string
		wantSource string
		wantOrigin string
	}{
		{
			name:       "secrets manager reference",
			env:        map[string]string{"AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER": "auth/access"},
			wantValue:  fromSM,
			wantSource: ResolverSecretsManager,
			wantOrigin: "auth/access",
		},
		{
			name:       "ssm reference",
			env:        map[string]string{"AWESOME_AUTH_JWT_ACCESS_SECRET_SSM_PARAMETER": "/auth/access"},
			wantValue:  fromSSM,
			wantSource: ResolverSSM,
			wantOrigin: "/auth/access",
		},
		{
			name:       "both, in the documented order",
			env:        map[string]string{"AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER": "auth/access", "AWESOME_AUTH_JWT_ACCESS_SECRET_SSM_PARAMETER": "/auth/access"},
			wantValue:  fromSM,
			wantSource: ResolverSecretsManager,
			wantOrigin: "auth/access",
		},
		{
			// Same precedence as every other knob: the environment layers over
			// the document, so an operator can repoint one stack at one secret
			// without editing the shared document.
			name:       "the environment overrides a document reference",
			doc:        map[string]any{"ssmParameter": "/auth/access"},
			env:        map[string]string{"AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER": "auth/access"},
			wantValue:  fromSM,
			wantSource: ResolverSecretsManager,
			wantOrigin: "auth/access",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			if tc.doc != nil {
				set(doc, "security.jwt.accessTokenSecret", tc.doc)
			}
			env := baseEnv()
			// The value variable stays set, and must lose: a reference is the
			// whole point, and silently preferring the plaintext one would leave
			// every migrated stack exactly as exposed as before.
			for k, v := range tc.env {
				env[k] = v
			}

			cfg, err := Load(t.Context(), Options{
				Document: doc,
				Getenv:   getenvFrom(env),
				Secrets: Resolvers{
					SecretsManager: fakeResolver{ResolverSecretsManager, map[string]string{"auth/access": fromSM}},
					SSM:            fakeResolver{ResolverSSM, map[string]string{"/auth/access": fromSSM}},
				},
			})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if got := cfg.AccessTokenSecret(); got != tc.wantValue {
				t.Errorf("resolved value = %q, want %q", got, tc.wantValue)
			}
			if got := cfg.SecretSource("security.jwt.accessTokenSecret"); got != tc.wantSource {
				t.Errorf("source = %q, want %q", got, tc.wantSource)
			}
			if got := cfg.Source("security.jwt.accessTokenSecret"); !strings.Contains(got, tc.wantOrigin) {
				t.Errorf("origin = %q, want it to name %q", got, tc.wantOrigin)
			}
		})
	}
}

// TestSecretRefEnvNamesAreDistinct guards the two suffixes against colliding
// with each other or with the value variables — a variable bound twice is a
// silent precedence bug.
func TestSecretRefEnvNamesAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for _, s := range SecretEnvNames() {
		seen[s.Env] = s.Path
	}
	for _, s := range SecretRefEnvNames() {
		if !strings.HasPrefix(s.Env, "AWESOME_AUTH_") {
			t.Errorf("%s does not use the AWESOME_AUTH_ prefix", s.Env)
		}
		if prev, dup := seen[s.Env]; dup {
			t.Errorf("%s is used twice, for %s and %s", s.Env, prev, s.Path)
		}
		seen[s.Env] = s.Path
	}
	for _, b := range envBindings() {
		if path, dup := seen[b.env]; dup {
			t.Errorf("secret reference variable %s is also an ordinary binding for %s", b.env, path)
		}
	}
}

func TestSecretEnvNamesFollowTheConvention(t *testing.T) {
	for _, s := range SecretEnvNames() {
		if !strings.HasPrefix(s.Env, "AWESOME_AUTH_") {
			t.Errorf("secret %s uses variable %s, which does not follow the convention", s.Path, s.Env)
		}
	}
}
