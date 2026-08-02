package config

import (
	"strings"
	"testing"
)

// TestEnvOverridesDocument pins the layering order of spec §4: file value, then
// AWESOME_AUTH_* override. One case per value kind, because the parsers differ
// and a bool that silently became false would turn a security knob off.
func TestEnvOverridesDocument(t *testing.T) {
	cases := []struct {
		name    string
		docPath string
		docVal  any
		env     string
		envVal  string
		check   func(*testing.T, *Config)
	}{
		{
			name:    "string",
			docPath: "cookies.sameSite",
			docVal:  "strict",
			env:     "AWESOME_AUTH_COOKIES_SAMESITE",
			envVal:  "lax",
			check: func(t *testing.T, c *Config) {
				if c.Cookies.SameSite != SameSiteLax {
					t.Errorf("cookies.sameSite = %q, want lax", c.Cookies.SameSite)
				}
			},
		},
		{
			name:    "bool",
			docPath: "cookies.secure",
			docVal:  false,
			env:     "AWESOME_AUTH_COOKIES_SECURE",
			envVal:  "true",
			check: func(t *testing.T, c *Config) {
				if !c.Cookies.Secure {
					t.Error("cookies.secure = false, want the env override to win")
				}
			},
		},
		{
			name:    "int",
			docPath: "security.password.bcryptSaltRounds",
			docVal:  10,
			env:     "AWESOME_AUTH_BCRYPT_SALT_ROUNDS",
			envVal:  "14",
			check: func(t *testing.T, c *Config) {
				if c.Security.Password.BcryptSaltRounds != 14 {
					t.Errorf("bcryptSaltRounds = %d, want 14", c.Security.Password.BcryptSaltRounds)
				}
			},
		},
		{
			name:    "duration",
			docPath: "security.jwt.accessTokenTtl",
			docVal:  "5m",
			env:     "AWESOME_AUTH_JWT_ACCESS_TTL",
			envVal:  "20m",
			check: func(t *testing.T, c *Config) {
				if c.Security.JWT.AccessTokenTTL.String() != "20m" {
					t.Errorf("accessTokenTtl = %q, want 20m", c.Security.JWT.AccessTokenTTL.String())
				}
			},
		},
		{
			name:    "comma separated list",
			docPath: "http.cors.origins",
			docVal:  []any{"https://old.example.com"},
			env:     "AWESOME_AUTH_CORS_ORIGINS",
			envVal:  "https://a.example.com, https://b.example.com,",
			check: func(t *testing.T, c *Config) {
				want := []string{"https://a.example.com", "https://b.example.com"}
				if len(c.HTTP.CORS.Origins) != len(want) {
					t.Fatalf("cors.origins = %v, want %v", c.HTTP.CORS.Origins, want)
				}
				for i := range want {
					if c.HTTP.CORS.Origins[i] != want[i] {
						t.Errorf("cors.origins[%d] = %q, want %q", i, c.HTTP.CORS.Origins[i], want[i])
					}
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			set(doc, tc.docPath, tc.docVal)
			env := baseEnv()
			env[tc.env] = tc.envVal

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			tc.check(t, cfg)
			if got := cfg.Source(tc.docPath); got != tc.env {
				t.Errorf("Source(%s) = %q, want the overriding variable %q", tc.docPath, got, tc.env)
			}
		})
	}
}

// TestDocumentOverridesDefault is the other half of the layering: without an env
// override, the document wins over the default, and the source says so.
func TestDocumentOverridesDefault(t *testing.T) {
	doc := baseDoc()
	set(doc, "sessions.checkOn", "allcalls")

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Sessions.CheckOn != SessionCheckOnAllCalls {
		t.Errorf("sessions.checkOn = %q, want allcalls", cfg.Sessions.CheckOn)
	}
	if got := cfg.Source("sessions.checkOn"); got != SourceDocument {
		t.Errorf("Source = %q, want %q", got, SourceDocument)
	}
	if got := cfg.Source("cookies.sameSite"); got != SourceDefault {
		t.Errorf("Source of an untouched knob = %q, want %q", got, SourceDefault)
	}
}

// TestEnvOnlyConfiguration covers the deployment shape where there is no document
// at all — everything comes from the function's environment block.
func TestEnvOnlyConfiguration(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL"] = "https://auth.example.com"
	env["AWESOME_AUTH_STORES_DRIVER"] = "dynamodb"
	env["AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME"] = "awesome-auth"

	cfg, err := Load(t.Context(), Options{Getenv: getenvFrom(env)})
	if err != nil {
		t.Fatalf("an env-only configuration must load:\n%v", err)
	}
	if cfg.Stores.Driver != StoreDriverDynamoDB {
		t.Errorf("stores.driver = %q, want dynamodb", cfg.Stores.Driver)
	}
	// schemaVersion is only required of a document; an env-only deployment gets
	// the version this build reads.
	if cfg.SchemaVersion != CurrentSchemaVersion {
		t.Errorf("schemaVersion = %d, want %d", cfg.SchemaVersion, CurrentSchemaVersion)
	}
}

// TestMalformedEnvValueIsReported: a boolean nobody can parse must not silently
// become false. AWESOME_AUTH_COOKIES_SECURE=yes-please turning into "not secure"
// is the exact failure this rejects.
func TestMalformedEnvValueIsReported(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_COOKIES_SECURE"] = "yes-please"

	_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	ve := validationError(t, err)
	found := false
	for _, d := range ve.Diagnostics {
		if d.Path == "cookies.secure" {
			found = true
			if d.Source != "AWESOME_AUTH_COOKIES_SECURE" {
				t.Errorf("source = %q, want the offending variable", d.Source)
			}
		}
	}
	if !found {
		t.Errorf("expected a diagnostic at cookies.secure, got:\n%v", ve)
	}
}

// TestUnknownKeyIsRejectedWithItsPath. A misspelled security key is the most
// dangerous configuration error there is, because the real knob keeps its default
// and everything else validates.
func TestUnknownKeyIsRejectedWithItsPath(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(Document)
		wantPath string
		wantHint string
	}{
		{
			name:     "misspelled nested key",
			mutate:   func(doc Document) { set(doc, "cookies.sameSight", "none") },
			wantPath: "cookies.sameSight",
			wantHint: "sameSite",
		},
		{
			name:     "misspelled top-level block",
			mutate:   func(doc Document) { set(doc, "cookie.secure", true) },
			wantPath: "cookie",
			wantHint: "cookies",
		},
		{
			name:     "unknown key in a secret reference",
			mutate:   func(doc Document) { set(doc, "security.jwt.accessTokenSecret.secretManager", "x") },
			wantPath: "security.jwt.accessTokenSecret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			ve := validationError(t, err)
			var found *Diagnostic
			for i := range ve.Diagnostics {
				if ve.Diagnostics[i].Path == tc.wantPath {
					found = &ve.Diagnostics[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("expected a diagnostic at %s, got:\n%v", tc.wantPath, ve)
			}
			if tc.wantHint != "" && !strings.Contains(found.Error(), tc.wantHint) {
				t.Errorf("diagnostic does not suggest %q:\n%s", tc.wantHint, found.Error())
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	doc, err := ParseJSON([]byte(`{
		"schemaVersion": 1,
		"deployment": {"publicUrl": "https://auth.example.com"},
		"cookies": {"secure": true, "sameSite": "none"},
		"stores": {"driver": "dynamodb", "connection": {"tableName": "awesome-auth"}}
	}`))
	if err != nil {
		t.Fatalf("ParseJSON: %v", err)
	}

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Cookies.Secure || cfg.Cookies.SameSite != SameSiteNone {
		t.Errorf("cookies = %+v, want secure sameSite=none", cfg.Cookies)
	}
}

func TestParseJSONRejectsGarbage(t *testing.T) {
	if _, err := ParseJSON([]byte("not json")); err == nil {
		t.Fatal("expected an error for a non-JSON document")
	}
}

// TestParseJSONRejectsANullDocument. "null" decodes to a nil map, and Load reads a
// nil Document as "there is no document" — so a file the operator actually shipped
// would be ignored along with the schemaVersion gate, and the stack would come up
// on defaults and environment alone.
func TestParseJSONRejectsANullDocument(t *testing.T) {
	if _, err := ParseJSON([]byte("null")); err == nil {
		t.Fatal("a null document must be refused, not read as an absent one")
	}
}

// TestSchemaVersionAccepted is the positive control for the two rejection cases in
// the rule table.
func TestSchemaVersionAccepted(t *testing.T) {
	doc := baseDoc()
	doc["schemaVersion"] = CurrentSchemaVersion

	if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())}); err != nil {
		t.Fatalf("the current schema version must be accepted:\n%v", err)
	}
}

// TestEnvBindingTableIsWellFormed guards the override surface itself: a duplicate
// variable name would make one binding unreachable, and a duplicate path would
// make two variables fight silently.
func TestEnvBindingTableIsWellFormed(t *testing.T) {
	seenEnv := map[string]string{}
	seenPath := map[string]string{}
	for _, b := range envBindings() {
		if !strings.HasPrefix(b.env, "AWESOME_AUTH_") {
			t.Errorf("%s does not use the AWESOME_AUTH_ prefix", b.env)
		}
		if prev, dup := seenEnv[b.env]; dup {
			t.Errorf("%s is bound twice, to %s and %s", b.env, prev, b.path)
		}
		seenEnv[b.env] = b.path
		if prev, dup := seenPath[b.path]; dup {
			t.Errorf("%s is overridden by two variables, %s and %s", b.path, prev, b.env)
		}
		seenPath[b.path] = b.env
	}

	// The secret knobs resolve through the resolver chain, not the binding table,
	// so their documented variables must not also appear as bindings.
	for _, s := range SecretEnvNames() {
		if path, dup := seenEnv[s.Env]; dup {
			t.Errorf("secret variable %s is also an ordinary binding for %s", s.Env, path)
		}
	}
}

// TestEnvBindingsCoverEveryStore: the store list lives in one table, and this
// asserts the env layer was generated from it rather than typed out.
func TestEnvBindingsCoverEveryStore(t *testing.T) {
	bound := map[string]bool{}
	for _, b := range envBindings() {
		bound[b.path] = true
	}
	for _, f := range storeFields(&StoreEnable{}) {
		path := "stores.enable." + f.name
		if !bound[path] {
			t.Errorf("%s has no environment override", path)
		}
	}
}
