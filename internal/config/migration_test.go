package config

import (
	"strings"
	"testing"
)

// The migration block is new in X1, so unlike every block before it there is no
// entry in unwiredDomains() to remove: it is wired by the same change that
// declares it. This is the tripwire for anyone who adds one by reflex, which
// would refuse every deployment that configures a block this build honours.
func TestMigrationIsNotAnUnwiredDomain(t *testing.T) {
	t.Parallel()
	for path := range UnwiredDomains() {
		if strings.HasPrefix(path, "stores") {
			t.Fatalf("%q is listed as unwired; stores.migration is wired by the change that declared it", path)
		}
	}
}

// The default is off, and the mode's default is the one that reads nobody else's
// directory on the login path. An operator who turns a source on without saying
// which mode they want must not get dual-read by omission.
func TestMigrationDefaultsAreOff(t *testing.T) {
	t.Parallel()
	m := Defaults().Stores.Migration
	if m.Active() {
		t.Errorf("the default migration block is active: %+v", m)
	}
	if m.Mode != MigrationModeImportOnly {
		t.Errorf("default mode = %q, want %q", m.Mode, MigrationModeImportOnly)
	}
	if m.DualRead() {
		t.Error("the default block dual-reads")
	}
	if m.VerifierConfigured() {
		t.Error("the default block configures a verifier")
	}
}

// The mode cannot act on its own: without a source it is inert, which is what
// lets a stack that has finished migrating leave the rest of the block in place.
func TestMigrationModeDoesNotActWithoutASource(t *testing.T) {
	t.Parallel()
	m := Migration{Mode: MigrationModeDualRead, UserPoolID: "eu-west-1_EXAMPLE00", ClientID: "c"}
	if m.DualRead() {
		t.Error("dual-read is on with no source")
	}
	if m.VerifierConfigured() {
		t.Error("a verifier is configured with no source")
	}
}

// A pool with no app client still imports and still dual-reads; it just never
// reaches the login path. That is the posture of a stack whose bulk import is
// finished, and the two halves have to be separable for it to exist.
func TestMigrationWithoutAnAppClientWiresNoVerifier(t *testing.T) {
	t.Parallel()
	m := Migration{Source: MigrationSourceCognito, UserPoolID: "eu-west-1_EXAMPLE00", Mode: MigrationModeDualRead}
	if !m.Active() || !m.DualRead() {
		t.Fatalf("the block is not active: %+v", m)
	}
	if m.VerifierConfigured() {
		t.Error("a verifier is configured with no app client id; AdminInitiateAuth is client-scoped and would be refused")
	}
}

func TestMigrationEnvironmentOverrides(t *testing.T) {
	t.Parallel()
	env := baseEnv()
	env["AWESOME_AUTH_STORES_MIGRATION_SOURCE"] = MigrationSourceCognito
	env["AWESOME_AUTH_STORES_MIGRATION_USER_POOL_ID"] = "eu-west-1_EXAMPLE00"
	env["AWESOME_AUTH_STORES_MIGRATION_CLIENT_ID"] = "exampleappclientid00000000"
	env["AWESOME_AUTH_STORES_MIGRATION_REGION"] = "eu-west-1"
	env["AWESOME_AUTH_STORES_MIGRATION_MODE"] = MigrationModeDualRead

	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := cfg.Stores.Migration
	if m.Source != MigrationSourceCognito || m.UserPoolID != "eu-west-1_EXAMPLE00" ||
		m.ClientID != "exampleappclientid00000000" || m.Region != "eu-west-1" || m.Mode != MigrationModeDualRead {
		t.Fatalf("migration = %+v", m)
	}
	if !m.DualRead() || !m.VerifierConfigured() {
		t.Errorf("the loaded block does not report itself active: %+v", m)
	}
	// Every knob must report the variable it came from, so a diagnostic can tell
	// an operator where to fix a value rather than only what is wrong with it.
	for _, path := range []string{
		"stores.migration.source", "stores.migration.userPoolId",
		"stores.migration.clientId", "stores.migration.region", "stores.migration.mode",
	} {
		if src := cfg.Source(path); !strings.HasPrefix(src, "AWESOME_AUTH_STORES_MIGRATION_") {
			t.Errorf("Source(%q) = %q, want the environment variable that supplied it", path, src)
		}
	}
}

// The vocabulary is refused before RS-13 asks whether the combination is usable,
// so a misspelling is reported as a misspelling.
func TestMigrationVocabularyIsValidated(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, path string
		mutate     func(Document)
	}{
		{"an unknown source", "stores.migration.source", func(doc Document) {
			set(doc, "stores.migration.source", "auth0")
			set(doc, "stores.migration.userPoolId", "eu-west-1_EXAMPLE00")
			set(doc, "stores.migration.region", "eu-west-1")
		}},
		{"an unknown mode", "stores.migration.mode", func(doc Document) {
			set(doc, "stores.migration.mode", "read-through")
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := baseDoc()
			tc.mutate(doc)
			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			verr := validationError(t, err)
			for _, d := range verr.Diagnostics {
				if d.Path == tc.path && strings.Contains(d.Problem, "is not a valid value") {
					return
				}
			}
			t.Fatalf("no vocabulary diagnostic on %s:\n%v", tc.path, err)
		})
	}
}

// A complete block loads. Without this the RS-13 cases above could all be
// passing because the block is refused for some other reason entirely.
func TestACompleteMigrationBlockLoads(t *testing.T) {
	t.Parallel()
	doc := baseDoc()
	set(doc, "stores.migration.source", MigrationSourceCognito)
	set(doc, "stores.migration.userPoolId", "eu-west-1_EXAMPLE00")
	set(doc, "stores.migration.clientId", "exampleappclientid00000000")
	set(doc, "stores.migration.region", "eu-west-1")
	set(doc, "stores.migration.mode", MigrationModeDualRead)

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("a complete migration block was refused: %v", err)
	}
	if !cfg.Stores.Migration.DualRead() {
		t.Error("the loaded block does not dual-read")
	}
}

// Only the DynamoDB driver carries the marker, and the rule that depends on it
// reads a capability rather than comparing a driver name.
func TestOnlyTheDynamoDBDriverHoldsTheMarker(t *testing.T) {
	t.Parallel()
	if !builtinCapabilities[StoreDriverDynamoDB].MigrationMarker {
		t.Error("the dynamodb driver does not report the marker capability, so RS-13 would refuse every migration")
	}
	for _, driver := range []string{StoreDriverMemory, StoreDriverPostgres} {
		if builtinCapabilities[driver].MigrationMarker {
			t.Errorf("the %q driver claims the marker capability; the marker is a DynamoDB profile attribute", driver)
		}
	}
}
