package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// baseDoc is the smallest document that loads cleanly: a schema version, a public
// URL that is not a shared AWS domain, and a real store driver. Every rule test
// starts from it and breaks exactly one thing, so an assertion on a rule cannot
// pass by accident because something else was also wrong.
func baseDoc() Document {
	return Document{
		"schemaVersion": 1,
		"deployment": map[string]any{
			"publicUrl": "https://auth.example.com",
		},
		"stores": map[string]any{
			"driver":     "dynamodb",
			"connection": map[string]any{"tableName": "awesome-auth"},
		},
	}
}

// baseEnv supplies the two signing secrets through their documented variables,
// which is the development-grade path of the secrets resolution order.
func baseEnv() map[string]string {
	return map[string]string{
		"AWESOME_AUTH_JWT_ACCESS_SECRET":  strings.Repeat("a", 40),
		"AWESOME_AUTH_JWT_REFRESH_SECRET": strings.Repeat("b", 40),
	}
}

func getenvFrom(env map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}
}

// set writes a dotted path into a document, creating intermediate objects. It
// keeps the rule table readable: one line per knob under test.
func set(doc Document, path string, value any) {
	parts := strings.Split(path, ".")
	cur := map[string]any(doc)
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

// validationError unwraps the error Load returned, failing the test when it is
// not the aggregate type.
func validationError(t *testing.T, err error) *ValidationError {
	t.Helper()
	if err == nil {
		t.Fatal("expected a validation error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T: %v", err, err)
	}
	return ve
}

// requireRule asserts that a specific rule fired at a specific path, and that the
// diagnostic actually tells the operator what to do. "an error occurred" is not
// what this package promises.
func requireRule(t *testing.T, err error, rule, path string) Diagnostic {
	t.Helper()
	ve := validationError(t, err)
	for _, d := range ve.Diagnostics {
		if d.Rule == rule && d.Path == path {
			if d.Problem == "" {
				t.Errorf("%s at %s has no problem statement", rule, path)
			}
			if d.Remedy == "" {
				t.Errorf("%s at %s has no remedy", rule, path)
			}
			if !strings.Contains(d.Error(), path) {
				t.Errorf("rendered diagnostic does not name the path: %s", d.Error())
			}
			return d
		}
	}
	t.Fatalf("expected rule %s at path %s; got:\n%v", rule, path, ve)
	return Diagnostic{}
}

func requireNoRule(t *testing.T, err error, rule string) {
	t.Helper()
	if err == nil {
		return
	}
	ve := validationError(t, err)
	if d := ve.Rule(rule); d != nil {
		t.Fatalf("did not expect rule %s, got: %s", rule, d.Error())
	}
}

// sprint renders a value the way a careless log statement would, so the leak test
// exercises the same path.
func sprint(v any) string { return fmt.Sprintf("%+v", v) }

// fakeResolver is a SecretResolver over a fixed table.
type fakeResolver struct {
	name string
	vals map[string]string
}

func (f fakeResolver) Name() string { return f.name }

func (f fakeResolver) Resolve(_ context.Context, ref string) (string, error) {
	if v, ok := f.vals[ref]; ok {
		return v, nil
	}
	return "", fmt.Errorf("%w: %s has no entry for %s", ErrSecretNotFound, f.name, ref)
}

// deniedResolver fails with something other than a miss, which must stop the
// resolution walk instead of falling through to a weaker store.
type deniedResolver struct{ name string }

func (f deniedResolver) Name() string { return f.name }

func (f deniedResolver) Resolve(_ context.Context, ref string) (string, error) {
	return "", fmt.Errorf("%s: access denied reading %s", f.name, ref)
}
