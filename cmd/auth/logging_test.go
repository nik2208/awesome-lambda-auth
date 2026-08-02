package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRedactionCoversEveryListedKey walks the published deny-list rather than a
// hand-picked sample, so a key added to the list without being honoured fails
// here.
func TestRedactionCoversEveryListedKey(t *testing.T) {
	t.Parallel()
	const canary = "eyJhbGciOiJIUzI1NiJ9.super-secret-value.signature"

	for _, key := range RedactedLogKeys() {
		var buf bytes.Buffer
		newLogger(&buf, slog.LevelDebug).Info("probe", slog.String(key, canary))
		out := buf.String()

		if strings.Contains(out, canary) {
			t.Errorf("key %q leaked its value: %s", key, out)
		}
		if !strings.Contains(out, RedactedValue) {
			t.Errorf("key %q was not replaced with %s: %s", key, RedactedValue, out)
		}
	}
}

// TestRedactionIsCaseInsensitive: an attribute may be built from a header name
// or a JSON field name, and the two spell the same secret differently.
func TestRedactionIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	const canary = "Bearer abc.def.ghi"

	for _, key := range []string{"Authorization", "AUTHORIZATION", "authorization", "Set-Cookie", "AccessToken"} {
		var buf bytes.Buffer
		newLogger(&buf, slog.LevelDebug).Info("probe", slog.String(key, canary))
		if strings.Contains(buf.String(), canary) {
			t.Errorf("key %q leaked its value: %s", key, buf.String())
		}
	}
}

// TestRedactionSurvivesWith proves the redaction rides on the handler and not
// on the call site, so a logger derived with .With cannot bypass it.
func TestRedactionSurvivesWith(t *testing.T) {
	t.Parallel()
	const canary = "hunter2-the-actual-password"

	var buf bytes.Buffer
	newLogger(&buf, slog.LevelDebug).
		With(slog.String("password", canary)).
		With(slog.String("requestId", "req-1")).
		Info("probe")

	out := buf.String()
	if strings.Contains(out, canary) {
		t.Errorf("a With-attached secret leaked: %s", out)
	}
	if !strings.Contains(out, "req-1") {
		t.Errorf("redaction swallowed a non-secret attribute: %s", out)
	}
}

// TestNonSecretAttributesSurvive: over-redacting is its own failure, because a
// log nobody can read is a log nobody keeps.
func TestNonSecretAttributesSurvive(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	newLogger(&buf, slog.LevelDebug).Info("probe",
		slog.String("path", "/auth/login"),
		slog.String("method", "POST"),
		slog.Int("status", 200),
		slog.String("userId", "usr_123"))

	out := buf.String()
	for _, want := range []string{"/auth/login", "POST", "200", "usr_123"} {
		if !strings.Contains(out, want) {
			t.Errorf("attribute %q was redacted but should not be: %s", want, out)
		}
	}
}

// TestAccessLogOmitsCredentialBearingParts pins what the request line does NOT
// contain: the query string (email flows carry single-use tokens there), the
// headers (Cookie, Authorization) and the body (passwords).
func TestAccessLogOmitsCredentialBearingParts(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelDebug)

	h := accessLog(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest(http.MethodPost, "/auth/reset-password?token=single-use-token-value", strings.NewReader(`{"password":"hunter2"}`))
	req.Header.Set("Authorization", "Bearer leaked.access.token")
	req.Header.Set("Cookie", "accessToken=leaked-cookie-value")
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	for _, forbidden := range []string{"single-use-token-value", "leaked.access.token", "leaked-cookie-value", "hunter2"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("access log leaked %q: %s", forbidden, out)
		}
	}
	for _, want := range []string{`"method":"POST"`, `"path":"/auth/reset-password"`, `"status":418`} {
		if !strings.Contains(out, want) {
			t.Errorf("access log is missing %s: %s", want, out)
		}
	}
}

// TestAccessLogUsesTheRequestScopedLogger: a line has to be traceable to an
// invocation, which is what the request id on the context logger is for.
func TestAccessLogUsesTheRequestScopedLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	scoped := newLogger(&buf, slog.LevelDebug).With(slog.String("requestId", "req-abc-123"))

	h := accessLog(newLogger(&bytes.Buffer{}, slog.LevelDebug), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	h.ServeHTTP(httptest.NewRecorder(), req.WithContext(withLogger(context.Background(), scoped)))

	if !strings.Contains(buf.String(), "req-abc-123") {
		t.Errorf("access log did not use the request-scoped logger: %s", buf.String())
	}
}

// TestStatusWriterDefaultsToOK: a handler that writes nothing produces a 200
// once the recorder is rendered, and the log has to say the same thing.
func TestStatusWriterDefaultsToOK(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	h := accessLog(newLogger(&buf, slog.LevelDebug), http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if !strings.Contains(buf.String(), `"status":200`) {
		t.Errorf("silent handler logged something other than 200: %s", buf.String())
	}
}

func TestLogLevel(t *testing.T) {
	t.Parallel()
	cases := map[string]slog.Level{
		"debug":    slog.LevelDebug,
		"DEBUG":    slog.LevelDebug,
		" warn ":   slog.LevelWarn,
		"warning":  slog.LevelWarn,
		"error":    slog.LevelError,
		"info":     slog.LevelInfo,
		"":         slog.LevelInfo,
		"nonsense": slog.LevelInfo, // never fail the deployment over a log level
	}
	for raw, want := range cases {
		getenv := func(string) (string, bool) { return raw, true }
		if got := logLevel(getenv); got != want {
			t.Errorf("logLevel(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestLoggerFromFallsBack(t *testing.T) {
	t.Parallel()
	fallback := newLogger(&bytes.Buffer{}, slog.LevelDebug)
	if got := loggerFrom(context.Background(), fallback); got != fallback {
		t.Errorf("loggerFrom returned %p, want the fallback %p", got, fallback)
	}
	if loggerFrom(context.Background(), nil) == nil {
		t.Error("loggerFrom(nil fallback) returned nil")
	}
}
