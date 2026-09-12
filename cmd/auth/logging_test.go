package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	auth "github.com/nik2208/awesome-go-auth"
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

// ── the correlation id ──────────────────────────────────────────────────────

// correlated wraps h the way New does: the core's carrier outermost, then
// correlationScope, then the access log. Every test below drives that
// composition rather than a middleware in isolation, because the order of the
// three is the thing that can break.
func correlated(log *slog.Logger, h http.Handler) http.Handler {
	return auth.EventContextMiddleware(auth.HTTPConfig{})(correlationScope(log)(accessLog(log, h)))
}

// TestCorrelationIDReachesEveryLineOfTheRequest is the claim: one header in, and
// both the handler's own line and the access log carry it — because the id goes
// onto the logger, not into a log call.
func TestCorrelationIDReachesEveryLineOfTheRequest(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelDebug)
	h := correlated(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loggerFrom(r.Context(), nil).Info("handler line")
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set(auth.CorrelationIDHeader, "trace-42")
	h.ServeHTTP(httptest.NewRecorder(), req)

	lines := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1
	if lines != 2 {
		t.Fatalf("expected the handler line and the access log, got %d line(s): %s", lines, buf.String())
	}
	if got := strings.Count(buf.String(), `"correlationId":"trace-42"`); got != 2 {
		t.Errorf("correlationId is on %d of 2 lines: %s", got, buf.String())
	}
}

// TestNoCorrelationHeaderLogsNoCorrelationID: the core does not mint an id for a
// caller that sent none, and neither does this. An invented id joins nothing to
// anything, and a reader could not tell it from a real one.
func TestNoCorrelationHeaderLogsNoCorrelationID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelDebug)
	h := correlated(log, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if strings.Contains(buf.String(), CorrelationIDLogKey) {
		t.Errorf("a request with no header produced a %s attribute: %s", CorrelationIDLogKey, buf.String())
	}
}

// TestTheLoggedCorrelationIDIsTheCarriersValue is the "the two cannot disagree"
// assertion, and it is deliberately written as an identity rather than against a
// literal: whatever the core's carrier resolved for this request is what the log
// says, so a change in EventContextFromRequest — the reference's array-first
// quirk for a repeated header, a host-supplied ClientIP, a new normalisation —
// moves both ends together or fails here.
func TestTheLoggedCorrelationIDIsTheCarriersValue(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	log := newLogger(&buf, slog.LevelDebug)

	var fromCarrier string
	h := correlated(log, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ec, ok := auth.EventContextFromContext(r.Context())
		if !ok {
			t.Error("no event context carrier reached the handler")
		}
		fromCarrier = ec.CorrelationID
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	// Sent twice, on two header lines. The reference takes the first
	// (node-auth auth.router.ts:407-410) and the port reproduces that; whatever
	// it takes, the log has to agree with it.
	req.Header.Add(auth.CorrelationIDHeader, "first-value")
	req.Header.Add(auth.CorrelationIDHeader, "second-value")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if fromCarrier == "" {
		t.Fatal("the carrier resolved no id, so this test proves nothing")
	}
	if !strings.Contains(buf.String(), `"`+CorrelationIDLogKey+`":"`+fromCarrier+`"`) {
		t.Errorf("the log does not carry the carrier's id %q: %s", fromCarrier, buf.String())
	}
	if strings.Contains(buf.String(), "second-value") {
		t.Errorf("the log took a value the carrier did not: %s", buf.String())
	}
}

// TestCorrelationIDIsBoundedInTheLog: the id is caller-supplied and CloudWatch
// bills by the ingested byte, so a 10 KB "correlation id" is 10 KB of somebody
// else's log bill on every request. Truncation is visible, so that a truncated
// id is never mistaken for a short one that simply matches nothing.
func TestCorrelationIDIsBoundedInTheLog(t *testing.T) {
	t.Parallel()

	long := strings.Repeat("a", maxCorrelationIDBytes*4)
	got := loggableCorrelationID(long)
	if len(got) > maxCorrelationIDBytes+len("…") {
		t.Errorf("logged id is %d bytes, want at most %d", len(got), maxCorrelationIDBytes+len("…"))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a truncated id is not visibly truncated: %q", got)
	}
	if short := loggableCorrelationID("  trace-42  "); short != "trace-42" {
		t.Errorf("loggableCorrelationID trimmed to %q, want %q", short, "trace-42")
	}
	// A multi-byte rune straddling the cut must not be halved: an invalid UTF-8
	// sequence in a log line is a line no query engine can index.
	if cut := loggableCorrelationID(strings.Repeat("é", maxCorrelationIDBytes)); !utf8.ValidString(cut) {
		t.Errorf("truncation produced invalid UTF-8: %q", cut)
	}
}

// TestOnlyAHeaderSafeCorrelationIDIsForwarded: net/http's transport refuses a
// header value outside 0x20..0x7E, so forwarding one unchecked would let a
// caller break this deployment's webhooks with a single request.
func TestOnlyAHeaderSafeCorrelationIDIsForwarded(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ raw, want string }{
		{"trace-42", "trace-42"},
		{"  trace-42 ", "trace-42"},
		{"", ""},
		{"bad\r\nX-Injected: 1", ""},
		{"bad\x00id", ""},
		{"é-not-ascii", ""},
		{strings.Repeat("a", maxCorrelationIDBytes+1), ""},
	} {
		if got := forwardableCorrelationID(tc.raw); got != tc.want {
			t.Errorf("forwardableCorrelationID(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

// TestCorrelatingTransportForwardsTheCarriersID drives the transport itself. The
// core builds every outbound request from the request's own context, so the id
// has to survive the hop without anything at the call site knowing about it.
func TestCorrelatingTransportForwardsTheCarriersID(t *testing.T) {
	t.Parallel()

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(auth.CorrelationIDHeader))
	}))
	t.Cleanup(srv.Close)

	client := correlatingClient(srv.Client())
	ctx := auth.ContextWithEventContext(context.Background(), auth.EventContext{CorrelationID: "trace-42"})

	do := func(reqCtx context.Context, preset string) {
		t.Helper()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		if preset != "" {
			req.Header.Set(auth.CorrelationIDHeader, preset)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		_ = resp.Body.Close()
	}

	do(ctx, "")                  // a carrier: forwarded
	do(context.Background(), "") // no carrier — a background job: no header
	do(ctx, "set-by-the-caller") // already set at the call site: left alone

	if want := []string{"trace-42", "", "set-by-the-caller"}; !slices.Equal(seen, want) {
		t.Errorf("the receiver saw %q, want %q", seen, want)
	}
}

// TestTheCorrelationIDCrossesTheWebhookBoundary is the propagation claim end to
// end, through the real Lambda event path: a caller's id arrives on a route,
// lands on this deployment's log line, and leaves on the outbound request the
// route causes — so the receiver's logs and these name the same request.
//
// Nothing between the two ends knows about it. The core builds the webhook
// request from the handler's context (delivery_webhook.go:207) and
// correlatingTransport reads the carrier off that context, which is why no
// delivery call site had to be touched.
func TestTheCorrelationIDCrossesTheWebhookBoundary(t *testing.T) {
	t.Parallel()

	rec := newWebhookReceiver(t)
	d := newDeliveryAppWith(t, webhookEnv(baseEnv(), rec.srv.URL+capabilityPath),
		func(o *Options) { o.HTTPClient = rec.srv.Client() })

	const owner = "correlated@example.test"
	d.register(t, owner)
	// Registration delivers too, and it was not correlated. Only what the next
	// request causes is the subject here.
	before := len(rec.deliveries())

	const id = "trace-e2e-1"
	if resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password",
		jsonHeaders(auth.CorrelationIDHeader, id), nil,
		`{"email":"`+owner+`"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password = %d, want 200 (body %s)", resp.StatusCode, resp.Body)
	}

	caused := rec.deliveries()[before:]
	if len(caused) == 0 {
		t.Fatal("the request caused no delivery, so this test proves nothing")
	}
	for _, delivery := range caused {
		if got := delivery.headers.Get(auth.CorrelationIDHeader); got != id {
			t.Errorf("the %s delivery carried %s %q, want the caller's %q",
				delivery.request.Kind, auth.CorrelationIDHeader, got, id)
		}
	}
	if !strings.Contains(d.log.String(), `"`+CorrelationIDLogKey+`":"`+id+`"`) {
		t.Errorf("the same id is not on this deployment's own log line:\n%s", d.log.String())
	}
}

// TestCorrelatingClientDoesNotMutateTheCallersClient: Options.HTTPClient belongs
// to whoever passed it, and a test that hands over an httptest server's client
// goes on using it afterwards.
func TestCorrelatingClientDoesNotMutateTheCallersClient(t *testing.T) {
	t.Parallel()

	base := &http.Client{Transport: http.DefaultTransport, Timeout: 7 * time.Second}
	wrapped := correlatingClient(base)

	if _, mutated := base.Transport.(correlatingTransport); mutated {
		t.Error("the caller's client was mutated")
	}
	if _, ok := wrapped.Transport.(correlatingTransport); !ok {
		t.Errorf("the returned client is not wrapped: %T", wrapped.Transport)
	}
	if wrapped.Timeout != base.Timeout {
		t.Errorf("wrapped timeout = %v, want the caller's %v", wrapped.Timeout, base.Timeout)
	}
	if nilled := correlatingClient(nil); nilled == nil || nilled.Transport == nil {
		t.Error("correlatingClient(nil) did not produce a usable client")
	}
}
