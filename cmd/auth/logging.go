package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"
)

// RedactedValue replaces the value of any attribute whose key is on the
// redaction list. It is a constant string rather than "" so that a redacted
// field is visibly redacted in the log, instead of looking like a field the
// caller forgot to set.
const RedactedValue = "[REDACTED]"

// redactedKeys is the explicit deny-list of attribute keys whose values never
// reach stdout. CloudWatch is queryable by anyone with logs:FilterLogEvents,
// which is a far larger set of people than those who may hold a session, so a
// token in a log line is a credential leak with an audit trail attached.
//
// The list is deny-by-key rather than deny-by-value on purpose: a value-shaped
// heuristic ("looks like a JWT") cannot be tested and fails open on the first
// format that was not anticipated, whereas a key that is not on this list is a
// reviewable omission. Every name is matched case-insensitively, and both the
// camelCase wire spelling and the HTTP header spelling are listed where they
// differ, because an attribute may be built from either.
var redactedKeys = []string{
	"accessToken",
	"access_token",
	"apiKey",
	"api_key",
	"authorization",
	"bearer",
	"bootstrapSecret",
	"clientSecret",
	"code",
	"cookie",
	"csrf",
	"csrfToken",
	"currentPassword",
	"jwt",
	"newPassword",
	"otp",
	"password",
	"passwordHash",
	"privateKey",
	"proxy-authorization",
	"refreshToken",
	"refresh_token",
	"secret",
	"session",
	"sessionToken",
	"set-cookie",
	"smsCode",
	"token",
	"tokenHash",
	"totp",
	"x-api-key",
	"x-csrf-token",
}

var redactedKeySet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(redactedKeys))
	for _, k := range redactedKeys {
		set[strings.ToLower(k)] = struct{}{}
	}
	return set
}()

// RedactedLogKeys returns the redaction list, sorted. Exported so a test can
// assert the list rather than the implementation, and so an operator can print
// what this build promises never to log.
func RedactedLogKeys() []string {
	out := make([]string, 0, len(redactedKeySet))
	for k := range redactedKeySet {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsRedactedLogKey reports whether an attribute key is redacted.
func IsRedactedLogKey(key string) bool {
	_, ok := redactedKeySet[strings.ToLower(key)]
	return ok
}

// newLogger returns the structured JSON logger the whole binary shares.
//
// Everything goes to stdout: CloudWatch captures both streams into the same log
// group, and splitting errors onto stderr only buys interleaving hazards.
func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if IsRedactedLogKey(a.Key) {
				return slog.String(a.Key, RedactedValue)
			}
			return a
		},
	}))
}

// LogLevelEnv names the variable that sets the log level. It is an operational
// knob, not a configuration knob: it must keep working when the configuration
// document is the thing that is broken, so it is deliberately outside the
// AWESOME_AUTH_* schema's refuse-to-start machinery.
const LogLevelEnv = "AWESOME_AUTH_LOG_LEVEL"

// logLevel reads LogLevelEnv. An unrecognised value falls back to info rather
// than failing: losing the deployment because a log level was misspelt would be
// a worse outcome than logging one level louder than intended.
func logLevel(getenv func(string) (string, bool)) slog.Level {
	raw, _ := getenv(LogLevelEnv)
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type loggerKey struct{}

// withLogger attaches a request-scoped logger to a context.
func withLogger(ctx context.Context, log *slog.Logger) context.Context {
	return context.WithValue(ctx, loggerKey{}, log)
}

// loggerFrom returns the request-scoped logger, or fallback when the context
// carries none.
func loggerFrom(ctx context.Context, fallback *slog.Logger) *slog.Logger {
	if log, ok := ctx.Value(loggerKey{}).(*slog.Logger); ok && log != nil {
		return log
	}
	if fallback != nil {
		return fallback
	}
	return slog.Default()
}

// statusWriter records what the handler wrote so the access log can report it.
type statusWriter struct {
	http.ResponseWriter
	status  int
	written int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.written += n
	return n, err
}

// Flush keeps the wrapped writer's http.Flusher behaviour reachable. The event
// adapter's recorder implements it, and a wrapper that swallowed it would make
// a streaming response path silently unavailable to any handler added later.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// accessLog emits one line per request.
//
// What is logged is the whole list: method, path, status, duration and response
// size. The query string is excluded because email-flow routes carry
// single-use tokens in it, headers are excluded because Cookie and
// Authorization live there, and the body is excluded because it carries
// passwords. Adding a field here means adding it to that argument.
func accessLog(fallback *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)

		status := sw.status
		if status == 0 {
			// A handler that returned without writing produces a 200 with an
			// empty body once the recorder is rendered.
			status = http.StatusOK
		}
		loggerFrom(r.Context(), fallback).Info("http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("durationMs", time.Since(start).Milliseconds()),
			slog.Int("responseBytes", sw.written),
		)
	})
}
