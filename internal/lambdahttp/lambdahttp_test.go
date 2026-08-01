package lambdahttp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// ---------------------------------------------------------------------------
// shared fixtures
// ---------------------------------------------------------------------------

// loginCookies is the three-cookie set an auth login response carries. If an
// adapter can only express one of these, login half-works: the browser keeps
// the access token and silently loses refresh and CSRF.
var loginCookies = []string{
	"__Host-access_token=aaa.bbb.ccc; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=900",
	"__Host-refresh_token=rrr.sss.ttt; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800",
	"csrf_token=zzz111; Path=/; Secure; SameSite=Lax; Max-Age=900",
}

// requestCookies is the same three cookies as a client would send them back.
var requestCookies = []string{
	"__Host-access_token=aaa.bbb.ccc",
	"__Host-refresh_token=rrr.sss.ttt",
	"csrf_token=zzz111",
}

// binaryBody is deliberately not valid UTF-8 (a PNG signature plus a lone
// 0xff), so it must come back base64-encoded.
var binaryBody = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a, 0xff, 0xfe, 0x00}

// loginHandler writes the response an auth login produces: JSON body, three
// Set-Cookie headers, and a CORS-with-credentials header set including a
// repeated Vary.
func loginHandler(w http.ResponseWriter, _ *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Access-Control-Allow-Origin", "https://app.example.com")
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", "X-Request-Id")
	h.Add("Vary", "Origin")
	h.Add("Vary", "Cookie")
	h.Add("Vary", "Access-Control-Request-Headers")
	for _, c := range loginCookies {
		h.Add("Set-Cookie", c)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"user":{"id":"u_1"}}`)
}

// binaryHandler writes a non-UTF-8 body.
func binaryHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(binaryBody)
}

// recorded holds what the wrapped handler saw.
type recorded struct {
	req  *http.Request
	body []byte
}

// capturingHandler returns a handler that records the request it served (with
// the body already drained and restored) before delegating to next.
func capturingHandler(next http.HandlerFunc) (http.Handler, *recorded) {
	rec := &recorded{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err == nil {
			rec.body = b
			r.Body = io.NopCloser(bytes.NewReader(b))
		}
		rec.req = r
		if next != nil {
			next(w, r)
		}
	})
	return h, rec
}

// ---------------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------------

func eq[T comparable](t *testing.T, what string, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

func eqSlice[T comparable](t *testing.T, what string, got, want []T) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

func eqMap(t *testing.T, what string, got, want map[string]string) {
	t.Helper()
	if !maps.Equal(got, want) {
		t.Errorf("%s = %#v, want %#v", what, got, want)
	}
}

// cookieValue reads a cookie through the standard library, which is the whole
// point: whatever the event shape delivered, http.Request.Cookie must find it.
func cookieValue(t *testing.T, r *http.Request, name string) string {
	t.Helper()
	c, err := r.Cookie(name)
	if err != nil {
		t.Fatalf("r.Cookie(%q): %v (Cookie header = %q)", name, err, r.Header.Get("Cookie"))
	}
	return c.Value
}

// assertLoginCookiesReadable checks all three auth cookies arrive intact.
func assertLoginCookiesReadable(t *testing.T, r *http.Request) {
	t.Helper()
	eq(t, `r.Cookie("__Host-access_token")`, cookieValue(t, r, "__Host-access_token"), "aaa.bbb.ccc")
	eq(t, `r.Cookie("__Host-refresh_token")`, cookieValue(t, r, "__Host-refresh_token"), "rrr.sss.ttt")
	eq(t, `r.Cookie("csrf_token")`, cookieValue(t, r, "csrf_token"), "zzz111")
	eq(t, "len(r.Cookies())", len(r.Cookies()), 3)
}

func mustNewRequest(t *testing.T, event any, opts Options) *http.Request {
	t.Helper()
	r, err := NewRequest(context.Background(), event, opts)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// Detect
// ---------------------------------------------------------------------------

func TestDetect(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		want    Kind
		wantErr error
	}{
		{
			name:    "alb via requestContext.elb",
			payload: `{"httpMethod":"GET","path":"/auth/login","requestContext":{"elb":{"targetGroupArn":"arn:aws:elasticloadbalancing:eu-west-1:000000000000:targetgroup/x/y"}}}`,
			want:    KindALB,
		},
		{
			name:    "http api v2 via version and stage",
			payload: `{"version":"2.0","routeKey":"$default","rawPath":"/auth/login","requestContext":{"stage":"$default","domainName":"abc.execute-api.eu-west-1.amazonaws.com","http":{"method":"POST"}}}`,
			want:    KindAPIGatewayV2,
		},
		{
			name:    "function url via lambda-url domain",
			payload: `{"version":"2.0","routeKey":"$default","rawPath":"/auth/login","requestContext":{"stage":"$default","domainName":"abcd1234.lambda-url.eu-west-1.on.aws","http":{"method":"POST"}}}`,
			want:    KindFunctionURL,
		},
		{
			name:    "function url without routeKey or stage",
			payload: `{"version":"2.0","rawPath":"/auth/login","requestContext":{"http":{"method":"POST"}}}`,
			want:    KindFunctionURL,
		},
		{
			name:    "rest proxy v1 via httpMethod",
			payload: `{"resource":"/{proxy+}","path":"/prod/auth/login","httpMethod":"POST","requestContext":{"stage":"prod","resourceId":"abc123"}}`,
			want:    KindAPIGatewayREST,
		},
		{
			name:    "v2 shaped payload with version omitted",
			payload: `{"rawPath":"/auth/login","requestContext":{"http":{"method":"GET"}}}`,
			want:    KindAPIGatewayV2,
		},
		{
			name:    "empty object is unsupported",
			payload: `{}`,
			want:    KindUnknown,
			wantErr: ErrUnsupportedEvent,
		},
		{
			name:    "s3 event is unsupported",
			payload: `{"Records":[{"eventSource":"aws:s3"}]}`,
			want:    KindUnknown,
			wantErr: ErrUnsupportedEvent,
		},
		{
			name:    "malformed json",
			payload: `{"version":`,
			want:    KindUnknown,
			wantErr: nil, // a json syntax error, not a sentinel
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Detect([]byte(tc.payload))
			eq(t, "kind", got, tc.want)
			switch {
			case tc.want == KindUnknown && err == nil:
				t.Fatalf("Detect(%s) = nil error, want an error", tc.payload)
			case tc.want != KindUnknown && err != nil:
				t.Fatalf("Detect(%s): unexpected error %v", tc.payload, err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Detect(%s) error = %v, want %v", tc.payload, err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// auto-detecting entry point
// ---------------------------------------------------------------------------

func TestHandleAutoDetects(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		// check receives the raw response JSON the adapter produced.
		check func(t *testing.T, raw []byte)
	}{
		{
			name: "http api v2 renders cookies array",
			payload: `{"version":"2.0","routeKey":"POST /auth/login","rawPath":"/auth/login","rawQueryString":"",
				"headers":{"host":"api.example.com"},
				"requestContext":{"stage":"$default","domainName":"api.example.com","http":{"method":"POST","path":"/auth/login","protocol":"HTTP/1.1","sourceIp":"203.0.113.7"}},
				"isBase64Encoded":false}`,
			check: func(t *testing.T, raw []byte) {
				var resp events.APIGatewayV2HTTPResponse
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				eq(t, "statusCode", resp.StatusCode, 200)
				eqSlice(t, "cookies", resp.Cookies, loginCookies)
			},
		},
		{
			name: "function url renders cookies array",
			payload: `{"version":"2.0","rawPath":"/auth/login","rawQueryString":"",
				"headers":{"host":"abcd.lambda-url.eu-west-1.on.aws"},
				"requestContext":{"domainName":"abcd.lambda-url.eu-west-1.on.aws","http":{"method":"POST","path":"/auth/login","protocol":"HTTP/1.1","sourceIp":"203.0.113.7"}},
				"isBase64Encoded":false}`,
			check: func(t *testing.T, raw []byte) {
				var resp events.LambdaFunctionURLResponse
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				eq(t, "statusCode", resp.StatusCode, 200)
				eqSlice(t, "cookies", resp.Cookies, loginCookies)
			},
		},
		{
			name: "rest v1 renders multiValueHeaders",
			payload: `{"resource":"/{proxy+}","path":"/auth/login","httpMethod":"POST",
				"headers":{"Host":"api.example.com"},
				"requestContext":{"stage":"prod","domainName":"api.example.com","protocol":"HTTP/1.1","identity":{"sourceIp":"203.0.113.7"}},
				"isBase64Encoded":false}`,
			check: func(t *testing.T, raw []byte) {
				var resp events.APIGatewayProxyResponse
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				eq(t, "statusCode", resp.StatusCode, 200)
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
				if _, dup := resp.Headers["Set-Cookie"]; dup {
					t.Errorf("Set-Cookie must not also appear in the single-value headers map")
				}
			},
		},
		{
			name: "alb renders multiValueHeaders",
			payload: `{"httpMethod":"POST","path":"/auth/login",
				"multiValueHeaders":{"host":["auth.example.com"],"x-forwarded-proto":["https"],"x-forwarded-for":["203.0.113.7"]},
				"requestContext":{"elb":{"targetGroupArn":"arn:aws:elasticloadbalancing:eu-west-1:000000000000:targetgroup/x/y"}},
				"isBase64Encoded":false}`,
			check: func(t *testing.T, raw []byte) {
				var resp events.ALBTargetGroupResponse
				if err := json.Unmarshal(raw, &resp); err != nil {
					t.Fatalf("unmarshal: %v", err)
				}
				eq(t, "statusCode", resp.StatusCode, 200)
				eq(t, "statusDescription", resp.StatusDescription, "200 OK")
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New(http.HandlerFunc(loginHandler), Options{})
			raw, err := a.Handle(context.Background(), json.RawMessage(tc.payload))
			if err != nil {
				t.Fatalf("Handle: %v", err)
			}
			tc.check(t, raw)
		})
	}
}

func TestHandleRejectsUnknownPayload(t *testing.T) {
	var seen error
	a := New(http.HandlerFunc(loginHandler), Options{
		OnError: func(_ context.Context, err error) { seen = err },
	})
	if _, err := a.Handle(context.Background(), json.RawMessage(`{"Records":[]}`)); !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatalf("Handle error = %v, want ErrUnsupportedEvent", err)
	}
	if !errors.Is(seen, ErrUnsupportedEvent) {
		t.Fatalf("OnError got %v, want ErrUnsupportedEvent", seen)
	}
}

// ---------------------------------------------------------------------------
// NewRequest, context plumbing, failure modes
// ---------------------------------------------------------------------------

func TestNewRequestRejectsUnsupportedEvent(t *testing.T) {
	_, err := NewRequest(context.Background(), events.SQSEvent{}, Options{})
	if !errors.Is(err, ErrUnsupportedEvent) {
		t.Fatalf("err = %v, want ErrUnsupportedEvent", err)
	}
}

func TestNewRequestAcceptsPointers(t *testing.T) {
	evt := &events.APIGatewayV2HTTPRequest{RawPath: "/auth/session"}
	evt.RequestContext.HTTP.Method = http.MethodGet
	r := mustNewRequest(t, evt, Options{})
	eq(t, "method", r.Method, http.MethodGet)
	eq(t, "path", r.URL.Path, "/auth/session")
}

func TestEventFromCarriesOriginalEvent(t *testing.T) {
	evt := events.APIGatewayV2HTTPRequest{RawPath: "/auth/session"}
	evt.RequestContext.RequestID = "req-42"
	evt.RequestContext.HTTP.Method = http.MethodGet

	r := mustNewRequest(t, evt, Options{})
	got, ok := EventFrom(r.Context()).(events.APIGatewayV2HTTPRequest)
	if !ok {
		t.Fatalf("EventFrom = %T, want events.APIGatewayV2HTTPRequest", EventFrom(r.Context()))
	}
	eq(t, "requestId", got.RequestContext.RequestID, "req-42")
	eq(t, "EventFrom(nil ctx)", EventFrom(nil), nil)
}

func TestContextIsPropagatedToHandler(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "lambda-ctx")

	h, rec := capturingHandler(nil)
	a := New(h, Options{})
	if _, err := a.HandleAPIGatewayV2(ctx, events.APIGatewayV2HTTPRequest{RawPath: "/"}); err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "ctx value", rec.req.Context().Value(ctxKey{}), any("lambda-ctx"))
}

func TestUndecodableBase64BodyYields400(t *testing.T) {
	var seen error
	called := false
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	a := New(h, Options{OnError: func(_ context.Context, err error) { seen = err }})

	resp, err := a.HandleAPIGatewayV2(context.Background(), events.APIGatewayV2HTTPRequest{
		RawPath:         "/auth/login",
		Body:            "!!! definitely not base64 !!!",
		IsBase64Encoded: true,
	})
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2 returned a lambda error, want a 400 response: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusBadRequest)
	eq(t, "body", resp.Body, "")
	eq(t, "handler called", called, false)
	if !errors.Is(seen, ErrBadRequestEvent) {
		t.Fatalf("OnError got %v, want ErrBadRequestEvent", seen)
	}
}

func TestHandlerPanicBecomes500(t *testing.T) {
	var seen error
	a := New(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), Options{OnError: func(_ context.Context, err error) { seen = err }})

	resp, err := a.HandleAPIGatewayV2(context.Background(), events.APIGatewayV2HTTPRequest{RawPath: "/auth/login"})
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusInternalServerError)
	if seen == nil || !strings.Contains(seen.Error(), "handler panic: boom") {
		t.Fatalf("OnError got %v, want a wrapped handler panic", seen)
	}
}

func TestNilHandlerIsNotFound(t *testing.T) {
	resp, err := New(nil, Options{}).HandleAPIGatewayV2(context.Background(),
		events.APIGatewayV2HTTPRequest{RawPath: "/auth/login"})
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusNotFound)
}

// ---------------------------------------------------------------------------
// header splitting policy
// ---------------------------------------------------------------------------

func TestSplitHeadersPolicy(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		headers map[string]string
		key     string
		want    []string
	}{
		{
			name:    "default splits x-forwarded-proto",
			headers: map[string]string{"x-forwarded-proto": "https,https"},
			key:     "X-Forwarded-Proto",
			want:    []string{"https", "https"},
		},
		{
			name:    "default splits x-forwarded-for and trims spaces",
			headers: map[string]string{"x-forwarded-for": "203.0.113.7, 70.41.3.18,150.172.238.178"},
			key:     "X-Forwarded-For",
			want:    []string{"203.0.113.7", "70.41.3.18", "150.172.238.178"},
		},
		{
			name:    "default leaves accept joined so Get stays useful",
			headers: map[string]string{"accept": "text/html,application/json"},
			key:     "Accept",
			want:    []string{"text/html,application/json"},
		},
		{
			name:    "default never splits cookie",
			headers: map[string]string{"cookie": "a=1,2; b=3"},
			key:     "Cookie",
			want:    []string{"a=1,2; b=3"},
		},
		{
			name:    "explicit empty slice disables splitting",
			opts:    Options{SplitHeaders: []string{}},
			headers: map[string]string{"x-forwarded-proto": "https,http"},
			key:     "X-Forwarded-Proto",
			want:    []string{"https,http"},
		},
		{
			name:    "custom list is honoured case-insensitively",
			opts:    Options{SplitHeaders: []string{"x-custom-list"}},
			headers: map[string]string{"x-custom-list": "a, b"},
			key:     "X-Custom-List",
			want:    []string{"a", "b"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustNewRequest(t, events.APIGatewayV2HTTPRequest{RawPath: "/", Headers: tc.headers}, tc.opts)
			eqSlice(t, "r.Header.Values("+tc.key+")", r.Header.Values(tc.key), tc.want)
		})
	}
}

func TestDefaultSplitHeadersIsStable(t *testing.T) {
	eqSlice(t, "DefaultSplitHeaders()", DefaultSplitHeaders(), []string{
		"Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto",
	})
}
