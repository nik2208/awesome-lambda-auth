package lambdahttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// funcURLEvent builds a realistic Lambda Function URL event. The payload is
// format 2.0 like the HTTP API's, but it never carries a stage segment and its
// domain is <url-id>.lambda-url.<region>.on.aws.
func funcURLEvent(mutate func(*events.LambdaFunctionURLRequest)) events.LambdaFunctionURLRequest {
	e := events.LambdaFunctionURLRequest{
		Version: "2.0",
		RawPath: "/auth/login",
		Headers: map[string]string{
			"host":              "abcd1234.lambda-url.eu-west-1.on.aws",
			"content-type":      "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for":   "203.0.113.7",
		},
		RequestContext: events.LambdaFunctionURLRequestContext{
			DomainName:   "abcd1234.lambda-url.eu-west-1.on.aws",
			DomainPrefix: "abcd1234",
			HTTP: events.LambdaFunctionURLRequestContextHTTPDescription{
				Method:   http.MethodPost,
				Path:     "/auth/login",
				Protocol: "HTTP/1.1",
				SourceIP: "203.0.113.7",
			},
		},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func TestFunctionURLInbound(t *testing.T) {
	tests := []struct {
		name  string
		event events.LambdaFunctionURLRequest
		opts  Options
		check func(t *testing.T, r *http.Request)
	}{
		{
			name: "cookies array becomes a readable Cookie header",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.Cookies = requestCookies
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "Cookie header", r.Header.Get("Cookie"),
					"__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111")
				assertLoginCookiesReadable(t, r)
			},
		},
		{
			name: "an empty entry in the cookies array is skipped",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.Cookies = []string{"csrf_token=zzz111", "", "  "}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "Cookie header", r.Header.Get("Cookie"), "csrf_token=zzz111")
				eq(t, "len(r.Cookies())", len(r.Cookies()), 1)
			},
		},
		{
			name: "nil header and query maps do not panic",
			event: events.LambdaFunctionURLRequest{
				Version: "2.0",
				RequestContext: events.LambdaFunctionURLRequestContext{
					HTTP: events.LambdaFunctionURLRequestContextHTTPDescription{Method: http.MethodGet},
				},
			},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/")
				eq(t, "rawQuery", r.URL.RawQuery, "")
				eq(t, "len(header)", len(r.Header), 0)
			},
		},
		{
			name:  "function urls are https and report the caller",
			event: funcURLEvent(nil),
			check: func(t *testing.T, r *http.Request) {
				if r.TLS == nil {
					t.Fatal("r.TLS = nil, want non-nil: function urls are https only")
				}
				eq(t, "host", r.Host, "abcd1234.lambda-url.eu-west-1.on.aws")
				eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
				eq(t, "method", r.Method, http.MethodPost)
			},
		},
		{
			name: "multi-value query from rawQueryString",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.RawQueryString = "scope=openid&scope=profile&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb"
			}),
			check: func(t *testing.T, r *http.Request) {
				q := r.URL.Query()
				eqSlice(t, `q["scope"]`, q["scope"], []string{"openid", "profile"})
				eq(t, "redirect_uri", q.Get("redirect_uri"), "https://app.example.com/cb")
			},
		},
		{
			name: "base64 body is decoded",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.Body = base64.StdEncoding.EncodeToString(binaryBody)
				e.IsBase64Encoded = true
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "contentLength", r.ContentLength, int64(len(binaryBody)))
			},
		},
		{
			name: "there is no stage to strip, and none is invented",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.RawPath = "/auth/login"
			}),
			opts: Options{StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "an explicit prefix is still stripped, e.g. behind CloudFront",
			event: funcURLEvent(func(e *events.LambdaFunctionURLRequest) {
				e.RawPath = "/api/auth/login"
			}),
			opts: Options{StagePrefix: "api"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mustNewRequest(t, tc.event, tc.opts))
		})
	}
}

func TestFunctionURLOutbound(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		check   func(t *testing.T, resp events.LambdaFunctionURLResponse)
	}{
		{
			name:    "three Set-Cookie headers survive in the cookies array",
			handler: loginHandler,
			check: func(t *testing.T, resp events.LambdaFunctionURLResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusOK)
				eqSlice(t, "cookies", resp.Cookies, loginCookies)
				if _, leaked := resp.Headers["Set-Cookie"]; leaked {
					t.Error("Set-Cookie leaked into the headers map; the function url response has no multiValueHeaders to fall back on")
				}
			},
		},
		{
			name:    "CORS headers and repeated Vary are preserved",
			handler: loginHandler,
			check: func(t *testing.T, resp events.LambdaFunctionURLResponse) {
				eqMap(t, "headers", resp.Headers, map[string]string{
					"Content-Type":                     "application/json",
					"Access-Control-Allow-Origin":      "https://app.example.com",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Expose-Headers":    "X-Request-Id",
					"Vary":                             "Origin,Cookie,Access-Control-Request-Headers",
				})
				eq(t, "body", resp.Body, `{"user":{"id":"u_1"}}`)
			},
		},
		{
			name:    "binary body is base64-encoded",
			handler: binaryHandler,
			check: func(t *testing.T, resp events.LambdaFunctionURLResponse) {
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, true)
				eq(t, "body", resp.Body, base64.StdEncoding.EncodeToString(binaryBody))
			},
		},
		{
			name: "a flushing handler is buffered rather than rejected",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
				f, ok := w.(http.Flusher)
				if !ok {
					t.Error("ResponseWriter does not implement http.Flusher")
					return
				}
				f.Flush()
				_, _ = w.Write([]byte("event: ping\ndata: {}\n\n"))
			},
			check: func(t *testing.T, resp events.LambdaFunctionURLResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusOK)
				eq(t, "body", resp.Body, "event: ping\ndata: {}\n\nevent: ping\ndata: {}\n\n")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New(tc.handler, Options{})
			resp, err := a.HandleFunctionURL(context.Background(), funcURLEvent(nil))
			if err != nil {
				t.Fatalf("HandleFunctionURL: %v", err)
			}
			tc.check(t, resp)
		})
	}
}
