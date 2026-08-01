package lambdahttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// v2Event builds a realistic HTTP API payload format 2.0 event and applies the
// per-case mutation.
func v2Event(mutate func(*events.APIGatewayV2HTTPRequest)) events.APIGatewayV2HTTPRequest {
	e := events.APIGatewayV2HTTPRequest{
		Version:  "2.0",
		RouteKey: "$default",
		RawPath:  "/auth/login",
		Headers: map[string]string{
			"host":              "api.example.com",
			"content-type":      "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for":   "203.0.113.7",
			"user-agent":        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		},
		RequestContext: events.APIGatewayV2HTTPRequestContext{
			Stage:      "$default",
			DomainName: "api.example.com",
			HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{
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

func TestAPIGatewayV2Inbound(t *testing.T) {
	tests := []struct {
		name  string
		event events.APIGatewayV2HTTPRequest
		opts  Options
		check func(t *testing.T, r *http.Request)
	}{
		{
			name: "cookies array becomes a readable Cookie header",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Cookies = requestCookies
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "Cookie header", r.Header.Get("Cookie"),
					"__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111")
				assertLoginCookiesReadable(t, r)
			},
		},
		{
			name:  "no cookies array leaves no Cookie header",
			event: v2Event(nil),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "Cookie header", r.Header.Get("Cookie"), "")
				eq(t, "len(r.Cookies())", len(r.Cookies()), 0)
			},
		},
		{
			name: "nil header and query maps do not panic",
			event: events.APIGatewayV2HTTPRequest{
				Version: "2.0",
				RequestContext: events.APIGatewayV2HTTPRequestContext{
					HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodGet},
				},
			},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "method", r.Method, http.MethodGet)
				eq(t, "path", r.URL.Path, "/")
				eq(t, "rawQuery", r.URL.RawQuery, "")
				eq(t, "host", r.Host, "")
				eq(t, "remoteAddr", r.RemoteAddr, "")
				eq(t, "contentLength", r.ContentLength, int64(0))
				eq(t, "len(header)", len(r.Header), 0)
			},
		},
		{
			name: "method, host, proto and remote address",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RequestContext.HTTP.Protocol = "HTTP/1.1"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "method", r.Method, http.MethodPost)
				eq(t, "host", r.Host, "api.example.com")
				eq(t, "Host header removed", r.Header.Get("Host"), "")
				eq(t, "proto", r.Proto, "HTTP/1.1")
				eq(t, "protoMajor", r.ProtoMajor, 1)
				eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
				eq(t, "requestURI", r.RequestURI, "/auth/login")
			},
		},
		{
			name:  "lowercased headers are canonicalised",
			event: v2Event(nil),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "Content-Type", r.Header.Get("Content-Type"), "application/json")
				eq(t, "User-Agent", r.Header.Get("User-Agent"), "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
				if _, dup := r.Header["content-type"]; dup {
					t.Errorf("header map kept the lowercase key as well as the canonical one")
				}
				eq(t, "len(header)", len(r.Header), 4) // host lifted out of the map
			},
		},
		{
			name:  "api gateway is https by default",
			event: v2Event(nil),
			check: func(t *testing.T, r *http.Request) {
				if r.TLS == nil {
					t.Fatal("r.TLS = nil, want a non-nil ConnectionState for an https request")
				}
				eq(t, "TLS.ServerName", r.TLS.ServerName, "api.example.com")
			},
		},
		{
			name: "x-forwarded-proto http wins over the default",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Headers["x-forwarded-proto"] = "http"
			}),
			check: func(t *testing.T, r *http.Request) {
				if r.TLS != nil {
					t.Fatal("r.TLS != nil, want nil when x-forwarded-proto is http")
				}
			},
		},
		{
			name: "chained x-forwarded-proto is split and still reads https",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Headers["x-forwarded-proto"] = "https,https"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "X-Forwarded-Proto", r.Header.Get("X-Forwarded-Proto"), "https")
				eqSlice(t, "X-Forwarded-Proto values", r.Header.Values("X-Forwarded-Proto"), []string{"https", "https"})
				if r.TLS == nil {
					t.Fatal("r.TLS = nil, want non-nil")
				}
			},
		},
		{
			name: "rawQueryString drives multi-value query parsing",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/auth/oauth/google"
				e.RawQueryString = "scope=openid&scope=email&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=a+b"
			}),
			check: func(t *testing.T, r *http.Request) {
				q := r.URL.Query()
				eqSlice(t, `q["scope"]`, q["scope"], []string{"openid", "email"})
				eq(t, "redirect_uri", q.Get("redirect_uri"), "https://app.example.com/cb")
				eq(t, "state", q.Get("state"), "a b")
				eq(t, "rawQuery", r.URL.RawQuery,
					"scope=openid&scope=email&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=a+b")
			},
		},
		{
			name: "percent-encoded path is decoded but round-trips escaped",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/auth/users/user%2Bone%40example.com"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "URL.Path", r.URL.Path, "/auth/users/user+one@example.com")
				eq(t, "URL.EscapedPath()", r.URL.EscapedPath(), "/auth/users/user%2Bone%40example.com")
			},
		},
		{
			name: "plain text body",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Body = `{"email":"a@example.com","password":"hunter2"}`
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "contentLength", r.ContentLength, int64(46))
				eq(t, "Content-Length header", r.Header.Get("Content-Length"), "46")
			},
		},
		{
			name: "base64 body is decoded",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Body = base64.StdEncoding.EncodeToString(binaryBody)
				e.IsBase64Encoded = true
				e.Headers["content-type"] = "application/octet-stream"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "contentLength", r.ContentLength, int64(len(binaryBody)))
				eq(t, "Content-Length header", r.Header.Get("Content-Length"), "11")
			},
		},
		{
			name: "stage prefix is kept when nothing is configured",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/prod/auth/login"
				e.RequestContext.Stage = "prod"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/prod/auth/login")
			},
		},
		{
			name: "explicit StagePrefix is stripped",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/prod/auth/login"
				e.RequestContext.Stage = "prod"
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
				eq(t, "requestURI", r.RequestURI, "/auth/login")
			},
		},
		{
			name: "StagePrefix accepts a leading slash",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/prod/auth/login"
			}),
			opts: Options{StagePrefix: "/prod/"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "StripStageFromEvent uses requestContext.stage",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/v1/auth/login"
				e.RequestContext.Stage = "v1"
			}),
			opts: Options{StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "the $default stage is never stripped",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/auth/login"
				e.RequestContext.Stage = "$default"
			}),
			opts: Options{StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "a path equal to the stage becomes root",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/prod"
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/")
			},
		},
		{
			name: "a lookalike prefix is not stripped",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/production/auth/login"
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/production/auth/login")
			},
		},
		{
			name: "stage stripping keeps the escaped path consistent",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RawPath = "/prod/auth/users/user%40example.com"
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "URL.Path", r.URL.Path, "/auth/users/user@example.com")
				eq(t, "URL.EscapedPath()", r.URL.EscapedPath(), "/auth/users/user%40example.com")
				eq(t, "requestURI", r.RequestURI, "/auth/users/user%40example.com")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mustNewRequest(t, tc.event, tc.opts))
		})
	}
}

func TestAPIGatewayV2InboundBodyBytes(t *testing.T) {
	h, rec := capturingHandler(nil)
	a := New(h, Options{})
	evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) {
		e.Body = base64.StdEncoding.EncodeToString(binaryBody)
		e.IsBase64Encoded = true
	})
	if _, err := a.HandleAPIGatewayV2(context.Background(), evt); err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eqSlice(t, "handler body", rec.body, binaryBody)
}

func TestAPIGatewayV2Outbound(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		check   func(t *testing.T, resp events.APIGatewayV2HTTPResponse)
	}{
		{
			name:    "three Set-Cookie headers survive in the cookies array",
			handler: loginHandler,
			check: func(t *testing.T, resp events.APIGatewayV2HTTPResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusOK)
				eqSlice(t, "cookies", resp.Cookies, loginCookies)
				if _, leaked := resp.Headers["Set-Cookie"]; leaked {
					t.Error("Set-Cookie leaked into the headers map, where v2 would comma-join it")
				}
			},
		},
		{
			name:    "CORS headers and repeated Vary are preserved",
			handler: loginHandler,
			check: func(t *testing.T, resp events.APIGatewayV2HTTPResponse) {
				eqMap(t, "headers", resp.Headers, map[string]string{
					"Content-Type":                     "application/json",
					"Access-Control-Allow-Origin":      "https://app.example.com",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Expose-Headers":    "X-Request-Id",
					"Vary":                             "Origin,Cookie,Access-Control-Request-Headers",
				})
				eq(t, "body", resp.Body, `{"user":{"id":"u_1"}}`)
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, false)
			},
		},
		{
			name:    "binary body is base64-encoded",
			handler: binaryHandler,
			check: func(t *testing.T, resp events.APIGatewayV2HTTPResponse) {
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, true)
				eq(t, "body", resp.Body, base64.StdEncoding.EncodeToString(binaryBody))
				eq(t, "Content-Type", resp.Headers["Content-Type"], "image/png")
			},
		},
		{
			name: "explicit status code with an empty body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			check: func(t *testing.T, resp events.APIGatewayV2HTTPResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusNoContent)
				eq(t, "body", resp.Body, "")
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, false)
				eq(t, "headers", len(resp.Headers), 0)
			},
		},
		{
			name: "an unauthorised response keeps its clearing cookies",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Set-Cookie", "__Host-access_token=; Path=/; Max-Age=0")
				w.Header().Add("Set-Cookie", "__Host-refresh_token=; Path=/; Max-Age=0")
				w.Header().Set("WWW-Authenticate", `Bearer realm="auth", error="invalid_token"`)
				w.WriteHeader(http.StatusUnauthorized)
			},
			check: func(t *testing.T, resp events.APIGatewayV2HTTPResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusUnauthorized)
				eqSlice(t, "cookies", resp.Cookies, []string{
					"__Host-access_token=; Path=/; Max-Age=0",
					"__Host-refresh_token=; Path=/; Max-Age=0",
				})
				// http.Header canonicalises to "Www-Authenticate"; header names
				// are case-insensitive on the wire, so this is the name the
				// adapter emits and clients match case-insensitively.
				eq(t, "Www-Authenticate", resp.Headers["Www-Authenticate"],
					`Bearer realm="auth", error="invalid_token"`)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New(tc.handler, Options{})
			resp, err := a.HandleAPIGatewayV2(context.Background(), v2Event(nil))
			if err != nil {
				t.Fatalf("HandleAPIGatewayV2: %v", err)
			}
			tc.check(t, resp)
		})
	}
}

// TestAPIGatewayV2HeaderRoundTrip proves an inbound header set comes back out
// with the same names and values: canonicalised once, never duplicated.
func TestAPIGatewayV2HeaderRoundTrip(t *testing.T) {
	echo := func(w http.ResponseWriter, r *http.Request) {
		for name, values := range r.Header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(http.StatusOK)
	}

	evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) {
		e.Cookies = requestCookies
		e.Headers = map[string]string{
			"host":              "api.example.com",
			"content-type":      "application/json",
			"x-forwarded-proto": "https",
			"authorization":     "Bearer aaa.bbb.ccc",
		}
	})

	resp, err := New(http.HandlerFunc(echo), Options{}).HandleAPIGatewayV2(context.Background(), evt)
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eqMap(t, "headers", resp.Headers, map[string]string{
		"Content-Type":      "application/json",
		"X-Forwarded-Proto": "https",
		"Authorization":     "Bearer aaa.bbb.ccc",
		"Cookie":            "__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111",
	})
	eq(t, "cookies", len(resp.Cookies), 0)
}
