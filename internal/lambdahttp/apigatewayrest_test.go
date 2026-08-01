package lambdahttp

import (
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// restEvent builds a realistic API Gateway REST proxy (payload format 1.0)
// event. A default execute-api URL serves under /<stage>/, so the path carries
// the stage segment.
func restEvent(mutate func(*events.APIGatewayProxyRequest)) events.APIGatewayProxyRequest {
	e := events.APIGatewayProxyRequest{
		Resource:   "/{proxy+}",
		Path:       "/prod/auth/login",
		HTTPMethod: http.MethodPost,
		MultiValueHeaders: map[string][]string{
			"Host":              {"abc123.execute-api.eu-west-1.amazonaws.com"},
			"Content-Type":      {"application/json"},
			"X-Forwarded-Proto": {"https"},
			"X-Forwarded-For":   {"203.0.113.7"},
		},
		RequestContext: events.APIGatewayProxyRequestContext{
			Stage:      "prod",
			DomainName: "abc123.execute-api.eu-west-1.amazonaws.com",
			Protocol:   "HTTP/1.1",
			Path:       "/prod/auth/login",
			HTTPMethod: http.MethodPost,
			Identity:   events.APIGatewayRequestIdentity{SourceIP: "203.0.113.7"},
		},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func TestAPIGatewayRESTInbound(t *testing.T) {
	tests := []struct {
		name  string
		event events.APIGatewayProxyRequest
		opts  Options
		check func(t *testing.T, r *http.Request)
	}{
		{
			name: "one Cookie header with three pairs is readable",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueHeaders["Cookie"] = []string{
					"__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111",
				}
			}),
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "three separate Cookie header values are readable",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueHeaders["Cookie"] = requestCookies
			}),
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "cookies arrive through the single-value header map too",
			event: events.APIGatewayProxyRequest{
				Path:       "/auth/session",
				HTTPMethod: http.MethodGet,
				Headers: map[string]string{
					"cookie": "__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111",
				},
			},
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "nil header and query maps do not panic",
			event: events.APIGatewayProxyRequest{
				Path:       "/auth/session",
				HTTPMethod: http.MethodGet,
			},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/session")
				eq(t, "rawQuery", r.URL.RawQuery, "")
				eq(t, "len(header)", len(r.Header), 0)
				eq(t, "remoteAddr", r.RemoteAddr, "")
				if r.TLS == nil {
					t.Fatal("r.TLS = nil, want non-nil: api gateway is https only")
				}
			},
		},
		{
			name: "the multi-value header map wins and is not merged with the single-value one",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.Headers = map[string]string{
					"Content-Type":      "application/json",
					"X-Forwarded-Proto": "https",
					"Host":              "abc123.execute-api.eu-west-1.amazonaws.com",
					"X-Forwarded-For":   "203.0.113.7",
				}
			}),
			check: func(t *testing.T, r *http.Request) {
				eqSlice(t, "Content-Type values", r.Header.Values("Content-Type"), []string{"application/json"})
				eq(t, "len(header)", len(r.Header), 3) // Host lifted out
			},
		},
		{
			name: "repeated headers arrive as separate values",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueHeaders["X-Forwarded-For"] = []string{"203.0.113.7", "70.41.3.18"}
			}),
			check: func(t *testing.T, r *http.Request) {
				eqSlice(t, "X-Forwarded-For", r.Header.Values("X-Forwarded-For"), []string{"203.0.113.7", "70.41.3.18"})
				eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
			},
		},
		{
			name: "multiValueQueryStringParameters are re-encoded in order",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueQueryStringParameters = map[string][]string{
					"scope":        {"openid", "email"},
					"state":        {"a b"},
					"redirect_uri": {"https://app.example.com/cb?x=1"},
				}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "rawQuery", r.URL.RawQuery,
					"redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb%3Fx%3D1&scope=openid&scope=email&state=a+b")
				q := r.URL.Query()
				eqSlice(t, `q["scope"]`, q["scope"], []string{"openid", "email"})
				eq(t, "state", q.Get("state"), "a b")
				eq(t, "redirect_uri", q.Get("redirect_uri"), "https://app.example.com/cb?x=1")
			},
		},
		{
			name: "the single-value query map is used when there is no multi-value one",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.QueryStringParameters = map[string]string{"token": "t o k+en", "next": "/dash"}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "rawQuery", r.URL.RawQuery, "next=%2Fdash&token=t+o+k%2Ben")
				eq(t, "token", r.URL.Query().Get("token"), "t o k+en")
				eq(t, "next", r.URL.Query().Get("next"), "/dash")
			},
		},
		{
			name: "the decoded path is not unescaped a second time",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.Path = "/prod/auth/users/user+one@example.com"
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "URL.Path", r.URL.Path, "/auth/users/user+one@example.com")
				eq(t, "URL.EscapedPath()", r.URL.EscapedPath(), "/auth/users/user+one@example.com")
			},
		},
		{
			name: "base64 body is decoded",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.Body = base64.StdEncoding.EncodeToString(binaryBody)
				e.IsBase64Encoded = true
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "contentLength", r.ContentLength, int64(len(binaryBody)))
				eq(t, "Content-Length header", r.Header.Get("Content-Length"), "11")
			},
		},
		{
			name:  "the stage prefix is kept when nothing is configured",
			event: restEvent(nil),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/prod/auth/login")
				eq(t, "requestURI", r.RequestURI, "/prod/auth/login")
			},
		},
		{
			name:  "explicit StagePrefix is stripped",
			event: restEvent(nil),
			opts:  Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
				eq(t, "requestURI", r.RequestURI, "/auth/login")
			},
		},
		{
			name:  "StripStageFromEvent uses requestContext.stage",
			event: restEvent(nil),
			opts:  Options{StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "StagePrefix wins over StripStageFromEvent",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.Path = "/v2/auth/login"
				e.RequestContext.Stage = "prod"
			}),
			opts: Options{StagePrefix: "v2", StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "query survives stage stripping",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueQueryStringParameters = map[string][]string{"code": {"abc"}}
			}),
			opts: Options{StagePrefix: "prod"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "requestURI", r.RequestURI, "/auth/login?code=abc")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mustNewRequest(t, tc.event, tc.opts))
		})
	}
}

func TestAPIGatewayRESTOutbound(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
		check   func(t *testing.T, resp events.APIGatewayProxyResponse)
	}{
		{
			name:    "three Set-Cookie headers survive in multiValueHeaders",
			handler: loginHandler,
			check: func(t *testing.T, resp events.APIGatewayProxyResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusOK)
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
				if _, dup := resp.Headers["Set-Cookie"]; dup {
					t.Error("Set-Cookie appears in both maps; api gateway would merge them unpredictably")
				}
			},
		},
		{
			name:    "single-valued CORS headers stay in headers, repeated Vary goes to multiValueHeaders",
			handler: loginHandler,
			check: func(t *testing.T, resp events.APIGatewayProxyResponse) {
				eqMap(t, "headers", resp.Headers, map[string]string{
					"Content-Type":                     "application/json",
					"Access-Control-Allow-Origin":      "https://app.example.com",
					"Access-Control-Allow-Credentials": "true",
					"Access-Control-Expose-Headers":    "X-Request-Id",
				})
				eqSlice(t, `multiValueHeaders["Vary"]`, resp.MultiValueHeaders["Vary"],
					[]string{"Origin", "Cookie", "Access-Control-Request-Headers"})
				eq(t, "len(multiValueHeaders)", len(resp.MultiValueHeaders), 2) // Vary + Set-Cookie
				eq(t, "body", resp.Body, `{"user":{"id":"u_1"}}`)
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, false)
			},
		},
		{
			name:    "binary body is base64-encoded",
			handler: binaryHandler,
			check: func(t *testing.T, resp events.APIGatewayProxyResponse) {
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, true)
				eq(t, "body", resp.Body, base64.StdEncoding.EncodeToString(binaryBody))
				eq(t, "Content-Type", resp.Headers["Content-Type"], "image/png")
			},
		},
		{
			name: "a redirect keeps Location and its cookie",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://app.example.com/callback?code=abc&state=x+y")
				w.Header().Add("Set-Cookie", "oauth_state=x; Path=/; HttpOnly; Secure; SameSite=Lax")
				w.WriteHeader(http.StatusFound)
			},
			check: func(t *testing.T, resp events.APIGatewayProxyResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusFound)
				eq(t, "Location", resp.Headers["Location"], "https://app.example.com/callback?code=abc&state=x+y")
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"],
					[]string{"oauth_state=x; Path=/; HttpOnly; Secure; SameSite=Lax"})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := New(tc.handler, Options{})
			resp, err := a.HandleAPIGatewayREST(context.Background(), restEvent(nil))
			if err != nil {
				t.Fatalf("HandleAPIGatewayREST: %v", err)
			}
			tc.check(t, resp)
		})
	}
}
