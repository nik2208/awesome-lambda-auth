package lambdahttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

const albTargetGroupARN = "arn:aws:elasticloadbalancing:eu-west-1:000000000000:targetgroup/auth/0123456789abcdef"

// albMultiValueEvent builds an ALB event as delivered when the target group has
// the multi-value headers attribute enabled: multiValueHeaders and
// multiValueQueryStringParameters are populated instead of their single-value
// counterparts.
func albMultiValueEvent(mutate func(*events.ALBTargetGroupRequest)) events.ALBTargetGroupRequest {
	e := events.ALBTargetGroupRequest{
		HTTPMethod: http.MethodPost,
		Path:       "/auth/login",
		MultiValueHeaders: map[string][]string{
			"host":              {"auth.example.com"},
			"content-type":      {"application/json"},
			"x-forwarded-proto": {"https"},
			"x-forwarded-for":   {"203.0.113.7"},
			"x-forwarded-port":  {"443"},
		},
		RequestContext: events.ALBTargetGroupRequestContext{
			ELB: events.ELBContext{TargetGroupArn: albTargetGroupARN},
		},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

// albSingleValueEvent builds an ALB event as delivered with the multi-value
// headers attribute off — the mode that cannot express two Set-Cookie headers.
func albSingleValueEvent(mutate func(*events.ALBTargetGroupRequest)) events.ALBTargetGroupRequest {
	e := events.ALBTargetGroupRequest{
		HTTPMethod: http.MethodPost,
		Path:       "/auth/login",
		Headers: map[string]string{
			"host":              "auth.example.com",
			"content-type":      "application/json",
			"x-forwarded-proto": "https",
			"x-forwarded-for":   "203.0.113.7",
		},
		RequestContext: events.ALBTargetGroupRequestContext{
			ELB: events.ELBContext{TargetGroupArn: albTargetGroupARN},
		},
	}
	if mutate != nil {
		mutate(&e)
	}
	return e
}

func TestALBInbound(t *testing.T) {
	tests := []struct {
		name  string
		event events.ALBTargetGroupRequest
		opts  Options
		check func(t *testing.T, r *http.Request)
	}{
		{
			name: "cookies from a single Cookie header are readable",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueHeaders["cookie"] = []string{
					"__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111",
				}
			}),
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "cookies from repeated Cookie headers are readable",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueHeaders["cookie"] = requestCookies
			}),
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "cookies in single-value mode are readable",
			event: albSingleValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.Headers["cookie"] = "__Host-access_token=aaa.bbb.ccc; __Host-refresh_token=rrr.sss.ttt; csrf_token=zzz111"
			}),
			check: func(t *testing.T, r *http.Request) { assertLoginCookiesReadable(t, r) },
		},
		{
			name: "nil header and query maps do not panic",
			event: events.ALBTargetGroupRequest{
				HTTPMethod: http.MethodGet,
				RequestContext: events.ALBTargetGroupRequestContext{
					ELB: events.ELBContext{TargetGroupArn: albTargetGroupARN},
				},
			},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "method", r.Method, http.MethodGet)
				eq(t, "path", r.URL.Path, "/")
				eq(t, "rawQuery", r.URL.RawQuery, "")
				eq(t, "len(header)", len(r.Header), 0)
				eq(t, "host", r.Host, "")
				eq(t, "remoteAddr", r.RemoteAddr, "")
			},
		},
		{
			name:  "the client address comes from x-forwarded-for",
			event: albMultiValueEvent(nil),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
				eq(t, "host", r.Host, "auth.example.com")
			},
		},
		{
			name: "a chained x-forwarded-for reports the original client",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueHeaders["x-forwarded-for"] = []string{"203.0.113.7, 70.41.3.18"}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
			},
		},
		{
			name:  "https listeners are detected from x-forwarded-proto",
			event: albMultiValueEvent(nil),
			check: func(t *testing.T, r *http.Request) {
				if r.TLS == nil {
					t.Fatal("r.TLS = nil, want non-nil when x-forwarded-proto is https")
				}
			},
		},
		{
			name: "a plain http listener is not reported as TLS",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueHeaders["x-forwarded-proto"] = []string{"http"}
			}),
			check: func(t *testing.T, r *http.Request) {
				if r.TLS != nil {
					t.Fatal("r.TLS != nil, want nil for an http listener")
				}
			},
		},
		{
			name: "an alb without x-forwarded-proto is not assumed to be TLS",
			event: events.ALBTargetGroupRequest{
				HTTPMethod: http.MethodGet,
				Path:       "/auth/session",
			},
			check: func(t *testing.T, r *http.Request) {
				if r.TLS != nil {
					t.Fatal("r.TLS != nil, want nil: an alb listener may be plain http")
				}
			},
		},
		{
			name: "percent-encoded query values are passed through by default",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueQueryStringParameters = map[string][]string{
					"scope":        {"openid", "email"},
					"redirect_uri": {"https%3A%2F%2Fapp.example.com%2Fcb"},
					"state":        {"a%20b"},
				}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "rawQuery", r.URL.RawQuery,
					"redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&scope=openid&scope=email&state=a%20b")
				q := r.URL.Query()
				eqSlice(t, `q["scope"]`, q["scope"], []string{"openid", "email"})
				eq(t, "redirect_uri", q.Get("redirect_uri"), "https://app.example.com/cb")
				eq(t, "state", q.Get("state"), "a b")
			},
		},
		{
			name: "ALBInputDecoded re-encodes decoded query values",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueQueryStringParameters = map[string][]string{
					"redirect_uri": {"https://app.example.com/cb"},
					"state":        {"a b"},
				}
			}),
			opts: Options{ALBInputDecoded: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "rawQuery", r.URL.RawQuery,
					"redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&state=a+b")
				eq(t, "redirect_uri", r.URL.Query().Get("redirect_uri"), "https://app.example.com/cb")
				eq(t, "state", r.URL.Query().Get("state"), "a b")
			},
		},
		{
			name: "the single-value query map is used in single-value mode",
			event: albSingleValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.QueryStringParameters = map[string]string{"code": "abc123", "state": "x%20y"}
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "rawQuery", r.URL.RawQuery, "code=abc123&state=x%20y")
				eq(t, "state", r.URL.Query().Get("state"), "x y")
			},
		},
		{
			name: "percent-encoded paths are decoded by default",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.Path = "/auth/users/user%40example.com"
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "URL.Path", r.URL.Path, "/auth/users/user@example.com")
				eq(t, "URL.EscapedPath()", r.URL.EscapedPath(), "/auth/users/user%40example.com")
			},
		},
		{
			name: "base64 body is decoded",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.Body = base64.StdEncoding.EncodeToString(binaryBody)
				e.IsBase64Encoded = true
			}),
			check: func(t *testing.T, r *http.Request) {
				eq(t, "contentLength", r.ContentLength, int64(len(binaryBody)))
			},
		},
		{
			name: "an explicit prefix is stripped, and no stage is invented",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.Path = "/auth-svc/auth/login"
			}),
			opts: Options{StagePrefix: "auth-svc"},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth/login")
			},
		},
		{
			name: "StripStageFromEvent is a no-op: alb events carry no stage",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.Path = "/auth-svc/auth/login"
			}),
			opts: Options{StripStageFromEvent: true},
			check: func(t *testing.T, r *http.Request) {
				eq(t, "path", r.URL.Path, "/auth-svc/auth/login")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.check(t, mustNewRequest(t, tc.event, tc.opts))
		})
	}
}

func TestALBOutbound(t *testing.T) {
	tests := []struct {
		name    string
		event   events.ALBTargetGroupRequest
		opts    Options
		handler http.HandlerFunc
		wantErr error
		check   func(t *testing.T, resp events.ALBTargetGroupResponse)
	}{
		{
			name:    "three Set-Cookie headers survive in multiValueHeaders",
			event:   albMultiValueEvent(nil),
			handler: loginHandler,
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusOK)
				eq(t, "statusDescription", resp.StatusDescription, "200 OK")
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
				if _, dup := resp.Headers["Set-Cookie"]; dup {
					t.Error("Set-Cookie must not appear in both header maps")
				}
			},
		},
		{
			name:    "CORS headers and repeated Vary are preserved",
			event:   albMultiValueEvent(nil),
			handler: loginHandler,
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				// In multi-value mode the single-value map is not read by the
				// load balancer, so every header must be in the array map.
				eq(t, "len(headers)", len(resp.Headers), 0)
				eqSlice(t, `multiValueHeaders["Content-Type"]`, resp.MultiValueHeaders["Content-Type"],
					[]string{"application/json"})
				eqSlice(t, `multiValueHeaders["Access-Control-Allow-Origin"]`,
					resp.MultiValueHeaders["Access-Control-Allow-Origin"], []string{"https://app.example.com"})
				eqSlice(t, `multiValueHeaders["Access-Control-Allow-Credentials"]`,
					resp.MultiValueHeaders["Access-Control-Allow-Credentials"], []string{"true"})
				eqSlice(t, `multiValueHeaders["Access-Control-Expose-Headers"]`,
					resp.MultiValueHeaders["Access-Control-Expose-Headers"], []string{"X-Request-Id"})
				eqSlice(t, `multiValueHeaders["Vary"]`, resp.MultiValueHeaders["Vary"],
					[]string{"Origin", "Cookie", "Access-Control-Request-Headers"})
				eq(t, "body", resp.Body, `{"user":{"id":"u_1"}}`)
			},
		},
		{
			name:    "binary body is base64-encoded",
			event:   albMultiValueEvent(nil),
			handler: binaryHandler,
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eq(t, "isBase64Encoded", resp.IsBase64Encoded, true)
				eq(t, "body", resp.Body, base64.StdEncoding.EncodeToString(binaryBody))
			},
		},
		{
			name:    "single-value mode fails loudly rather than dropping two of three cookies",
			event:   albSingleValueEvent(nil),
			handler: loginHandler,
			wantErr: ErrMultiValueHeadersDisabled,
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusInternalServerError)
				eq(t, "headers", len(resp.Headers), 0)
				eq(t, "multiValueHeaders", len(resp.MultiValueHeaders), 0)
			},
		},
		{
			name:  "single-value mode also rejects any other repeated header",
			event: albSingleValueEvent(nil),
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Add("Vary", "Origin")
				w.Header().Add("Vary", "Cookie")
				w.WriteHeader(http.StatusOK)
			},
			wantErr: ErrMultiValueHeadersDisabled,
			check:   func(t *testing.T, resp events.ALBTargetGroupResponse) {},
		},
		{
			name:  "single-value mode can still carry exactly one cookie",
			event: albSingleValueEvent(nil),
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Add("Set-Cookie", loginCookies[0])
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			},
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eqMap(t, "headers", resp.Headers, map[string]string{
					"Content-Type": "application/json",
					"Set-Cookie":   loginCookies[0],
				})
				eq(t, "multiValueHeaders", len(resp.MultiValueHeaders), 0)
				eq(t, "body", resp.Body, `{"ok":true}`)
			},
		},
		{
			name:    "ALBMultiValueHeaders=Enabled overrides detection",
			event:   albSingleValueEvent(nil),
			opts:    Options{ALBMultiValueHeaders: Enabled},
			handler: loginHandler,
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
			},
		},
		{
			name:    "ALBMultiValueHeaders=Disabled overrides detection",
			event:   albMultiValueEvent(nil),
			opts:    Options{ALBMultiValueHeaders: Disabled},
			handler: loginHandler,
			wantErr: ErrMultiValueHeadersDisabled,
			check:   func(t *testing.T, resp events.ALBTargetGroupResponse) {},
		},
		{
			name:  "an unusual status code still gets a description",
			event: albMultiValueEvent(nil),
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(599)
			},
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eq(t, "statusCode", resp.StatusCode, 599)
				eq(t, "statusDescription", resp.StatusDescription, "599 Status")
			},
		},
		{
			name: "nil maps in, empty response out",
			event: events.ALBTargetGroupRequest{
				HTTPMethod: http.MethodGet,
				RequestContext: events.ALBTargetGroupRequestContext{
					ELB: events.ELBContext{TargetGroupArn: albTargetGroupARN},
				},
			},
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			},
			check: func(t *testing.T, resp events.ALBTargetGroupResponse) {
				eq(t, "statusCode", resp.StatusCode, http.StatusNoContent)
				eq(t, "statusDescription", resp.StatusDescription, "204 No Content")
				eq(t, "body", resp.Body, "")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var seen error
			opts := tc.opts
			opts.OnError = func(_ context.Context, err error) { seen = err }

			resp, err := New(tc.handler, opts).HandleALB(context.Background(), tc.event)
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatalf("HandleALB: unexpected error %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("HandleALB error = %v, want %v", err, tc.wantErr)
			case tc.wantErr != nil && !errors.Is(seen, tc.wantErr):
				t.Fatalf("OnError got %v, want %v", seen, tc.wantErr)
			}
			tc.check(t, resp)
		})
	}
}
