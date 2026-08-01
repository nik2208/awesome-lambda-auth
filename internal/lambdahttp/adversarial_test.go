package lambdahttp

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

// ---------------------------------------------------------------------------
// ALB response header maps
//
// AWS documents the rule in "Responses with multi-value headers": "You must use
// multiValueHeaders if you have enabled multi-value headers and headers
// otherwise." The documented multi-value example puts even a single-valued
// Content-Type in the array map. Splitting a response across the two maps
// therefore loses every single-valued header on the way to the client.
// ---------------------------------------------------------------------------

func TestALBMultiValueModeUsesOnlyMultiValueHeaders(t *testing.T) {
	resp, err := New(http.HandlerFunc(loginHandler), Options{}).
		HandleALB(context.Background(), albMultiValueEvent(nil))
	if err != nil {
		t.Fatalf("HandleALB: %v", err)
	}

	eq(t, "len(headers)", len(resp.Headers), 0)
	for k, want := range map[string]string{
		"Content-Type":                     "application/json",
		"Access-Control-Allow-Origin":      "https://app.example.com",
		"Access-Control-Allow-Credentials": "true",
		"Access-Control-Expose-Headers":    "X-Request-Id",
	} {
		eqSlice(t, "multiValueHeaders["+k+"]", resp.MultiValueHeaders[k], []string{want})
	}
	eqSlice(t, `multiValueHeaders["Vary"]`, resp.MultiValueHeaders["Vary"],
		[]string{"Origin", "Cookie", "Access-Control-Request-Headers"})
	eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], loginCookies)
	eq(t, "len(multiValueHeaders)", len(resp.MultiValueHeaders), 6)
}

// A 302 is how the OAuth callback finishes. Location is single-valued, so under
// the old split it landed in headers and an ALB in multi-value mode dropped it:
// the browser would get a bodyless 302 with nowhere to go.
func TestALBMultiValueModeKeepsLocation(t *testing.T) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://app.example.com/callback?code=abc")
		w.Header().Add("Set-Cookie", "oauth_state=x; Path=/; HttpOnly; Secure")
		w.WriteHeader(http.StatusFound)
	}
	resp, err := New(http.HandlerFunc(h), Options{}).
		HandleALB(context.Background(), albMultiValueEvent(nil))
	if err != nil {
		t.Fatalf("HandleALB: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusFound)
	eq(t, "len(headers)", len(resp.Headers), 0)
	eqSlice(t, `multiValueHeaders["Location"]`, resp.MultiValueHeaders["Location"],
		[]string{"https://app.example.com/callback?code=abc"})
}

// The mirror image: with the attribute off the response must use headers only.
func TestALBSingleValueModeUsesOnlyHeaders(t *testing.T) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", loginCookies[0])
		w.WriteHeader(http.StatusOK)
	}
	resp, err := New(http.HandlerFunc(h), Options{}).
		HandleALB(context.Background(), albSingleValueEvent(nil))
	if err != nil {
		t.Fatalf("HandleALB: %v", err)
	}
	eq(t, "len(multiValueHeaders)", len(resp.MultiValueHeaders), 0)
	eqMap(t, "headers", resp.Headers, map[string]string{
		"Content-Type": "application/json",
		"Set-Cookie":   loginCookies[0],
	})
}

// ---------------------------------------------------------------------------
// SplitHeaders and the multi-value request maps
//
// AWS's own proxy-integration example shows a client header sent as one line
// with a comma in it arriving as a SINGLE multiValueHeaders element:
//
//	-H 'header3: value1,value2'  ->  "multiValueHeaders": {"header3": ["value1,value2"]}
//
// So the comma-joining SplitHeaders exists to undo happens in the multi-value
// map too, and the CloudFront -> ALB x-forwarded-proto case it was written for
// is an ALB event, which is exactly where the multi-value map is used.
// ---------------------------------------------------------------------------

func TestSplitHeadersAppliesToMultiValueEventMaps(t *testing.T) {
	tests := []struct {
		name  string
		event any
	}{
		{
			name: "alb multiValueHeaders",
			event: albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
				e.MultiValueHeaders["x-forwarded-proto"] = []string{"https,https"}
				e.MultiValueHeaders["x-forwarded-for"] = []string{"203.0.113.7, 70.41.3.18"}
			}),
		},
		{
			name: "rest v1 multiValueHeaders",
			event: restEvent(func(e *events.APIGatewayProxyRequest) {
				e.MultiValueHeaders["X-Forwarded-Proto"] = []string{"https,https"}
				e.MultiValueHeaders["X-Forwarded-For"] = []string{"203.0.113.7, 70.41.3.18"}
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustNewRequest(t, tc.event, Options{})
			// The whole point of the option: an equality check on Get must work.
			eq(t, `Get("X-Forwarded-Proto")`, r.Header.Get("X-Forwarded-Proto"), "https")
			eqSlice(t, "X-Forwarded-Proto values", r.Header.Values("X-Forwarded-Proto"),
				[]string{"https", "https"})
			eqSlice(t, "X-Forwarded-For values", r.Header.Values("X-Forwarded-For"),
				[]string{"203.0.113.7", "70.41.3.18"})
			eq(t, "remoteAddr", r.RemoteAddr, "203.0.113.7:0")
		})
	}
}

// Splitting must stay off for headers outside the allowlist even in the
// multi-value map — above all Cookie, where a comma is an ordinary value byte.
func TestMultiValueEventMapDoesNotSplitCookieOrAccept(t *testing.T) {
	evt := albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
		e.MultiValueHeaders["cookie"] = []string{"prefs=a,b,c; csrf_token=zzz111"}
		e.MultiValueHeaders["accept"] = []string{"text/html,application/json"}
	})
	r := mustNewRequest(t, evt, Options{})
	eqSlice(t, "Cookie values", r.Header.Values("Cookie"), []string{"prefs=a,b,c; csrf_token=zzz111"})
	eqSlice(t, "Accept values", r.Header.Values("Accept"), []string{"text/html,application/json"})
	eq(t, `r.Cookie("prefs")`, cookieValue(t, r, "prefs"), "a,b,c")
	eq(t, `r.Cookie("csrf_token")`, cookieValue(t, r, "csrf_token"), "zzz111")
}

// A non-nil empty SplitHeaders must disable splitting on the multi-value path
// too, otherwise the option means different things per event shape.
func TestSplitHeadersDisabledAppliesToMultiValueEventMaps(t *testing.T) {
	evt := albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
		e.MultiValueHeaders["x-forwarded-proto"] = []string{"https,http"}
	})
	r := mustNewRequest(t, evt, Options{SplitHeaders: []string{}})
	eqSlice(t, "X-Forwarded-Proto values", r.Header.Values("X-Forwarded-Proto"), []string{"https,http"})
}

// ---------------------------------------------------------------------------
// panic after a partial write
// ---------------------------------------------------------------------------

// The adapter buffers, so nothing has reached the client yet when a handler
// panics mid-response: it can and must return a clean 500 rather than a 200
// with a truncated body. For an auth service the truncated body is a
// half-serialised session payload and the headers are real Set-Cookies.
func TestPanicAfterPartialWriteBecomes500(t *testing.T) {
	var seen error
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Add("Set-Cookie", loginCookies[0])
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"user":{"id":"u_1"`))
		panic("boom after write")
	}
	a := New(http.HandlerFunc(h), Options{OnError: func(_ context.Context, err error) { seen = err }})

	resp, err := a.HandleAPIGatewayV2(context.Background(), v2Event(nil))
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusInternalServerError)
	eq(t, "body", resp.Body, "")
	eq(t, "len(cookies)", len(resp.Cookies), 0)
	eq(t, "len(headers)", len(resp.Headers), 0)
	if seen == nil {
		t.Fatal("OnError was not called for a panic after a partial write")
	}
}

func TestAbortHandlerAfterPartialWriteBecomes500(t *testing.T) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic(http.ErrAbortHandler)
	}
	resp, err := New(http.HandlerFunc(h), Options{}).
		HandleAPIGatewayV2(context.Background(), v2Event(nil))
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusInternalServerError)
	eq(t, "body", resp.Body, "")
}

// ---------------------------------------------------------------------------
// bodies that HTTP forbids
// ---------------------------------------------------------------------------

// net/http's server discards handler writes for HEAD, 204 and 304. The adapter
// buffers instead of writing to a socket, so it has to do the same explicitly —
// otherwise a 304 from a conditional GET on /auth/session goes back to
// CloudFront with a body, which is a protocol violation.
func TestBodiesForbiddenByStatusOrMethodAreDropped(t *testing.T) {
	tests := []struct {
		name   string
		method string
		code   int
		want   string
	}{
		{name: "HEAD keeps no body", method: http.MethodHead, code: http.StatusOK, want: ""},
		{name: "204 keeps no body", method: http.MethodGet, code: http.StatusNoContent, want: ""},
		{name: "304 keeps no body", method: http.MethodGet, code: http.StatusNotModified, want: ""},
		{name: "200 GET keeps its body", method: http.MethodGet, code: http.StatusOK, want: `{"ok":true}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.code)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}
			evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.RequestContext.HTTP.Method = tc.method
			})
			resp, err := New(http.HandlerFunc(h), Options{}).
				HandleAPIGatewayV2(context.Background(), evt)
			if err != nil {
				t.Fatalf("HandleAPIGatewayV2: %v", err)
			}
			eq(t, "statusCode", resp.StatusCode, tc.code)
			eq(t, "body", resp.Body, tc.want)
			eq(t, "isBase64Encoded", resp.IsBase64Encoded, false)
			// Headers are still meaningful on all of these.
			eq(t, "Content-Type", resp.Headers["Content-Type"], "application/json")
		})
	}
}

// A 304 still has to carry the cookies a session refresh set.
func TestNotModifiedKeepsCookies(t *testing.T) {
	h := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", loginCookies[0])
		w.Header().Add("Set-Cookie", loginCookies[1])
		w.WriteHeader(http.StatusNotModified)
	}
	resp, err := New(http.HandlerFunc(h), Options{}).
		HandleAPIGatewayV2(context.Background(), v2Event(nil))
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "statusCode", resp.StatusCode, http.StatusNotModified)
	eqSlice(t, "cookies", resp.Cookies, loginCookies[:2])
}

// ---------------------------------------------------------------------------
// Set-Cookie values that contain commas and equals signs
// ---------------------------------------------------------------------------

// A cookie with an absolute Expires date carries a comma inside a single
// Set-Cookie value ("Expires=Wed, 21 Oct 2026 ..."). Any code path that joins
// or splits cookies on commas corrupts it into two invalid cookies.
const expiringCookie = "session=abc%3Ddef; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT; HttpOnly; Secure; SameSite=None"

func TestSetCookieWithExpiresCommaIsNeverSplitOrJoined(t *testing.T) {
	single := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", expiringCookie)
		w.WriteHeader(http.StatusOK)
	}
	pair := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Add("Set-Cookie", expiringCookie)
		w.Header().Add("Set-Cookie", "csrf_token=zzz111; Path=/; Expires=Thu, 22 Oct 2026 07:28:00 GMT")
		w.WriteHeader(http.StatusOK)
	}
	wantPair := []string{
		expiringCookie,
		"csrf_token=zzz111; Path=/; Expires=Thu, 22 Oct 2026 07:28:00 GMT",
	}

	t.Run("v2 cookies array", func(t *testing.T) {
		resp, err := New(http.HandlerFunc(pair), Options{}).
			HandleAPIGatewayV2(context.Background(), v2Event(nil))
		if err != nil {
			t.Fatalf("HandleAPIGatewayV2: %v", err)
		}
		eqSlice(t, "cookies", resp.Cookies, wantPair)
	})

	t.Run("function url cookies array", func(t *testing.T) {
		resp, err := New(http.HandlerFunc(pair), Options{}).
			HandleFunctionURL(context.Background(), funcURLEvent(nil))
		if err != nil {
			t.Fatalf("HandleFunctionURL: %v", err)
		}
		eqSlice(t, "cookies", resp.Cookies, wantPair)
	})

	t.Run("rest multiValueHeaders", func(t *testing.T) {
		resp, err := New(http.HandlerFunc(pair), Options{}).
			HandleAPIGatewayREST(context.Background(), restEvent(nil))
		if err != nil {
			t.Fatalf("HandleAPIGatewayREST: %v", err)
		}
		eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], wantPair)
	})

	t.Run("alb multi-value mode", func(t *testing.T) {
		resp, err := New(http.HandlerFunc(pair), Options{}).
			HandleALB(context.Background(), albMultiValueEvent(nil))
		if err != nil {
			t.Fatalf("HandleALB: %v", err)
		}
		eqSlice(t, `multiValueHeaders["Set-Cookie"]`, resp.MultiValueHeaders["Set-Cookie"], wantPair)
	})

	t.Run("alb single-value mode keeps one intact", func(t *testing.T) {
		resp, err := New(http.HandlerFunc(single), Options{}).
			HandleALB(context.Background(), albSingleValueEvent(nil))
		if err != nil {
			t.Fatalf("HandleALB: %v", err)
		}
		eq(t, "Set-Cookie", resp.Headers["Set-Cookie"], expiringCookie)
	})
}

// ---------------------------------------------------------------------------
// inbound cookie edge cases
// ---------------------------------------------------------------------------

func TestInboundCookieEdgeCases(t *testing.T) {
	// A base64url JWT segment ends in '=' padding and an opaque session value
	// may hold a comma; neither is a cookie delimiter.
	awkward := []string{
		"session=YWJjZA==",
		"prefs=a,b,c",
		"dup=first",
		"dup=second",
	}

	t.Run("v2 cookies array", func(t *testing.T) {
		evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) { e.Cookies = awkward })
		r := mustNewRequest(t, evt, Options{})
		eq(t, "Cookie header", r.Header.Get("Cookie"),
			"session=YWJjZA==; prefs=a,b,c; dup=first; dup=second")
		eq(t, "len(r.Cookies())", len(r.Cookies()), 4)
		eq(t, `r.Cookie("session")`, cookieValue(t, r, "session"), "YWJjZA==")
		eq(t, `r.Cookie("prefs")`, cookieValue(t, r, "prefs"), "a,b,c")
		// Cookie() returns the first match; both duplicates must survive.
		eq(t, `r.Cookie("dup")`, cookieValue(t, r, "dup"), "first")
		var dups []string
		for _, c := range r.Cookies() {
			if c.Name == "dup" {
				dups = append(dups, c.Value)
			}
		}
		eqSlice(t, "duplicate cookie values", dups, []string{"first", "second"})
	})

	t.Run("alb single Cookie header", func(t *testing.T) {
		evt := albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
			e.MultiValueHeaders["cookie"] = []string{"session=YWJjZA==; prefs=a,b,c"}
		})
		r := mustNewRequest(t, evt, Options{})
		eq(t, `r.Cookie("session")`, cookieValue(t, r, "session"), "YWJjZA==")
		eq(t, `r.Cookie("prefs")`, cookieValue(t, r, "prefs"), "a,b,c")
	})
}

// ---------------------------------------------------------------------------
// bodies
// ---------------------------------------------------------------------------

func TestEmptyBodyIsNotAnError(t *testing.T) {
	tests := []struct {
		name  string
		event events.APIGatewayV2HTTPRequest
	}{
		{
			name:  "no body at all",
			event: v2Event(nil),
		},
		{
			name: "empty body flagged as base64",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Body = ""
				e.IsBase64Encoded = true
			}),
		},
		{
			name: "empty body not flagged",
			event: v2Event(func(e *events.APIGatewayV2HTTPRequest) {
				e.Body = ""
				e.Headers["content-length"] = "0"
			}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := mustNewRequest(t, tc.event, Options{})
			eq(t, "contentLength", r.ContentLength, int64(0))
			eq(t, "Content-Length header", r.Header.Get("Content-Length"), "")
			if r.Body == nil {
				t.Fatal("r.Body = nil, want a non-nil empty body")
			}
			buf := make([]byte, 1)
			if n, err := r.Body.Read(buf); n != 0 || err == nil {
				t.Fatalf("read empty body = (%d, %v), want (0, io.EOF)", n, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// paths and queries
// ---------------------------------------------------------------------------

func TestPathEqualToStagePrefixKeepsQuery(t *testing.T) {
	evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) {
		e.RawPath = "/prod"
		e.RawQueryString = "code=abc&state=x%20y"
	})
	r := mustNewRequest(t, evt, Options{StagePrefix: "prod"})
	eq(t, "path", r.URL.Path, "/")
	eq(t, "escapedPath", r.URL.EscapedPath(), "/")
	eq(t, "requestURI", r.RequestURI, "/?code=abc&state=x%20y")
	eq(t, "state", r.URL.Query().Get("state"), "x y")
}

// "/prod/" is the stage root with a trailing slash: it must not collapse a
// segment or lose the slash a router may route on.
func TestStagePrefixWithTrailingSlashPath(t *testing.T) {
	evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) { e.RawPath = "/prod/" })
	r := mustNewRequest(t, evt, Options{StagePrefix: "prod"})
	eq(t, "path", r.URL.Path, "/")
	eq(t, "requestURI", r.RequestURI, "/")
}

func TestRepeatedQueryKeyWithEmptyValues(t *testing.T) {
	t.Run("rest multi-value", func(t *testing.T) {
		evt := restEvent(func(e *events.APIGatewayProxyRequest) {
			e.MultiValueQueryStringParameters = map[string][]string{"myKey": {"", ""}}
		})
		r := mustNewRequest(t, evt, Options{})
		eq(t, "rawQuery", r.URL.RawQuery, "myKey=&myKey=")
		eqSlice(t, `q["myKey"]`, r.URL.Query()["myKey"], []string{"", ""})
	})
	t.Run("alb multi-value passthrough", func(t *testing.T) {
		evt := albMultiValueEvent(func(e *events.ALBTargetGroupRequest) {
			e.MultiValueQueryStringParameters = map[string][]string{"myKey": {"", "val2"}}
		})
		r := mustNewRequest(t, evt, Options{})
		eq(t, "rawQuery", r.URL.RawQuery, "myKey=&myKey=val2")
		eqSlice(t, `q["myKey"]`, r.URL.Query()["myKey"], []string{"", "val2"})
	})
}

// ---------------------------------------------------------------------------
// header values that are not plain ASCII tokens
// ---------------------------------------------------------------------------

func TestNonASCIIHeaderValueSurvivesBothWays(t *testing.T) {
	const utf8Value = "Prénom Ünïcode — 日本語"

	echo := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Echo", r.Header.Get("X-Display-Name"))
		w.WriteHeader(http.StatusOK)
	}
	evt := v2Event(func(e *events.APIGatewayV2HTTPRequest) {
		e.Headers["x-display-name"] = utf8Value
	})

	r := mustNewRequest(t, evt, Options{})
	eq(t, "X-Display-Name", r.Header.Get("X-Display-Name"), utf8Value)

	resp, err := New(http.HandlerFunc(echo), Options{}).HandleAPIGatewayV2(context.Background(), evt)
	if err != nil {
		t.Fatalf("HandleAPIGatewayV2: %v", err)
	}
	eq(t, "X-Echo", resp.Headers["X-Echo"], utf8Value)
}

// ---------------------------------------------------------------------------
// Detect / Handle robustness
// ---------------------------------------------------------------------------

func TestDetectRejectsNonObjectPayloads(t *testing.T) {
	for _, payload := range []string{`null`, `[]`, `"a string"`, `123`} {
		t.Run(payload, func(t *testing.T) {
			if _, err := Detect([]byte(payload)); err == nil {
				t.Fatalf("Detect(%s) = nil error, want an error", payload)
			}
		})
	}
}

// A misconfigured single-value ALB target group must fail the invocation, not
// return 200 with two of three cookies missing — through Handle as well as
// through HandleALB.
func TestHandleSurfacesALBSingleValueFailure(t *testing.T) {
	payload := `{"httpMethod":"POST","path":"/auth/login",
		"headers":{"host":"auth.example.com","x-forwarded-proto":"https"},
		"requestContext":{"elb":{"targetGroupArn":"` + albTargetGroupARN + `"}},
		"isBase64Encoded":false}`
	raw, err := New(http.HandlerFunc(loginHandler), Options{}).
		Handle(context.Background(), []byte(payload))
	if !errors.Is(err, ErrMultiValueHeadersDisabled) {
		t.Fatalf("Handle error = %v (payload %s), want ErrMultiValueHeadersDisabled", err, raw)
	}
	if raw != nil {
		t.Errorf("Handle returned a payload alongside the error: %s", raw)
	}
}
