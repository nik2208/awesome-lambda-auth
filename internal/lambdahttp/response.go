package lambdahttp

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/aws/aws-lambda-go/events"
)

// responseRecorder is the http.ResponseWriter handed to the wrapped handler. It
// buffers status, headers and body so they can be rendered into whichever event
// response shape the invocation needs.
type responseRecorder struct {
	header      http.Header
	code        int
	wroteHeader bool
	body        bytes.Buffer
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{header: make(http.Header), code: http.StatusOK}
}

// statusOnlyRecorder builds a bodyless response, used when an event could not
// be normalised into a request and the handler never ran. It carries no body
// on purpose: inventing an error payload here would put bytes on the wire that
// the reference implementation's contract does not define.
func statusOnlyRecorder(code int) *responseRecorder {
	rec := newResponseRecorder()
	rec.code = code
	rec.wroteHeader = true
	return rec
}

func (r *responseRecorder) Header() http.Header { return r.header }

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(b)
}

func (r *responseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	// 1xx are informational: net/http lets a handler send them and then send
	// the real status afterwards.
	if code >= 100 && code < 200 {
		return
	}
	if code < 100 || code > 999 {
		code = http.StatusInternalServerError
	}
	r.code = code
	r.wroteHeader = true
}

// Flush satisfies http.Flusher so handlers that stream (SSE, chunked JSON) run
// without special-casing. The buffered adapter has nowhere to flush to; a
// Function URL response-streaming writer will implement it for real.
func (r *responseRecorder) Flush() {}

// reset discards everything written so far and installs code, used when a
// handler panicked mid-response.
func (r *responseRecorder) reset(code int) {
	r.header = make(http.Header)
	r.body.Reset()
	r.code = code
	r.wroteHeader = true
}

// dropForbiddenBody discards a body that HTTP does not allow to be sent.
// net/http's server does this at the socket, silently swallowing the handler's
// writes; the adapter buffers instead, so without this a HEAD or a 304 hands
// AWS a body and AWS forwards it verbatim. Headers are kept: a 304 still has to
// carry the Set-Cookie headers a session refresh produced.
func (r *responseRecorder) dropForbiddenBody(method string) {
	if bodyAllowed(method, r.code) {
		return
	}
	r.body.Reset()
}

// bodyAllowed mirrors net/http's rule: no body for a HEAD request and none for
// 204 or 304, whatever the handler wrote. (1xx never reaches the recorder.)
func bodyAllowed(method string, code int) bool {
	if method == http.MethodHead {
		return false
	}
	switch code {
	case http.StatusNoContent, http.StatusNotModified:
		return false
	}
	return true
}

// splitSetCookie separates Set-Cookie from the rest of the headers. Every
// shape needs this split: v2 and Function URL move cookies into the dedicated
// "cookies" array, REST and ALB into multiValueHeaders. The returned header is
// a copy, so the recorder is left untouched.
func splitSetCookie(h http.Header) (cookies []string, rest http.Header) {
	rest = make(http.Header, len(h))
	// Sorted so that two keys differing only in case — a handler may write
	// straight into the map instead of going through Header.Add — merge in a
	// deterministic order rather than by map iteration order.
	for _, k := range slices.Sorted(maps.Keys(h)) {
		key := http.CanonicalHeaderKey(k)
		if key == "Set-Cookie" {
			cookies = append(cookies, h[k]...)
			continue
		}
		rest[key] = append(rest[key], h[k]...)
	}
	return cookies, rest
}

// joinedHeaders renders headers for the shapes that only have a single-value
// map (HTTP API v2, Function URL). Repeated values are comma-joined, which is
// how those integrations expect multi-value headers such as Vary. Set-Cookie
// must already have been removed — comma-joining cookies is exactly the bug
// this package exists to prevent.
func joinedHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for _, k := range slices.Sorted(maps.Keys(h)) {
		vs := h[k]
		if len(vs) == 0 {
			continue
		}
		out[k] = strings.Join(vs, ",")
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// multiValueHeaderMap renders every header as an array. That is what an ALB
// target group with the multi-value headers attribute enabled expects: AWS
// documents the response rule as "You must use multiValueHeaders if you have
// enabled multi-value headers and headers otherwise", and its own example puts
// a single-valued Content-Type in the array map. Leaving single-valued headers
// in the other map loses them — Content-Type, the CORS set, Location on an
// OAuth redirect — while the cookies alone get through.
func multiValueHeaderMap(h http.Header, cookies []string) map[string][]string {
	out := make(map[string][]string, len(h)+1)
	for _, k := range slices.Sorted(maps.Keys(h)) {
		if len(h[k]) == 0 {
			continue
		}
		out[k] = slices.Clone(h[k])
	}
	if len(cookies) > 0 {
		out["Set-Cookie"] = slices.Clone(cookies)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitHeaderMaps renders headers for API Gateway REST v1, which has both maps
// and documents that it merges them ("If you specify values for both headers
// and multiValueHeaders, API Gateway merges them into a single list"). A header
// still goes to exactly one map — single-valued ones to headers, repeated ones
// and Set-Cookie to multiValueHeaders — so the merge has nothing to reconcile.
func splitHeaderMaps(h http.Header, cookies []string) (map[string]string, map[string][]string) {
	var single map[string]string
	var multi map[string][]string

	for _, k := range slices.Sorted(maps.Keys(h)) {
		vs := h[k]
		switch len(vs) {
		case 0:
		case 1:
			if single == nil {
				single = make(map[string]string)
			}
			single[k] = vs[0]
		default:
			if multi == nil {
				multi = make(map[string][]string)
			}
			multi[k] = slices.Clone(vs)
		}
	}

	if len(cookies) > 0 {
		if multi == nil {
			multi = make(map[string][]string)
		}
		multi["Set-Cookie"] = slices.Clone(cookies)
	}
	return single, multi
}

// singleHeaderMap renders headers for an ALB target group with multi-value
// headers disabled. That mode has one slot per header name, so anything
// repeated — above all a second Set-Cookie — is unrepresentable and reported
// instead of dropped.
func singleHeaderMap(h http.Header, cookies []string) (map[string]string, error) {
	out := make(map[string]string, len(h)+1)
	for _, k := range slices.Sorted(maps.Keys(h)) {
		vs := h[k]
		if len(vs) > 1 {
			return nil, fmt.Errorf("%w: header %q has %d values", ErrMultiValueHeadersDisabled, k, len(vs))
		}
		if len(vs) == 1 {
			out[k] = vs[0]
		}
	}

	switch len(cookies) {
	case 0:
	case 1:
		out["Set-Cookie"] = cookies[0]
	default:
		return nil, fmt.Errorf(
			"%w: response sets %d cookies but a single-value ALB response can carry only one Set-Cookie",
			ErrMultiValueHeadersDisabled, len(cookies))
	}
	return out, nil
}

// albMultiValueEnabled reports whether the target group has the multi-value
// headers attribute on. The load balancer populates multiValueHeaders and
// multiValueQueryStringParameters only in that mode, which makes the event
// itself a reliable signal; Options.ALBMultiValueHeaders overrides it.
func albMultiValueEnabled(evt events.ALBTargetGroupRequest, opts Options) bool {
	switch opts.ALBMultiValueHeaders {
	case Enabled:
		return true
	case Disabled:
		return false
	default:
		return len(evt.MultiValueHeaders) > 0 || len(evt.MultiValueQueryStringParameters) > 0
	}
}

// encodeBody renders the response body, base64-encoding it when it is not
// valid UTF-8. Text stays readable in logs and in the event payload; binary
// (images, compressed payloads) survives intact.
func encodeBody(body []byte) (string, bool) {
	if len(body) == 0 {
		return "", false
	}
	if utf8.Valid(body) {
		return string(body), false
	}
	return base64.StdEncoding.EncodeToString(body), true
}

// statusDescription renders the "200 OK" form the ALB integration expects.
func statusDescription(code int) string {
	text := http.StatusText(code)
	if text == "" {
		return strconv.Itoa(code) + " Status"
	}
	return strconv.Itoa(code) + " " + text
}
