// Package lambdahttp normalises the AWS Lambda HTTP event shapes into standard
// *http.Request values and renders whatever an http.Handler writes back into
// the matching event-specific response shape.
//
// Four inbound shapes are supported:
//
//   - API Gateway HTTP API, payload format 2.0 (events.APIGatewayV2HTTPRequest)
//   - API Gateway REST API proxy, payload format 1.0 (events.APIGatewayProxyRequest)
//   - Lambda Function URL (events.LambdaFunctionURLRequest)
//   - Application Load Balancer target group (events.ALBTargetGroupRequest)
//
// Wiring a binary is one line:
//
//	lambda.Start(lambdahttp.New(mux, lambdahttp.Options{}).Handle)
//
// or, when the deployment shape is known at build time, the per-shape entry
// point (HandleAPIGatewayV2, HandleAPIGatewayREST, HandleFunctionURL,
// HandleALB) which is typed and skips event sniffing.
//
// # Multiple Set-Cookie headers
//
// This is the reason the package exists. An auth service sets three cookies on
// a single login response (access token, refresh token, CSRF token) and every
// event shape represents that differently:
//
//   - HTTP API v2 and Function URL: the dedicated "cookies" []string response
//     field. Inbound, request cookies also arrive in a "cookies" array and NOT
//     as a Cookie header, so the adapter reconstructs the Cookie header —
//     without that step http.Request.Cookie() finds nothing.
//   - REST v1 and ALB: multiValueHeaders["Set-Cookie"].
//   - ALB with multi-value headers disabled cannot express more than one
//     Set-Cookie at all. The adapter detects that mode and fails with
//     ErrMultiValueHeadersDisabled rather than silently dropping cookies.
//
// # Response streaming
//
// The buffered path here is deliberately split into NewRequest (inbound
// normalisation) and the rendering of a recorded response, so a future Function
// URL response-streaming handler can reuse NewRequest unchanged and supply its
// own streaming http.ResponseWriter.
package lambdahttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/textproto"
	"runtime/debug"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// Kind identifies a supported Lambda HTTP event shape.
type Kind string

// The supported event shapes, plus KindUnknown for an unrecognised payload.
const (
	KindUnknown        Kind = ""
	KindAPIGatewayV2   Kind = "apigateway-http-v2"
	KindAPIGatewayREST Kind = "apigateway-rest-v1"
	KindFunctionURL    Kind = "function-url"
	KindALB            Kind = "alb"
)

// Tristate is a three-valued switch for options that can be auto-detected from
// the incoming event but sometimes need to be forced by the operator.
type Tristate int8

// Tristate values.
const (
	// Auto lets the adapter infer the setting from the event.
	Auto Tristate = iota
	// Enabled forces the setting on, whatever the event looks like.
	Enabled
	// Disabled forces the setting off, whatever the event looks like.
	Disabled
)

// Options configures an Adapter. The zero value is usable and makes no guesses:
// no path is stripped, ALB behaviour is inferred from the event, and the
// default comma-splitting header set is applied.
type Options struct {
	// StagePrefix is stripped from the front of the request path before the
	// handler sees it, e.g. "/prod" or "prod". A default execute-api URL serves
	// under https://<id>.execute-api.<region>.amazonaws.com/<stage>/, so the
	// event path carries a stage segment that the handler's routes do not know
	// about. Empty means strip nothing: the adapter never guesses a prefix.
	//
	// Note that stripping the stage also breaks __Host- cookie prefixes and
	// Path-scoped refresh cookies unless a custom domain is used, because the
	// browser still sees the stage segment.
	StagePrefix string

	// StripStageFromEvent strips requestContext.stage from the request path.
	// It is an explicit opt-in, not a guess, and it is ignored when the stage
	// is empty or "$default" (HTTP APIs and Function URLs, which serve at the
	// root). StagePrefix wins when both are set.
	StripStageFromEvent bool

	// SplitHeaders lists request headers whose comma-joined single-value form
	// is split back into separate http.Header values. AWS collapses repeated
	// request headers into one comma-joined string in the single-value header
	// map, which breaks equality checks such as
	// r.Header.Get("X-Forwarded-Proto") == "https" behind CloudFront -> ALB.
	//
	// nil selects DefaultSplitHeaders. A non-nil empty slice disables
	// splitting. Names are matched case-insensitively.
	//
	// Splitting is deliberately conservative: http.Header.Get returns only the
	// first value, so splitting a header such as Cache-Control or Accept would
	// hide the rest of the list from ordinary handlers.
	SplitHeaders []string

	// ALBMultiValueHeaders declares whether the ALB target group has the
	// multi-value headers attribute enabled. Auto infers it from the event:
	// the load balancer sends multiValueHeaders/multiValueQueryStringParameters
	// only when the attribute is on.
	//
	// With the attribute off, a response carrying more than one value for any
	// header — in practice, more than one Set-Cookie — cannot be expressed and
	// the adapter returns ErrMultiValueHeadersDisabled instead of dropping it.
	ALBMultiValueHeaders Tristate

	// ALBInputDecoded declares that the load balancer delivers the request path
	// and query-string values already URL-decoded. The default (false) matches
	// documented ALB behaviour, where both arrive percent-encoded and are
	// passed through untouched. API Gateway, by contrast, always decodes, and
	// the adapter re-encodes its values itself.
	ALBInputDecoded bool

	// OnError, when set, receives every error the adapter handles internally:
	// event normalisation failures, recovered handler panics, and unrenderable
	// responses. It is an observability hook — the adapter still returns the
	// error and/or an error status to the caller.
	OnError func(context.Context, error)
}

// DefaultSplitHeaders returns the request headers the adapter splits on commas
// when they arrive comma-joined in a single-value header map. Each entry is a
// header whose first list element is the meaningful one, so http.Header.Get
// keeps returning something sensible after the split.
func DefaultSplitHeaders() []string {
	return []string{
		"Forwarded",
		"Via",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-Proto",
	}
}

func (o Options) splitSet() map[string]struct{} {
	names := o.SplitHeaders
	if names == nil {
		names = DefaultSplitHeaders()
	}
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[textproto.CanonicalMIMEHeaderKey(n)] = struct{}{}
	}
	return set
}

// Adapter serves Lambda HTTP events with an http.Handler.
type Adapter struct {
	handler http.Handler
	opts    Options
}

// New returns an Adapter that dispatches every supported Lambda HTTP event to
// h. opts may be the zero Options.
func New(h http.Handler, opts Options) *Adapter {
	if h == nil {
		h = http.NotFoundHandler()
	}
	return &Adapter{handler: h, opts: opts}
}

// Handle is the auto-detecting entry point, suitable for lambda.Start. It
// sniffs the payload with Detect, dispatches to the matching per-shape entry
// point and marshals the result.
//
// KindAPIGatewayV2 and KindFunctionURL carry the same request fields and the
// same response fields — status code, headers map, cookies array, body,
// isBase64Encoded — so confusing one for the other cannot change what reaches
// the client. (The v2 struct additionally serialises a null multiValueHeaders,
// which HTTP APIs ignore.)
func (a *Adapter) Handle(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	kind, err := Detect(payload)
	if err != nil {
		a.reportError(ctx, err)
		return nil, err
	}

	var out any
	switch kind {
	case KindALB:
		var evt events.ALBTargetGroupRequest
		if err := json.Unmarshal(payload, &evt); err != nil {
			return a.unmarshalFailure(ctx, kind, err)
		}
		resp, err := a.HandleALB(ctx, evt)
		if err != nil {
			return nil, err
		}
		out = resp
	case KindFunctionURL:
		var evt events.LambdaFunctionURLRequest
		if err := json.Unmarshal(payload, &evt); err != nil {
			return a.unmarshalFailure(ctx, kind, err)
		}
		resp, err := a.HandleFunctionURL(ctx, evt)
		if err != nil {
			return nil, err
		}
		out = resp
	case KindAPIGatewayV2:
		var evt events.APIGatewayV2HTTPRequest
		if err := json.Unmarshal(payload, &evt); err != nil {
			return a.unmarshalFailure(ctx, kind, err)
		}
		resp, err := a.HandleAPIGatewayV2(ctx, evt)
		if err != nil {
			return nil, err
		}
		out = resp
	case KindAPIGatewayREST:
		var evt events.APIGatewayProxyRequest
		if err := json.Unmarshal(payload, &evt); err != nil {
			return a.unmarshalFailure(ctx, kind, err)
		}
		resp, err := a.HandleAPIGatewayREST(ctx, evt)
		if err != nil {
			return nil, err
		}
		out = resp
	default:
		err := fmt.Errorf("%w: %q", ErrUnsupportedEvent, kind)
		a.reportError(ctx, err)
		return nil, err
	}

	raw, err := json.Marshal(out)
	if err != nil {
		err = fmt.Errorf("lambdahttp: marshal %s response: %w", kind, err)
		a.reportError(ctx, err)
		return nil, err
	}
	return raw, nil
}

func (a *Adapter) unmarshalFailure(ctx context.Context, kind Kind, cause error) (json.RawMessage, error) {
	err := fmt.Errorf("lambdahttp: unmarshal %s event: %w", kind, cause)
	a.reportError(ctx, err)
	return nil, err
}

// HandleAPIGatewayV2 serves an API Gateway HTTP API payload format 2.0 event.
// Response headers are comma-joined into the headers map and every Set-Cookie
// goes to the dedicated cookies array; multiValueHeaders is left unset because
// HTTP APIs ignore it.
func (a *Adapter) HandleAPIGatewayV2(ctx context.Context, evt events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	rec, err := a.serve(ctx, v2ProxyRequest(evt, a.opts))
	if err != nil {
		a.reportError(ctx, err)
		rec = statusOnlyRecorder(http.StatusBadRequest)
	}
	body, isB64 := encodeBody(rec.body.Bytes())
	cookies, rest := splitSetCookie(rec.header)
	return events.APIGatewayV2HTTPResponse{
		StatusCode:      rec.code,
		Headers:         joinedHeaders(rest),
		Cookies:         cookies,
		Body:            body,
		IsBase64Encoded: isB64,
	}, nil
}

// HandleFunctionURL serves a Lambda Function URL event. The response shape is
// the same as HTTP API v2: comma-joined headers plus a cookies array, which is
// the only way a Function URL can return more than one Set-Cookie.
func (a *Adapter) HandleFunctionURL(ctx context.Context, evt events.LambdaFunctionURLRequest) (events.LambdaFunctionURLResponse, error) {
	rec, err := a.serve(ctx, functionURLProxyRequest(evt, a.opts))
	if err != nil {
		a.reportError(ctx, err)
		rec = statusOnlyRecorder(http.StatusBadRequest)
	}
	body, isB64 := encodeBody(rec.body.Bytes())
	cookies, rest := splitSetCookie(rec.header)
	return events.LambdaFunctionURLResponse{
		StatusCode:      rec.code,
		Headers:         joinedHeaders(rest),
		Cookies:         cookies,
		Body:            body,
		IsBase64Encoded: isB64,
	}, nil
}

// HandleAPIGatewayREST serves an API Gateway REST API proxy (payload format
// 1.0) event. Headers with a single value go to headers, headers with several
// values — and Set-Cookie always — go to multiValueHeaders, so no key is ever
// present in both maps.
func (a *Adapter) HandleAPIGatewayREST(ctx context.Context, evt events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	rec, err := a.serve(ctx, restProxyRequest(evt, a.opts))
	if err != nil {
		a.reportError(ctx, err)
		rec = statusOnlyRecorder(http.StatusBadRequest)
	}
	body, isB64 := encodeBody(rec.body.Bytes())
	cookies, rest := splitSetCookie(rec.header)
	single, multi := splitHeaderMaps(rest, cookies)
	return events.APIGatewayProxyResponse{
		StatusCode:        rec.code,
		Headers:           single,
		MultiValueHeaders: multi,
		Body:              body,
		IsBase64Encoded:   isB64,
	}, nil
}

// HandleALB serves an Application Load Balancer target group event.
//
// When the target group has multi-value headers enabled, EVERY header is
// returned in multiValueHeaders and the single-value headers map is left unset:
// AWS specifies one map or the other per mode, not a split across both, so a
// single-valued Content-Type or Location left in headers would be dropped.
// When the attribute is off, and the handler produced
// more than one value for any header (typically more than one Set-Cookie), the
// response cannot be expressed: HandleALB returns ErrMultiValueHeadersDisabled
// so the invocation fails visibly instead of a login half-succeeding with two
// of its three cookies missing.
func (a *Adapter) HandleALB(ctx context.Context, evt events.ALBTargetGroupRequest) (events.ALBTargetGroupResponse, error) {
	rec, err := a.serve(ctx, albProxyRequest(evt, a.opts))
	if err != nil {
		a.reportError(ctx, err)
		rec = statusOnlyRecorder(http.StatusBadRequest)
	}
	body, isB64 := encodeBody(rec.body.Bytes())
	cookies, rest := splitSetCookie(rec.header)

	resp := events.ALBTargetGroupResponse{
		StatusCode:        rec.code,
		StatusDescription: statusDescription(rec.code),
		Body:              body,
		IsBase64Encoded:   isB64,
	}

	if albMultiValueEnabled(evt, a.opts) {
		resp.MultiValueHeaders = multiValueHeaderMap(rest, cookies)
		return resp, nil
	}

	single, err := singleHeaderMap(rest, cookies)
	if err != nil {
		a.reportError(ctx, err)
		return events.ALBTargetGroupResponse{
			StatusCode:        http.StatusInternalServerError,
			StatusDescription: statusDescription(http.StatusInternalServerError),
		}, err
	}
	resp.Headers = single
	return resp, nil
}

// NewRequest converts a supported Lambda HTTP event into an *http.Request that
// any http.Handler can serve unchanged. event must be one of
// events.APIGatewayV2HTTPRequest, events.APIGatewayProxyRequest,
// events.LambdaFunctionURLRequest or events.ALBTargetGroupRequest (pointers to
// those types are accepted too); anything else yields ErrUnsupportedEvent.
//
// ctx becomes the request context, so the Lambda deadline and request ID stay
// reachable from the handler, and the original event is attached to it — see
// EventFrom.
//
// It is exported so that alternative response paths, such as Function URL
// response streaming, can reuse the inbound normalisation as-is.
func NewRequest(ctx context.Context, event any, opts Options) (*http.Request, error) {
	var pr *proxyRequest
	switch e := event.(type) {
	case events.APIGatewayV2HTTPRequest:
		pr = v2ProxyRequest(e, opts)
	case *events.APIGatewayV2HTTPRequest:
		pr = v2ProxyRequest(*e, opts)
	case events.APIGatewayProxyRequest:
		pr = restProxyRequest(e, opts)
	case *events.APIGatewayProxyRequest:
		pr = restProxyRequest(*e, opts)
	case events.LambdaFunctionURLRequest:
		pr = functionURLProxyRequest(e, opts)
	case *events.LambdaFunctionURLRequest:
		pr = functionURLProxyRequest(*e, opts)
	case events.ALBTargetGroupRequest:
		pr = albProxyRequest(e, opts)
	case *events.ALBTargetGroupRequest:
		pr = albProxyRequest(*e, opts)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedEvent, event)
	}
	return newHTTPRequest(ctx, pr, opts)
}

// serve normalises the event, runs the handler and returns the recording
// writer. A non-nil error means the event could not be normalised; the handler
// was not called.
func (a *Adapter) serve(ctx context.Context, pr *proxyRequest) (*responseRecorder, error) {
	req, err := newHTTPRequest(ctx, pr, a.opts)
	if err != nil {
		return nil, err
	}
	rec := newResponseRecorder()
	a.invoke(rec, req)
	rec.dropForbiddenBody(req.Method)
	return rec, nil
}

// invoke runs the handler, converting a panic into a 500 rather than failing
// the whole Lambda invocation with an opaque runtime error.
//
// The recorder is always reset, including when the handler had already written
// a status, headers and part of the body. Unlike net/http's server, nothing has
// reached the client yet, so the adapter can still return a clean 500 instead
// of a 200 carrying a truncated session payload and real Set-Cookie headers.
func (a *Adapter) invoke(rec *responseRecorder, req *http.Request) {
	defer func() {
		p := recover()
		if p == nil {
			return
		}
		if p == http.ErrAbortHandler {
			a.reportError(req.Context(), fmt.Errorf("lambdahttp: handler aborted the response"))
		} else {
			a.reportError(req.Context(), fmt.Errorf("lambdahttp: handler panic: %v\n%s", p, debug.Stack()))
		}
		rec.reset(http.StatusInternalServerError)
	}()
	a.handler.ServeHTTP(rec, req)
}

func (a *Adapter) reportError(ctx context.Context, err error) {
	if a.opts.OnError != nil && err != nil {
		a.opts.OnError(ctx, err)
	}
}

// detectProbe holds just enough of every payload to tell the shapes apart.
type detectProbe struct {
	Version        string  `json:"version"`
	RouteKey       *string `json:"routeKey"`
	HTTPMethod     string  `json:"httpMethod"`
	RawPath        *string `json:"rawPath"`
	RequestContext struct {
		ELB        *json.RawMessage `json:"elb"`
		HTTP       *json.RawMessage `json:"http"`
		DomainName string           `json:"domainName"`
		Stage      *string          `json:"stage"`
	} `json:"requestContext"`
}

// Detect identifies which Lambda HTTP event shape a raw payload is.
//
// The discriminators are, in order: requestContext.elb (ALB), version "2.0"
// (HTTP API v2 or Function URL, told apart by the <id>.lambda-url.<region>.on.aws
// domain name because the two request payloads are otherwise identical), and
// finally a top-level httpMethod (REST proxy v1). Payloads matching none of
// those yield ErrUnsupportedEvent.
func Detect(payload []byte) (Kind, error) {
	var p detectProbe
	if err := json.Unmarshal(payload, &p); err != nil {
		return KindUnknown, fmt.Errorf("lambdahttp: sniff event payload: %w", err)
	}

	switch {
	case p.RequestContext.ELB != nil:
		return KindALB, nil
	case p.Version == "2.0":
		if strings.Contains(p.RequestContext.DomainName, ".lambda-url.") {
			return KindFunctionURL, nil
		}
		if p.RouteKey == nil && p.RequestContext.Stage == nil {
			return KindFunctionURL, nil
		}
		return KindAPIGatewayV2, nil
	case p.HTTPMethod != "":
		return KindAPIGatewayREST, nil
	case p.RawPath != nil && p.RequestContext.HTTP != nil:
		// version was omitted but the payload is structurally 2.0.
		return KindAPIGatewayV2, nil
	default:
		return KindUnknown, fmt.Errorf("%w: payload matches no supported HTTP event shape", ErrUnsupportedEvent)
	}
}
