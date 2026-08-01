package lambdahttp

import "errors"

// Sentinel errors returned by the package. Every error the adapter produces
// wraps one of these (or an underlying encoding/parsing error) with context, so
// callers can match with errors.Is.
var (
	// ErrUnsupportedEvent means the payload or value is not one of the four
	// supported Lambda HTTP event shapes.
	ErrUnsupportedEvent = errors.New("lambdahttp: unsupported lambda event")

	// ErrMultiValueHeadersDisabled means the response could not be rendered
	// because the ALB target group has multi-value headers turned off and the
	// handler emitted more than one value for some header. For an auth service
	// this is almost always more than one Set-Cookie, i.e. a login that would
	// otherwise half-succeed.
	ErrMultiValueHeadersDisabled = errors.New("lambdahttp: alb multi-value headers are disabled, response headers would be lost")

	// ErrBadRequestEvent means a well-formed event carried a field the adapter
	// could not turn into an *http.Request, such as an undecodable base64 body.
	ErrBadRequestEvent = errors.New("lambdahttp: malformed request event")
)
