package aws

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// theToken stands in for the plaintext credential every message this transport
// carries has in it. Every error assertion below checks it does not appear:
// a transport that quotes what it failed to send writes a live magic link into
// CloudWatch, where it stays for the log group's retention and is readable by
// anyone with logs:FilterLogEvents.
const theToken = "vJ8Qm2LpX0aZrK4tN7bY6dC1sW5hG3fE"

type fakeSES struct {
	inputs []*sesv2.SendEmailInput
	err    error
}

func (f *fakeSES) SendEmail(_ context.Context, in *sesv2.SendEmailInput, _ ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &sesv2.SendEmailOutput{MessageId: awssdk.String("0100000000000000-abcdefgh")}, nil
}

func (f *fakeSES) last(t *testing.T) *sesv2.SendEmailInput {
	t.Helper()
	if len(f.inputs) == 0 {
		t.Fatal("SES was never called")
	}
	return f.inputs[len(f.inputs)-1]
}

func newTestSES(t *testing.T, opts SESOptions) (*SESTransport, *fakeSES) {
	t.Helper()
	api := &fakeSES{}
	opts.Client = api
	transport, err := NewSESTransport(opts)
	if err != nil {
		t.Fatalf("NewSESTransport: %v", err)
	}
	return transport, api
}

func TestSESSendBuildsAV2Request(t *testing.T) {
	t.Parallel()
	transport, api := newTestSES(t, SESOptions{From: "no-reply@example.test", FromName: "Example App"})

	msg := auth.MailMessage{
		To:      "user@recipient.test",
		Subject: "Example App - Magic Link Login",
		Body:    `<html><body><a href="https://auth.example.test/auth/magic-link/verify?token=` + theToken + `">Sign In</a></body></html>`,
		IsHTML:  true,
	}
	if err := transport.Send(t.Context(), msg); err != nil {
		t.Fatalf("Send: %v", err)
	}

	in := api.last(t)
	if got := awssdk.ToString(in.FromEmailAddress); got != `"Example App" <no-reply@example.test>` {
		t.Errorf("FromEmailAddress = %q, want the display name and address quoted per RFC 5322", got)
	}
	if got := in.Destination.ToAddresses; len(got) != 1 || got[0] != msg.To {
		t.Errorf("ToAddresses = %v, want exactly [%s]", got, msg.To)
	}
	if in.Content == nil || in.Content.Simple == nil {
		t.Fatalf("Content.Simple is nil; the transport must send simple content, not raw")
	}
	simple := in.Content.Simple
	if got := awssdk.ToString(simple.Subject.Data); got != msg.Subject {
		t.Errorf("Subject = %q, want %q", got, msg.Subject)
	}
	if simple.Body.Html == nil {
		t.Fatalf("an IsHTML message was sent as text; the link would arrive as markup")
	}
	if got := awssdk.ToString(simple.Body.Html.Data); got != msg.Body {
		t.Errorf("Html body = %q, want the rendered template verbatim", got)
	}
	if got := awssdk.ToString(simple.Body.Html.Charset); got != "UTF-8" {
		t.Errorf("Html charset = %q, want UTF-8 — the it templates are not ASCII", got)
	}
	if simple.Body.Text != nil {
		t.Errorf("an HTML message also carried a text part, which this transport does not synthesise")
	}
	if in.ConfigurationSetName != nil {
		t.Errorf("ConfigurationSetName = %q with none configured, want it absent", awssdk.ToString(in.ConfigurationSetName))
	}
}

func TestSESSendPlainText(t *testing.T) {
	t.Parallel()
	transport, api := newTestSES(t, SESOptions{From: "no-reply@example.test"})

	if err := transport.Send(t.Context(), auth.MailMessage{To: "user@recipient.test", Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	simple := api.last(t).Content.Simple
	if simple.Body.Text == nil || simple.Body.Html != nil {
		t.Errorf("a non-HTML message must go out as Body.Text only")
	}
	// No display name configured: the header is the bare address, not `"" <a@b>`.
	if got := awssdk.ToString(api.last(t).FromEmailAddress); got != "<no-reply@example.test>" {
		t.Errorf("FromEmailAddress = %q, want the bare address", got)
	}
}

func TestSESConfigurationSetIsAttachedWhenSet(t *testing.T) {
	t.Parallel()
	transport, api := newTestSES(t, SESOptions{From: "no-reply@example.test", ConfigurationSetName: "auth-events"})

	if err := transport.Send(t.Context(), auth.MailMessage{To: "user@recipient.test", Subject: "s", Body: "b"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if got := awssdk.ToString(api.last(t).ConfigurationSetName); got != "auth-events" {
		t.Errorf("ConfigurationSetName = %q, want auth-events", got)
	}
}

// TestSESSendErrorPropagatesWithoutTheCredential is the whole reason the error
// path is written by hand. The route above this one answers 500 and leaves the
// stored token in place; what must not also happen is the token being logged.
func TestSESSendErrorPropagatesWithoutTheCredential(t *testing.T) {
	t.Parallel()
	api := &fakeSES{err: &sestypes.MessageRejected{Message: awssdk.String("Email address is not verified.")}}
	transport, err := NewSESTransport(SESOptions{From: "no-reply@example.test", FromName: "Example App", Client: api})
	if err != nil {
		t.Fatalf("NewSESTransport: %v", err)
	}

	body := `<a href="https://auth.example.test/auth/reset-password?token=` + theToken + `">Reset</a>`
	sendErr := transport.Send(t.Context(), auth.MailMessage{
		To:      "victim@recipient.test",
		Subject: "Example App - Password Reset",
		Body:    body,
		IsHTML:  true,
	})
	if sendErr == nil {
		t.Fatal("a rejected send returned nil; the route would answer 200 for a mail that never left")
	}

	// The cause has to survive: a caller distinguishes a rejected identity from
	// a throttle from a sandbox by matching on the SDK's own error.
	var rejected *sestypes.MessageRejected
	if !errors.As(sendErr, &rejected) {
		t.Errorf("error %v does not unwrap to the SDK's own; the cause is lost", sendErr)
	}

	msg := sendErr.Error()
	for _, leaked := range []string{theToken, body, "victim@recipient.test", "victim"} {
		if strings.Contains(msg, leaked) {
			t.Errorf("the error quotes %q, which reaches CloudWatch:\n%s", leaked, msg)
		}
	}
	// It must still be actionable: the identity that was refused and the
	// recipient's domain are both safe and both diagnostic.
	for _, want := range []string{"no-reply@example.test", "recipient.test"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the error omits %q, leaving nothing to act on:\n%s", want, msg)
		}
	}
}

// TestSESSendErrorWithARealisticSDKMessage pins the boundary the Send doc
// comment draws, using SES's actual MessageRejected wording rather than a
// sanitised stub.
//
// The claim being tested is precise, and the sanitised fixture above cannot
// test it: the token never reaches the error, because no error path touches the
// body or the subject and SES does not echo them — while the recipient address
// CAN reach it, because SES puts it in this particular message and the SDK error
// is passed through so errors.As still works. Anyone tempted to promise more
// than that has to change this test first.
func TestSESSendErrorWithARealisticSDKMessage(t *testing.T) {
	t.Parallel()

	const recipient = "victim@recipient.test"
	api := &fakeSES{err: &sestypes.MessageRejected{Message: awssdk.String(
		"Email address is not verified. The following identities failed the check in region EU-WEST-1: " + recipient)}}
	transport, err := NewSESTransport(SESOptions{From: "no-reply@example.test", Client: api})
	if err != nil {
		t.Fatalf("NewSESTransport: %v", err)
	}

	body := `<a href="https://auth.example.test/auth/magic-link/verify?token=` + theToken + `">Sign In</a>`
	sendErr := transport.Send(t.Context(), auth.MailMessage{
		To: recipient, Subject: "Example App - Magic Link Login", Body: body, IsHTML: true,
	})
	if sendErr == nil {
		t.Fatal("a rejected send returned nil")
	}

	msg := sendErr.Error()
	for _, leaked := range []string{theToken, body} {
		if strings.Contains(msg, leaked) {
			t.Errorf("the error quotes the credential, which reaches CloudWatch:\n%s", msg)
		}
	}
	// The transport's own half still names nobody: everything before the wrapped
	// cause is the identity and the recipient's domain.
	own, _, _ := strings.Cut(msg, "Email address is not verified")
	if strings.Contains(own, recipient) {
		t.Errorf("the transport's own wording names the mailbox:\n%s", own)
	}
}

// TestSESClientIsLazy is the cold-start guard. cmd/auth builds this transport
// during init, which is bounded at 8 seconds by startTimeout; constructing an
// SDK client there — and, off Lambda, walking a credential chain that can reach
// IMDS over the network — for a capability most invocations never use is the
// cost this indirection exists to avoid.
func TestSESClientIsLazy(t *testing.T) {
	t.Parallel()

	var builds atomic.Int64
	api := &fakeSES{}
	transport := &SESTransport{
		from:        "<no-reply@example.test>",
		fromAddress: "no-reply@example.test",
		client: &lazyClient[SESAPI]{build: func(context.Context) (SESAPI, error) {
			builds.Add(1)
			return api, nil
		}},
	}

	if got := builds.Load(); got != 0 {
		t.Fatalf("the client was built %d times before any message was sent, want 0", got)
	}
	for i := 0; i < 3; i++ {
		if err := transport.Send(t.Context(), auth.MailMessage{To: "user@recipient.test", Subject: "s", Body: "b"}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := builds.Load(); got != 1 {
		t.Errorf("the client was built %d times across 3 messages, want 1 — the connection pool is being thrown away", got)
	}
}

// TestSESClientBuildFailureIsReportedNotPanicked: the lazy build can fail, and
// a deployment with no resolvable region must learn that from the send rather
// than from a nil dereference.
func TestSESClientBuildFailureIsReportedNotPanicked(t *testing.T) {
	t.Parallel()

	want := errors.New("no region configured")
	transport := &SESTransport{
		from:        "<no-reply@example.test>",
		fromAddress: "no-reply@example.test",
		client:      &lazyClient[SESAPI]{build: func(context.Context) (SESAPI, error) { return nil, want }},
	}
	err := transport.Send(t.Context(), auth.MailMessage{To: "user@recipient.test", Subject: "s", Body: "b"})
	if !errors.Is(err, want) {
		t.Fatalf("Send error = %v, want it to wrap %v", err, want)
	}
}

func TestSESConstructorRefusesABadSender(t *testing.T) {
	t.Parallel()

	for _, from := range []string{"", "   ", "not-an-address", "a@b@c"} {
		if _, err := NewSESTransport(SESOptions{From: from}); err == nil {
			t.Errorf("NewSESTransport accepted from = %q; SES would reject every message and the fault would surface per request", from)
		}
	}
}

func TestSESRefusesAnEmptyRecipient(t *testing.T) {
	t.Parallel()
	transport, api := newTestSES(t, SESOptions{From: "no-reply@example.test"})

	if err := transport.Send(t.Context(), auth.MailMessage{Subject: "s", Body: "b"}); err == nil {
		t.Error("Send accepted a message with no recipient")
	}
	if len(api.inputs) != 0 {
		t.Errorf("SES was called %d times for a message with no recipient, want 0", len(api.inputs))
	}
}

func TestEmailDomain(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"user@example.test": "example.test",
		"user@":             "unparseable",
		"nonsense":          "unparseable",
		"":                  "unparseable",
	}
	for in, want := range cases {
		if got := emailDomain(in); got != want {
			t.Errorf("emailDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
