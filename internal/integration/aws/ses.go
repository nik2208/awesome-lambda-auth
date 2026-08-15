package aws

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	sestypes "github.com/aws/aws-sdk-go-v2/service/sesv2/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// Why SES v2 and not the classic SES API.
//
// Both can send a message and both are authorised by the same IAM action
// (`ses:SendEmail` against an `identity/<domain-or-address>` resource — the v2
// API kept the v1 IAM prefix), so the choice is not about permissions:
//
//   - v2 is where AWS puts new capability. Configuration sets, the account-level
//     suppression list, virtual deliverability manager and the tenant/identity
//     management APIs are v2-only; classic SES is maintained, not developed.
//   - v2 takes one SendEmail for simple *and* raw content. Classic splits them
//     into SendEmail and SendRawEmail, so the day this transport grows an
//     attachment or a List-Unsubscribe header it would change API rather than
//     change a field.
//   - The v2 request shape is auth.MailMessage's shape. Destination.ToAddresses,
//     Content.Simple.Subject and Content.Simple.Body.Html map one-to-one onto To,
//     Subject and Body, so there is no assembly step in which the credential-
//     bearing body could be mangled.
//
// Nothing here needs v1. Picking the API on the way out is cheaper than picking
// it again later.

// SESAPI is the single SES call this transport makes. Declared here rather than
// imported so a test injects a fake instead of a socket, the same way
// SecretsManagerAPI and the DynamoDB store's client interface do.
type SESAPI interface {
	SendEmail(ctx context.Context, in *sesv2.SendEmailInput, optFns ...func(*sesv2.Options)) (*sesv2.SendEmailOutput, error)
}

// SESOptions configures NewSESTransport.
type SESOptions struct {
	// From is the envelope and header sender. Required, and it must be a
	// verified SES identity (or fall under a verified domain), because SES
	// rejects anything else outright. It is email.mailer.from.
	From string

	// FromName is the display name, email.mailer.fromName. Empty sends a bare
	// address, which is legal and is what the reference does when the knob is
	// unset.
	FromName string

	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION, which the Lambda runtime always sets — and which is the region
	// the identity has to be verified in, since SES identities are regional.
	Region string

	// ConfigurationSetName attaches an SES configuration set to every message,
	// which is how bounce and complaint events reach an event destination. There
	// is no configuration knob for it yet; it is here so the deployment that
	// wants delivery telemetry does not have to change this type to get it.
	ConfigurationSetName string

	// Client injects an SESAPI. Non-nil skips the lazy build entirely, which is
	// how tests drive the transport without an AWS account.
	Client SESAPI
}

// SESTransport delivers auth.MailMessage through Amazon SES.
//
// It implements auth.MailerTransport, which is the one-method seam the upstream
// mailers render into: this type knows how to put a rendered message on the
// wire and nothing about magic links, reset tokens or templates. The five
// senders are composed from it in cmd/auth.
type SESTransport struct {
	// from is the fully rendered From header — `Name <addr>` when a display name
	// was configured, the bare address otherwise.
	from string

	// fromAddress is the address alone, kept for the error messages so that a
	// rejected send names the identity that was refused.
	fromAddress string

	configurationSet string

	client *lazyClient[SESAPI]
}

// Compile-time proof that this is the seam upstream asks for. Cheap, and it
// fails at build time rather than at the first magic-link mail if the interface
// ever moves.
var _ auth.MailerTransport = (*SESTransport)(nil)

// NewSESTransport builds the transport. It performs no I/O and makes no client:
// see lazyClient for why the SDK client is deferred to the first message.
//
// The only failure it reports is a missing or unparseable From address, which
// is a configuration fault that must abort the cold start rather than surface
// as a 500 on the first password reset.
func NewSESTransport(opts SESOptions) (*SESTransport, error) {
	addr := strings.TrimSpace(opts.From)
	if addr == "" {
		return nil, errors.New("ses: no sender address; email.mailer.from is what SES sends as, and it must be a verified identity")
	}
	if _, err := mail.ParseAddress(addr); err != nil {
		return nil, fmt.Errorf("ses: email.mailer.from %q is not a valid address: %w", addr, err)
	}

	t := &SESTransport{
		// (&mail.Address{}).String() does the RFC 5322 quoting and the RFC 2047
		// encoding of a non-ASCII display name. Building the header by hand is
		// how a comma or an accent in fromName turns into a rejected send.
		from:             (&mail.Address{Name: strings.TrimSpace(opts.FromName), Address: addr}).String(),
		fromAddress:      addr,
		configurationSet: strings.TrimSpace(opts.ConfigurationSetName),
	}

	if opts.Client != nil {
		t.client = &lazyClient[SESAPI]{build: func(context.Context) (SESAPI, error) { return opts.Client, nil }}
		return t, nil
	}
	shared := &lazyConfig{region: opts.Region}
	t.client = &lazyClient[SESAPI]{build: func(ctx context.Context) (SESAPI, error) {
		cfg, err := shared.get(ctx)
		if err != nil {
			return nil, err
		}
		return sesv2.NewFromConfig(cfg), nil
	}}
	return t, nil
}

// Send implements auth.MailerTransport.
//
// Every message this transport carries has a credential in it — a magic-link
// URL, a reset token, a verification token — so no error path may quote the
// body, the subject or the recipient. What a failure says is: SES refused, from
// this identity, to this recipient's domain, because <the SDK's own error>.
// That is enough to tell a suppressed domain from an unverified identity from a
// sandboxed account, and none of the text this method writes is credential
// material.
//
// One honest caveat about the wrapped half. The SDK error is passed through so
// that errors.As still reaches the API's own type — a caller cannot otherwise
// tell a throttle from a sandbox — and its Message comes from SES, not from
// here. SES does put a recipient address in some of them: MessageRejected for an
// unverified destination reads "...The following identities failed the check in
// region X: <address>". So the guarantee this method makes is that no *token*
// can reach CloudWatch, because the body and subject are never touched by an
// error path and SES never echoes them; a recipient address can, through the
// service's own wording. Redacting that would mean rewriting the SDK error and
// losing the cause with it, which is a worse trade for a value the account's
// SES event destinations already carry.
func (t *SESTransport) Send(ctx context.Context, msg auth.MailMessage) error {
	to := strings.TrimSpace(msg.To)
	if to == "" {
		return errors.New("ses: message has no recipient")
	}

	api, err := t.client.get(ctx)
	if err != nil {
		return fmt.Errorf("ses: cannot build a client: %w", err)
	}

	content := &sestypes.Content{Data: awssdk.String(msg.Body), Charset: awssdk.String("UTF-8")}
	body := &sestypes.Body{Text: content}
	if msg.IsHTML {
		// The built-in templates are HTML documents and set IsHTML. A text-only
		// alternative is deliberately not synthesised here: stripping tags out of
		// a template to make one would produce a second, worse rendering of a
		// message carrying a credential, and getting that wrong is how a link
		// arrives broken.
		body = &sestypes.Body{Html: content}
	}

	in := &sesv2.SendEmailInput{
		FromEmailAddress: awssdk.String(t.from),
		Destination:      &sestypes.Destination{ToAddresses: []string{to}},
		Content: &sestypes.EmailContent{
			Simple: &sestypes.Message{
				Subject: &sestypes.Content{Data: awssdk.String(msg.Subject), Charset: awssdk.String("UTF-8")},
				Body:    body,
			},
		},
	}
	if t.configurationSet != "" {
		in.ConfigurationSetName = awssdk.String(t.configurationSet)
	}

	if _, err := api.SendEmail(ctx, in); err != nil {
		return fmt.Errorf("ses: sending from %s to a %s recipient failed: %w", t.fromAddress, emailDomain(to), err)
	}
	return nil
}

// emailDomain returns the domain half of an address, for an error message that
// has to be actionable without naming a person. SES failures are overwhelmingly
// domain-shaped — a suppressed domain, a sandbox that has not verified the
// recipient, a reputation block — so the domain is the useful half, and it is
// also the half that identifies nobody.
func emailDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return addr[i+1:]
	}
	return "unparseable"
}
