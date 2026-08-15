package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// Why SNS Publish straight to a phone number, and not a topic.
//
// SNS has two SMS shapes. Publish with TopicArn fans a message out to whoever
// subscribed; Publish with PhoneNumber sends one message to one handset. A
// one-time code has exactly one recipient, chosen at send time, and it must
// reach that handset and no other — so the topic shape is not a heavier version
// of what is wanted here, it is the wrong thing: it would need a subscription
// per user, created and confirmed before the first login, and every subscriber
// of a topic receives every message published to it. Publish-to-phone-number is
// the primitive; nothing is being simplified away by using it.
//
// The consequence worth knowing is on the IAM side. A phone number is not an
// AWS resource, so `sns:Publish` to one cannot be scoped by Resource — see
// infra/sam/template.yaml, which uses NotResource to grant exactly this and
// deny publishing to every topic in the account.

// SNSAPI is the single SNS call this transport makes. Declared here so a test
// injects a fake, as SESAPI and SecretsManagerAPI are.
type SNSAPI interface {
	Publish(ctx context.Context, in *sns.PublishInput, optFns ...func(*sns.Options)) (*sns.PublishOutput, error)
}

// SNSOptions configures NewSNSTransport. The zero value is what a Lambda uses.
type SNSOptions struct {
	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION. It matters more than it looks: SMS spend limits, origination
	// identities and the sandbox destination allowlist are all per-region.
	Region string

	// Client injects an SNSAPI. Non-nil skips the lazy build.
	Client SNSAPI
}

// SNSTransport delivers a one-time code to a handset through SNS.
//
// It satisfies auth.SMSTransport structurally — that interface is
// Send(ctx, phone, message) with no types of its own — and upstream's
// SMSTransportSender turns it into the auth.SMSCodeSender the core wants.
type SNSTransport struct {
	client *lazyClient[SNSAPI]
}

var _ auth.SMSTransport = (*SNSTransport)(nil)

// NewSNSTransport builds the transport. It performs no I/O and cannot fail: SNS
// needs no per-deployment configuration at all, because the destination arrives
// with each message and the credentials come from the execution role. The
// client is built on the first message; see lazyClient.
func NewSNSTransport(opts SNSOptions) *SNSTransport {
	if opts.Client != nil {
		return &SNSTransport{client: &lazyClient[SNSAPI]{
			build: func(context.Context) (SNSAPI, error) { return opts.Client, nil },
		}}
	}
	shared := &lazyConfig{region: opts.Region}
	return &SNSTransport{client: &lazyClient[SNSAPI]{
		build: func(ctx context.Context) (SNSAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return sns.NewFromConfig(cfg), nil
		},
	}}
}

// Send implements auth.SMSTransport.
//
// The message is auth.SMSCodeMessage(code) and therefore carries the plaintext
// code, and the phone number is the recipient's. Neither appears in any text
// this method writes, for the same reason SESTransport quotes neither body nor
// mailbox: the caller logs what it is handed.
//
// The same caveat as SESTransport.Send applies to the wrapped SDK error, and
// with the same conclusion. SNS never echoes the Message parameter, so the code
// cannot come back in an error; SNS's own InvalidParameter wording for a
// malformed destination does quote the number. The E.164 check below is the
// reason that path is rare rather than routine, and passing the cause through
// is what lets a caller tell a throttle from a spend cap from a sandbox.
func (t *SNSTransport) Send(ctx context.Context, phone, message string) error {
	number := strings.TrimSpace(phone)
	if number == "" {
		return errors.New("sns: message has no destination number")
	}
	if !strings.HasPrefix(number, "+") {
		// SNS takes E.164 and nothing else. Rejecting here rather than letting
		// SNS answer InvalidParameter names the actual fault — a stored number
		// with no country code — instead of a generic API error, and guessing a
		// country code from the deployment's region would silently text a
		// stranger. The reference's HTTP gateway accepted local formats; that is
		// a real difference and it belongs to the number, not to this call.
		return errors.New("sns: the stored phone number is not in E.164 form (it must begin with '+' and a country code); SNS cannot route it")
	}

	api, err := t.client.get(ctx)
	if err != nil {
		return fmt.Errorf("sns: cannot build a client: %w", err)
	}

	if _, err := api.Publish(ctx, &sns.PublishInput{
		PhoneNumber: awssdk.String(number),
		Message:     awssdk.String(message),
		MessageAttributes: map[string]snstypes.MessageAttributeValue{
			// Not a knob, and not a default worth inheriting. SNS's account-wide
			// default is Promotional, which is delivered at lower priority and is
			// what carriers drop first under load — and in several countries
			// promotional traffic is blocked outright on do-not-disturb
			// registries. A login code that arrives late is a failed login, so
			// every message this transport sends is Transactional.
			"AWS.SNS.SMS.SMSType": {
				DataType:    awssdk.String("String"),
				StringValue: awssdk.String("Transactional"),
			},
		},
	}); err != nil {
		return fmt.Errorf("sns: publishing a text message failed: %w", err)
	}
	return nil
}
