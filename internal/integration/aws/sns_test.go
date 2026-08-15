package aws

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	snstypes "github.com/aws/aws-sdk-go-v2/service/sns/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// theCode is the plaintext one-time code, the SMS counterpart of theToken. The
// store holds only its hash; this transport is the one place it exists in
// clear, so no error path may quote it.
const theCode = "418293"

const thePhone = "+15550100"

type fakeSNS struct {
	inputs []*sns.PublishInput
	err    error
}

func (f *fakeSNS) Publish(_ context.Context, in *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.inputs = append(f.inputs, in)
	if f.err != nil {
		return nil, f.err
	}
	return &sns.PublishOutput{MessageId: awssdk.String("11111111-2222-3333-4444-555555555555")}, nil
}

func TestSNSPublishesToThePhoneNumber(t *testing.T) {
	t.Parallel()
	api := &fakeSNS{}
	transport := NewSNSTransport(SNSOptions{Client: api})

	if err := transport.Send(t.Context(), thePhone, auth.SMSCodeMessage(theCode)); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if len(api.inputs) != 1 {
		t.Fatalf("SNS called %d times, want 1", len(api.inputs))
	}
	in := api.inputs[0]

	if got := awssdk.ToString(in.PhoneNumber); got != thePhone {
		t.Errorf("PhoneNumber = %q, want %q", got, thePhone)
	}
	// TopicArn must stay empty: a topic fans the code out to every subscriber,
	// which for a second factor is the opposite of what is wanted.
	if in.TopicArn != nil {
		t.Errorf("TopicArn = %q; a one-time code goes to one handset, not to a topic", awssdk.ToString(in.TopicArn))
	}
	if in.TargetArn != nil {
		t.Errorf("TargetArn = %q, want it absent", awssdk.ToString(in.TargetArn))
	}
	if got := awssdk.ToString(in.Message); got != auth.SMSCodeMessage(theCode) {
		t.Errorf("Message = %q, want the shared %q wording", got, auth.SMSCodeMessage(theCode))
	}

	attr, ok := in.MessageAttributes["AWS.SNS.SMS.SMSType"]
	if !ok {
		t.Fatal("no AWS.SNS.SMS.SMSType attribute; the account default is Promotional, which carriers deprioritise and some registries block")
	}
	if got := awssdk.ToString(attr.StringValue); got != "Transactional" {
		t.Errorf("SMSType = %q, want Transactional", got)
	}
	if got := awssdk.ToString(attr.DataType); got != "String" {
		t.Errorf("SMSType DataType = %q, want String", got)
	}
}

// TestSNSRefusesANumberItCannotRoute: SNS takes E.164 only. Catching it here
// names the fault — a stored number with no country code — instead of leaving
// an opaque InvalidParameter from the API, and it never guesses a country code,
// which would text a stranger.
func TestSNSRefusesANumberItCannotRoute(t *testing.T) {
	t.Parallel()

	for _, phone := range []string{"", "   ", "5550100", "0044 7700 900000", "(555) 010-0"} {
		api := &fakeSNS{}
		transport := NewSNSTransport(SNSOptions{Client: api})

		err := transport.Send(t.Context(), phone, auth.SMSCodeMessage(theCode))
		if err == nil {
			t.Errorf("Send accepted phone %q", phone)
		}
		if len(api.inputs) != 0 {
			t.Errorf("SNS was called for phone %q, want the refusal to be local", phone)
		}
		if err != nil && strings.Contains(err.Error(), theCode) {
			t.Errorf("the refusal for %q quotes the code:\n%s", phone, err)
		}
	}
}

func TestSNSPublishErrorPropagatesWithoutTheCode(t *testing.T) {
	t.Parallel()

	api := &fakeSNS{err: &snstypes.ThrottledException{Message: awssdk.String("Rate exceeded.")}}
	transport := NewSNSTransport(SNSOptions{Client: api})

	message := auth.SMSCodeMessage(theCode)
	err := transport.Send(t.Context(), thePhone, message)
	if err == nil {
		t.Fatal("a throttled publish returned nil; the route would answer 200 for a text that never left")
	}

	var throttled *snstypes.ThrottledException
	if !errors.As(err, &throttled) {
		t.Errorf("error %v does not unwrap to the SDK's own; a throttle is indistinguishable from a spend cap", err)
	}
	for _, leaked := range []string{theCode, message, thePhone} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("the error quotes %q, which reaches CloudWatch:\n%s", leaked, err)
		}
	}
}

// TestSNSClientIsLazy: same cold-start guard as TestSESClientIsLazy. An SMS
// deployment must pay nothing at init for a transport most invocations never
// touch, and must not rebuild the client — and its connection pool — per code.
func TestSNSClientIsLazy(t *testing.T) {
	t.Parallel()

	var builds atomic.Int64
	api := &fakeSNS{}
	transport := &SNSTransport{client: &lazyClient[SNSAPI]{build: func(context.Context) (SNSAPI, error) {
		builds.Add(1)
		return api, nil
	}}}

	if got := builds.Load(); got != 0 {
		t.Fatalf("the client was built %d times before any message was sent, want 0", got)
	}
	for i := 0; i < 3; i++ {
		if err := transport.Send(t.Context(), thePhone, auth.SMSCodeMessage(theCode)); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if got := builds.Load(); got != 1 {
		t.Errorf("the client was built %d times across 3 messages, want 1", got)
	}
}

// TestNewSNSTransportDoesNoWork: the constructor is called on the init path, so
// it must not touch the network or the credential chain. Nothing is injected
// here and no AWS environment exists in this test, yet it must still return.
func TestNewSNSTransportDoesNoWork(t *testing.T) {
	t.Parallel()

	if transport := NewSNSTransport(SNSOptions{}); transport == nil {
		t.Fatal("NewSNSTransport returned nil")
	}
}

// TestNewSESTransportDoesNoWork is the same statement for mail. Construction
// with no injected client and no AWS environment must succeed, because the
// client that would need one is not built yet.
func TestNewSESTransportDoesNoWork(t *testing.T) {
	t.Parallel()

	if _, err := NewSESTransport(SESOptions{From: "no-reply@example.test"}); err != nil {
		t.Fatalf("NewSESTransport: %v", err)
	}
}
