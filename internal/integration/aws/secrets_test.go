package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// theSecret is a stand-in signing key. Every error assertion below checks that
// it does not appear in the message: a resolver that names the value it failed
// on writes the signing key into CloudWatch, which is the exposure this whole
// package exists to remove.
const theSecret = "PLKM2yq0tRZfV6cN8wXbQ1sJhG4uD7aE"

type fakeSecretsManager struct {
	values map[string]string
	err    error
	binary bool
	calls  map[string]int
}

func (f *fakeSecretsManager) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	id := awssdk.ToString(in.SecretId)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[id]++
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[id]
	if !ok {
		return nil, &smtypes.ResourceNotFoundException{Message: awssdk.String("Secrets Manager can't find the specified secret.")}
	}
	if f.binary {
		return &secretsmanager.GetSecretValueOutput{SecretBinary: []byte(v)}, nil
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: awssdk.String(v)}, nil
}

type fakeSSM struct {
	values     map[string]string
	err        error
	calls      map[string]int
	decryption []bool
}

func (f *fakeSSM) GetParameter(_ context.Context, in *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	name := awssdk.ToString(in.Name)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	f.calls[name]++
	f.decryption = append(f.decryption, awssdk.ToBool(in.WithDecryption))
	if f.err != nil {
		return nil, f.err
	}
	v, ok := f.values[name]
	if !ok {
		return nil, &ssmtypes.ParameterNotFound{Message: awssdk.String("Parameter not found.")}
	}
	return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: awssdk.String(v)}}, nil
}

func smResolver(api SecretsManagerAPI) config.SecretResolver {
	return NewSecretResolvers(SecretResolverOptions{SecretsManager: api}).SecretsManager
}

func ssmResolver(api SSMAPI) config.SecretResolver {
	return NewSecretResolvers(SecretResolverOptions{SSM: api}).SSM
}

// TestSecretsManagerReadsBothStoredShapes pins the two shapes a Secrets Manager
// secret actually has in the wild: a bare string, and the JSON document the
// console produces. The '#key' selector is this build's choice of syntax for the
// second one — docs/spec/config-schema.md specifies none.
func TestSecretsManagerReadsBothStoredShapes(t *testing.T) {
	api := &fakeSecretsManager{values: map[string]string{
		"awesome-auth/jwt-access": theSecret,
		"awesome-auth/jwt":        `{"accessTokenSecret":` + `"` + theSecret + `","refreshTokenSecret":"other"}`,
	}}
	r := smResolver(api)

	for _, tc := range []struct{ name, ref, want string }{
		{"raw string", "awesome-auth/jwt-access", theSecret},
		{"json key", "awesome-auth/jwt#accessTokenSecret", theSecret},
		{"json key, second entry", "awesome-auth/jwt#refreshTokenSecret", "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := r.Resolve(t.Context(), tc.ref)
			if err != nil {
				t.Fatalf("resolve %s: %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("resolved %s to the wrong value", tc.ref)
			}
		})
	}
}

// TestSecretsManagerFetchesOncePerColdStart: a Secrets Manager read is a network
// call, is billed per call and throttles. One reference, one fetch — including
// when two knobs select two keys out of the same JSON secret.
func TestSecretsManagerFetchesOncePerColdStart(t *testing.T) {
	api := &fakeSecretsManager{values: map[string]string{
		"awesome-auth/jwt": `{"access":"` + theSecret + `","refresh":"other"}`,
	}}
	r := smResolver(api)

	for _, ref := range []string{
		"awesome-auth/jwt#access",
		"awesome-auth/jwt#refresh",
		"awesome-auth/jwt#access",
	} {
		if _, err := r.Resolve(t.Context(), ref); err != nil {
			t.Fatalf("resolve %s: %v", ref, err)
		}
	}
	if n := api.calls["awesome-auth/jwt"]; n != 1 {
		t.Errorf("GetSecretValue called %d times, want 1", n)
	}
}

// TestMissingSecretFallsThrough: only "there is no such secret" is a miss, and a
// miss is what makes the documented resolution order an order.
func TestMissingSecretFallsThrough(t *testing.T) {
	cases := map[string]struct {
		resolve func() (string, error)
	}{
		"secrets manager, no such secret": {func() (string, error) {
			return smResolver(&fakeSecretsManager{}).Resolve(context.Background(), "awesome-auth/absent")
		}},
		"secrets manager, empty value": {func() (string, error) {
			return smResolver(&fakeSecretsManager{values: map[string]string{"awesome-auth/empty": ""}}).
				Resolve(context.Background(), "awesome-auth/empty")
		}},
		"secrets manager, json document without the key": {func() (string, error) {
			return smResolver(&fakeSecretsManager{values: map[string]string{"awesome-auth/jwt": `{"other":"x"}`}}).
				Resolve(context.Background(), "awesome-auth/jwt#access")
		}},
		"ssm, no such parameter": {func() (string, error) {
			return ssmResolver(&fakeSSM{}).Resolve(context.Background(), "/awesome-auth/absent")
		}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tc.resolve()
			if !errors.Is(err, config.ErrSecretNotFound) {
				t.Fatalf("error is not ErrSecretNotFound, so the chain would stop instead of falling through: %v", err)
			}
		})
	}
}

// TestReadFailureIsNotAMiss: a denied read, a throttle or a secret stored in a
// shape this build cannot use must stop the resolution walk. Falling through
// would turn "the execution role cannot read this" into "the secret is empty",
// and the deployment would come up signing tokens with nothing.
func TestReadFailureIsNotAMiss(t *testing.T) {
	denied := &smtypes.InvalidRequestException{Message: awssdk.String("AccessDeniedException")}

	cases := map[string]struct {
		resolve  func() (string, error)
		wantRef  string
		wantWord string
	}{
		"secrets manager denies the read": {
			resolve: func() (string, error) {
				return smResolver(&fakeSecretsManager{err: denied}).Resolve(context.Background(), "awesome-auth/jwt-access")
			},
			wantRef:  "awesome-auth/jwt-access",
			wantWord: "secretsmanager",
		},
		"secret holds binary": {
			resolve: func() (string, error) {
				return smResolver(&fakeSecretsManager{binary: true, values: map[string]string{"awesome-auth/bin": theSecret}}).
					Resolve(context.Background(), "awesome-auth/bin")
			},
			wantRef:  "awesome-auth/bin",
			wantWord: "binary",
		},
		"json selector against a non-json value": {
			resolve: func() (string, error) {
				return smResolver(&fakeSecretsManager{values: map[string]string{"awesome-auth/raw": theSecret}}).
					Resolve(context.Background(), "awesome-auth/raw#access")
			},
			wantRef:  "awesome-auth/raw",
			wantWord: "JSON",
		},
		"json selector against a non-string member": {
			resolve: func() (string, error) {
				return smResolver(&fakeSecretsManager{values: map[string]string{"awesome-auth/jwt": `{"access":42}`}}).
					Resolve(context.Background(), "awesome-auth/jwt#access")
			},
			wantRef:  "awesome-auth/jwt",
			wantWord: "not a JSON string",
		},
		"ssm denies the read": {
			resolve: func() (string, error) {
				return ssmResolver(&fakeSSM{err: errors.New("AccessDeniedException: not authorized")}).
					Resolve(context.Background(), "/awesome-auth/jwt-access")
			},
			wantRef:  "/awesome-auth/jwt-access",
			wantWord: "ssm",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := tc.resolve()
			if err == nil {
				t.Fatal("expected an error")
			}
			if errors.Is(err, config.ErrSecretNotFound) {
				t.Errorf("a read failure was reported as a miss, so the chain would fall through: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantRef) {
				t.Errorf("the error does not name the failing reference %q: %v", tc.wantRef, err)
			}
			if !strings.Contains(err.Error(), tc.wantWord) {
				t.Errorf("the error does not say what went wrong (%q): %v", tc.wantWord, err)
			}
		})
	}
}

// TestErrorsNeverEchoTheValue is the one that matters. Every failure path that
// has the payload in hand must report the reference and nothing else —
// encoding/json in particular quotes the offending input in its own message.
func TestErrorsNeverEchoTheValue(t *testing.T) {
	// A payload that is not JSON, so the decoder fails with the value in reach.
	for _, ref := range []string{"awesome-auth/raw#access", "awesome-auth/notobject#access"} {
		api := &fakeSecretsManager{values: map[string]string{
			"awesome-auth/raw":       theSecret,
			"awesome-auth/notobject": `["` + theSecret + `"]`,
		}}
		_, err := smResolver(api).Resolve(t.Context(), ref)
		if err == nil {
			t.Fatalf("%s: expected an error", ref)
		}
		if strings.Contains(err.Error(), theSecret) {
			t.Errorf("%s: the error echoed the secret value: %v", ref, err)
		}
	}
}

// TestSSMAlwaysDecrypts: a secret-valued knob has no business in a plaintext
// String parameter, and WithDecryption is simply ignored for one — so there is
// no case in which sending it is wrong, and forgetting it returns ciphertext
// that would be used as a signing key.
func TestSSMAlwaysDecrypts(t *testing.T) {
	api := &fakeSSM{values: map[string]string{"/awesome-auth/jwt-access": theSecret}}
	got, err := ssmResolver(api).Resolve(t.Context(), "/awesome-auth/jwt-access")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != theSecret {
		t.Errorf("resolved the wrong value")
	}
	for _, on := range api.decryption {
		if !on {
			t.Errorf("GetParameter was called without WithDecryption")
		}
	}
}

// TestSSMReadsJSONKey: the selector syntax is the same in both stores, because
// two syntaxes for one idea is one too many.
func TestSSMReadsJSONKey(t *testing.T) {
	api := &fakeSSM{values: map[string]string{"/awesome-auth/jwt": `{"access":"` + theSecret + `"}`}}
	got, err := ssmResolver(api).Resolve(t.Context(), "/awesome-auth/jwt#access")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != theSecret {
		t.Errorf("resolved the wrong value")
	}
}

// TestResolverNamesMatchTheChain: config.resolveOne reports the source by these
// names, and Config.SecretSource surfaces them to diagnostics.
func TestResolverNamesMatchTheChain(t *testing.T) {
	r := NewSecretResolvers(SecretResolverOptions{})
	if got := r.SecretsManager.Name(); got != config.ResolverSecretsManager {
		t.Errorf("Secrets Manager resolver names itself %q, want %q", got, config.ResolverSecretsManager)
	}
	if got := r.SSM.Name(); got != config.ResolverSSM {
		t.Errorf("SSM resolver names itself %q, want %q", got, config.ResolverSSM)
	}
}

// TestNewSecretResolversPerformsNoIO: cmd/auth builds the chain before
// config.Load on every cold start, including the deployments that reference no
// store at all. Constructing it must not walk the credential chain or touch the
// network — the clients are built on the first Resolve that needs one.
func TestNewSecretResolversPerformsNoIO(t *testing.T) {
	// The constructor takes no context and returns no error, which is the
	// structural proof: there is nowhere for a call to fail or be cancelled.
	// This test guards that signature against being "improved" later.
	r := NewSecretResolvers(SecretResolverOptions{Region: "eu-west-1"})
	if r.SecretsManager == nil || r.SSM == nil {
		t.Fatal("NewSecretResolvers left a store unwired")
	}
	if r.Env != nil {
		t.Error("NewSecretResolvers wired an Env resolver; config.Load owns that one, over its own Getenv")
	}
}

// TestSplitSecretRef pins the separator against the characters the two stores
// actually allow in a name, ARNs included.
func TestSplitSecretRef(t *testing.T) {
	cases := []struct{ ref, id, key string }{
		{"awesome-auth/jwt-access", "awesome-auth/jwt-access", ""},
		{"awesome-auth/jwt#access", "awesome-auth/jwt", "access"},
		{"arn:aws:secretsmanager:eu-west-1:111122223333:secret:awesome-auth/jwt-AbCdEf", "arn:aws:secretsmanager:eu-west-1:111122223333:secret:awesome-auth/jwt-AbCdEf", ""},
		{"arn:aws:secretsmanager:eu-west-1:111122223333:secret:awesome-auth/jwt-AbCdEf#access", "arn:aws:secretsmanager:eu-west-1:111122223333:secret:awesome-auth/jwt-AbCdEf", "access"},
		{"/awesome-auth/prod/jwt#access", "/awesome-auth/prod/jwt", "access"},
	}
	for _, tc := range cases {
		id, key := splitSecretRef(tc.ref)
		if id != tc.id || key != tc.key {
			t.Errorf("splitSecretRef(%q) = (%q, %q), want (%q, %q)", tc.ref, id, key, tc.id, tc.key)
		}
	}
}
