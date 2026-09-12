package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/smithy-go"
)

const (
	testPool     = "eu-west-1_EXAMPLE00"
	testClientID = "exampleappclientid00000000"
	testAddress  = "ada@example.test"
)

// fakeCognito is the CognitoAPI every test in this repository uses in place of a
// user pool. It records what it was asked and answers what the test told it to.
type fakeCognito struct {
	pages []*cip.ListUsersOutput
	page  int

	getUser    *cip.AdminGetUserOutput
	authResult *cip.AdminInitiateAuthOutput

	listErr error
	getErr  error
	authErr error

	listInputs []*cip.ListUsersInput
	getInputs  []*cip.AdminGetUserInput
	authInputs []*cip.AdminInitiateAuthInput
}

func (f *fakeCognito) ListUsers(_ context.Context, in *cip.ListUsersInput, _ ...func(*cip.Options)) (*cip.ListUsersOutput, error) {
	f.listInputs = append(f.listInputs, in)
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.page >= len(f.pages) {
		return &cip.ListUsersOutput{}, nil
	}
	out := f.pages[f.page]
	f.page++
	return out, nil
}

func (f *fakeCognito) AdminGetUser(_ context.Context, in *cip.AdminGetUserInput, _ ...func(*cip.Options)) (*cip.AdminGetUserOutput, error) {
	f.getInputs = append(f.getInputs, in)
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.getUser, nil
}

func (f *fakeCognito) AdminInitiateAuth(_ context.Context, in *cip.AdminInitiateAuthInput, _ ...func(*cip.Options)) (*cip.AdminInitiateAuthOutput, error) {
	f.authInputs = append(f.authInputs, in)
	if f.authErr != nil {
		return nil, f.authErr
	}
	if f.authResult != nil {
		return f.authResult, nil
	}
	return &cip.AdminInitiateAuthOutput{
		AuthenticationResult: &ciptypes.AuthenticationResultType{AccessToken: awssdk.String("ignored")},
	}, nil
}

// apiError builds a service error with the code and message the SDK would carry,
// so the mapping can be exercised without a network.
func apiError(code, message string) error {
	return &smithy.GenericAPIError{Code: code, Message: message}
}

func newTestDirectory(t *testing.T, api CognitoAPI, clientID string) CognitoDirectory {
	t.Helper()
	d, err := NewCognitoDirectory(CognitoOptions{UserPoolID: testPool, ClientID: clientID, Client: api})
	if err != nil {
		t.Fatalf("NewCognitoDirectory: %v", err)
	}
	return d
}

func TestCognitoDirectoryRequiresAUserPool(t *testing.T) {
	t.Parallel()
	if _, err := NewCognitoDirectory(CognitoOptions{Client: &fakeCognito{}}); err == nil {
		t.Fatal("NewCognitoDirectory with no pool id succeeded; a directory that addresses nothing must not build")
	}
}

func TestCognitoListUsersPagesAndFlattensAttributes(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{pages: []*cip.ListUsersOutput{{
		Users: []ciptypes.UserType{{
			Username:   awssdk.String("ada"),
			Enabled:    true,
			UserStatus: ciptypes.UserStatusTypeConfirmed,
			Attributes: []ciptypes.AttributeType{
				{Name: awssdk.String("email"), Value: awssdk.String(testAddress)},
				{Name: awssdk.String("email_verified"), Value: awssdk.String("true")},
				{Name: awssdk.String("custom:department"), Value: awssdk.String("analytics")},
				// A nameless attribute: dropped rather than stored under "".
				{Value: awssdk.String("orphan")},
			},
		}},
		PaginationToken: awssdk.String("page-2"),
	}}}
	d := newTestDirectory(t, api, "")

	page, err := d.ListUsers(t.Context(), "", 200)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if page.NextToken != "page-2" {
		t.Errorf("NextToken = %q, want page-2", page.NextToken)
	}
	if len(page.Users) != 1 {
		t.Fatalf("got %d users, want 1", len(page.Users))
	}
	u := page.Users[0]
	if u.Attr("email") != testAddress || u.Attr("email_verified") != "true" || u.Attr("custom:department") != "analytics" {
		t.Errorf("attributes = %v", u.Attributes)
	}
	if _, ok := u.Attributes[""]; ok {
		t.Error("a nameless attribute was stored under the empty key; it names nothing and must be dropped")
	}
	if u.Status != string(ciptypes.UserStatusTypeConfirmed) {
		t.Errorf("Status = %q, want CONFIRMED", u.Status)
	}

	// The page size is clamped to Cognito's own ceiling rather than passed
	// through, so a migration cannot stop halfway on an InvalidParameterException.
	if got := awssdk.ToInt32(api.listInputs[0].Limit); got != maxListUsersPageSize {
		t.Errorf("Limit = %d, want it clamped to %d", got, maxListUsersPageSize)
	}
}

func TestCognitoGetUserMapsTheMiss(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{getErr: apiError("UserNotFoundException", "User does not exist.")}
	d := newTestDirectory(t, api, "")

	if _, err := d.GetUser(t.Context(), testAddress); !errors.Is(err, ErrCognitoUserNotFound) {
		t.Fatalf("GetUser error = %v, want ErrCognitoUserNotFound", err)
	}
}

func TestCognitoGetUserSpendsNoCallOnAnEmptyUsername(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{}
	d := newTestDirectory(t, api, "")

	if _, err := d.GetUser(t.Context(), "   "); !errors.Is(err, ErrCognitoUserNotFound) {
		t.Fatalf("GetUser(\"\") = %v, want ErrCognitoUserNotFound", err)
	}
	if len(api.getInputs) != 0 {
		t.Error("an empty username reached the API; it can only fail, and this is an unauthenticated path")
	}
}

func TestCognitoVerifyPasswordUsesTheAdminFlow(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{}
	d := newTestDirectory(t, api, testClientID)

	if err := d.VerifyPassword(t.Context(), testAddress, "correct horse"); err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if len(api.authInputs) != 1 {
		t.Fatalf("AdminInitiateAuth called %d times, want 1", len(api.authInputs))
	}
	in := api.authInputs[0]
	if in.AuthFlow != ciptypes.AuthFlowTypeAdminUserPasswordAuth {
		t.Errorf("AuthFlow = %q, want ADMIN_USER_PASSWORD_AUTH", in.AuthFlow)
	}
	if awssdk.ToString(in.ClientId) != testClientID || awssdk.ToString(in.UserPoolId) != testPool {
		t.Errorf("addressed %q/%q, want %q/%q",
			awssdk.ToString(in.UserPoolId), awssdk.ToString(in.ClientId), testPool, testClientID)
	}
	if in.AuthParameters["USERNAME"] != testAddress || in.AuthParameters["PASSWORD"] != "correct horse" {
		t.Errorf("AuthParameters = %v", in.AuthParameters)
	}
}

func TestCognitoVerifyPasswordNeedsAnAppClient(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{}
	d := newTestDirectory(t, api, "")

	err := d.VerifyPassword(t.Context(), testAddress, "pw")
	if err == nil {
		t.Fatal("VerifyPassword with no client id succeeded")
	}
	if len(api.authInputs) != 0 {
		t.Error("AdminInitiateAuth was called with no client id; Cognito would refuse it and the call is wasted")
	}
}

// A challenge is not proof. Accepting one would let the migration silently strip
// a pool's second factor: the core adopts the password on ok=true and from then
// on that password alone signs the person in here.
func TestCognitoVerifyPasswordRefusesAChallenge(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{authResult: &cip.AdminInitiateAuthOutput{
		ChallengeName: ciptypes.ChallengeNameTypeSmsMfa,
		Session:       awssdk.String("session"),
	}}
	d := newTestDirectory(t, api, testClientID)

	if err := d.VerifyPassword(t.Context(), testAddress, "pw"); !errors.Is(err, ErrCognitoChallenge) {
		t.Fatalf("VerifyPassword error = %v, want ErrCognitoChallenge", err)
	}
}

// Neither tokens nor a challenge must never be read as success.
func TestCognitoVerifyPasswordRefusesAnEmptyAnswer(t *testing.T) {
	t.Parallel()
	api := &fakeCognito{authResult: &cip.AdminInitiateAuthOutput{}}
	d := newTestDirectory(t, api, testClientID)

	if err := d.VerifyPassword(t.Context(), testAddress, "pw"); !errors.Is(err, ErrCognitoPasswordRejected) {
		t.Fatalf("VerifyPassword error = %v, want ErrCognitoPasswordRejected", err)
	}
}

func TestCognitoErrorMapping(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		code    string
		message string
		want    error
	}{
		{"wrong password", "NotAuthorizedException", "Incorrect username or password.", ErrCognitoPasswordRejected},
		{"app client has a secret", "NotAuthorizedException",
			"Client " + testClientID + " is configured with secret but SECRET_HASH was not received", ErrCognitoClientHasSecret},
		{"unknown user", "UserNotFoundException", "User does not exist.", ErrCognitoUserNotFound},
		{"unconfirmed", "UserNotConfirmedException", "User is not confirmed.", ErrCognitoUserNotConfirmed},
		{"reset required", "PasswordResetRequiredException", "Password reset required for the user", ErrCognitoPasswordResetRequired},
		{"throttled", "TooManyRequestsException", "Too many requests", ErrCognitoThrottled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			api := &fakeCognito{authErr: apiError(tc.code, tc.message)}
			d := newTestDirectory(t, api, testClientID)

			err := d.VerifyPassword(t.Context(), testAddress, "pw")
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyPassword error = %v, want %v", err, tc.want)
			}
		})
	}
}

// The SDK's own message is never rendered, for the reason kmsError gives: these
// calls carry an address and a password, and Cognito quotes its inputs back in
// several of its messages.
func TestCognitoErrorsDoNotQuoteTheSDKMessage(t *testing.T) {
	t.Parallel()
	const leak = "the-password-was-hunter2"
	api := &fakeCognito{authErr: apiError("InvalidParameterException", leak)}
	d := newTestDirectory(t, api, testClientID)

	err := d.VerifyPassword(t.Context(), testAddress, "pw")
	if err == nil {
		t.Fatal("VerifyPassword succeeded")
	}
	if got := err.Error(); strings.Contains(got, leak) {
		t.Errorf("the rendered error quotes the SDK message: %q", got)
	}
	// The cause stays reachable, which is how a caller tells a throttle from a
	// denial without anything being printed.
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		t.Error("the SDK error is no longer reachable through errors.As")
	}
}
