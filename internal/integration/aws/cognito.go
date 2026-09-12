package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	cip "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	ciptypes "github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/aws/smithy-go"
)

// Why exactly three calls, and why two seams rather than one.
//
// The migration off Cognito needs the user pool to answer three questions and
// no others: who is in it (ListUsers), what does it hold about one person
// (AdminGetUser), and is this the password it holds for them
// (AdminInitiateAuth). Everything else the API offers — creating users,
// changing passwords, deleting the pool — is a capability the IAM policy in
// infra/sam/template.yaml deliberately does not grant, and an interface that
// named those actions would be an invitation to grant them. The narrow
// interface is the documentation of the blast radius, exactly as the DynamoDB
// store's API interface is (internal/store/dynamodb/store.go).
//
// Two seams, because two different callers need two different things:
//
//   - CognitoAPI is SDK-shaped, one method per API call, and exists so a test
//     injects a fake instead of a socket. It is the sibling of SESAPI, SNSAPI
//     and KMSAPI.
//   - CognitoDirectory is SDK-free — plain strings, a plain struct, sentinel
//     errors — and is what internal/store/migrating and cmd/migrate depend on.
//     The product rule is that the AWS SDK appears only under
//     internal/integration/aws and internal/store/dynamodb (cmd/auth/app.go,
//     Options.IDPKeySource), and a seam typed in SDK terms would export that
//     dependency to every implementor and every one of their tests. This is the
//     same split KMS already has: KMSAPI for the fake, IDPKeySource for the rest
//     of the product.
//
// Neither seam is a Cognito abstraction layer. The translation below is one
// function per call, it drops nothing the product reads, and it is where the
// error mapping lives — which is the one piece of behaviour worth having in a
// single place, because a login's answer depends on telling "that is not the
// password" apart from "the pool did not answer".

// CognitoAPI is the slice of the Cognito user-pool API this product uses.
// Declared here rather than imported so a test injects a fake, as SESAPI,
// SNSAPI and KMSAPI are.
type CognitoAPI interface {
	ListUsers(ctx context.Context, in *cip.ListUsersInput, optFns ...func(*cip.Options)) (*cip.ListUsersOutput, error)
	AdminGetUser(ctx context.Context, in *cip.AdminGetUserInput, optFns ...func(*cip.Options)) (*cip.AdminGetUserOutput, error)
	AdminInitiateAuth(ctx context.Context, in *cip.AdminInitiateAuthInput, optFns ...func(*cip.Options)) (*cip.AdminInitiateAuthOutput, error)
}

// The answers a Cognito call can give that the callers have to tell apart.
//
// The division that matters is between a *decision* and a *failure*. The
// password-verifier seam upstream says a non-nil error is "a failure to decide,
// not a rejection", and that the login fails closed on one
// (awesome-go-auth/password_verifier.go). So every sentinel below that means
// "this account cannot prove this password here" has to be answerable as
// (false, false, nil) by the verifier, and only the ones that mean "the pool
// did not answer" may reach the core as an error and become a 500.
var (
	// ErrCognitoUserNotFound: the pool has no such user. A decision.
	ErrCognitoUserNotFound = errors.New("cognito: the user pool holds no such user")

	// ErrCognitoPasswordRejected: the pool has the user and this is not their
	// password — or the account is disabled, which Cognito reports with the same
	// NotAuthorizedException and which this package deliberately does not try to
	// tell apart. A decision, and the one this whole file exists to obtain.
	ErrCognitoPasswordRejected = errors.New("cognito: the user pool did not accept that password")

	// ErrCognitoUserNotConfirmed: the account exists but was never confirmed, so
	// Cognito refuses the sign-in before it judges the password. A decision: the
	// person cannot sign in to the old system either, and inventing a local
	// account for them out of a password Cognito never validated would be
	// strictly worse than the migration not applying.
	ErrCognitoUserNotConfirmed = errors.New("cognito: the account exists but has never been confirmed")

	// ErrCognitoPasswordResetRequired: the pool was told to force a reset (an
	// admin-created user, or a pool-wide policy). Cognito refuses the sign-in
	// without judging the password, so this is a decision for the same reason.
	ErrCognitoPasswordResetRequired = errors.New("cognito: the user pool requires a password reset before sign-in")

	// ErrCognitoChallenge: the credentials were right and the pool wants a
	// second step — SMS_MFA, SOFTWARE_TOKEN_MFA, NEW_PASSWORD_REQUIRED. A
	// decision, and a deliberately conservative one: see VerifyPassword.
	ErrCognitoChallenge = errors.New("cognito: the user pool answered with a challenge instead of tokens")

	// ErrCognitoThrottled: the pool refused to answer this time. A failure.
	ErrCognitoThrottled = errors.New("cognito: the user pool throttled the request")

	// ErrCognitoClientHasSecret: the app client named by stores.migration.clientId
	// was created with a client secret, so ADMIN_USER_PASSWORD_AUTH needs a
	// SECRET_HASH this product does not compute. A failure, and a configuration
	// one: it is the same on every request and an operator has to be able to read
	// it out of the log as itself rather than as "wrong password" on every login.
	ErrCognitoClientHasSecret = errors.New("cognito: the migration app client is configured with a client secret, which this product does not send")
)

// CognitoUser is one user pool record in terms no AWS package owns.
//
// Attributes is the pool's attribute list flattened into a map, standard and
// custom: "email", "email_verified", "phone_number", "given_name",
// "family_name", "sub", and every "custom:<name>" the pool defines. It is
// flattened rather than kept as a list because every consumer wants it by name
// and Cognito guarantees one value per name.
type CognitoUser struct {
	// Username is the pool's own handle for the record. It is what AdminGetUser
	// and AdminInitiateAuth address, and it is NOT necessarily the email: a pool
	// with alias attributes hands out an opaque sub as the username.
	Username string

	// Enabled is false for an administratively disabled account.
	Enabled bool

	// Status is Cognito's UserStatus (CONFIRMED, UNCONFIRMED, FORCE_CHANGE_PASSWORD,
	// …), carried verbatim so the migration CLI can report what it skipped.
	Status string

	Attributes map[string]string

	CreatedAt time.Time
	UpdatedAt time.Time
}

// Attr returns one attribute, or "".
func (u CognitoUser) Attr(name string) string { return u.Attributes[name] }

// CognitoUserPage is one page of ListUsers. NextToken is empty on the last page,
// which is what makes "loop until it is empty" the whole paging contract.
type CognitoUserPage struct {
	Users     []CognitoUser
	NextToken string
}

// CognitoDirectory is the SDK-free seam the rest of the product depends on.
//
// Three methods, one per call, named for the question rather than for the API:
// the callers are a migration CLI and a login-path verifier, and neither should
// have to know that "is this the password" is spelled AdminInitiateAuth with an
// auth flow constant.
type CognitoDirectory interface {
	// ListUsers returns one page. pageToken is "" for the first page and the
	// previous page's NextToken afterwards. limit is Cognito's per-page cap
	// (1..60); zero asks for the service default.
	ListUsers(ctx context.Context, pageToken string, limit int32) (CognitoUserPage, error)

	// GetUser resolves one user by the pool's username or by an alias the pool
	// accepts (an email address, where the pool was created with email as an
	// alias or as the sign-in attribute). ErrCognitoUserNotFound for a miss.
	GetUser(ctx context.Context, username string) (CognitoUser, error)

	// VerifyPassword asks the pool whether password is this user's. nil means
	// yes; every other answer is one of the sentinels above.
	VerifyPassword(ctx context.Context, username, password string) error
}

// CognitoOptions configures NewCognitoDirectory.
type CognitoOptions struct {
	// UserPoolID is the pool every call addresses. Required.
	UserPoolID string

	// ClientID is an app client in that pool, and it is required only for
	// VerifyPassword: AdminInitiateAuth is a client-scoped call and Cognito
	// refuses one with no ClientId. The app client must have
	// ALLOW_ADMIN_USER_PASSWORD_AUTH among its explicit auth flows and must have
	// been created WITHOUT a client secret — see ErrCognitoClientHasSecret.
	//
	// Empty is legal and is what the bulk-import half of the migration uses: it
	// reads the pool and never signs anyone in.
	ClientID string

	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION. It matters here more than it looks: a user pool id is region-
	// scoped by its own prefix, and the pool being migrated away from commonly
	// lives in a different region — or a different account — from the stack doing
	// the migrating. RS-13 refuses a pool id with no region for that reason.
	Region string

	// Profile names a profile in the shared config file. Always empty in the
	// Lambda, where credentials come from the execution role; it exists for
	// cmd/migrate, which commonly reads a pool in one account and writes a table
	// in another and therefore needs two credential sources in one process.
	Profile string

	// Client injects a CognitoAPI. Non-nil skips the lazy build entirely, which
	// is how tests drive the directory without an AWS account.
	Client CognitoAPI
}

// cognitoDirectory is the real implementation over the AWS SDK v2.
type cognitoDirectory struct {
	pool     string
	clientID string
	client   *lazyClient[CognitoAPI]
}

var _ CognitoDirectory = (*cognitoDirectory)(nil)

// NewCognitoDirectory builds the directory. It performs no I/O and makes no
// client: see lazyClient for why the SDK client is deferred to the first call.
//
// The only failure it reports is a missing user pool id, which is a
// configuration fault that must abort the cold start rather than surface as a
// 500 on the first login of a migrating user.
func NewCognitoDirectory(opts CognitoOptions) (CognitoDirectory, error) {
	pool := strings.TrimSpace(opts.UserPoolID)
	if pool == "" {
		return nil, errors.New("cognito: no user pool id; stores.migration.userPoolId is what every call addresses")
	}

	d := &cognitoDirectory{pool: pool, clientID: strings.TrimSpace(opts.ClientID)}
	if opts.Client != nil {
		d.client = &lazyClient[CognitoAPI]{build: func(context.Context) (CognitoAPI, error) { return opts.Client, nil }}
		return d, nil
	}
	shared := &lazyConfig{region: opts.Region, profile: opts.Profile}
	d.client = &lazyClient[CognitoAPI]{build: func(ctx context.Context) (CognitoAPI, error) {
		cfg, err := shared.get(ctx)
		if err != nil {
			return nil, err
		}
		return cip.NewFromConfig(cfg), nil
	}}
	return d, nil
}

// maxListUsersPageSize is Cognito's own ceiling for ListUsers.Limit. Asking for
// more is an InvalidParameterException, so the value is clamped rather than
// passed through: a migration that stops halfway because someone wrote 100 in a
// flag is a worse failure than a page of 60.
const maxListUsersPageSize int32 = 60

// ListUsers implements CognitoDirectory.
func (d *cognitoDirectory) ListUsers(ctx context.Context, pageToken string, limit int32) (CognitoUserPage, error) {
	api, err := d.client.get(ctx)
	if err != nil {
		return CognitoUserPage{}, fmt.Errorf("cognito: cannot build a client: %w", err)
	}

	in := &cip.ListUsersInput{UserPoolId: awssdk.String(d.pool)}
	if limit > 0 {
		if limit > maxListUsersPageSize {
			limit = maxListUsersPageSize
		}
		in.Limit = awssdk.Int32(limit)
	}
	if pageToken != "" {
		in.PaginationToken = awssdk.String(pageToken)
	}

	out, err := api.ListUsers(ctx, in)
	if err != nil {
		return CognitoUserPage{}, d.mapError("list users", err)
	}

	page := CognitoUserPage{Users: make([]CognitoUser, 0, len(out.Users))}
	for _, u := range out.Users {
		page.Users = append(page.Users, CognitoUser{
			Username:   awssdk.ToString(u.Username),
			Enabled:    u.Enabled,
			Status:     string(u.UserStatus),
			Attributes: flattenCognitoAttributes(u.Attributes),
			CreatedAt:  awssdk.ToTime(u.UserCreateDate),
			UpdatedAt:  awssdk.ToTime(u.UserLastModifiedDate),
		})
	}
	page.NextToken = awssdk.ToString(out.PaginationToken)
	return page, nil
}

// GetUser implements CognitoDirectory.
func (d *cognitoDirectory) GetUser(ctx context.Context, username string) (CognitoUser, error) {
	if strings.TrimSpace(username) == "" {
		// Not an API call: Cognito answers InvalidParameterException for an empty
		// username, and this method is reached from a lookup miss on an
		// unauthenticated route, where a round trip that can only fail is a round
		// trip an attacker gets to spend for free.
		return CognitoUser{}, ErrCognitoUserNotFound
	}
	api, err := d.client.get(ctx)
	if err != nil {
		return CognitoUser{}, fmt.Errorf("cognito: cannot build a client: %w", err)
	}

	out, err := api.AdminGetUser(ctx, &cip.AdminGetUserInput{
		UserPoolId: awssdk.String(d.pool),
		Username:   awssdk.String(username),
	})
	if err != nil {
		return CognitoUser{}, d.mapError("get user", err)
	}
	return CognitoUser{
		Username:   awssdk.ToString(out.Username),
		Enabled:    out.Enabled,
		Status:     string(out.UserStatus),
		Attributes: flattenCognitoAttributes(out.UserAttributes),
		CreatedAt:  awssdk.ToTime(out.UserCreateDate),
		UpdatedAt:  awssdk.ToTime(out.UserLastModifiedDate),
	}, nil
}

// VerifyPassword implements CognitoDirectory.
//
// ADMIN_USER_PASSWORD_AUTH and not USER_PASSWORD_AUTH or SRP. The admin flow is
// the only one that takes the plaintext password server-side over an
// IAM-authenticated call: USER_PASSWORD_AUTH is the unauthenticated client-side
// equivalent, which would mean this function's request could be made by anyone
// who learned the app client id, and SRP is a multi-round protocol whose whole
// purpose — never sending the password — is pointless here, because the password
// arrived in the login request this call is serving.
//
// Nothing in the response is kept. AdminInitiateAuth hands back Cognito's own
// access, id and refresh tokens on success and they are deliberately dropped on
// the floor: the only question asked is whether the password was right, the
// answer this product gives the person is a session this deployment minted, and
// a Cognito refresh token held in a Lambda's memory is a credential with nowhere
// to go and a lifetime measured in days.
//
// A challenge is treated as "not the password", not as success. Cognito answers
// with a ChallengeName and no AuthenticationResult when the pool wants a second
// factor, or a new password, before it will complete the sign-in. Accepting one
// as proof would be the most consequential thing in this file: the core adopts
// the password on ok=true and from then on that password alone signs the person
// in here, so a pool whose users are protected by SMS_MFA would have that factor
// silently removed by the act of migrating. The person keeps working — their old
// credential still signs them in to the old system, and this deployment's own
// 2FA is theirs to enrol — and what is refused is only the shortcut.
func (d *cognitoDirectory) VerifyPassword(ctx context.Context, username, password string) error {
	if d.clientID == "" {
		return errors.New("cognito: no app client id; AdminInitiateAuth is client-scoped and stores.migration.clientId is required to verify a password")
	}
	if strings.TrimSpace(username) == "" || password == "" {
		// Same reasoning as GetUser, and one more: an empty password is one the
		// core never adopts anyway (password_verifier.go), so the round trip could
		// not change the outcome.
		return ErrCognitoPasswordRejected
	}
	api, err := d.client.get(ctx)
	if err != nil {
		return fmt.Errorf("cognito: cannot build a client: %w", err)
	}

	out, err := api.AdminInitiateAuth(ctx, &cip.AdminInitiateAuthInput{
		UserPoolId: awssdk.String(d.pool),
		ClientId:   awssdk.String(d.clientID),
		AuthFlow:   ciptypes.AuthFlowTypeAdminUserPasswordAuth,
		AuthParameters: map[string]string{
			"USERNAME": username,
			"PASSWORD": password,
		},
	})
	if err != nil {
		return d.mapError("verify password", err)
	}
	if out.ChallengeName != "" {
		return fmt.Errorf("%w: %s", ErrCognitoChallenge, out.ChallengeName)
	}
	if out.AuthenticationResult == nil {
		// Neither tokens nor a challenge. Nothing documents this combination, and
		// a verifier must not read "no explicit refusal" as "yes".
		return ErrCognitoPasswordRejected
	}
	return nil
}

// mapError turns an SDK error into one of this package's sentinels.
//
// The SDK error is never rendered into the message, for the reason kmsError
// gives: the only thing that reaches an operator is the API error code, which is
// the part they act on. Here there is a second reason — every call this file
// makes carries an address or a password in its input, and Cognito's own
// InvalidParameterException wording quotes the parameter it objected to. The
// cause stays reachable through %w, so errors.As still finds smithy.APIError for
// anyone who deliberately asks; nothing prints it.
func (d *cognitoDirectory) mapError(op string, err error) error {
	wrap := func(sentinel error) error {
		return &cognitoError{op: op, code: apiErrorCode(err), sentinel: sentinel, cause: err}
	}

	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return wrap(nil)
	}
	switch apiErr.ErrorCode() {
	case "UserNotFoundException":
		return wrap(ErrCognitoUserNotFound)
	case "UserNotConfirmedException":
		return wrap(ErrCognitoUserNotConfirmed)
	case "PasswordResetRequiredException":
		return wrap(ErrCognitoPasswordResetRequired)
	case "TooManyRequestsException", "LimitExceededException", "TooManyFailedAttemptsException":
		return wrap(ErrCognitoThrottled)
	case "NotAuthorizedException":
		// The one place Cognito's own message is read rather than discarded, and
		// the exception is argued rather than convenient. An app client created
		// with a secret answers NotAuthorizedException — the identical code a
		// wrong password produces — with a message that says so, and there is no
		// other signal anywhere in the API. Left unmapped, a whole deployment's
		// worth of migrating logins would report "that is not the password" and
		// the operator would have no way to learn otherwise; mapped, it is a
		// configuration error in the cold-start-adjacent log on the first login.
		//
		// The message is matched, not printed, and it carries no credential: it
		// names the app client and the missing SECRET_HASH parameter, never the
		// password (which Cognito does not echo) and never the address.
		if strings.Contains(apiErr.ErrorMessage(), "SECRET_HASH") {
			return wrap(ErrCognitoClientHasSecret)
		}
		return wrap(ErrCognitoPasswordRejected)
	default:
		return wrap(nil)
	}
}

// cognitoError is what this package reports for a failed Cognito call, and it
// exists for the property kmsError exists for: the rendered message is composed
// here and nowhere else, so the SDK's own message cannot reach a log.
//
// That matters more here than almost anywhere. Every call this file makes
// carries an address, and one of them carries a plaintext password; Cognito's
// InvalidParameterException wording quotes the parameter it objected to. What is
// printed instead is the sentinel — which is a sentence written in this file —
// and the API error code, which is the part an operator acts on.
//
// Unwrap returns both the sentinel and the cause so that errors.Is reaches the
// decision AND errors.As still reaches smithy.APIError, without either of them
// being rendered.
type cognitoError struct {
	op       string
	code     string
	sentinel error
	cause    error
}

func (e *cognitoError) Error() string {
	if e.sentinel != nil {
		return fmt.Sprintf("%s (%s)", e.sentinel.Error(), e.code)
	}
	return fmt.Sprintf("cognito: %s failed: %s", e.op, e.code)
}

func (e *cognitoError) Unwrap() []error {
	if e.sentinel == nil {
		return []error{e.cause}
	}
	return []error{e.sentinel, e.cause}
}

// flattenCognitoAttributes turns Cognito's attribute list into a map.
//
// A nil name is dropped rather than stored under "": the list is service-shaped
// (every element is a pointer pair) and an entry with no name names nothing, so
// keeping it would create a map key that no caller can ask for on purpose but
// that an attribute map could accidentally match.
func flattenCognitoAttributes(attrs []ciptypes.AttributeType) map[string]string {
	out := make(map[string]string, len(attrs))
	for _, a := range attrs {
		name := awssdk.ToString(a.Name)
		if name == "" {
			continue
		}
		out[name] = awssdk.ToString(a.Value)
	}
	return out
}
