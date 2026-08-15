package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The delivery tests drive the real HTTP surface with fake transports, which is
// the only level at which the interesting claims are checkable: that a given
// route picks a given template, that the link in the body is the one the verify
// route accepts, and that a transport failure reaches the wire as the status the
// spec documents. Asserting on the sender functions in isolation would prove
// none of those, because the mapping from route to template is upstream's and
// the point of the test is that this port wired it up correctly.
//
// No AWS client is constructed anywhere below: newDelivery takes the transports
// from Options, exactly as it takes the persistence layer from Options.Stores.

const (
	testMailerFrom     = "no-reply@example.test"
	testMailerFromName = "Example App"
	// The base every emailed link must be built under: deployment.publicUrl
	// (baseEnv) plus http.apiPrefix. No knob of its own — see newDelivery.
	testLinkBase = "https://auth.example.test/auth"
	testPhone    = "+15550100"
)

// fakeMailer is an auth.MailerTransport that records instead of sending. err,
// when set, is returned *after* recording, so a test can read the credential
// out of a message the deployment believes was never delivered — which is what
// makes the "the token stays stored" claim checkable.
type fakeMailer struct {
	mu   sync.Mutex
	sent []auth.MailMessage
	err  error
}

func (f *fakeMailer) Send(_ context.Context, msg auth.MailMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, msg)
	return f.err
}

func (f *fakeMailer) messages() []auth.MailMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]auth.MailMessage(nil), f.sent...)
}

func (f *fakeMailer) only(t *testing.T) auth.MailMessage {
	t.Helper()
	msgs := f.messages()
	if len(msgs) != 1 {
		t.Fatalf("mailer holds %d messages, want exactly 1: %+v", len(msgs), msgs)
	}
	return msgs[0]
}

func (f *fakeMailer) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = nil
}

func (f *fakeMailer) fail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

type sentText struct{ phone, message string }

// fakeSMS is an auth.SMSTransport. It records for the same reason fakeMailer
// does: the code is the credential and the test has to see it to prove it was
// not logged.
type fakeSMS struct {
	mu   sync.Mutex
	sent []sentText
	err  error
}

func (f *fakeSMS) Send(_ context.Context, phone, message string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentText{phone, message})
	return f.err
}

func (f *fakeSMS) messages() []sentText {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]sentText(nil), f.sent...)
}

// mailerEnv turns the mailer block on the way the schema requires it: an
// endpoint and a from address together, because internal/config refuses either
// without the other. The endpoint is never contacted — SES is reached by API —
// and unwiredKnobs says so at cold start; see TestDeliveryKnobGapsAreReported.
func mailerEnv(base map[string]string, extra ...string) map[string]string {
	return with(with(base,
		"AWESOME_AUTH_MAILER_ENDPOINT", "https://mail.example.test/send",
		"AWESOME_AUTH_MAILER_FROM", testMailerFrom,
		"AWESOME_AUTH_MAILER_FROM_NAME", testMailerFromName,
	), extra...)
}

// smsEnv turns the sms block on. The endpoint is likewise never contacted; it
// is the schema's required key and therefore the signal that SMS delivery is
// wanted at all.
func smsEnv(base map[string]string) map[string]string {
	return with(base, "AWESOME_AUTH_SMS_ENDPOINT", "https://sms.example.test/send")
}

type deliveryApp struct {
	app  *App
	mail *fakeMailer
	sms  *fakeSMS
	log  *bytes.Buffer
}

func newDeliveryApp(t *testing.T, env map[string]string) *deliveryApp {
	t.Helper()
	d := &deliveryApp{mail: &fakeMailer{}, sms: &fakeSMS{}, log: &bytes.Buffer{}}
	app, err := New(context.Background(), Options{
		Getenv: envFunc(env),
		// Debug, and captured: half the assertions below are about what does
		// NOT appear in this buffer.
		Logger: newLogger(d.log, slog.LevelDebug),
		Stores: memoryStores,
		Mail:   d.mail,
		SMS:    d.sms,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.app = app
	return d
}

// register creates a user and returns its bearer access token, for the two
// authenticated delivery routes.
func (d *deliveryApp) register(t *testing.T, email string) string {
	t.Helper()
	resp := invoke(t, d.app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(email))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d, want 201 (body %s)", resp.StatusCode, resp.Body)
	}
	token, _ := decodeBody(t, resp)["accessToken"].(string)
	if token == "" {
		t.Fatalf("register returned no access token: %s", resp.Body)
	}
	return token
}

func bearer(token string) map[string]string {
	return map[string]string{
		"content-type":          "application/json",
		"authorization":         "Bearer " + token,
		auth.AuthStrategyHeader: auth.AuthStrategyBearer,
	}
}

// linkIn pulls the href out of a rendered mail body. The templates are HTML and
// the link is the only thing in them a client acts on, so this is what the
// assertions compare.
func linkIn(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, `<a href="`)
	if !ok {
		t.Fatalf("no link in the mail body:\n%s", body)
	}
	href, _, ok := strings.Cut(rest, `"`)
	if !ok {
		t.Fatalf("unterminated link in the mail body:\n%s", body)
	}
	return href
}

func tokenIn(t *testing.T, link string) string {
	t.Helper()
	_, token, ok := strings.Cut(link, "?token=")
	if !ok {
		t.Fatalf("link %q carries no token", link)
	}
	return token
}

// TestUnconfiguredDeliveryKeepsTheReferenceBehaviour pins the decision this
// port makes about a deployment that configures neither block: nothing changes.
//
// The two halves of the answer are different on purpose and both are the
// reference's. /magic-link/send and /sms/send check their configuration before
// they do anything and answer a coded 500, because the credential cannot travel
// in the response body and there is nowhere else for it to go. The three token
// routes check nothing, mail nothing and still answer 200 — an unguessable,
// single-use, expiring token that nobody receives costs the caller a mail that
// never arrives and nothing else.
//
// The tempting third behaviour, refusing to start without a mailer, is wrong:
// a deployment serving bearer clients that never touch a passwordless route is
// legitimate, and upstream's own Config.validate does not ask for a sender
// either.
func TestUnconfiguredDeliveryKeepsTheReferenceBehaviour(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, baseEnv())
	token := d.register(t, "unconfigured@example.test")

	t.Run("magic-link/send is a coded 500", func(t *testing.T) {
		resp := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil,
			`{"email":"unconfigured@example.test"}`)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", resp.StatusCode, resp.Body)
		}
		if got := decodeBody(t, resp)["code"]; got != auth.CodeEmailNotConfigured {
			t.Errorf("code = %v, want %s", got, auth.CodeEmailNotConfigured)
		}
	})

	t.Run("sms/send is a coded 500", func(t *testing.T) {
		resp := invoke(t, d.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil,
			`{"email":"unconfigured@example.test"}`)
		if resp.StatusCode != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", resp.StatusCode, resp.Body)
		}
		if got := decodeBody(t, resp)["code"]; got != auth.CodeSMSNotConfigured {
			t.Errorf("code = %v, want %s", got, auth.CodeSMSNotConfigured)
		}
	})

	t.Run("the token routes still succeed silently", func(t *testing.T) {
		for _, tc := range []struct {
			path, body string
			headers    map[string]string
		}{
			{"/auth/forgot-password", `{"email":"unconfigured@example.test"}`, jsonHeaders()},
			{"/auth/change-email/request", `{"newEmail":"moved@example.test"}`, bearer(token)},
		} {
			resp := invoke(t, d.app, http.MethodPost, tc.path, tc.headers, nil, tc.body)
			if resp.StatusCode != http.StatusOK {
				t.Errorf("%s status = %d, want 200 with no mailer (body %s)", tc.path, resp.StatusCode, resp.Body)
			}
		}
	})

	if got := len(d.mail.messages()); got != 0 {
		t.Errorf("%d messages were sent by a deployment with no mailer configured", got)
	}
}

// TestConfiguredMailerWiresEveryMailRoute is the positive half of the gating,
// and the per-flow template assertion in one pass: each route must render its
// own template and build its link under the configured base.
func TestConfiguredMailerWiresEveryMailRoute(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(baseEnv()))
	const owner = "owner@example.test"
	token := d.register(t, owner)

	cases := []struct {
		name      string
		path      string
		body      string
		headers   map[string]string
		wantTo    string
		wantPath  string
		wantInSub string
	}{
		{
			name:      "magic-link/send",
			path:      "/auth/magic-link/send",
			body:      fmt.Sprintf(`{"email":%q}`, owner),
			headers:   jsonHeaders(),
			wantTo:    owner,
			wantPath:  testLinkBase + auth.MagicLinkVerifyPath,
			wantInSub: "Magic Link",
		},
		{
			name:      "forgot-password",
			path:      "/auth/forgot-password",
			body:      fmt.Sprintf(`{"email":%q}`, owner),
			headers:   jsonHeaders(),
			wantTo:    owner,
			wantPath:  testLinkBase + auth.PasswordResetPath,
			wantInSub: "Password Reset",
		},
		{
			// The one message that does NOT go to the account's own address:
			// this mail verifies that the new mailbox exists, so it goes there.
			name:      "change-email/request",
			path:      "/auth/change-email/request",
			body:      `{"newEmail":"moved@example.test"}`,
			headers:   bearer(token),
			wantTo:    "moved@example.test",
			wantPath:  testLinkBase + auth.EmailChangeConfirmPath,
			wantInSub: "Confirm Email Change",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d.mail.reset()

			resp := invoke(t, d.app, http.MethodPost, tc.path, tc.headers, nil, tc.body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body %s)", resp.StatusCode, resp.Body)
			}

			msg := d.mail.only(t)
			if msg.To != tc.wantTo {
				t.Errorf("To = %q, want %q", msg.To, tc.wantTo)
			}
			if !msg.IsHTML {
				t.Errorf("message is not marked HTML, so SES would send the markup as plain text")
			}
			if !strings.HasPrefix(msg.Subject, testMailerFromName) {
				t.Errorf("Subject %q does not begin with the app name from email.mailer.fromName", msg.Subject)
			}
			if !strings.Contains(msg.Subject, tc.wantInSub) {
				t.Errorf("Subject = %q, want it to name this flow (%q) — the wrong template was rendered", msg.Subject, tc.wantInSub)
			}
			link := linkIn(t, msg.Body)
			if !strings.HasPrefix(link, tc.wantPath+"?token=") {
				t.Errorf("link = %q, want it under %q — the base is deployment.publicUrl + http.apiPrefix", link, tc.wantPath)
			}
			if tokenIn(t, link) == "" {
				t.Errorf("link %q carries an empty token", link)
			}
		})
	}
}

// TestVerificationEmailUsesItsOwnTemplate is the fifth sender, and it is driven
// through the core rather than over HTTP for a reason that is worth recording:
// the core hardcodes email.verification.mode to "none" (cmd/auth's unwiredKnobs
// reports the knob), so every account this build registers is already verified
// and POST /send-verification-email answers 400 "Email is already verified"
// before delivery is reached. There is no configuration that produces an
// unverified account over the wire, so the account is made directly in the
// store and the same composed core is asked to send.
//
// What is under test is unchanged: the option set built by deliveryOptions, and
// which template and URL builder the verification sender inside it picks.
func TestVerificationEmailUsesItsOwnTemplate(t *testing.T) {
	t.Parallel()

	mailer := &fakeMailer{}
	core, users := newDeliveryCore(t, mailerEnv(baseEnv()), mailer, nil)

	user, err := users.CreateUser(context.Background(), auth.User{
		Email:           "unverified@example.test",
		IsEmailVerified: false,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := core.SendVerificationEmailToken(context.Background(), auth.EmailVerificationInput{
		UserID: user.ID, TenantID: user.TenantID,
	}); err != nil {
		t.Fatalf("SendVerificationEmailToken: %v", err)
	}

	msg := mailer.only(t)
	if msg.To != user.Email {
		t.Errorf("To = %q, want %q", msg.To, user.Email)
	}
	if !strings.Contains(msg.Subject, "Verify Your Email") {
		t.Errorf("Subject = %q, want the verify_email template's", msg.Subject)
	}
	link := linkIn(t, msg.Body)
	if !strings.HasPrefix(link, testLinkBase+auth.EmailVerificationPath+"?token=") {
		t.Errorf("link = %q, want it under %q", link, testLinkBase+auth.EmailVerificationPath)
	}

	// And the failure contract: a transport error is the generic 500 here, not a
	// swallow, and the token survives it — the link above still verifies.
	mailer.reset()
	mailer.fail(errors.New("transport is down"))
	if _, err := core.SendVerificationEmailToken(context.Background(), auth.EmailVerificationInput{
		UserID: user.ID, TenantID: user.TenantID,
	}); !errors.Is(err, auth.ErrDeliveryFailed) {
		t.Errorf("error = %v, want it to wrap auth.ErrDeliveryFailed so the route answers a generic 500", err)
	}
	undelivered := tokenIn(t, linkIn(t, mailer.only(t).Body))
	if err := core.VerifyEmail(context.Background(), auth.VerifyEmailInput{Token: undelivered}); err != nil {
		t.Errorf("the token minted before a failed send was not stored: %v", err)
	}
}

// newDeliveryCore composes the same auth core cmd/auth builds — coreOptions plus
// deliveryOptions — over a memory store the caller keeps a handle on. It exists
// for the flows that cannot be reached over the wire in this build.
func newDeliveryCore(t *testing.T, env map[string]string, mail auth.MailerTransport, sms auth.SMSTransport) (*auth.Auth, *auth.MemoryUserStore) {
	t.Helper()

	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	deliver, err := newDelivery(cfg, mail, sms, discardLogger())
	if err != nil {
		t.Fatalf("newDelivery: %v", err)
	}
	users := auth.NewMemoryUserStore()
	core, err := auth.New(append(
		coreOptions(cfg, users, auth.NewMemorySessionStore(), discardLogger()),
		deliveryOptions(deliver, discardLogger())...)...)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return core, users
}

// TestMagicLinkFromTheMailIsAcceptedByTheVerifyRoute closes the loop. Asserting
// the link's shape only proves it matches this port's idea of the shape; feeding
// it back to /magic-link/verify proves the base, the path and the token are the
// ones the wire actually accepts.
func TestMagicLinkFromTheMailIsAcceptedByTheVerifyRoute(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(baseEnv()))
	const owner = "roundtrip@example.test"
	d.register(t, owner)

	resp := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil,
		fmt.Sprintf(`{"email":%q}`, owner))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("magic-link/send status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	link := linkIn(t, d.mail.only(t).Body)
	verify := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q}`, tokenIn(t, link)))
	if verify.StatusCode != http.StatusOK {
		t.Fatalf("the token from the emailed link was rejected: status %d (body %s)", verify.StatusCode, verify.Body)
	}
	if decodeBody(t, verify)["accessToken"] == nil {
		t.Errorf("magic-link/verify issued no access token: %s", verify.Body)
	}
}

// TestResetTokenFromTheMailIsAcceptedByTheResetRoute is the second round trip,
// and it closes the gap TestConfiguredMailerWiresEveryMailRoute leaves open.
//
// That test proves the reset mail carries a link under /reset-password with a
// non-empty token, which a copy-paste that mailed the *verification* token under
// the reset URL would also satisfy. Only spending the token on the route that is
// supposed to accept it proves the pairing, so this one resets the password and
// then logs in with the new one.
func TestResetTokenFromTheMailIsAcceptedByTheResetRoute(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(baseEnv()))
	const owner = "resetroundtrip@example.test"
	d.register(t, owner)

	resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil,
		fmt.Sprintf(`{"email":%q}`, owner))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	msg := d.mail.only(t)
	link := linkIn(t, msg.Body)
	if !strings.HasPrefix(link, testLinkBase+auth.PasswordResetPath+"?token=") {
		t.Fatalf("link = %q, want it under %q", link, testLinkBase+auth.PasswordResetPath)
	}

	const newPassword = "another-correct-horse-battery"
	spend := invoke(t, d.app, http.MethodPost, "/auth/reset-password",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, tokenIn(t, link), newPassword))
	if spend.StatusCode != http.StatusOK {
		t.Fatalf("the token from the reset mail was rejected by /reset-password: status %d (body %s)", spend.StatusCode, spend.Body)
	}

	login := invoke(t, d.app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"email":%q,"password":%q}`, owner, newPassword))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login with the reset password failed: status %d (body %s)", login.StatusCode, login.Body)
	}
}

// TestLocaleComesFromTheMailerBlock: email.mailer.defaultLang selects the
// built-in template set, and an unknown locale falls back to English rather
// than failing the send.
func TestLocaleComesFromTheMailerBlock(t *testing.T) {
	t.Parallel()

	cases := map[string]string{"it": "Reimposta Password", "en": "Password Reset", "de": "Password Reset"}
	for lang, want := range cases {
		t.Run(lang, func(t *testing.T) {
			t.Parallel()
			env := mailerEnv(baseEnv())
			// "de" is not in the schema's enum, so it can only be reached by
			// building the delivery directly; the two real values go through the
			// whole loader.
			if lang == "de" {
				d := &delivery{
					mail:      &fakeMailer{},
					templates: auth.NewMailTemplater(testMailerFromName),
					appName:   testMailerFromName,
					baseURL:   testLinkBase,
					locale:    lang,
				}
				subject, _, err := d.templates.Render(d.locale, "reset_password", auth.MailTemplateData{})
				if err != nil {
					t.Fatalf("Render: %v", err)
				}
				if !strings.Contains(subject, want) {
					t.Errorf("subject = %q, want the English fallback %q", subject, want)
				}
				return
			}

			env = with(env, "AWESOME_AUTH_MAILER_DEFAULT_LANG", lang)
			d := newDeliveryApp(t, env)
			const owner = "locale@example.test"
			d.register(t, owner)

			resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil,
				fmt.Sprintf(`{"email":%q}`, owner))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("forgot-password status = %d (body %s)", resp.StatusCode, resp.Body)
			}
			if got := d.mail.only(t).Subject; !strings.Contains(got, want) {
				t.Errorf("subject = %q, want it rendered in %q (%q)", got, lang, want)
			}
		})
	}
}

// TestTransportFailureReachesTheWire covers the failure contract, which differs
// per route and is upstream's, not this port's:
//
//   - /magic-link/send, /send-verification-email and /change-email/request
//     answer the generic 500. A transport failure must not describe itself to
//     the caller, and it must not be silently swallowed either.
//   - /forgot-password answers 200 anyway, because the alternative is an
//     enumeration oracle: a known address would 500 while an unknown one 200s.
//
// The stored credential survives all four, which is the second half of the
// contract and the reason the failure is tolerable at all. The fake records
// before it fails, so the test can take the token out of a message the
// deployment believes never left and spend it — if the store had rolled back,
// the verify route would refuse it.
func TestTransportFailureReachesTheWire(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(baseEnv()))
	const owner = "failing@example.test"
	token := d.register(t, owner)
	d.mail.fail(errors.New("ses: sending from no-reply@example.test to a example.test recipient failed: MessageRejected"))

	for _, tc := range []struct {
		name, path, body string
		headers          map[string]string
		wantStatus       int
	}{
		{"magic-link/send", "/auth/magic-link/send", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders(), http.StatusInternalServerError},
		{"change-email/request", "/auth/change-email/request", `{"newEmail":"elsewhere@example.test"}`, bearer(token), http.StatusInternalServerError},
		{"forgot-password", "/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders(), http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.mail.reset()
			resp := invoke(t, d.app, http.MethodPost, tc.path, tc.headers, nil, tc.body)
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", resp.StatusCode, tc.wantStatus, resp.Body)
			}
			if tc.wantStatus == http.StatusInternalServerError {
				// Generic, code-less: a mail gateway is not entitled to pick a
				// wire code for the route it failed on.
				if code := decodeBody(t, resp)["code"]; code != nil {
					t.Errorf("a transport failure answered with code %v; the reference's answer here is code-less", code)
				}
			}
			if got := len(d.mail.messages()); got != 1 {
				t.Fatalf("the transport was called %d times, want 1", got)
			}
		})
	}

	// The credential outlived the failed send: spend the magic-link token that
	// was minted for a message the deployment reported as a 500.
	d.mail.reset()
	if resp := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil,
		fmt.Sprintf(`{"email":%q}`, owner)); resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("magic-link/send status = %d, want 500", resp.StatusCode)
	}
	undelivered := tokenIn(t, linkIn(t, d.mail.only(t).Body))

	d.mail.fail(nil)
	verify := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q}`, undelivered))
	if verify.StatusCode != http.StatusOK {
		t.Errorf("the token minted before a failed send was not stored: verify answered %d (body %s)", verify.StatusCode, verify.Body)
	}
}

// TestSMSDeliveryUsesTheSharedWording: the message body is upstream's
// SMSCodeMessage, not a rewording, because it lands on a real handset and the
// family ports must not drift on it.
func TestSMSDeliveryUsesTheSharedWording(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, smsEnv(baseEnv()))
	const owner = "texted@example.test"
	token := d.register(t, owner)

	if resp := invoke(t, d.app, http.MethodPost, "/auth/add-phone", bearer(token), nil,
		fmt.Sprintf(`{"phoneNumber":%q}`, testPhone)); resp.StatusCode != http.StatusOK {
		t.Fatalf("add-phone status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	resp := invoke(t, d.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil,
		fmt.Sprintf(`{"email":%q}`, owner))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sms/send status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	sent := d.sms.messages()
	if len(sent) != 1 {
		t.Fatalf("%d text messages sent, want 1", len(sent))
	}
	if sent[0].phone != testPhone {
		t.Errorf("phone = %q, want %q", sent[0].phone, testPhone)
	}
	code := strings.TrimPrefix(sent[0].message, "Your verification code is: ")
	if code == sent[0].message || code == "" {
		t.Fatalf("message = %q, want auth.SMSCodeMessage's wording", sent[0].message)
	}

	// /sms/verify takes a userId, not an address: only /sms/send treats the
	// address as enumerable.
	me := invoke(t, d.app, http.MethodGet, "/auth/me", bearer(token), nil, "")
	userID, _ := decodeBody(t, me)["id"].(string)
	if userID == "" {
		t.Fatalf("/me returned no id: %s", me.Body)
	}
	verify := invoke(t, d.app, http.MethodPost, "/auth/sms/verify",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"userId":%q,"code":%q}`, userID, code))
	if verify.StatusCode != http.StatusOK {
		t.Errorf("the texted code was rejected: status %d (body %s)", verify.StatusCode, verify.Body)
	}
}

// TestConfiguringOneHalfDoesNotWireTheOther: the two blocks gate independently,
// so a mail-only deployment still answers SMS_NOT_CONFIGURED and vice versa.
func TestConfiguringOneHalfDoesNotWireTheOther(t *testing.T) {
	t.Parallel()

	t.Run("mail only", func(t *testing.T) {
		t.Parallel()
		d := newDeliveryApp(t, mailerEnv(baseEnv()))
		d.register(t, "mailonly@example.test")
		resp := invoke(t, d.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil,
			`{"email":"mailonly@example.test"}`)
		if got := decodeBody(t, resp)["code"]; got != auth.CodeSMSNotConfigured {
			t.Errorf("code = %v, want %s", got, auth.CodeSMSNotConfigured)
		}
	})

	t.Run("sms only", func(t *testing.T) {
		t.Parallel()
		d := newDeliveryApp(t, smsEnv(baseEnv()))
		d.register(t, "smsonly@example.test")
		resp := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil,
			`{"email":"smsonly@example.test"}`)
		if got := decodeBody(t, resp)["code"]; got != auth.CodeEmailNotConfigured {
			t.Errorf("code = %v, want %s", got, auth.CodeEmailNotConfigured)
		}
	})
}

// TestNoCredentialReachesTheLog is the assertion the whole delivery path is
// arranged around. The cold-start logger is the deployment's CloudWatch log
// group; a token or a one-time code in it is a credential at rest, readable for
// the retention period by anyone with logs:FilterLogEvents, and it would be
// minted fresh on every request.
//
// The failing-transport case is the one that matters: that is when this binary
// writes the most about delivery — upstream's Auth.ForgotPassword logs the
// swallowed failure through the core logger, which cmd/auth funnels into slog.
func TestNoCredentialReachesTheLog(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, smsEnv(mailerEnv(baseEnv())))
	const owner = "quiet@example.test"
	token := d.register(t, owner)

	if resp := invoke(t, d.app, http.MethodPost, "/auth/add-phone", bearer(token), nil,
		fmt.Sprintf(`{"phoneNumber":%q}`, testPhone)); resp.StatusCode != http.StatusOK {
		t.Fatalf("add-phone status = %d (body %s)", resp.StatusCode, resp.Body)
	}

	for _, failing := range []bool{false, true} {
		if failing {
			d.mail.fail(errors.New("transport is down"))
			d.sms.err = errors.New("transport is down")
		}
		for _, tc := range []struct {
			path, body string
			headers    map[string]string
		}{
			{"/auth/magic-link/send", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
			{"/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
			{"/auth/change-email/request", `{"newEmail":"quieter@example.test"}`, bearer(token)},
			{"/auth/sms/send", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
		} {
			invoke(t, d.app, http.MethodPost, tc.path, tc.headers, nil, tc.body)
		}
	}

	out := d.log.String()
	if out == "" {
		t.Fatal("nothing was logged at all, so this test proves nothing")
	}

	var credentials []string
	for _, msg := range d.mail.messages() {
		link := linkIn(t, msg.Body)
		credentials = append(credentials, tokenIn(t, link), msg.Body)
	}
	for _, text := range d.sms.messages() {
		credentials = append(credentials, strings.TrimPrefix(text.message, "Your verification code is: "))
	}
	if len(credentials) == 0 {
		t.Fatal("no credential was captured, so this test proves nothing")
	}
	for _, secret := range credentials {
		if secret == "" {
			continue
		}
		if strings.Contains(out, secret) {
			t.Errorf("a delivered credential appears in the cold-start log:\n%s", out)
		}
	}
}

// TestDeliveryKnobGapsAreReported: every knob of the two blocks that describes
// an HTTP gateway is unusable here, and the operator has to learn that from the
// deployment log rather than from a rotation that changed nothing.
func TestDeliveryKnobGapsAreReported(t *testing.T) {
	t.Parallel()

	env := smsEnv(mailerEnv(baseEnv(),
		"AWESOME_AUTH_MAILER_API_KEY", "mailer-key",
		"AWESOME_AUTH_MAILER_PROVIDER", "sendgrid"))
	env = with(env,
		"AWESOME_AUTH_SMS_API_KEY", "sms-key",
		"AWESOME_AUTH_SMS_USERNAME", "sms-user",
		"AWESOME_AUTH_SMS_PASSWORD", "sms-pass")

	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}

	got := map[string]bool{}
	for _, gap := range unwiredKnobs(cfg) {
		got[gap.Path] = true
		if gap.Problem == "" || gap.Remedy == "" {
			t.Errorf("gap %s has an empty problem or remedy", gap.Path)
		}
	}
	for _, want := range []string{
		"email.mailer.endpoint", "email.mailer.apiKey", "email.mailer.provider",
		"sms.endpoint", "sms.apiKey", "sms.username", "sms.password",
	} {
		if !got[want] {
			t.Errorf("unwiredKnobs did not report %s, so a configured knob is silently inert", want)
		}
	}
	// Honoured knobs must stay out, or the warning becomes noise nobody reads.
	for _, unwanted := range []string{"email.mailer.from", "email.mailer.fromName", "email.mailer.defaultLang", "sms.codeTtlMinutes"} {
		if got[unwanted] {
			t.Errorf("unwiredKnobs reported %s, which this build does honour", unwanted)
		}
	}

	// And nothing at all when neither block is configured.
	plain, err := config.Load(context.Background(), config.Options{Getenv: envFunc(baseEnv())})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	for _, gap := range unwiredKnobs(plain) {
		if strings.HasPrefix(gap.Path, "email.mailer") || strings.HasPrefix(gap.Path, "sms") {
			t.Errorf("unconfigured delivery still reported %s", gap.Path)
		}
	}
}

// TestDeliveryCredentialsWithoutTheirBlockAreStillReported is the loud half of
// the gating decision, and it exists because un-gating the two domains removed
// the thing that used to be loud here.
//
// A credential is the part of these blocks that lives in Secrets Manager, so it
// is the part a stack template carries and the part an operator sets first; the
// switch — email.mailer.from, sms.endpoint — is the part that gets forgotten. A
// Secret resolved from its plain environment variable leaves no reference in the
// Config tree, so validate.go's "is this block configured" test does not see it,
// mailConfigured and smsConfigured are both false, and delivery is simply off.
// Until this port wired the blocks, that combination was refused outright by the
// phase gap, whose secretPrefix covered exactly these paths. Nothing may replace
// that refusal with silence.
func TestDeliveryCredentialsWithoutTheirBlockAreStillReported(t *testing.T) {
	t.Parallel()

	env := with(baseEnv(),
		"AWESOME_AUTH_MAILER_API_KEY", "mailer-key",
		"AWESOME_AUTH_SMS_API_KEY", "sms-key",
		"AWESOME_AUTH_SMS_USERNAME", "sms-user",
		"AWESOME_AUTH_SMS_PASSWORD", "sms-pass")

	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if mailConfigured(cfg) || smsConfigured(cfg) {
		t.Fatal("a credential alone must not switch delivery on; the test premise is gone")
	}

	got := map[string]knobGap{}
	for _, gap := range unwiredKnobs(cfg) {
		got[gap.Path] = gap
	}
	for _, want := range []string{"email.mailer.apiKey", "sms.apiKey", "sms.username", "sms.password"} {
		gap, ok := got[want]
		if !ok {
			t.Errorf("%s resolves to a value, delivery is off, and nothing said so", want)
			continue
		}
		// The remedy has to name the switch, not just call the knob unused: an
		// operator reading "nothing in this build reads it" about a key would
		// reasonably conclude mail is being sent by other means.
		wantSwitch := "sms.endpoint"
		if strings.HasPrefix(want, "email.") {
			wantSwitch = "email.mailer.from"
		}
		if !strings.Contains(gap.Remedy, wantSwitch) {
			t.Errorf("the remedy for %s does not name %s, the knob that would turn delivery on:\n%s", want, wantSwitch, gap.Remedy)
		}
	}
	// The two endpoints are not reported: they are not set, so there is nothing
	// to be inert about.
	for _, unwanted := range []string{"email.mailer.endpoint", "sms.endpoint"} {
		if _, ok := got[unwanted]; ok {
			t.Errorf("unwiredKnobs reported %s, which was never configured", unwanted)
		}
	}
}

// TestMailerProviderNamingSESIsNotAGap: the knob is free-form in the schema and
// the reference uses it to pick a backend. Naming what is actually deployed is
// a correct document, not a gap.
func TestMailerProviderNamingSESIsNotAGap(t *testing.T) {
	t.Parallel()

	for _, provider := range []string{"ses", "SES", "Ses"} {
		cfg, err := config.Load(context.Background(), config.Options{
			Getenv: envFunc(mailerEnv(baseEnv(), "AWESOME_AUTH_MAILER_PROVIDER", provider)),
		})
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		for _, gap := range unwiredKnobs(cfg) {
			if gap.Path == "email.mailer.provider" {
				t.Errorf("provider %q was reported as a gap: %s", provider, gap.Problem)
			}
		}
	}
}

// TestMailerAppName: the templates greet with and prefix every subject with
// email.mailer.fromName, and fall back to the sender's domain rather than
// rendering a subject that starts with " - ".
func TestMailerAppName(t *testing.T) {
	t.Parallel()

	cases := []struct{ from, fromName, want string }{
		{"no-reply@example.test", "Example App", "Example App"},
		{"no-reply@example.test", "  ", "example.test"},
		{"no-reply@example.test", "", "example.test"},
		{"broken", "", ""},
	}
	for _, tc := range cases {
		cfg := config.Defaults()
		cfg.Email.Mailer.From = tc.from
		cfg.Email.Mailer.FromName = tc.fromName
		if got := mailerAppName(cfg); got != tc.want {
			t.Errorf("mailerAppName(from=%q, fromName=%q) = %q, want %q", tc.from, tc.fromName, got, tc.want)
		}
	}
}

// TestDeliveryGatingIsConfigDriven: injecting a transport must not switch
// delivery on by itself, or a test would exercise a composition the binary
// never builds.
func TestDeliveryGatingIsConfigDriven(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name              string
		env               map[string]string
		wantMail, wantSMS bool
		wantOptions       int
	}{
		{"neither block", baseEnv(), false, false, 0},
		{"mailer only", mailerEnv(baseEnv()), true, false, 4},
		{"sms only", smsEnv(baseEnv()), false, true, 1},
		{"both", smsEnv(mailerEnv(baseEnv())), true, true, 5},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(tc.env)})
			if err != nil {
				t.Fatalf("config.Load: %v", err)
			}
			// Both transports are injected in every case; only the configuration
			// decides whether they are used.
			d, err := newDelivery(cfg, &fakeMailer{}, &fakeSMS{}, discardLogger())
			if err != nil {
				t.Fatalf("newDelivery: %v", err)
			}
			if (d.mail != nil) != tc.wantMail {
				t.Errorf("mail transport present = %v, want %v", d.mail != nil, tc.wantMail)
			}
			if (d.sms != nil) != tc.wantSMS {
				t.Errorf("sms transport present = %v, want %v", d.sms != nil, tc.wantSMS)
			}
			if got := len(deliveryOptions(d, discardLogger())); got != tc.wantOptions {
				t.Errorf("deliveryOptions returned %d options, want %d", got, tc.wantOptions)
			}
			if d.baseURL != testLinkBase {
				t.Errorf("baseURL = %q, want %q", d.baseURL, testLinkBase)
			}
		})
	}
}

// TestLinkTokenDeliveryFollowsTheMailer: POST /link-request used to store a
// token and answer success without mailing anything, and the cold-start log
// said so. With a mailer it now sends; without one the old behaviour — which is
// the reference's for an unconfigured transport — is what remains.
func TestLinkTokenDeliveryFollowsTheMailer(t *testing.T) {
	t.Parallel()

	// The linking routes exist only when their two stores are enabled, so the
	// log line this asserts on only exists then.
	linkStores := func(env map[string]string) map[string]string {
		return with(env,
			"AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true",
			"AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS", "true")
	}

	t.Run("wired when a mailer exists", func(t *testing.T) {
		t.Parallel()
		d := newDeliveryApp(t, linkStores(mailerEnv(baseEnv())))
		if !strings.Contains(d.log.String(), `"linkTokenDelivery":"ses"`) {
			t.Errorf("cold-start log does not report link-token delivery as wired:\n%s", d.log.String())
		}
	})

	t.Run("absent without one", func(t *testing.T) {
		t.Parallel()
		d := newDeliveryApp(t, linkStores(baseEnv()))
		if !strings.Contains(d.log.String(), `"linkTokenDelivery":"none`) {
			t.Errorf("cold-start log does not report link-token delivery as absent:\n%s", d.log.String())
		}
	})
}

// TestLinkTokenMailReusesTheVerificationTemplate pins the template choice, and
// the per-request locale that only this sender has: upstream forwards the
// request's emailLang field to it verbatim.
func TestLinkTokenMailReusesTheVerificationTemplate(t *testing.T) {
	t.Parallel()

	mailer := &fakeMailer{}
	d := &delivery{
		mail:      mailer,
		templates: auth.NewMailTemplater(testMailerFromName),
		appName:   testMailerFromName,
		baseURL:   testLinkBase,
		locale:    "en",
	}

	const linkURL = "https://app.example.test/auth/link-verify?token=abc"
	if err := d.deliverLinkToken(context.Background(), auth.LinkTokenDelivery{
		Email: "linked@example.test", Provider: "google", Token: "abc", URL: linkURL,
	}); err != nil {
		t.Fatalf("deliverLinkToken: %v", err)
	}
	msg := mailer.only(t)
	if msg.To != "linked@example.test" {
		t.Errorf("To = %q", msg.To)
	}
	if !strings.Contains(msg.Subject, "Verify Your Email") {
		t.Errorf("Subject = %q, want the verification template's — the reference mails link tokens through its verification sender", msg.Subject)
	}
	if got := linkIn(t, msg.Body); got != linkURL {
		t.Errorf("link = %q, want the URL upstream built (%q); this sender must not rebuild it", got, linkURL)
	}

	mailer.reset()
	if err := d.deliverLinkToken(context.Background(), auth.LinkTokenDelivery{
		Email: "linked@example.test", Token: "abc", URL: linkURL, EmailLang: "it",
	}); err != nil {
		t.Fatalf("deliverLinkToken: %v", err)
	}
	if got := mailer.only(t).Subject; !strings.Contains(got, "Verifica Email") {
		t.Errorf("Subject = %q, want the emailLang override honoured", got)
	}
}
