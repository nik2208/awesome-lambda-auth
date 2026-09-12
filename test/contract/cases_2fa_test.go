package contract

import (
	"strings"
	"testing"
)

// enrolTOTP walks the enrolment half of the flow and returns the shared secret:
// POST /2fa/setup mints a secret (nothing is persisted), POST /2fa/verify-setup
// proves possession with a live code and is what actually enables it (§3, 2fa
// setup / verify-setup). Field names are literals on purpose — /2fa/verify-setup
// takes `token` and `secret`, while /2fa/verify takes `tempToken` and
// `totpCode`, and clients have been broken by exactly that asymmetry.
func enrolTOTP(t *testing.T, c *Client) string {
	t.Helper()
	setup := c.POST(t, "/2fa/setup", nil, CSRF())
	setup.mustStatus(t, 200)
	secret := setup.str(t, "secret")

	verify := c.POST(t, "/2fa/verify-setup",
		body{"token": totpNow(t, secret), "secret": secret}, CSRF())
	verify.mustSuccessOnly(t)
	return secret
}

func init() {
	register(
		Case{
			Name:  "2fa/setup-response-shape",
			Doc:   "§3 (POST /2fa/setup) — 200 {\"secret\":\"<base32>\",\"otpauthUrl\":\"otpauth://totp/…\",\"qrCode\":\"data:image/png;base64,…\"}; the served UI renders the QR from qrCode",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				r := c.POST(t, "/2fa/setup", nil, CSRF())
				r.mustStatus(t, 200)

				if secret := r.str(t, "secret"); secret == "" {
					t.Errorf("secret must be a non-empty base32 string\n  %s", r.where())
				}
				if url := r.str(t, "otpauthUrl"); !strings.HasPrefix(url, "otpauth://totp/") {
					t.Errorf("otpauthUrl must start with otpauth://totp/, got %q\n  %s", url, r.where())
				}
				// qrCode is deliberately absent, and that is registered upstream
				// as the deviation `totp-setup-omits-qrcode`: a QR encoder is
				// neither stdlib nor golang.org/x/crypto, so a client renders
				// otpauthUrl itself. The reference's served UI guards with
				// `if (setupData.qrCode)`, so the QR simply does not appear and
				// the user types the secret.
				//
				// Asserted as absent rather than skipped: if a qrCode ever
				// starts arriving, this fails and says to retire the deviation
				// instead of leaving the register describing a port that has
				// moved on.
				if r.hasKey(t, "qrCode") {
					t.Errorf("response now carries qrCode — the registered deviation `totp-setup-omits-qrcode` is stale, retire it from CompatibilityNotes() and pin the data:image/png;base64 shape here\n  %s",
						r.where())
				}
			},
		},

		Case{
			Name:  "2fa/round-trip",
			Doc:   "§3.1, §3 (2fa/verify) — enrol TOTP, log in, take the tempToken out of the login response, complete /2fa/verify: 200 {requiresTwoFactor,tempToken,available2faMethods} then a full session",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				enrolled, acct := e.LoginCookie(t)
				secret := enrolTOTP(t, enrolled)

				// A fresh client: the challenge must be complete in itself.
				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				login.mustStatus(t, 200)

				m := login.obj(t)
				if m["requiresTwoFactor"] != true {
					t.Fatalf("a TOTP-enrolled account logged in without a second factor: want \"requiresTwoFactor\":true, got %v\n  %s",
						keysOf(m), login.where())
				}
				tempToken := login.str(t, "tempToken")
				if tempToken == "" {
					t.Fatalf("the challenge must carry a tempToken\n  %s", login.where())
				}
				methods, ok := m["available2faMethods"].([]any)
				if !ok {
					t.Fatalf("available2faMethods must be an array, got %T\n  %s", m["available2faMethods"], login.where())
				}
				if !containsString(methods, "totp") {
					t.Errorf("available2faMethods must contain \"totp\" for an enrolled account, got %v\n  %s",
						methods, login.where())
				}

				// No session is issued yet: the challenge carries no token
				// cookies, in either mode.
				if login.cookie(cookieAccess) != nil || login.cookie(cookieRefresh) != nil {
					t.Errorf("the 2FA challenge issued session cookies before the second factor was presented (Set-Cookie: %v)\n  %s",
						login.SetCookie, login.where())
				}

				// Step-up completes with the tempToken taken out of that body.
				done := c.POST(t, "/2fa/verify", body{"tempToken": tempToken, "totpCode": totpNow(t, secret)})
				done.mustSuccessOnly(t)
				if done.cookie(cookieAccess) == nil {
					t.Errorf("completing 2FA in cookie mode must set the accessToken cookie (Set-Cookie: %v)\n  %s",
						done.SetCookie, done.where())
				}
				c.GET(t, "/me").mustStatus(t, 200)
			},
		},

		Case{
			Name: "2fa/temp-token-is-not-accepted-by-me",
			Doc: "§3.1 / §3 — the tempToken is a step-up credential for /2fa/verify; on its own it must not stand in for a session, " +
				"and the refusal is the middleware's own 403 {\"error\":\"Invalid or expired access token\"} with no `code`",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				enrolled, acct := e.LoginCookie(t)
				enrolTOTP(t, enrolled)

				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				login.mustStatus(t, 200)
				tempToken := login.str(t, "tempToken")
				if tempToken == "" {
					t.Fatalf("the challenge carried no tempToken, so there is nothing to present\n  %s", login.where())
				}

				// The claim, stated first and separately from the envelope: a
				// half-authentication must not be a full one. The reference
				// mints its tempToken as an ordinary access token with a five
				// minute life and nothing distinguishing it, so this case fails
				// against it by design — the typed temp token is the registered
				// deviation `temp-token-is-typed-not-an-access-token`, and the
				// five-minute bypass it closes is worth the divergence.
				r := e.NewClient().GET(t, "/me", Bearer(tempToken))
				if r.Status == 200 {
					t.Fatalf("the login tempToken opened GET /me on its own, so a stolen half-authentication is a full one\n  %s", r.where())
				}
				// And the refusal is the ordinary bad-token answer, not a
				// 2FA-flavoured one: a client must not be able to tell a
				// step-up token presented as a session from any other unusable
				// token, or the error becomes an oracle for what the token is.
				r.mustCodelessError(t, 403, "Invalid or expired access token")
			},
		},

		Case{
			Name:  "2fa/bearer-mode-round-trip",
			Doc:   "hard point 8, §3 — completing /2fa/verify with X-Auth-Strategy: bearer returns top-level tokens and sets no cookies",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				enrolled, acct := e.LoginCookie(t)
				secret := enrolTOTP(t, enrolled)

				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				login.mustStatus(t, 200)
				tempToken := login.str(t, "tempToken")

				done := c.POST(t, "/2fa/verify",
					body{"tempToken": tempToken, "totpCode": totpNow(t, secret)}, BearerStrategy())
				done.mustStatus(t, 200)
				if done.str(t, "accessToken") == "" || done.str(t, "refreshToken") == "" {
					t.Errorf("bearer step-up must return both tokens at the top level\n  %s", done.where())
				}
				done.mustNoCookies(t)
			},
		},

		Case{
			Name:  "2fa/wrong-code-is-a-code-less-401",
			Doc:   "§3 (2fa/verify), §4.4 — a wrong TOTP code is 401 {\"error\":\"Invalid TOTP code\"} with no `code` field",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				enrolled, acct := e.LoginCookie(t)
				enrolTOTP(t, enrolled)

				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				login.mustStatus(t, 200)

				c.POST(t, "/2fa/verify", body{"tempToken": login.str(t, "tempToken"), "totpCode": "000000"}).
					mustCodelessError(t, 401, "Invalid TOTP code")
			},
		},

		Case{
			Name: "2fa/verify-wrong-code-is-uniform",
			Doc: "§3 (2fa/verify), §4.4 — every way of getting the step-up token wrong answers the same " +
				"401 {\"error\":\"Invalid or expired access token\",\"code\":\"INVALID_ACCESS_TOKEN\"}",
			Needs: []Capability{CapTOTP},
			Run: func(t *testing.T, e *Env) {
				enrolled, acct := e.LoginCookie(t)
				secret := enrolTOTP(t, enrolled)

				c := e.NewClient()
				login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
				login.mustStatus(t, 200)
				valid := login.str(t, "tempToken")

				// This route has no missing-token branch: an absent tempToken
				// simply fails verification, so "you sent nothing" and "you sent
				// something wrong" are one answer. That is what keeps the route
				// from telling an attacker which half of the guess was right —
				// and it is checked for both because a port that added a
				// helpful "tempToken is required" would be adding the oracle.
				for _, tc := range []struct {
					name string
					b    body
				}{
					{"no tempToken at all", body{"totpCode": "000000"}},
					{"an empty tempToken", body{"tempToken": "", "totpCode": "000000"}},
					{"a tempToken that is not a token", body{"tempToken": "not-a-token", "totpCode": "000000"}},
					{"a structurally valid token signed by nobody", body{
						"tempToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4IiwidHlwIjoidGVtcCJ9.AAAA",
						"totpCode":  "000000",
					}},
				} {
					t.Run(tc.name, func(t *testing.T) {
						e.NewClient().POST(t, "/2fa/verify", tc.b).
							mustError(t, 401, "INVALID_ACCESS_TOKEN", "Invalid or expired access token")
					})
				}

				// The code this route answers is deliberately NOT the
				// INVALID_TEMP_TOKEN its siblings answer for the same failure:
				// the reference verifies the tempToken here through
				// verifyAccessToken and lets that error through unchanged
				// (auth.router.ts:862 vs :1096), so the same mistake has two
				// codes depending on the 2FA method. Pinned rather than
				// harmonised — a client that special-cases TOTP today would
				// break if this route started agreeing with the others.
				//
				// And the challenge the user actually holds still completes:
				// none of the refusals above may consume it, or a mistyped code
				// from somebody else would cost this user their login.
				c.POST(t, "/2fa/verify", body{"tempToken": valid, "totpCode": totpNow(t, secret)}).
					mustSuccessOnly(t)
			},
		},
	)
}

func containsString(list []any, want string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
