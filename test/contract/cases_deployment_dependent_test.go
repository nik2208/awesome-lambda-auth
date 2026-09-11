package contract

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Routes whose answer depends on what the operator wired, not on what the
// contract says. Each case reads the deployment and then asserts the shape of
// whichever documented answer it got: a suite that fails because mail is not
// configured is a broken suite, and a suite that stops looking because mail is
// not configured is a useless one.
//
// The trap in that arrangement is a branch that only logs. "Accept 200 or 500"
// is legitimate exactly as long as each branch then pins the full shape of the
// answer it took; the moment one branch stops asserting, every corruption that
// can steer the route into that branch becomes invisible.

// assertDeclaresAbsence is what the absence branches assert. An absence cannot
// be positively verified from outside — that is what RequireEnv is for — but it
// can be checked for self-consistency, and both checks here have caught
// something a log line would not:
//
//   - the answer must not carry the payload it claims not to have;
//   - it must not contradict the probe, which called this same route seconds
//     earlier. A route that answered 200 to the probe and "absent" to the case
//     is not an unconfigured store, it is an unstable one.
func assertDeclaresAbsence(t *testing.T, e *Env, r *Resp, feature Capability, payloadKey string) {
	t.Helper()
	var m map[string]any
	if json.Unmarshal(r.Body, &m) == nil {
		if _, ok := m[payloadKey]; ok {
			t.Errorf("this answer declares the store absent and then carries %q anyway\n  %s", payloadKey, r.where())
		}
	}
	if bytes.HasPrefix(bytes.TrimSpace(r.Body), []byte("[")) {
		t.Errorf("this answer declares the store absent and then returns a bare array\n  %s", r.where())
	}
	if e.can(feature) {
		t.Errorf(`the probe found %q on this deployment and this case then found it absent, on the same route within the same run.
  probe: %s
  now:   %s`, feature, e.Caps[feature].why, r.where())
	}
}

func init() {
	register(
		Case{
			Name: "linked-accounts/wrapped-or-declared-absent",
			Doc:  "hard point 6, §4 — with a linked-accounts store: 200 {\"linkedAccounts\":[…]}, an object wrapper and never a bare array. Without one, the route must say so rather than pretend",
			Run: func(t *testing.T, e *Env) {
				c, _ := e.LoginCookie(t)
				r := c.GET(t, "/linked-accounts")

				switch r.Status {
				case 200:
					m := r.obj(t)
					raw, ok := m["linkedAccounts"]
					if !ok {
						t.Fatalf("body has no \"linkedAccounts\" key; the Angular client reads res.linkedAccounts and a bare array breaks it, got %v\n  %s",
							keysOf(m), r.where())
					}
					if _, ok := raw.([]any); !ok {
						t.Errorf("\"linkedAccounts\" is %T, want an array\n  %s", raw, r.where())
					}
				case 404:
					// "Not mounted" is the reference's absence (§4,
					// auth.router.ts:1456) and its body is Express's HTML
					// fall-through, so there is no shape to pin — but there is
					// still something to assert. An absence must be an absence:
					// it must not carry the payload, and it must not contradict
					// what the probe saw a moment earlier on this same route.
					assertDeclaresAbsence(t, e, r, CapLinkedAccounts, "linkedAccounts")
					t.Logf("no linked-accounts store is wired and the route is not mounted (the reference's behaviour with the store absent)\n  %s", r.where())
				case 500, 501:
					r.mustError(t, r.Status, "NOT_IMPLEMENTED", "")
					assertDeclaresAbsence(t, e, r, CapLinkedAccounts, "linkedAccounts")
					t.Logf("linked accounts are switched off in this deployment (stores.enable.linkedAccounts)\n  %s", r.where())
				default:
					t.Fatalf("unexpected answer: want 200 with the wrapper, or a declared absence (404/500/501)\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "magic-link/send/configured-or-EMAIL_NOT_CONFIGURED",
			Doc:  "§3 (magic-link/send) — with a mail transport: 200 {\"success\":true}. Without one: 500 {\"error\":\"Email not configured\",\"code\":\"EMAIL_NOT_CONFIGURED\"}",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/magic-link/send", body{"email": acct.Email})

				switch r.Status {
				case 200:
					r.mustSuccessOnly(t)
					t.Logf("a mail transport is configured in this deployment\n  %s", r.where())
				case 500:
					r.mustError(t, 500, "EMAIL_NOT_CONFIGURED", "Email not configured")
					t.Logf("no mail transport is configured in this deployment\n  %s", r.where())
				default:
					t.Fatalf("want 200 with a mailer or 500 EMAIL_NOT_CONFIGURED without one\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "magic-link/send/unknown-address-does-not-leak",
			Doc:  "§3 (magic-link/send) — in login mode an unknown address is answered exactly like a known one; the strategy returns silently (anti-enumeration)",
			Run: func(t *testing.T, e *Env) {
				known := e.NewAccount(t)
				unknown := randomAccount()

				a := e.NewClient().POST(t, "/magic-link/send", body{"email": known.Email})
				b := e.NewClient().POST(t, "/magic-link/send", body{"email": unknown.Email})

				// "Answered exactly like" is the whole property, and the status
				// line is the part of the answer an oracle is least likely to
				// differ in: a leak arrives as a field, a message, a hint. Both
				// halves of the response have to match.
				if a.Status != b.Status {
					t.Errorf("known and unknown addresses are distinguishable by status: %d vs %d\n  known:   %s\n  unknown: %s",
						a.Status, b.Status, a.where(), b.where())
				}
				if !bytes.Equal(a.Body, b.Body) {
					t.Errorf("known and unknown addresses are distinguishable by body, which is an account-enumeration oracle\n  known:   %s\n  unknown: %s",
						a.where(), b.where())
				}
				for _, r := range []*Resp{a, b} {
					if bytes.Contains(r.Body, []byte(known.Email)) || bytes.Contains(r.Body, []byte(unknown.Email)) {
						t.Errorf("the response echoes the address it was asked about\n  %s", r.where())
					}
				}
			},
		},

		Case{
			Name: "sms/send/configured-or-SMS_NOT_CONFIGURED",
			Doc:  "§3 (sms/send) — without an SMS transport: 500 {\"error\":\"SMS is not configured\",\"code\":\"SMS_NOT_CONFIGURED\"}. With one, an account with no phone number is 400 PHONE_NOT_SET",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				r := e.NewClient().POST(t, "/sms/send", body{"email": acct.Email})

				switch r.Status {
				case 500:
					r.mustError(t, 500, "SMS_NOT_CONFIGURED", "SMS is not configured")
					t.Logf("no SMS transport is configured in this deployment\n  %s", r.where())
				case 400:
					r.mustError(t, 400, "PHONE_NOT_SET", "User does not have a phone number configured")
					t.Logf("an SMS transport is configured in this deployment\n  %s", r.where())
				case 200:
					r.mustSuccessOnly(t)
					t.Logf("an SMS transport is configured and the account had a phone number\n  %s", r.where())
				default:
					t.Fatalf("want 500 SMS_NOT_CONFIGURED, 400 PHONE_NOT_SET or 200\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "forgot-password/unknown-address-is-a-plain-success",
			Doc:  "§2 (forgot-password) — always 200 {\"success\":true}, whether or not the address exists, mailer or no mailer: explicit anti-enumeration; the optional emailLang body field is accepted and changes nothing on the wire",
			Run: func(t *testing.T, e *Env) {
				unknown := randomAccount()
				e.NewClient().POST(t, "/forgot-password", body{"email": unknown.Email}).
					mustSuccessOnly(t)

				// emailLang is the optional field every mail route's body
				// carries (§2, "Request body: {email, emailLang?}"); the
				// served auth.js never sends it, the Angular and Flutter
				// clients may. Accepted means the same plain success — not a
				// validation error, not a different body — and it is asked
				// about the same unknown address, so a deployment with a live
				// sender still has nothing to send.
				e.NewClient().POST(t, "/forgot-password", body{"email": unknown.Email, "emailLang": "it"}).
					mustSuccessOnly(t)
			},
		},
	)
}
