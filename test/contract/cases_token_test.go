package contract

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// The shape of the token itself.
//
// Everything else in this suite treats a token as opaque, which is right: a
// client is handed one and sends it back, and the family's clients do not parse
// it. This file is the one exception, and the reason is that the token is not
// only a credential here — it is also the carrier of whatever
// security.jwt.extraClaims and security.jwt.claimsWebhook put in it, and a
// deployment that configures those has a consumer downstream that does read the
// payload. That consumer is outside this repository and outside the family, so
// the only thing standing between it and a silent re-encoding is a case here.
//
// The payload is decoded the way such a consumer decodes it — split on ".",
// base64url without padding, JSON — and nothing is verified: this suite holds no
// signing secret and must not pretend to. Verification is the deployment's job
// and `/me` is the case that proves the token works.

// jwsPayload splits a compact JWS and returns its decoded claims, failing the
// case when the token is not one.
func jwsPayload(t *testing.T, r *Resp, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a three-part JWS: %d segment(s)\n  %s", len(parts), r.where())
	}
	for i, part := range parts {
		if part == "" {
			t.Fatalf("segment %d of the token is empty\n  %s", i, r.where())
		}
	}
	// RawURLEncoding: a JWS segment is base64url with the padding stripped
	// (RFC 7515 §2), and a decoder expecting padding is the classic way a
	// consumer breaks on one token in four.
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("the token payload is not unpadded base64url: %v\n  %s", err, r.where())
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("the token payload is not a JSON object: %v\n  %s", err, r.where())
	}
	return claims
}

func init() {
	register(
		Case{
			Name: "token/bearer-access-token-is-a-jws-with-the-session-claims",
			Doc: "§1.5, §4 — a bearer access token is a three-part compact JWS whose payload carries sub, sid, typ and iss; " +
				"typ is what separates it from a refresh token and from a 2FA tempToken",
			Run: func(t *testing.T, e *Env) {
				acct := e.NewAccount(t)
				login := e.NewClient().POST(t, "/login",
					body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
				login.mustStatus(t, 200)

				access := login.str(t, "accessToken")
				if access == "" {
					t.Fatalf("a bearer login returned no accessToken\n  %s", login.where())
				}
				claims := jwsPayload(t, login, access)

				// sub identifies the account. The clients read it off /me
				// rather than out of the token, but a resource server behind
				// this deployment reads it here and nowhere else.
				if sub, _ := claims["sub"].(string); sub == "" {
					t.Errorf("the payload carries no sub, so nothing downstream can say whose token this is: %v\n  %s",
						keysOf(claims), login.where())
				}
				// sid binds the token to its session, which is what makes
				// DELETE /sessions/{handle} and SESSION_REVOKED mean anything.
				if sid, _ := claims["sid"].(string); sid == "" {
					t.Errorf("the payload carries no sid, so the token is not bound to a session and revocation cannot reach it: %v\n  %s",
						keysOf(claims), login.where())
				}
				// typ is the one that matters most: it is the only thing
				// telling an access token, a refresh token and the 2FA
				// tempToken apart, and it is why a tempToken cannot open /me.
				if typ, _ := claims["typ"].(string); typ != "access" {
					t.Errorf("typ = %#v, want \"access\" — typ is what keeps a refresh token and a tempToken out of the access-token gate\n  %s",
						claims["typ"], login.where())
				}
				// iss is checked on every parse, so a token minted under one
				// issuer is refused under another. Its value is a deployment
				// decision and is not pinned here; its presence is not.
				if iss, _ := claims["iss"].(string); iss == "" {
					t.Errorf("the payload carries no iss: %v\n  %s", keysOf(claims), login.where())
				}
				// The lifetime claims, because a consumer that refreshes early
				// reads exp and a consumer that caches reads iat.
				for _, name := range []string{"iat", "exp"} {
					if _, ok := claims[name].(float64); !ok {
						t.Errorf("%s = %#v, want a NumericDate (a JSON number)\n  %s", name, claims[name], login.where())
					}
				}

				// The refresh token is the same shape with a different typ,
				// which is the whole of the distinction.
				refresh := login.str(t, "refreshToken")
				if refresh == "" {
					t.Fatalf("a bearer login returned no refreshToken\n  %s", login.where())
				}
				if typ, _ := jwsPayload(t, login, refresh)["typ"].(string); typ != "refresh" {
					t.Errorf("the refresh token's typ = %#v, want \"refresh\"; if the two tokens are indistinguishable, one is the other\n  %s",
						typ, login.where())
				}

				// No credential material rides along inside the payload. It is
				// signed, not encrypted: anyone holding the token reads this.
				for _, leaked := range []string{"password", "passwordHash", "totpSecret", "secret", "refreshToken"} {
					if _, present := claims[leaked]; present {
						t.Errorf("the token payload carries %q, and a JWS payload is readable by anyone holding the token\n  %s",
							leaked, login.where())
					}
				}
			},
		},
	)
}
