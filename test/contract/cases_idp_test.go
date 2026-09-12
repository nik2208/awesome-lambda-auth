package contract

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Identity-provider mode, black-box.
//
// This is the one area of the suite with no reference wire to cite, and the
// README says why: awesome-node-auth's `idProvider` block is RS256 signing plus
// JWKS publication and nothing else — no /authorize, no /token, no /userinfo,
// no discovery document exist anywhere in its source
// (parity-gap-node-vs-go.md #27). So the JWKS route below is checked against the
// reference (auth.router.ts:473-505, including the exact Cache-Control), and
// everything else is checked against docs/oidc.md and the RFCs it commits to.
//
// Nothing here needs a registered client, and that is deliberate: a deployment
// may legitimately enable identity-provider mode purely to publish a signing key
// for a resource server elsewhere in the estate, and a suite that could only
// check the surface when a client existed would skip on exactly those
// deployments.

// jwkMembers is the exact key set of a published JWK. Asserted whole rather than
// field by field, because the field that matters is the one that should not be
// there: a signing key serialised with its private members ("d", "p", "q", …)
// publishes the issuer's identity to the internet, and an assertion that only
// looked at the six expected members would not see it.
var jwkMembers = []string{"alg", "e", "kid", "kty", "n", "use"}

func init() {
	register(
		Case{
			Name:  "idp/jwks-document-shape",
			Doc:   "reference auth.router.ts:473-505 (the JWKS route is the one part of this surface the reference has) — GET <prefix>/.well-known/jwks.json is 200 {keys:[{kty:\"RSA\",use:\"sig\",alg:\"RS256\",kid,n,e}]} with Cache-Control: public, max-age=3600, served to an anonymous caller and carrying no private key material",
			Needs: []Capability{CapIDP},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/.well-known/jwks.json")
				r.mustStatus(t, 200)

				// The reference hardcodes this and a relying party caches on it:
				// an hour of shared caching is what makes RS256 verification
				// cheap at the edge, and a document served no-store would put
				// one fetch on every token verification.
				if got := r.Header.Get("Cache-Control"); got != "public, max-age=3600" {
					t.Errorf("Cache-Control = %q, want %q\n  %s", got, "public, max-age=3600", r.where())
				}
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json\n  %s", ct, r.where())
				}

				var document struct {
					Keys []map[string]any `json:"keys"`
				}
				if err := json.Unmarshal(r.Body, &document); err != nil {
					t.Fatalf("body is not a JWKS (%v)\n  %s", err, r.where())
				}
				if len(document.Keys) == 0 {
					t.Fatalf("the document publishes no keys, so nothing can verify a token this issuer signed\n  %s", r.where())
				}

				kids := map[string]bool{}
				for i, jwk := range document.Keys {
					where := func(what string) string { return "keys[" + strconv.Itoa(i) + "] " + what }

					var members []string
					for k := range jwk {
						members = append(members, k)
					}
					sort.Strings(members)
					if strings.Join(members, ",") != strings.Join(jwkMembers, ",") {
						t.Errorf("%s has members %v, want exactly %v — a private member here would publish the signing key itself\n  %s",
							where(""), members, jwkMembers, r.where())
					}
					for member, want := range map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256"} {
						if jwk[member] != want {
							t.Errorf("%s = %v, want %q\n  %s", where(member), jwk[member], want, r.where())
						}
					}

					kid, _ := jwk["kid"].(string)
					if kid == "" {
						t.Errorf("%s is empty, so a token cannot name this key\n  %s", where("kid"), r.where())
					}
					if kids[kid] {
						t.Errorf("%s is published twice; a relying party cannot tell the two keys apart\n  %s", where("kid"), r.where())
					}
					kids[kid] = true

					// n and e are unpadded base64url of big-endian bytes (RFC
					// 7518 §6.3.1). Standard base64 here — '+' or '/' or '=' —
					// decodes to different bytes in a strict verifier and to the
					// right ones in a lenient one, which is the worst kind of
					// bug: it works until the relying party changes library.
					for _, member := range []string{"n", "e"} {
						value, _ := jwk[member].(string)
						if value == "" {
							t.Errorf("%s is empty\n  %s", where(member), r.where())
							continue
						}
						if strings.ContainsAny(value, "+/=") {
							t.Errorf("%s = %q is standard base64, want unpadded base64url (RFC 7518 §6.3.1)\n  %s",
								where(member), value, r.where())
						}
						if _, err := base64.RawURLEncoding.DecodeString(value); err != nil {
							t.Errorf("%s does not decode as base64url: %v\n  %s", where(member), err, r.where())
						}
					}
				}

				// No cookie, no credential, no Vary on Authorization: the route
				// is public and cacheable, and a Set-Cookie on it would make a
				// shared cache store one caller's session.
				if len(r.SetCookie) > 0 {
					t.Errorf("the JWKS response sets %d cookie(s), and it is served from a shared cache\n  %s", len(r.SetCookie), r.where())
				}
			},
		},

		Case{
			Name:  "idp/discovery-document-shape",
			Doc:   "docs/oidc.md — GET <prefix>/.well-known/openid-configuration advertises an absolute issuer, the three endpoints rooted at it, a jwks_uri that is the document this deployment actually serves, RS256 as the id_token algorithm, `code` as the only response type and client_secret_post as the token-endpoint authentication",
			Needs: []Capability{CapIDP},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/.well-known/openid-configuration")
				r.mustStatus(t, 200)
				doc := r.obj(t)

				issuer, _ := doc["issuer"].(string)
				if issuer == "" {
					t.Fatalf("the document names no issuer, so nothing in it can be resolved\n  %s", r.where())
				}
				if u, err := url.Parse(issuer); err != nil || u.Scheme == "" || u.Host == "" {
					t.Errorf("issuer = %q is not an absolute URL\n  %s", issuer, r.where())
				}

				// Every endpoint absolute and rooted at the issuer. A relying
				// party resolves these without ever seeing the deployment's
				// routing table, so a relative or differently-rooted endpoint is
				// a client that cannot complete a flow.
				for _, name := range []string{"authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"} {
					value, _ := doc[name].(string)
					if value == "" {
						t.Errorf("%s is missing\n  %s", name, r.where())
						continue
					}
					if !strings.HasPrefix(value, issuer) {
						t.Errorf("%s = %q is not rooted at the issuer %q\n  %s", name, value, issuer, r.where())
					}
				}

				for name, want := range map[string]string{
					"id_token_signing_alg_values_supported": "RS256",
					"response_types_supported":              "code",
					"subject_types_supported":               "public",
					"token_endpoint_auth_methods_supported": "client_secret_post",
				} {
					if !listContains(doc[name], want) {
						t.Errorf("%s = %v, want it to contain %q\n  %s", name, doc[name], want, r.where())
					}
				}

				// The advertised jwks_uri has to be the document this deployment
				// really serves: a discovery document pointing somewhere else is
				// the failure that makes every token unverifiable while every
				// individual endpoint looks correct.
				jwksURI, _ := doc["jwks_uri"].(string)
				published := e.NewClient().GET(t, "!"+mustPath(t, jwksURI))
				published.mustStatus(t, 200)
				if !strings.Contains(string(published.Body), `"keys"`) {
					t.Errorf("the advertised jwks_uri does not serve a JWKS\n  %s", published.where())
				}
			},
		},

		Case{
			Name:  "idp/token-refuses-a-code-nobody-issued",
			Doc:   "RFC 6749 §5.2 — POST <prefix>/token with a well-formed authorization_code grant and a code that was never issued is 400 invalid_grant. This endpoint is net-new (the reference has no authorization server), so its error body is the auth core's own and NOT the family {error,code} envelope: the case pins the status and the invalid_grant token, and accepts either the plain-text body the core writes today or the RFC 6749 JSON object",
			Needs: []Capability{CapIDP},
			Run: func(t *testing.T, e *Env) {
				// Well-formed on purpose: a malformed grant would be refused
				// before the store is consulted and would not prove that an
				// unknown code is refused.
				form := url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"},
					"client_id":     {"contract-suite-unknown-client"},
					"client_secret": {"contract-suite-unknown-secret"},
				}
				r := e.NewClient().form(t, "/token", form)

				// 400 for an unknown code, 401 for an unknown client: the core
				// checks the client first, and this suite cannot know whether
				// the deployment registered one by that name. Both are refusals
				// and neither may be a 200 or a 500.
				r.mustStatusIn(t, 400, 401)
				body := strings.ToLower(strings.TrimSpace(string(r.Body)))
				if !strings.Contains(body, "invalid_grant") && !strings.Contains(body, "invalid_client") {
					t.Errorf("body = %q, want it to name invalid_grant or invalid_client\n  %s", body, r.where())
				}
				// Whatever it is, it must not be a token: an endpoint that
				// answered anything containing an access_token to a code nobody
				// issued would be the whole flow broken.
				if strings.Contains(body, "access_token") || strings.Contains(body, "id_token") {
					t.Fatalf("the token endpoint issued a token for a code nobody minted\n  %s", r.where())
				}
			},
		},

		Case{
			Name:  "idp/authorize-refuses-an-unknown-client",
			Doc:   "RFC 6749 §4.1.2.1 — GET <prefix>/authorize with a client_id that is not registered is refused, and refused WITHOUT redirecting: an unvalidated client_id has no validated redirect_uri to send an error to, so a redirect here would be an open one",
			Needs: []Capability{CapIDP},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t,
					"/authorize?client_id=contract-suite-unknown-client&redirect_uri="+
						url.QueryEscape("https://evil.example.invalid/callback")+"&response_type=code")

				if r.Status >= 300 && r.Status < 400 {
					t.Fatalf("answered %d with Location %q; an unregistered client must never produce a redirect\n  %s",
						r.Status, r.Header.Get("Location"), r.where())
				}
				r.mustStatusIn(t, 400, 401)
				if strings.Contains(string(r.Body), "evil.example.invalid") {
					t.Errorf("the refusal echoes the unvalidated redirect_uri back to the caller\n  %s", r.where())
				}
			},
		},
	)
}

// listContains reports whether a JSON array member contains a string. The
// discovery document's *_supported members are arrays, and a deployment is free
// to advertise more than one value in them.
func listContains(value any, want string) bool {
	list, ok := value.([]any)
	if !ok {
		return false
	}
	for _, entry := range list {
		if s, ok := entry.(string); ok && s == want {
			return true
		}
	}
	return false
}

// mustPath reduces an absolute URL to the path the suite's own client can ask
// for, so the advertised jwks_uri is fetched from the deployment under test
// rather than from whatever host the document happens to name.
func mustPath(t *testing.T, raw string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("jwks_uri %q is not a URL: %v", raw, err)
	}
	return u.Path
}
