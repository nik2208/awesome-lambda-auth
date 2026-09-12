package aws

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"
	auth "github.com/nik2208/awesome-go-auth"
)

// The fake signs with a local RSA key, which is the only way to prove the thing
// that matters: that a JWS built through this signer verifies against the public
// key this signer publishes. A fake that returned a fixed byte string would
// exercise the plumbing and none of the cryptography, and the failure it cannot
// catch — a MessageType, a signing algorithm or a digest that does not match
// what RS256 means — is exactly the failure that reaches the wire as "every
// relying party rejects our tokens".

type fakeKMS struct {
	keys map[string]*rsa.PrivateKey

	// arnFor renames a key in the GetPublicKey answer, which is how an alias
	// resolves to the ARN Sign is then expected to use.
	arnFor map[string]string

	keyUsage   kmstypes.KeyUsageType
	algorithms []kmstypes.SigningAlgorithmSpec

	// getHang makes GetPublicKey block until its context is done, which is what
	// a throttled or unreachable KMS looks like from here.
	getHang bool

	getErr  error
	signErr error

	mu         sync.Mutex
	getCalls   map[string]int
	signInputs []*kms.SignInput
}

func newFakeKMS(t *testing.T, ids ...string) *fakeKMS {
	t.Helper()
	f := &fakeKMS{
		keys:       make(map[string]*rsa.PrivateKey, len(ids)),
		arnFor:     make(map[string]string, len(ids)),
		getCalls:   make(map[string]int, len(ids)),
		keyUsage:   kmstypes.KeyUsageTypeSignVerify,
		algorithms: []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256},
	}
	for _, id := range ids {
		// 2048 bits, the KeySpec the stack creates. Generating a smaller key
		// would make the suite faster and would stop proving that a real
		// RSA-2048 signature round-trips.
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate key for %s: %v", id, err)
		}
		f.keys[id] = key
		f.arnFor[id] = "arn:aws:kms:eu-west-1:000000000000:key/" + id
	}
	return f
}

func (f *fakeKMS) GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.mu.Lock()
	f.getCalls[awssdk.ToString(in.KeyId)]++
	f.mu.Unlock()

	if f.getHang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.getErr != nil {
		return nil, f.getErr
	}
	key, ok := f.keys[awssdk.ToString(in.KeyId)]
	if !ok {
		return nil, &fakeAPIError{code: "NotFoundException"}
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{
		KeyId:             awssdk.String(f.arnFor[awssdk.ToString(in.KeyId)]),
		PublicKey:         der,
		KeyUsage:          f.keyUsage,
		SigningAlgorithms: f.algorithms,
	}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.mu.Lock()
	f.signInputs = append(f.signInputs, in)
	f.mu.Unlock()

	if f.signErr != nil {
		return nil, f.signErr
	}
	key, ok := f.keyByRef(awssdk.ToString(in.KeyId))
	if !ok {
		return nil, &fakeAPIError{code: "NotFoundException"}
	}
	if in.MessageType != kmstypes.MessageTypeDigest {
		return nil, &fakeAPIError{code: "ValidationException"}
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, in.Message)
	if err != nil {
		return nil, err
	}
	return &kms.SignOutput{Signature: sig}, nil
}

// keyByRef resolves either the configured id or the ARN GetPublicKey returned,
// because the signer is expected to switch to the ARN once it has one.
func (f *fakeKMS) keyByRef(ref string) (*rsa.PrivateKey, bool) {
	if key, ok := f.keys[ref]; ok {
		return key, true
	}
	for id, arn := range f.arnFor {
		if arn == ref {
			return f.keys[id], true
		}
	}
	return nil, false
}

func (f *fakeKMS) lastSignInput(t *testing.T) *kms.SignInput {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.signInputs) == 0 {
		t.Fatal("nothing was signed")
	}
	return f.signInputs[len(f.signInputs)-1]
}

// fakeAPIError is a smithy.APIError, which is what apiErrorCode reads to name a
// failure without quoting the SDK's message.
type fakeAPIError struct {
	code    string
	message string
}

func (e *fakeAPIError) Error() string {
	return fmt.Sprintf("api error %s: %s", e.code, e.message)
}
func (e *fakeAPIError) ErrorCode() string             { return e.code }
func (e *fakeAPIError) ErrorMessage() string          { return e.message }
func (e *fakeAPIError) ErrorFault() smithy.ErrorFault { return smithy.FaultServer }

func newTestSigner(t *testing.T, f *fakeKMS, keyID string, previous ...string) *KMSSigner {
	t.Helper()
	signer, err := NewKMSSigner(KMSSignerOptions{KeyID: keyID, PreviousKeyIDs: previous, Client: f})
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}
	return signer
}

// TestKMSSignerProducesAVerifiableJWS is the end-to-end claim: a token built
// through the core's own JWS builder, signed by this signer, verifies against
// the key this signer publishes in the JWKS document.
//
// Verified against the published JWK rather than against the fake's key, because
// a relying party has nothing else: it fetches the document, picks the key by
// kid, and checks the signature. If the kid, the modulus or the exponent this
// package publishes did not describe the key that signed, that is precisely the
// step that would fail.
func TestKMSSignerProducesAVerifiableJWS(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	signer := newTestSigner(t, f, "signing-key")

	kid, err := signer.Resolve(t.Context())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	token, err := auth.BuildRS256JWT(signer, kid, map[string]any{"sub": "usr_1", "iss": "https://auth.example.test/auth"})
	if err != nil {
		t.Fatalf("BuildRS256JWT: %v", err)
	}

	document, err := signer.JWKS(t.Context())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(document) != 1 {
		t.Fatalf("JWKS published %d keys, want 1", len(document))
	}
	if document[0].Kid != kid {
		t.Errorf("published kid %q, signed under %q", document[0].Kid, kid)
	}
	if document[0].Alg != "RS256" || document[0].Kty != "RSA" || document[0].Use != "sig" {
		t.Errorf("published JWK is %+v, want kty RSA / use sig / alg RS256", document[0])
	}

	pub, err := document[0].RSAPublicKey()
	if err != nil {
		t.Fatalf("published JWK does not decode: %v", err)
	}
	verifyJWS(t, token, pub)
}

// verifyJWS is a relying party in four lines: split, hash the signing input,
// check the signature. Written out rather than borrowed from the core so the
// test does not verify through the same code path that signed.
func verifyJWS(t *testing.T, token string, pub *rsa.PublicKey) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("the published key does not verify the token this signer produced: %v", err)
	}
}

// TestKMSSignerSendsOnlyTheDigest pins the privacy property this signer exists
// for: the request carries the 32-byte SHA-256 of the signing input and nothing
// else, so the token's claims — the subject's id, their email — never reach AWS.
//
// MessageType is asserted too, because DIGEST and RAW take the same field: a
// signer that sent RAW with a 32-byte message would produce a signature over the
// digest's *bytes* rather than over the token, which no verifier accepts, and
// nothing would report an error.
func TestKMSSignerSendsOnlyTheDigest(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	signer := newTestSigner(t, f, "signing-key")
	if _, err := signer.Resolve(t.Context()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	const signingInput = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3JfMSJ9"
	digest := sha256.Sum256([]byte(signingInput))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	in := f.lastSignInput(t)
	if in.MessageType != kmstypes.MessageTypeDigest {
		t.Errorf("MessageType = %s, want %s", in.MessageType, kmstypes.MessageTypeDigest)
	}
	if in.SigningAlgorithm != kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
		t.Errorf("SigningAlgorithm = %s, want %s", in.SigningAlgorithm, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256)
	}
	if len(in.Message) != sha256.Size {
		t.Errorf("the request carried %d bytes, want exactly the %d-byte digest", len(in.Message), sha256.Size)
	}
	if string(in.Message) != string(digest[:]) {
		t.Errorf("the request carried something other than the digest it was given")
	}
	// The ARN GetPublicKey resolved, not the configured id: an alias re-pointed
	// after cold start must not silently sign with a key this process never
	// published.
	if got, want := awssdk.ToString(in.KeyId), f.arnFor["signing-key"]; got != want {
		t.Errorf("signed with key %q, want the resolved ARN %q", got, want)
	}
}

// TestKMSSignerRefusesAnythingButSHA256: the kid this signer publishes goes into
// a header that says RS256, so a request for another hash has to fail here
// rather than produce a signature no verifier accepts.
func TestKMSSignerRefusesAnythingButSHA256(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	signer := newTestSigner(t, f, "signing-key")
	if _, err := signer.Resolve(t.Context()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	digest := sha256.Sum256([]byte("input"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
		t.Error("Sign accepted a SHA-512 request for an RS256 signer")
	}
	if _, err := signer.Sign(rand.Reader, digest[:16], crypto.SHA256); err == nil {
		t.Error("Sign accepted a 16-byte digest")
	}
	f.mu.Lock()
	calls := len(f.signInputs)
	f.mu.Unlock()
	if calls != 0 {
		t.Errorf("a refused request still reached KMS %d time(s)", calls)
	}
}

// TestKMSGetPublicKeyFailureIsAColdStartRefusal is the guarantee that separates
// Resolve from Public: a key that cannot be fetched must fail the deployment,
// not every request.
//
// The second half is what makes it a guarantee rather than a convention. Even if
// a caller forgot to Resolve, the core refuses the signer at construction —
// NewIDP consults Public() and will not build an IDP around a nil key — so there
// is no path on which an unresolved signer reaches a request and answers 500.
func TestKMSGetPublicKeyFailureIsAColdStartRefusal(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	f.getErr = &fakeAPIError{code: "AccessDeniedException", message: "not authorized to perform kms:GetPublicKey"}
	signer := newTestSigner(t, f, "signing-key")

	_, err := signer.Resolve(t.Context())
	if err == nil {
		t.Fatal("Resolve succeeded with a denied kms:GetPublicKey")
	}
	if !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Errorf("the error does not name the API failure:\n%v", err)
	}
	if signer.Public() != nil {
		t.Error("Public() returned a key after a failed Resolve")
	}

	if _, err := auth.NewIDP(auth.IDPConfig{Signer: signer}, nil); err == nil {
		t.Error("the auth core built an IDP around an unresolved signer; a request would then be the first thing to discover the key is missing")
	}

	// And a caller that skipped Resolve entirely gets a message naming the fix
	// rather than a nil dereference.
	digest := sha256.Sum256([]byte("input"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil || !strings.Contains(err.Error(), "Resolve") {
		t.Errorf("Sign before Resolve = %v, want an error naming Resolve", err)
	}
}

// TestKMSErrorsNeverCarryTheDigestOrTheSignature pins the rule the kmsError type
// exists for. The fake fails with an error message that quotes both — which is
// the adversarial case, not a realistic one — and none of it may reach the text
// this package renders.
//
// The signature is the token's third segment: a log line carrying one is a
// credential in CloudWatch. The digest is the SHA-256 of the token's header and
// claims, which lets an offline attacker test candidate signatures without ever
// holding the token.
func TestKMSErrorsNeverCarryTheDigestOrTheSignature(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	signer := newTestSigner(t, f, "signing-key")
	if _, err := signer.Resolve(t.Context()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	digest := sha256.Sum256([]byte("eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c3JfMSJ9"))
	digestHex := hex.EncodeToString(digest[:])
	digestB64 := base64.RawURLEncoding.EncodeToString(digest[:])
	const signature = "Q2xhaW1zLXNpZ25hdHVyZS1ieXRlcy10aGF0LW11c3Qtbm90LWJlLWxvZ2dlZA"

	f.signErr = &fakeAPIError{
		code:    "ThrottlingException",
		message: "failed signing message " + digestHex + " / " + digestB64 + " producing " + signature,
	}

	_, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err == nil {
		t.Fatal("Sign succeeded against a failing KMS")
	}
	rendered := err.Error()
	for name, secret := range map[string]string{
		"the digest in hex":      digestHex,
		"the digest in base64":   digestB64,
		"the signature material": signature,
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("the rendered error carries %s:\n%s", name, rendered)
		}
	}
	if !strings.Contains(rendered, "ThrottlingException") {
		t.Errorf("the rendered error does not name the API failure, which is the part an operator acts on:\n%s", rendered)
	}

	// The cause stays reachable: telling a throttle from a denial is how a
	// caller decides whether to retry, and dropping it to redact a message would
	// be the wrong trade.
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) || apiErr.ErrorCode() != "ThrottlingException" {
		t.Errorf("errors.As cannot reach the API error through the wrapper: %v", err)
	}
}

// TestKMSKidIsDerivedFromTheKeyMaterial recomputes the kid from the DER the fake
// returned, without going through KeyFingerprint, so the derivation is pinned by
// an independent calculation rather than by agreement with itself.
func TestKMSKidIsDerivedFromTheKeyMaterial(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "signing-key")
	signer := newTestSigner(t, f, "signing-key")

	kid, err := signer.Resolve(t.Context())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(f.keys["signing-key"].Public())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	want := base64.RawURLEncoding.EncodeToString(sum[:])[:16]
	if kid != want {
		t.Errorf("kid = %q, want base64url(sha256(SPKI))[:16] = %q", kid, want)
	}
	if len(kid) != 16 {
		t.Errorf("kid is %d characters, want 16", len(kid))
	}
	if got := signer.KeyID(); got != kid {
		t.Errorf("KeyID() = %q, want %q", got, kid)
	}
}

// TestKMSJWKSPublishesTheRotationSet: the signing key first, then every retired
// key, each under its own kid, and each one able to verify what it signed.
func TestKMSJWKSPublishesTheRotationSet(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "key-2026", "key-2025", "key-2024")
	signer := newTestSigner(t, f, "key-2026", "key-2025", "key-2024")
	if _, err := signer.Resolve(t.Context()); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	document, err := signer.JWKS(t.Context())
	if err != nil {
		t.Fatalf("JWKS: %v", err)
	}
	if len(document) != 3 {
		t.Fatalf("published %d keys, want 3", len(document))
	}
	if document[0].Kid != signer.KeyID() {
		t.Errorf("the signing key is not published first: head kid %q, signing kid %q", document[0].Kid, signer.KeyID())
	}

	seen := map[string]bool{}
	for i, jwk := range document {
		if seen[jwk.Kid] {
			t.Errorf("kid %q is published twice", jwk.Kid)
		}
		seen[jwk.Kid] = true

		pub, err := jwk.RSAPublicKey()
		if err != nil {
			t.Fatalf("key %d does not decode: %v", i, err)
		}
		// Each published key must be the key it claims to be: a rotation that
		// published the signing key three times under three kids would look
		// right in every shape assertion and verify nothing.
		id := []string{"key-2026", "key-2025", "key-2024"}[i]
		if pub.N.Cmp(f.keys[id].N) != 0 {
			t.Errorf("published key %d is not %s", i, id)
		}
	}
}

// TestKMSJWKSRefusesADuplicateKey: two key ids resolving to one public key means
// the rotation was configured against a key that never changed, and publishing
// it twice under one kid would hide that.
func TestKMSJWKSRefusesADuplicateKey(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "current")
	// An alias pointing at the same key, which is the realistic way to get here.
	f.keys["alias/current"] = f.keys["current"]
	f.arnFor["alias/current"] = f.arnFor["current"]

	signer := newTestSigner(t, f, "current", "alias/current")
	if _, err := signer.JWKS(t.Context()); err == nil {
		t.Fatal("JWKS published one key twice instead of refusing")
	}

	// And two RETIRED ids resolving to one key, which the primary is not part
	// of at all. The config layer refuses only entries that are textually equal,
	// so this pair — an id and its alias, or one ARN spelled two ways — reaches
	// the signer, and a check written against the primary alone would publish
	// the key twice under one kid.
	t.Run("two retired ids that resolve to one key", func(t *testing.T) {
		t.Parallel()
		f := newFakeKMS(t, "current", "retired")
		f.keys["alias/retired"] = f.keys["retired"]
		f.arnFor["alias/retired"] = f.arnFor["retired"]

		signer := newTestSigner(t, f, "current", "retired", "alias/retired")
		_, err := signer.JWKS(t.Context())
		if err == nil {
			t.Fatal("JWKS published one retired key twice instead of refusing")
		}
		if !strings.Contains(err.Error(), "alias/retired") || !strings.Contains(err.Error(), `"retired"`) {
			t.Errorf("the refusal does not name both ids:\n%v", err)
		}
	})
}

// TestKMSResolveIsBounded: the cold-start fetch has a deadline of its own.
//
// Without one, a throttled or unreachable KMS spends the whole init budget —
// shared with secret resolution, the store build and the template seed — and
// the deployment's diagnostic becomes "startup deadline exceeded" instead of
// the key that could not be read. The context here is Background precisely so
// that the only thing that can end the call is the signer's own bound.
func TestKMSResolveIsBounded(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "current")
	f.getHang = true

	const bound = 200 * time.Millisecond
	signer, err := NewKMSSigner(KMSSignerOptions{KeyID: "current", Client: f, ResolveTimeout: bound})
	if err != nil {
		t.Fatalf("NewKMSSigner: %v", err)
	}

	start := time.Now()
	_, err = signer.Resolve(context.Background())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Resolve returned no error against a KMS that never answers")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("the error does not say the request timed out:\n%v", err)
	}
	// Generous, because the claim is the order of magnitude: bounded by the
	// signer's own timeout rather than by the service's willingness to answer.
	if elapsed > 20*bound {
		t.Errorf("Resolve took %s with a %s timeout; the fetch is not bounded", elapsed, bound)
	}
	if DefaultKMSResolveTimeout <= 0 {
		t.Error("the default resolve timeout is not positive, so an unconfigured signer is unbounded")
	}
}

// TestKMSRefusesAKeyThatCannotSignRS256 covers the three cold-start checks on the
// key itself. Each of them is a deployment that otherwise comes up, publishes a
// JWKS document and then fails every single token request.
func TestKMSRefusesAKeyThatCannotSignRS256(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		breakIt func(*fakeKMS)
		want    string
	}{
		{
			name:    "a key that cannot sign at all",
			breakIt: func(f *fakeKMS) { f.keyUsage = kmstypes.KeyUsageTypeEncryptDecrypt },
			want:    "ENCRYPT_DECRYPT",
		},
		{
			name: "an RSA key with no PKCS#1 v1.5 algorithm",
			breakIt: func(f *fakeKMS) {
				f.algorithms = []kmstypes.SigningAlgorithmSpec{kmstypes.SigningAlgorithmSpecRsassaPssSha256}
			},
			want: "RSASSA_PKCS1_V1_5_SHA_256",
		},
		{
			name:    "a key that resolves to nothing",
			breakIt: func(f *fakeKMS) { delete(f.keys, "signing-key") },
			want:    "NotFoundException",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeKMS(t, "signing-key")
			tc.breakIt(f)
			signer := newTestSigner(t, f, "signing-key")

			_, err := signer.Resolve(t.Context())
			if err == nil {
				t.Fatal("Resolve accepted a key that cannot produce an RS256 signature")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error does not say what is wrong (want %q):\n%v", tc.want, err)
			}
		})
	}
}

// TestKMSPublicKeyIsFetchedOnce: kms:GetPublicKey is a billed API call on the
// path of every JWKS build, and the document is rebuilt on nothing. One call per
// key per process is the whole point of memoising.
func TestKMSPublicKeyIsFetchedOnce(t *testing.T) {
	t.Parallel()
	f := newFakeKMS(t, "current", "retired")
	signer := newTestSigner(t, f, "current", "retired")

	for range 5 {
		if _, err := signer.Resolve(t.Context()); err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if _, err := signer.JWKS(t.Context()); err != nil {
			t.Fatalf("JWKS: %v", err)
		}
		signer.Public()
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	for id, calls := range f.getCalls {
		if calls != 1 {
			t.Errorf("kms:GetPublicKey called %d times for %s, want 1", calls, id)
		}
	}
}

// TestKMSSignerRequiresAKeyID: a signer with no key would build, resolve nothing
// and fail on the first token.
func TestKMSSignerRequiresAKeyID(t *testing.T) {
	t.Parallel()
	if _, err := NewKMSSigner(KMSSignerOptions{KeyID: "  "}); err == nil {
		t.Fatal("NewKMSSigner accepted an empty key id")
	}
}

// TestKeyFingerprintIsStableAndDistinct: the property a rotation rests on. The
// same key material always produces the same kid, and different material never
// produces the same one — otherwise a rotation would publish two keys a relying
// party cannot tell apart.
func TestKeyFingerprintIsStableAndDistinct(t *testing.T) {
	t.Parallel()
	first, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	second, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	derOf := func(key *rsa.PrivateKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return der
	}

	if KeyFingerprint(derOf(first)) != KeyFingerprint(derOf(first)) {
		t.Error("the same key produced two different kids")
	}
	if KeyFingerprint(derOf(first)) == KeyFingerprint(derOf(second)) {
		t.Error("two different keys produced the same kid")
	}
}
