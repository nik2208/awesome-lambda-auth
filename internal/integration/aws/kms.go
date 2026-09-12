package aws

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/smithy-go"

	auth "github.com/nik2208/awesome-go-auth"
)

// The RS256 signer of identity-provider mode, backed by an AWS KMS asymmetric
// key.
//
// ── why KMS and not a PEM ────────────────────────────────────────────────────
//
// The reference configures idProvider.privateKey as a PEM string and signs
// in-process (src/services/token.service.ts:47). Under Lambda that means the
// private key of the deployment's identity provider is a value the function
// reads at cold start and holds in memory for the life of the execution
// environment: anyone who can make the function print, log or leak a string can
// take the key and mint tokens for any user, from anywhere, for as long as the
// key lives. A KMS key cannot be exported at all. The function holds kms:Sign
// on one key ARN, every signature is an API call CloudTrail records, and
// revoking the capability is an IAM edit rather than a key rotation.
//
// The PEM path stays supported — it is the reference's own configuration, and a
// development stack should not need a KMS key — and cmd/auth chooses between
// them; RS-4 refuses a deployment that configures both.
//
// ── what leaves the process ──────────────────────────────────────────────────
//
// Exactly 32 bytes per signature. RS256 is RSASSA-PKCS1-v1_5 over the SHA-256 of
// the signing input (RFC 7518 §3.3), and the core's BuildRS256JWT computes that
// digest itself before calling Sign (jwks.go). So this signer sends
// MessageType: DIGEST with the 32-byte digest as the message, and the token's
// header and claims — which carry the subject's id and email — never reach AWS
// at all. The alternative, MessageType: RAW, would put every token's payload in
// a KMS request and in whatever logs sit between here and the service.
//
// ── what a kid is ────────────────────────────────────────────────────────────
//
// The kid is derived from the key material: base64url(sha256(SPKI DER))[:16].
// Not the key id, not the ARN, and not the reference's fixed
// "provisioner-key-1": a kid derived from the public key is stable across
// re-deploys of the same key, different for a different key, and safe to publish
// (it is a hash of something already public). That is what makes a rotation
// additive — add the new key id, make it primary, keep the old one in
// kmsPreviousKeyIds until the last token it signed has expired, then drop it —
// with no window in which a token names a kid the JWKS document does not carry.
// It is registered as the product deviation idp-kid-derived-from-key-material.

// KMSAPI is the slice of the KMS client this signer uses. Two calls: one per
// signature, one per key at cold start. Declared here rather than imported so a
// test injects a fake, exactly as SESAPI, SNSAPI and SecretsManagerAPI are.
//
// Its methods speak the AWS SDK's types, which is why it is NOT the seam
// cmd/auth is built against: the product rule is that the SDK appears only in
// this package and in internal/store/dynamodb, and an interface with
// SDK-typed methods exports the dependency to everyone who implements it — a
// test double included. IDPKeySource below is the seam that crosses the
// boundary; this one stays inside it.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
}

// IDPKeySource is everything the composition root needs from the identity
// provider's signing key, in types no AWS package owns: a crypto.Signer for
// auth.IDPConfig.Signer, the kid the key material derives, and the JWKs the
// document publishes.
//
// This is the seam cmd/auth injects through, so that its tests are written
// against crypto.Signer and auth.JWK and never import the AWS SDK — the same
// posture as Options.Mail and Options.SMS, which are auth.MailerTransport and
// auth.SMSTransport rather than SESAPI and SNSAPI. KMSSigner is the production
// implementation and NewKMSKeySource is the factory that builds it.
type IDPKeySource interface {
	crypto.Signer

	// Resolve fetches the signing key's public half and returns its kid. Called
	// once, at cold start; its error must abort the init.
	Resolve(ctx context.Context) (string, error)

	// JWKS returns the published key set, the signing key first.
	JWKS(ctx context.Context) ([]auth.JWK, error)
}

var _ IDPKeySource = (*KMSSigner)(nil)

// NewKMSKeySource is the production IDPKeySource: an RS256 signer over a KMS
// asymmetric key, with the retired keys of a rotation published beside it.
//
// It exists so that the composition root names one function and passes three
// configured strings, rather than filling in a KMSSignerOptions whose Client
// field is an SDK-typed interface it must never mention.
func NewKMSKeySource(keyID string, previousKeyIDs []string, region string) (IDPKeySource, error) {
	return NewKMSSigner(KMSSignerOptions{
		KeyID:          keyID,
		PreviousKeyIDs: previousKeyIDs,
		Region:         region,
	})
}

// DefaultKMSSignTimeout bounds one kms:Sign call.
//
// Signing happens inside a request API Gateway abandons after 29 seconds, and
// the function's own timeout is shorter still, so an unbounded call to a
// throttled or unreachable KMS turns one slow signature into a function timeout
// with nothing in the log to say why. Two seconds is an order of magnitude above
// the p99 of an RSA-2048 sign and well inside any sane function timeout.
const DefaultKMSSignTimeout = 2 * time.Second

// DefaultKMSResolveTimeout bounds one kms:GetPublicKey call.
//
// Resolve and JWKS run inside the Lambda's init phase, whose whole budget is
// cmd/auth's start timeout — shared with secret resolution, the store build and
// the template seed. Without a bound of its own, a throttled or unreachable KMS
// consumes all of it and the operator is told the init deadline expired rather
// than which key could not be read. Three seconds is well above the p99 of a
// GetPublicKey and small enough to leave the rest of the cold start room to
// fail with its own message.
const DefaultKMSResolveTimeout = 3 * time.Second

// KMSSignerOptions configures NewKMSSigner.
type KMSSignerOptions struct {
	// KeyID is the key that signs: a key id, an alias (alias/awesome-auth-idp)
	// or an ARN. Required.
	KeyID string

	// PreviousKeyIDs are keys that sign nothing and are published in the JWKS
	// document after the primary, so that tokens minted before a rotation keep
	// verifying until they expire.
	PreviousKeyIDs []string

	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION. A key in another region is named by its ARN instead.
	Region string

	// SignTimeout bounds one Sign call. Zero means DefaultKMSSignTimeout.
	SignTimeout time.Duration

	// ResolveTimeout bounds one GetPublicKey call. Zero means
	// DefaultKMSResolveTimeout. It is derived from the caller's context, so a
	// shorter init deadline still wins.
	ResolveTimeout time.Duration

	// Client injects a KMSAPI. Non-nil skips the lazy build.
	Client KMSAPI
}

// KMSSigner implements crypto.Signer over a KMS asymmetric key, which is what
// the core's IDPConfig.Signer and BuildRS256JWT take.
type KMSSigner struct {
	keyID          string
	previous       []string
	signTimeout    time.Duration
	resolveTimeout time.Duration
	client         *lazyClient[KMSAPI]

	// mu guards the memoised key material. Public() is consulted per token by
	// BuildRS256JWT and Sign runs concurrently on every request, so the whole
	// critical section is deliberately one map or field read.
	mu   sync.Mutex
	keys map[string]kmsKey

	// primary is the resolved signing key, held outside the map so Public() —
	// which has neither an error return nor a context — is a field read.
	primary *kmsKey
}

// kmsKey is one resolved KMS public key: the parsed SPKI, the kid derived from
// it, and the JWK the JWKS document publishes.
type kmsKey struct {
	// arn is the key ARN GetPublicKey resolved, which is what Sign then names.
	// Pinning it matters for an alias: an alias re-pointed between cold start
	// and a signature would otherwise sign with a key whose public half this
	// process never published, and every token minted after the move would name
	// a kid no relying party can look up.
	arn string
	pub *rsa.PublicKey
	kid string
	jwk auth.JWK
}

var _ crypto.Signer = (*KMSSigner)(nil)

// NewKMSSigner builds the signer. It performs no I/O — the SDK client is built
// on first use (lazyClient) and the key material is fetched by Resolve — so a
// deployment pays for it only when identity-provider mode is actually on.
func NewKMSSigner(opts KMSSignerOptions) (*KMSSigner, error) {
	keyID := strings.TrimSpace(opts.KeyID)
	if keyID == "" {
		return nil, errors.New("kms: a signing key id is required")
	}
	s := &KMSSigner{
		keyID:          keyID,
		signTimeout:    opts.SignTimeout,
		resolveTimeout: opts.ResolveTimeout,
		keys:           make(map[string]kmsKey, 1+len(opts.PreviousKeyIDs)),
	}
	if s.signTimeout <= 0 {
		s.signTimeout = DefaultKMSSignTimeout
	}
	if s.resolveTimeout <= 0 {
		s.resolveTimeout = DefaultKMSResolveTimeout
	}
	for _, id := range opts.PreviousKeyIDs {
		if id = strings.TrimSpace(id); id != "" {
			s.previous = append(s.previous, id)
		}
	}
	if opts.Client != nil {
		s.client = &lazyClient[KMSAPI]{
			build: func(context.Context) (KMSAPI, error) { return opts.Client, nil },
		}
		return s, nil
	}
	shared := &lazyConfig{region: opts.Region}
	s.client = &lazyClient[KMSAPI]{
		build: func(ctx context.Context) (KMSAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return kms.NewFromConfig(cfg), nil
		},
	}
	return s, nil
}

// Resolve fetches and memoises the signing key's public half, and returns the
// kid derived from it.
//
// It is called once, at cold start, and its error must abort the init. That is
// the whole reason it exists as a separate method: crypto.Signer.Public has no
// error return, so a signer that discovered a missing key, a denied
// kms:GetPublicKey or a key of the wrong type on the first request would answer
// 500 to every token request for the life of the execution environment, with the
// cause visible only in whatever the caller happened to log. Resolving here
// turns all three into a failed deployment.
func (s *KMSSigner) Resolve(ctx context.Context) (string, error) {
	key, err := s.resolveKey(ctx, s.keyID)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.primary = &key
	s.mu.Unlock()
	return key.kid, nil
}

// Public implements crypto.Signer. It returns the memoised public key, or nil
// before Resolve has run — which the core refuses at construction ("signer
// public key is <nil>, want *rsa.PublicKey"), so an unresolved signer cannot
// reach a request.
func (s *KMSSigner) Public() crypto.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return nil
	}
	return s.primary.pub
}

// KeyID reports the kid of the signing key, empty before Resolve.
func (s *KMSSigner) KeyID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return ""
	}
	return s.primary.kid
}

// JWKS returns the keys the JWKS document publishes: the signing key first, then
// each of PreviousKeyIDs in the order configured.
//
// The core takes the first entry from the signer itself (IDP.JWKS puts Signer's
// key at the head) and the rest from IDPConfig.PublicKeys, so cmd/auth passes
// the tail of this slice. The head is returned too because a caller building a
// document by hand needs it, and because a test can then assert the whole
// published set from one call.
func (s *KMSSigner) JWKS(ctx context.Context) ([]auth.JWK, error) {
	primary, err := s.resolveKey(ctx, s.keyID)
	if err != nil {
		return nil, err
	}
	out := make([]auth.JWK, 0, 1+len(s.previous))
	out = append(out, primary.jwk)
	// Every kid published so far, not just the primary's. Two retired ids can
	// resolve to one key as easily as a retired id and the primary can — an id
	// and its alias, one ARN spelled two ways — and the config layer only
	// catches entries that are textually equal, so the set is the check that
	// sees the key material rather than the string.
	published := map[string]string{primary.kid: s.keyID}
	for _, id := range s.previous {
		key, err := s.resolveKey(ctx, id)
		if err != nil {
			return nil, err
		}
		if first, dup := published[key.kid]; dup {
			// Two key ids resolving to one public key. Publishing it twice would
			// be harmless to a verifier and a lie to a reader, and it means the
			// rotation was configured against a key that never changed.
			return nil, fmt.Errorf("kms: retired key %q has the same public key as %q, so the rotation would publish one key twice under kid %s", id, first, key.kid)
		}
		published[key.kid] = id
		out = append(out, key.jwk)
	}
	return out, nil
}

// Sign implements crypto.Signer for the one shape RS256 needs.
//
// rand is ignored: the randomness of a PKCS#1 v1.5 signature is not this side's
// to supply, and KMS takes none. opts must be crypto.SHA256 and digest must be
// its 32 bytes, because that is what the header carrying this signer's kid
// claims — a token that said RS256 over anything else would be a signature no
// verifier accepts, produced without an error anywhere.
func (s *KMSSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("kms: RS256 signs a SHA-256 digest; the caller asked for %v", hashName(opts))
	}
	if len(digest) != sha256.Size {
		// The length and nothing else: see kmsError for why no message this
		// package composes may carry the digest itself.
		return nil, fmt.Errorf("kms: RS256 signs a %d-byte SHA-256 digest, got %d bytes", sha256.Size, len(digest))
	}

	key, err := s.signingKey()
	if err != nil {
		return nil, err
	}

	// A fresh context, not the request's: Sign takes no context, which is
	// crypto.Signer's shape and not something this package can widen. The
	// timeout is what keeps a throttled KMS from consuming the whole function
	// deadline; the trade is that cancelling the HTTP request does not cancel
	// the signature, which costs one in-flight API call.
	ctx, cancel := context.WithTimeout(context.Background(), s.signTimeout)
	defer cancel()

	api, err := s.client.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("kms: cannot build a client: %w", err)
	}
	out, err := api.Sign(ctx, &kms.SignInput{
		KeyId:            awssdk.String(key),
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256,
	})
	if err != nil {
		return nil, &kmsError{op: "sign", keyID: key, cause: err}
	}
	if len(out.Signature) == 0 {
		return nil, &kmsError{op: "sign", keyID: key, cause: errors.New("empty signature")}
	}
	return out.Signature, nil
}

// signingKey is the ARN resolved at cold start. Signing by ARN rather than by
// the configured id is what pins an alias to the key whose public half this
// process published.
func (s *KMSSigner) signingKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return "", errors.New("kms: the signing key was never resolved; call Resolve at cold start so a missing key fails the deployment instead of every request")
	}
	return s.primary.arn, nil
}

// resolveKey fetches one key's public half and memoises it for the life of the
// process.
//
// Only successes are cached. A failure here aborts the cold start, so caching it
// would buy nothing; not caching it means a caller that retries — a test, a
// second JWKS build — gets a fresh answer rather than a stale verdict.
//
// The call is bounded by resolveTimeout, derived from the caller's context so
// that a shorter init deadline still wins. Unbounded, one unreachable key would
// spend the whole cold-start budget and the deployment's diagnostic would be
// "startup deadline exceeded" instead of the key that could not be read.
func (s *KMSSigner) resolveKey(ctx context.Context, id string) (kmsKey, error) {
	s.mu.Lock()
	key, cached := s.keys[id]
	s.mu.Unlock()
	if cached {
		return key, nil
	}

	ctx, cancel := context.WithTimeout(ctx, s.resolveTimeout)
	defer cancel()

	api, err := s.client.get(ctx)
	if err != nil {
		return kmsKey{}, fmt.Errorf("kms: cannot build a client: %w", err)
	}
	out, err := api.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: awssdk.String(id)})
	if err != nil {
		return kmsKey{}, &kmsError{op: "get public key", keyID: id, cause: err}
	}
	key, err = newKMSKey(id, out)
	if err != nil {
		return kmsKey{}, err
	}

	s.mu.Lock()
	s.keys[id] = key
	s.mu.Unlock()
	return key, nil
}

// newKMSKey turns a GetPublicKey answer into the key material the JWKS document
// and the signer need, refusing every key that cannot produce an RS256
// signature.
//
// The three checks are all cold-start checks for a mistake that is otherwise
// discovered on the wire: a symmetric key, a key whose usage is ENCRYPT_DECRYPT,
// and an RSA key whose signing algorithms do not include
// RSASSA_PKCS1_V1_5_SHA_256 each produce a deployment that comes up, publishes a
// JWKS document and then fails every token request.
func newKMSKey(id string, out *kms.GetPublicKeyOutput) (kmsKey, error) {
	if out == nil || len(out.PublicKey) == 0 {
		return kmsKey{}, fmt.Errorf("kms: key %q returned no public key", id)
	}
	if out.KeyUsage != "" && out.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
		return kmsKey{}, fmt.Errorf("kms: key %q has usage %s, want %s: it cannot sign", id, out.KeyUsage, kmstypes.KeyUsageTypeSignVerify)
	}
	if len(out.SigningAlgorithms) > 0 && !supportsRS256(out.SigningAlgorithms) {
		return kmsKey{}, fmt.Errorf("kms: key %q does not support %s, which is what RS256 is; its algorithms are %v",
			id, kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, out.SigningAlgorithms)
	}

	parsed, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return kmsKey{}, fmt.Errorf("kms: key %q: parse public key: %w", id, err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return kmsKey{}, fmt.Errorf("kms: key %q is %T, want *rsa.PublicKey (RS256 is RSA)", id, parsed)
	}

	kid := KeyFingerprint(out.PublicKey)
	jwk, err := auth.NewRSAJWK(pub, kid)
	if err != nil {
		return kmsKey{}, fmt.Errorf("kms: key %q: %w", id, err)
	}
	arn := id
	if out.KeyId != nil && *out.KeyId != "" {
		arn = *out.KeyId
	}
	return kmsKey{arn: arn, pub: pub, kid: kid, jwk: jwk}, nil
}

// KeyFingerprint derives a JWK kid from DER-encoded SubjectPublicKeyInfo:
// base64url(sha256(der)), truncated to 16 characters.
//
// Truncated because a kid is a label, not a commitment: it selects a key out of
// a published document, and the signature is what proves anything. Sixteen
// base64url characters are 96 bits, far beyond the collision risk of a set that
// holds two or three keys, and short enough to read in a token header. Exported
// so the PEM path in cmd/auth derives its kid the same way, and so a test can
// compute the expected value independently of this file.
func KeyFingerprint(spkiDER []byte) string {
	sum := sha256.Sum256(spkiDER)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}

func supportsRS256(algorithms []kmstypes.SigningAlgorithmSpec) bool {
	for _, a := range algorithms {
		if a == kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256 {
			return true
		}
	}
	return false
}

func hashName(opts crypto.SignerOpts) any {
	if opts == nil {
		return "no hash"
	}
	return opts.HashFunc()
}

// kmsError is what this package reports for a failed KMS call.
//
// It exists for one property: the rendered message is composed here and nowhere
// else. The two values that must never appear in a log line are the digest — the
// SHA-256 of a token's header and claims, which lets an offline attacker check
// candidate signatures without the token — and the signature itself, which IS
// the token's last segment: a log line carrying one is a credential in
// CloudWatch. The SDK's own message is therefore never printed. It stays
// reachable through errors.As, which is how a caller tells a throttle from a
// denial, and through Unwrap for anyone who deliberately asks for it.
//
// What is printed instead is the API error code (ThrottlingException,
// AccessDeniedException, NotFoundException, KMSInvalidStateException, …), which
// is the part an operator acts on.
type kmsError struct {
	op    string
	keyID string
	cause error
}

func (e *kmsError) Error() string {
	return fmt.Sprintf("kms: %s with key %s failed: %s", e.op, e.keyID, apiErrorCode(e.cause))
}

func (e *kmsError) Unwrap() error { return e.cause }

// apiErrorCode names the failure without quoting the SDK's message.
func apiErrorCode(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		return apiErr.ErrorCode()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "the request timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "the request was cancelled"
	}
	return "the request did not complete"
}
