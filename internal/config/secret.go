package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Secret is a reference to a secret-valued knob. It deliberately does not hold
// the secret: spec §1 requires that secrets never appear as plaintext in the
// configuration document, and a type that cannot carry the value is a stronger
// guarantee than a review comment saying not to.
//
// The document form is an object naming one or more stores; the resolution order
// of spec §1 decides which one wins, and a store that has no entry for the knob
// falls through to the next:
//
//	security:
//	  jwt:
//	    accessTokenSecret:
//	      secretsManager: awesome-auth/prod/jwt-access
//
//	    # or
//	      ssmParameter: /awesome-auth/prod/jwt-access
//
//	    # or, development only, the name of a variable to read
//	      envVar: MY_JWT_ACCESS_SECRET
//
// A bare string is accepted by the decoder and then rejected by validation with
// the knob's dotted path, which is a far more useful error than a decode failure
// that says only "cannot unmarshal string".
//
// The environment can name a store too, without a document: the knob's
// documented AWESOME_AUTH_* variable suffixed with SecretsManagerEnvSuffix or
// SSMParameterEnvSuffix carries a reference rather than a value. See
// applySecretRefEnv for why that suffix exists at all.
type Secret struct {
	// SecretsManager is a Secrets Manager secret id or ARN. Highest priority.
	SecretsManager string `json:"secretsManager,omitempty"`

	// SSMParameter is an SSM Parameter Store SecureString name. Second priority.
	SSMParameter string `json:"ssmParameter,omitempty"`

	// EnvVar overrides the documented AWESOME_AUTH_* variable name for this
	// knob. Lowest priority, and development-only: a secret in a Lambda
	// environment variable is visible to anyone with lambda:GetFunction.
	EnvVar string `json:"envVar,omitempty"`

	// literal holds a value written straight into the document. It exists only
	// so validation can say "you put a plaintext secret in the document, here is
	// the path", and is never resolved.
	literal string

	// err retains a decode problem for validation to report with the path.
	err error
}

// UnmarshalJSON accepts the reference object, or a bare string (retained for
// validation to reject), or null.
func (s *Secret) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "null" {
		return nil
	}
	if strings.HasPrefix(trimmed, `"`) {
		var lit string
		if err := json.Unmarshal(data, &lit); err != nil {
			return err
		}
		*s = Secret{literal: lit}
		return nil
	}

	// A named alias avoids recursing into this method, and DisallowUnknownFields
	// turns a typo such as "secretManager" into a reported problem instead of a
	// silently unset secret and a 500 on the first login.
	type alias struct {
		SecretsManager string `json:"secretsManager"`
		SSMParameter   string `json:"ssmParameter"`
		EnvVar         string `json:"envVar"`
	}
	dec := json.NewDecoder(strings.NewReader(trimmed))
	dec.DisallowUnknownFields()
	var a alias
	if err := dec.Decode(&a); err != nil {
		*s = Secret{err: fmt.Errorf("%w", err)}
		return nil
	}
	*s = Secret{SecretsManager: a.SecretsManager, SSMParameter: a.SSMParameter, EnvVar: a.EnvVar}
	return nil
}

// MarshalJSON emits the reference form only. A literal never survives
// validation, so it is not worth round-tripping.
func (s Secret) MarshalJSON() ([]byte, error) {
	type alias struct {
		SecretsManager string `json:"secretsManager,omitempty"`
		SSMParameter   string `json:"ssmParameter,omitempty"`
		EnvVar         string `json:"envVar,omitempty"`
	}
	return json.Marshal(alias{s.SecretsManager, s.SSMParameter, s.EnvVar})
}

// String redacts. Secret holds no plaintext, but a store reference in a log line
// is still a hint nobody needs.
func (s Secret) String() string { return "config.Secret{redacted}" }

// configured reports whether the document or an override pointed this knob at
// any store. It says nothing about whether the store has a value.
func (s Secret) configured() bool {
	return s.SecretsManager != "" || s.SSMParameter != "" || s.EnvVar != ""
}

func (s Secret) parseErr() error { return s.err }

// resolvedSecret is the outcome of resolving one Secret.
type resolvedSecret struct {
	value  string
	source string

	// failed records that the reference was resolvable in principle but the read
	// itself did not work — a denied permission, or a store this build cannot
	// reach. It suppresses the "secret is missing" rules, because reporting both
	// would bury the real cause under a symptom.
	failed bool
}

// Resolver names for diagnostics and for Config.SecretSource.
const (
	ResolverSecretsManager = "secretsmanager"
	ResolverSSM            = "ssm"
	ResolverEnv            = "env"
)

// ErrSecretNotFound means the reference was well formed but the store holds no
// such secret. Resolvers must return it (wrapped is fine) rather than an empty
// string, so that "typo in the ARN" and "the secret is empty" stay
// distinguishable.
var ErrSecretNotFound = errors.New("config: secret not found")

// ErrResolverUnavailable means a reference names a store this build cannot talk
// to. It is what the placeholder resolvers return when no AWS-backed resolver has
// been injected (cmd/auth injects both from internal/integration/aws).
var ErrResolverUnavailable = errors.New("config: secret store not available in this build")

// SecretResolver fetches a secret from one backing store.
//
// The interface exists so that the AWS-backed implementations can live under
// internal/integration/aws and be injected: this package must not import the AWS
// SDK, because the core stays cloud-agnostic and has to remain deployable
// somewhere without Secrets Manager.
type SecretResolver interface {
	// Name identifies the store for diagnostics: ResolverSecretsManager,
	// ResolverSSM or ResolverEnv.
	Name() string

	// Resolve returns the secret ref names. It returns ErrSecretNotFound when the
	// store has no such entry.
	Resolve(ctx context.Context, ref string) (string, error)
}

// Resolvers is the set of stores consulted for secret-valued knobs, in the
// documented order: Secrets Manager, then SSM SecureString, then a plain
// environment variable. A nil member means that store is not wired; a reference
// to it is then a refuse-to-start error naming the knob, never a silently empty
// secret.
type Resolvers struct {
	SecretsManager SecretResolver
	SSM            SecretResolver
	Env            SecretResolver
}

// EnvSecretResolver reads secrets from process environment variables. It is the
// resolver of last resort behind Secrets Manager and SSM (both wired from
// internal/integration/aws by cmd/auth); it is development-grade by definition,
// and Load emits a deploy-time warning when a production stack depends on it.
type EnvSecretResolver struct {
	// Lookup defaults to os.LookupEnv. Injected in tests, and by the deployment
	// tooling when it wants to resolve against a captured environment.
	Lookup func(string) (string, bool)
}

// Name implements SecretResolver.
func (r EnvSecretResolver) Name() string { return ResolverEnv }

// Resolve implements SecretResolver.
func (r EnvSecretResolver) Resolve(_ context.Context, ref string) (string, error) {
	lookup := r.Lookup
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(ref)
	if !ok || v == "" {
		return "", fmt.Errorf("%w: environment variable %s is unset or empty", ErrSecretNotFound, ref)
	}
	return v, nil
}

// UnavailableResolver stands in for a store this build cannot reach. Load uses
// it for Secrets Manager and SSM when nothing is injected, so a document
// referencing them fails
// with an actionable message naming the knob, instead of starting with an empty
// signing secret.
type UnavailableResolver struct {
	// StoreName is ResolverSecretsManager or ResolverSSM.
	StoreName string
	// Reason completes the sentence "... is not available in this build because
	// <reason>".
	Reason string
}

// Name implements SecretResolver.
func (r UnavailableResolver) Name() string { return r.StoreName }

// Resolve implements SecretResolver.
func (r UnavailableResolver) Resolve(_ context.Context, ref string) (string, error) {
	reason := r.Reason
	if reason == "" {
		reason = "no resolver was injected for it"
	}
	return "", fmt.Errorf("%w: %s reference %q cannot be resolved: %s", ErrResolverUnavailable, r.StoreName, ref, reason)
}

// secretSlot binds a Secret field to its dotted path and to the AWESOME_AUTH_*
// variable the spec documents for it. Keeping the binding in one table is what
// lets the resolver, the env layer and the diagnostics agree on names.
//
// get returns the Secret by value on purpose: oauth provider entries live in a
// map, so a pointer would point into a copy and a caller that assumed otherwise
// would write into nothing.
type secretSlot struct {
	path string
	env  string
	get  func(*Config) Secret
}

// secretSlots enumerates every secret-valued knob. The oauth entries are built
// per configured provider, since the provider set is open.
func secretSlots(c *Config) []secretSlot {
	slots := []secretSlot{
		{"security.jwt.accessTokenSecret", "AWESOME_AUTH_JWT_ACCESS_SECRET", func(c *Config) Secret { return c.Security.JWT.AccessTokenSecret }},
		{"security.jwt.refreshTokenSecret", "AWESOME_AUTH_JWT_REFRESH_SECRET", func(c *Config) Secret { return c.Security.JWT.RefreshTokenSecret }},
		{"email.mailer.apiKey", "AWESOME_AUTH_MAILER_API_KEY", func(c *Config) Secret { return c.Email.Mailer.APIKey }},
		{"email.deliveryWebhook.secret", "AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET", func(c *Config) Secret { return c.Email.DeliveryWebhook.Secret }},
		{"sms.apiKey", "AWESOME_AUTH_SMS_API_KEY", func(c *Config) Secret { return c.SMS.APIKey }},
		{"sms.username", "AWESOME_AUTH_SMS_USERNAME", func(c *Config) Secret { return c.SMS.Username }},
		{"sms.password", "AWESOME_AUTH_SMS_PASSWORD", func(c *Config) Secret { return c.SMS.Password }},
		{"idProvider.privateKey", "AWESOME_AUTH_IDP_PRIVATE_KEY", func(c *Config) Secret { return c.IDProvider.PrivateKey }},
		{"admin.bootstrapSecret", "AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET", func(c *Config) Secret { return c.Admin.BootstrapSecret }},
		{"admin.rootUser.passwordHash", "AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH", func(c *Config) Secret { return c.Admin.RootUser.PasswordHash }},
		{"stores.connection.password", "AWESOME_AUTH_STORES_CONNECTION_PASSWORD", func(c *Config) Secret { return c.Stores.Connection.Password }},
		{"tools.sse.distributor.password", "AWESOME_AUTH_TOOLS_SSE_DISTRIBUTOR_PASSWORD", func(c *Config) Secret { return c.Tools.SSE.Distributor.Password }},
	}
	for _, name := range sortedKeys(c.OAuth.Providers) {
		name := name
		slots = append(slots, secretSlot{
			path: "oauth.providers." + name + ".clientSecret",
			env:  "AWESOME_AUTH_OAUTH_" + upperSnake(name) + "_CLIENT_SECRET",
			get:  func(c *Config) Secret { return c.OAuth.Providers[name].ClientSecret },
		})
	}
	return slots
}

// Suffixes that turn a secret knob's documented AWESOME_AUTH_* variable into a
// store *reference* rather than a value.
//
//	AWESOME_AUTH_JWT_ACCESS_SECRET                 the value  (development only)
//	AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER  a Secrets Manager id or ARN
//	AWESOME_AUTH_JWT_ACCESS_SECRET_SSM_PARAMETER   an SSM SecureString name
//
// The suffixes mirror the document keys one-for-one, so there is nothing new to
// learn and nothing to parse — no URI scheme, no discriminator.
const (
	SecretsManagerEnvSuffix = "_SECRETSMANAGER"
	SSMParameterEnvSuffix   = "_SSM_PARAMETER"
)

// SecretRefEnvNames returns the AWESOME_AUTH_*_SECRETSMANAGER and
// AWESOME_AUTH_*_SSM_PARAMETER variables this build honours, paired with the
// dotted path each one points at a store for. Exported for the same reason as
// EnvBindings and SecretEnvNames: deployment tooling validating a stack template
// needs the whole surface, not two thirds of it.
func SecretRefEnvNames() []struct{ Env, Path string } {
	slots := secretSlots(Defaults())
	out := make([]struct{ Env, Path string }, 0, 2*len(slots))
	for _, slot := range slots {
		out = append(out,
			struct{ Env, Path string }{slot.env + SecretsManagerEnvSuffix, slot.path},
			struct{ Env, Path string }{slot.env + SSMParameterEnvSuffix, slot.path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	return out
}

// applySecretRefEnv layers a store reference from the environment over whatever
// the document said, which is the same precedence every other knob has.
//
// It exists because the deployment that most needs Secrets Manager is the one
// with no configuration document at all. A CloudFormation template can only
// reach a knob through the environment, and until now the only secret-shaped
// thing it could put there was the value — which is precisely the exposure this
// mechanism removes: an environment variable is readable by anyone holding
// lambda:GetFunction, an ARN is not worth reading.
//
// Setting both suffixes is allowed and means what the document form means: try
// Secrets Manager, fall through to SSM if it has no such secret.
func applySecretRefEnv(s Secret, slot secretSlot, getenv func(string) (string, bool)) Secret {
	if v, ok := getenv(slot.env + SecretsManagerEnvSuffix); ok && strings.TrimSpace(v) != "" {
		s.SecretsManager = strings.TrimSpace(v)
	}
	if v, ok := getenv(slot.env + SSMParameterEnvSuffix); ok && strings.TrimSpace(v) != "" {
		s.SSMParameter = strings.TrimSpace(v)
	}
	return s
}

// resolveSecrets walks every secret slot in the documented order and records the
// outcome on the Config. A reference that cannot be resolved is a diagnostic
// naming the knob; a knob that was never configured is simply absent, and the
// rules decide whether that is fatal.
func resolveSecrets(ctx context.Context, c *Config, r Resolvers, getenv func(string) (string, bool), d *diagnostics) {
	c.secrets = make(map[string]resolvedSecret)
	for _, slot := range secretSlots(c) {
		s := applySecretRefEnv(slot.get(c), slot, getenv)
		if s.literal != "" {
			// A literal is never resolved: reporting the path is the whole point.
			d.errf(RulePlaintextSecret, slot.path,
				"a secret is written as a literal value in the configuration document",
				"remove it and reference a store instead: {secretsManager: <id>} or {ssmParameter: <name>}, or in development set "+slot.env)
			continue
		}
		if err := s.parseErr(); err != nil {
			d.errf(RulePlaintextSecret, slot.path,
				"the secret reference is malformed: "+err.Error(),
				"use exactly one of secretsManager, ssmParameter or envVar")
			continue
		}

		value, source, err := resolveOne(ctx, s, slot, r)
		if err != nil {
			// Not finding a value is only a problem if some rule needs the knob,
			// and the rules report that with their own wording. A resolver that
			// is wired but broken, or a store this build cannot reach, is
			// reported here because nothing else will notice.
			if s.configured() && !errors.Is(err, ErrSecretNotFound) {
				d.errf(RulePlaintextSecret, slot.path,
					"the secret could not be resolved: "+err.Error(),
					"check the reference and the execution role's read permission on it")
				c.secrets[slot.path] = resolvedSecret{source: source, failed: true}
			}
			continue
		}
		c.secrets[slot.path] = resolvedSecret{value: value, source: source}

		// Record where the value came from as the knob's source, so a diagnostic
		// about a too-short secret can say which of the three places to go and
		// fix. Without this the most common RS-1 report names no origin at all.
		c.sources[slot.path] = describeSecretOrigin(s, slot, source)
	}
}

// describeSecretOrigin renders a secret's origin for a diagnostic. It names the
// reference, never the value.
func describeSecretOrigin(s Secret, slot secretSlot, source string) string {
	switch source {
	case ResolverSecretsManager:
		return "Secrets Manager reference " + s.SecretsManager
	case ResolverSSM:
		return "SSM parameter " + s.SSMParameter
	default:
		if s.EnvVar != "" {
			return s.EnvVar
		}
		return slot.env
	}
}

// resolveOne walks the documented resolution order for a single knob: Secrets
// Manager, then SSM SecureString, then the plain environment variable.
//
// A store that simply has no entry falls through to the next one, which is what
// makes the order an order. Any other failure — no resolver wired for a store the
// document references, a denied read — stops the walk and is reported: falling
// through would turn "the execution role cannot read this secret" into "the
// secret is empty", and the deployment would come up signing tokens with nothing.
func resolveOne(ctx context.Context, s Secret, slot secretSlot, r Resolvers) (string, string, error) {
	if ref := s.SecretsManager; ref != "" {
		if r.SecretsManager == nil {
			return "", ResolverSecretsManager, fmt.Errorf("%w: no Secrets Manager resolver is wired", ErrResolverUnavailable)
		}
		v, err := r.SecretsManager.Resolve(ctx, ref)
		if err == nil {
			return v, ResolverSecretsManager, nil
		}
		if !errors.Is(err, ErrSecretNotFound) {
			return "", ResolverSecretsManager, err
		}
	}
	if ref := s.SSMParameter; ref != "" {
		if r.SSM == nil {
			return "", ResolverSSM, fmt.Errorf("%w: no SSM resolver is wired", ErrResolverUnavailable)
		}
		v, err := r.SSM.Resolve(ctx, ref)
		if err == nil {
			return v, ResolverSSM, nil
		}
		if !errors.Is(err, ErrSecretNotFound) {
			return "", ResolverSSM, err
		}
	}

	// The documented AWESOME_AUTH_* name is the default; envVar renames it.
	name := slot.env
	if s.EnvVar != "" {
		name = s.EnvVar
	}
	if r.Env == nil {
		return "", ResolverEnv, fmt.Errorf("%w: no environment resolver is wired", ErrResolverUnavailable)
	}
	v, err := r.Env.Resolve(ctx, name)
	return v, ResolverEnv, err
}

func upperSnake(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z':
			b.WriteByte(ch - 32)
		case ch >= 'A' && ch <= 'Z':
			if i > 0 && s[i-1] >= 'a' && s[i-1] <= 'z' {
				b.WriteByte('_')
			}
			b.WriteByte(ch)
		case ch >= '0' && ch <= '9':
			b.WriteByte(ch)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
