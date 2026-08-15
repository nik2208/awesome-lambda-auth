package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambdacontext"
	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/nethttp"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	"github.com/nik2208/awesome-lambda-auth/internal/lambdahttp"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// Where the configuration document comes from.
//
// §4 of docs/spec/config-schema.md leaves the format decision open (YAML file
// vs SSM tree vs both), so this binary commits to the smallest thing that keeps
// every option available: it reads a JSON document, from a file or from the
// environment, and does not care who produced it. A YAML front end or an SSM
// compiler plugs in later by writing that JSON, and neither the loader nor this
// entrypoint changes.
const (
	// ConfigFileEnv names a path to a JSON configuration document. In a Lambda
	// that is a file baked into the deployment package or mounted from EFS.
	ConfigFileEnv = "AWESOME_AUTH_CONFIG_FILE"

	// ConfigJSONEnv carries a JSON configuration document inline. Convenient for
	// a small stack and for tests; secrets never appear in it, because
	// secret-valued knobs hold a store reference and not a value.
	ConfigJSONEnv = "AWESOME_AUTH_CONFIG_JSON"
)

// StoreFactory builds the persistence layer for a validated configuration.
// Injected so that the composition can be tested without an AWS account: the
// production factory is defaultStoreFactory.
type StoreFactory func(ctx context.Context, cfg *config.Config, log *slog.Logger) (auth.UserStore, auth.SessionStore, error)

// Options configures New. The zero value is what main uses: the real
// environment, the real filesystem, a JSON logger on stdout and the real
// stores.
type Options struct {
	Getenv   func(string) (string, bool)
	ReadFile func(string) ([]byte, error)
	Logger   *slog.Logger
	Stores   StoreFactory

	// Secrets are the stores consulted for secret-valued knobs. The zero value
	// wires the real AWS-backed resolvers; a test injects fakes.
	Secrets config.Resolvers

	// Mail and SMS inject the credential-delivery transports, for the same
	// reason Stores is injectable: the composition has to be provable without an
	// AWS account. Nil — the zero value — builds the real SES and SNS transports.
	//
	// Injecting one does NOT switch delivery on. Whether a sender is wired at
	// all stays a question about the configuration (see mailConfigured and
	// smsConfigured in delivery.go), so a test cannot accidentally exercise a
	// composition the binary would never build.
	Mail auth.MailerTransport
	SMS  auth.SMSTransport
}

// App is one cold start's worth of state.
//
// Everything expensive is built here, once, and read-only afterwards: the
// configuration document, the resolved secrets, the AWS client and its
// connection pool, the store, the auth core and the routing table. Handle then
// does nothing but adapt an event and dispatch it. Getting that split wrong is
// the classic serverless performance bug — a store constructed per invocation
// pays a fresh credential chain and TLS handshake on every login — and it is
// also a correctness bug here, because a refuse-to-start rule would surface as
// a 500 per request instead of a failed deployment.
type App struct {
	// Config is the validated configuration this instance came up with.
	Config *config.Config

	// Logger is the process logger. Per-request loggers derive from it.
	Logger *slog.Logger

	// Handler is the fully wrapped HTTP surface, exposed so a test can drive it
	// directly as well as through a synthetic Lambda event.
	Handler http.Handler

	adapter *lambdahttp.Adapter
}

// New performs the whole cold start and returns an App ready to serve, or an
// error that must abort the init.
//
// It never returns a partially usable App: a configuration problem, an
// unsupported store or an unbuildable auth core all fail here, where the
// Lambda service reports an init failure the deployment can see, rather than
// per request where it looks like an outage.
func New(ctx context.Context, opts Options) (*App, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.LookupEnv
	}
	readFile := opts.ReadFile
	if readFile == nil {
		readFile = os.ReadFile
	}
	log := opts.Logger
	if log == nil {
		log = newLogger(os.Stdout, logLevel(getenv))
	}
	newStores := opts.Stores
	if newStores == nil {
		newStores = defaultStoreFactory
	}

	doc, err := loadDocument(getenv, readFile)
	if err != nil {
		return nil, err
	}

	// The AWS-backed secret resolvers are constructed here and injected, because
	// internal/config must not import the AWS SDK: the loader defines the
	// SecretResolver interface and this entrypoint is the one place allowed to
	// know which cloud the deployment runs in. Building them costs nothing —
	// the SDK client is created on the first reference that actually needs one,
	// so a stack whose secrets all come from the environment pays no cold-start
	// penalty for the capability.
	secrets := opts.Secrets
	if secrets.SecretsManager == nil && secrets.SSM == nil {
		secrets = awsintegration.NewSecretResolvers(awsintegration.SecretResolverOptions{})
	}

	cfg, err := config.Load(ctx, config.Options{Document: doc, Getenv: getenv, Secrets: secrets})
	if err != nil {
		return nil, err
	}

	// Warnings are not failures, but they are the only notice an operator gets
	// that a production secret is sitting in a plain environment variable, so
	// they are logged before anything else can bury them.
	for _, w := range cfg.Warnings() {
		log.Warn("configuration warning",
			slog.String("path", w.Path),
			slog.String("source", w.Source),
			slog.String("problem", w.Problem),
			slog.String("remedy", w.Remedy))
	}
	for _, gap := range unwiredKnobs(cfg) {
		log.Warn("configured knob is not wired to the auth core",
			slog.String("path", gap.Path),
			slog.String("problem", gap.Problem),
			slog.String("remedy", gap.Remedy))
	}

	if err := checkStoreSupport(cfg); err != nil {
		return nil, err
	}

	users, sessions, err := newStores(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	// Credential delivery. Built before the core because every sender option is
	// derived from it, and it performs no I/O: both AWS clients are deferred to
	// the first message actually sent (delivery.go).
	deliver, err := newDelivery(cfg, opts.Mail, opts.SMS, log)
	if err != nil {
		return nil, err
	}

	coreOpts := coreOptions(cfg, users, sessions, log)
	coreOpts = append(coreOpts, deliveryOptions(deliver, log)...)
	coreOpts = append(coreOpts, oauthOptions(cfg, users, deliver, log)...)

	core, err := auth.New(coreOpts...)
	if err != nil {
		return nil, fmt.Errorf("auth core: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	// The auth surface comes entirely from the imported adapter. Nothing in this
	// binary may add a route under the api prefix: a route that exists here and
	// not in the other family ports is a wire divergence by construction.
	nethttp.MountWithConfig(mux, core, httpConfig(cfg))

	var handler http.Handler = mux
	// Refresh-token rotation replay detection needs a per-request precondition
	// carrier installed on the request context: the DynamoDB store fills it in
	// GetSessionByRefreshTokenHash and consumes it in UpdateSession so that two
	// concurrent refreshes of one token resolve to a single winner and a replay is
	// revoked immediately instead of one request later. rotation.go documents this
	// as "the HTTP layer must call it once per request"; without it the store logs
	// warnDegradedRotation and falls back to attribute_not_exists(revokedAt). Only
	// the DynamoDB store consumes the scope — the memory store ignores it — so the
	// wrap is gated on the driver to avoid a pointless allocation per request.
	if cfg.Stores.Driver == config.StoreDriverDynamoDB {
		handler = rotationScopeMiddleware(handler)
	}
	handler = corsMiddleware(cfg.HTTP.CORS.Origins)(handler)
	handler = accessLog(log, handler)

	app := &App{Config: cfg, Logger: log, Handler: handler}
	app.adapter = lambdahttp.New(handler, lambdahttp.Options{
		// deployment.stage exists precisely so the event layer can strip the
		// stage segment an execute-api URL puts in front of every path
		// (see config.Deployment.Stage). Empty means strip nothing.
		StagePrefix: cfg.Deployment.Stage,
		OnError: func(ctx context.Context, err error) {
			loggerFrom(ctx, log).Error("event adapter", slog.String("error", err.Error()))
		},
	})

	log.Info("cold start complete",
		slog.String("environment", cfg.Deployment.Environment),
		slog.String("storeDriver", cfg.Stores.Driver),
		slog.String("apiPrefix", cfg.HTTP.APIPrefix),
		slog.Bool("csrfEnabled", cfg.Security.CSRF.Enabled),
		slog.Bool("cookiesSecure", cfg.Cookies.Secure),
		slog.String("sessionCheckOn", cfg.Sessions.CheckOn))

	return app, nil
}

// Handle is the lambda.Start entrypoint.
//
// Its only per-request work is attaching the request id, so a log line can be
// traced back to an invocation, and handing the payload to the adapter.
func (a *App) Handle(ctx context.Context, payload json.RawMessage) (json.RawMessage, error) {
	log := a.Logger
	if lc, ok := lambdacontext.FromContext(ctx); ok && lc.AwsRequestID != "" {
		log = log.With(slog.String("requestId", lc.AwsRequestID))
	}
	return a.adapter.Handle(withLogger(ctx, log), payload)
}

// rotationScopeMiddleware installs the DynamoDB refresh-rotation precondition
// carrier on every request context. See internal/store/dynamodb/rotation.go:
// the store reads the scope out of the request context, so it must be installed
// on the *request's* context (r.Context()) rather than the cold-start context.
func rotationScopeMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(ddbstore.WithRotationScope(r.Context())))
	})
}

// healthz is a readiness probe that costs nothing: it answers from memory and
// never touches a store, so a health check cannot itself consume DynamoDB
// capacity or wake a throttled table. Reaching it at all already proves the
// cold start succeeded, since a failed init never gets to serve.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// loadDocument reads the configuration document, if there is one. Returning a
// nil Document is legitimate and means "defaults plus AWESOME_AUTH_* overrides",
// which is how a minimal development stack runs.
func loadDocument(getenv func(string) (string, bool), readFile func(string) ([]byte, error)) (config.Document, error) {
	path, hasPath := getenv(ConfigFileEnv)
	inline, hasInline := getenv(ConfigJSONEnv)
	path, inline = strings.TrimSpace(path), strings.TrimSpace(inline)
	hasPath, hasInline = hasPath && path != "", hasInline && inline != ""

	switch {
	case hasPath && hasInline:
		// Picking one silently would make the deployment depend on which
		// variable a template happened to set last.
		return nil, fmt.Errorf("config: %s and %s are both set; supply the configuration document exactly once", ConfigFileEnv, ConfigJSONEnv)
	case hasPath:
		data, err := readFile(path)
		if err != nil {
			return nil, fmt.Errorf("config: read %s=%s: %w", ConfigFileEnv, path, err)
		}
		return config.ParseJSON(data)
	case hasInline:
		return config.ParseJSON([]byte(inline))
	default:
		return nil, nil
	}
}

// coreOptions maps the validated configuration onto the auth core's option set.
//
// Only knobs the core actually accepts appear here. The ones it does not are
// reported by unwiredKnobs rather than quietly dropped.
func coreOptions(cfg *config.Config, users auth.UserStore, sessions auth.SessionStore, log *slog.Logger) []auth.Option {
	return []auth.Option{
		auth.WithSecret(cfg.AccessTokenSecret()),
		auth.WithTokenTTLs(cfg.Security.JWT.AccessTokenTTL.Duration(), cfg.Security.JWT.RefreshTokenTTL.Duration()),
		auth.WithSessionCheckOn(cfg.Sessions.CheckOn),
		auth.WithUserStore(users),
		auth.WithSessionStore(sessions),
		// The core logs through a printf callback; funnelling it into slog keeps
		// every line in the deployment one JSON format.
		auth.WithLogger(func(format string, args ...any) {
			log.Warn("auth core", slog.String("message", fmt.Sprintf(format, args...)))
		}),
	}
}

// oauthStoreProvider is what this binary needs from a store to back the
// account-linking routes.
//
// It is a structural assertion on the user store rather than a wider
// StoreFactory signature, because these two are the only optional stores the auth
// core does *not* discover by type assertion: LinkedAccountStore and
// PendingLinkStore both declare Save and Delete, so no single type can implement
// both, and the core takes them as explicit members of auth.OAuthWiring
// (awesome-go-auth oauth_wire.go:170-179). Something has to hand them over, and
// the composition root is the only place that knows which driver is in play.
type oauthStoreProvider interface {
	LinkedAccounts() auth.LinkedAccountStore
	PendingLinks() auth.PendingLinkStore
}

// oauthOptions wires the two OAuth stores when the driver has them and the
// operator asked for them.
//
// Each is gated on its own stores.enable key, which is the mechanism the schema
// already defines for exactly this: "a disabled store makes its feature routes and
// admin tabs absent, exactly as an absent injected store does in the reference"
// (config.StoreEnable). With a key off, its routes answer NOT_IMPLEMENTED, which
// is the truth rather than a silent 500.
//
// OAuthWiring.Service stays nil on purpose. The provider registry comes from the
// oauth.* configuration block, which internal/config/phases.go still refuses as a
// P4 domain, so GET /oauth/{provider} keeps answering the reference's
// "<Provider> OAuth not configured" stub — a configuration gap, not a store one.
// The four account-linking routes need no provider registry and work as soon as
// the stores are here.
func oauthOptions(cfg *config.Config, users auth.UserStore, deliver *delivery, log *slog.Logger) []auth.Option {
	provider, ok := users.(oauthStoreProvider)
	if !ok {
		return nil
	}
	wiring := auth.OAuthWiring{
		// The redirect allowlist and the fallback origin the emailed link points
		// at. Both come from blocks P1 already wires, so neither drags the oauth
		// domain in.
		AllowedOrigins: cfg.HTTP.CORS.Origins,
		SiteURL:        cfg.Deployment.PublicURL,
	}
	if cfg.Stores.Enable.LinkedAccounts {
		wiring.LinkedAccounts = provider.LinkedAccounts()
	}
	if cfg.Stores.Enable.PendingLinks {
		wiring.PendingLinks = provider.PendingLinks()
	}
	if wiring.LinkedAccounts == nil && wiring.PendingLinks == nil {
		return nil
	}
	// DeliverLinkToken used to be unconditionally absent, and the log line here
	// said so. It is wired now whenever a mail transport exists, so POST
	// /link-request sends the verification mail instead of storing a token
	// nobody receives. With no mailer it is still nil, and the route still
	// answers success without sending anything — which is what the reference
	// does with no transport configured, so the fallback is not a degradation
	// but the unconfigured behaviour.
	delivery := "none — POST /link-request stores the token and answers success without sending mail"
	if deliver != nil && deliver.mail != nil {
		wiring.DeliverLinkToken = deliver.deliverLinkToken
		delivery = "ses"
	}
	log.Info("oauth account-linking stores wired",
		slog.Bool("linkedAccounts", wiring.LinkedAccounts != nil),
		slog.Bool("pendingLinks", wiring.PendingLinks != nil),
		slog.String("linkTokenDelivery", delivery))
	return []auth.Option{auth.WithOAuth(wiring)}
}

// httpConfig maps the cookie, CSRF and prefix knobs onto the shared wire layer.
//
// Cookie Max-Age is deliberately left at zero: HTTPConfig.resolve derives it
// from the token TTLs, which is what keeps a cookie from outliving the token it
// carries when an operator changes security.jwt.accessTokenTtl. The cookie
// *name* prefix is likewise derived by the core (CookieOptions.CookieName) and
// is not a knob in either layer.
func httpConfig(cfg *config.Config) auth.HTTPConfig {
	return auth.HTTPConfig{
		APIPrefix: cfg.HTTP.APIPrefix,
		Cookies: auth.CookieOptions{
			Secure:           cfg.Cookies.Secure,
			SameSite:         sameSite(cfg.Cookies.SameSite),
			Path:             cfg.Cookies.Path,
			Domain:           cfg.Cookies.Domain,
			RefreshTokenPath: cfg.Cookies.RefreshTokenPath,
		},
		CSRF: auth.CSRFConfig{Enabled: cfg.Security.CSRF.Enabled},
	}
}

func sameSite(v string) http.SameSite {
	switch v {
	case config.SameSiteStrict:
		return http.SameSiteStrictMode
	case config.SameSiteNone:
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
}

// defaultStoreFactory builds the real persistence layer.
func defaultStoreFactory(ctx context.Context, cfg *config.Config, log *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
	switch cfg.Stores.Driver {
	case config.StoreDriverDynamoDB:
		client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{
			Region:   cfg.Stores.Connection.Region,
			Endpoint: cfg.Stores.Connection.Endpoint,
		})
		if err != nil {
			return nil, nil, err
		}
		store, err := ddbstore.New(client, ddbstore.Options{
			TableName: cfg.Stores.Connection.TableName,
			Logger:    log,
		})
		if err != nil {
			return nil, nil, err
		}
		// The deviations are logged once, at cold start, so they show up in the
		// deployment log rather than being discovered from a client's bug report.
		for _, note := range store.CompatibilityNotes() {
			log.Info("store compatibility note", slog.String("note", note))
		}
		return store, store, nil

	case config.StoreDriverMemory:
		// RS-12 already refuses this driver in production, so reaching it means
		// a development stack. Each cold start gets its own empty store, and
		// concurrent execution environments do not share one.
		log.Warn("using the in-memory store: state is per execution environment and is lost on every cold start",
			slog.String("path", "stores.driver"))
		return memoryStoreBundle{
			MemoryUserStore: auth.NewMemoryUserStore(),
			links:           auth.NewMemoryLinkedAccounts(),
			pending:         auth.NewMemoryPendingLinks(),
		}, auth.NewMemorySessionStore(), nil

	default:
		return nil, nil, fmt.Errorf("stores.driver: %q is not implemented in this build; use %q or %q",
			cfg.Stores.Driver, config.StoreDriverDynamoDB, config.StoreDriverMemory)
	}
}

// memoryStoreBundle is the in-memory user store plus the two OAuth stores the
// core cannot find by type assertion, so that the development driver reaches the
// account-linking routes the same way the DynamoDB one does.
//
// The embedded pointer is what keeps the rest working: every optional interface
// the core *does* discover on the user store — MagicLinkStore, SMSStore,
// TOTPStore and the rest — is satisfied by method promotion, so wrapping it
// cannot quietly narrow the feature set.
type memoryStoreBundle struct {
	*auth.MemoryUserStore
	links   auth.LinkedAccountStore
	pending auth.PendingLinkStore
}

func (m memoryStoreBundle) LinkedAccounts() auth.LinkedAccountStore { return m.links }
func (m memoryStoreBundle) PendingLinks() auth.PendingLinkStore     { return m.pending }

// driverStores lists the stores.enable.<store> keys each driver can actually
// back. A key that is enabled and absent from its driver's set is a knob that
// validates and then does nothing, which spec §1.17 treats as a
// misconfiguration rather than a no-op.
func driverStores(driver string) (map[string]bool, bool) {
	switch driver {
	case config.StoreDriverDynamoDB:
		// internal/store/dynamodb implements UserStore, UserAccountStore,
		// UserPasswordStore, SessionStore, SessionLookupStore, SessionAdminStore,
		// the four single-use token stores, TOTPStore, LinkedAccountStore and
		// PendingLinkStore. Everything else is deliberately absent — see that
		// package's interfaces.go.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true,
		}, true
	case config.StoreDriverMemory:
		// awesome-go-auth ships MemoryLinkedAccounts and MemoryPendingLinks, so the
		// development driver backs the same two keys.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true,
		}, true
	default:
		return nil, false
	}
}

// checkStoreSupport refuses a stores.enable set the selected driver cannot
// honour, and refuses the two stores nothing works without.
func checkStoreSupport(cfg *config.Config) error {
	supported, known := driverStores(cfg.Stores.Driver)
	if !known {
		return fmt.Errorf("stores.driver: %q is not implemented in this build; use %q or %q",
			cfg.Stores.Driver, config.StoreDriverDynamoDB, config.StoreDriverMemory)
	}

	var problems []string
	enabled := enabledStores(cfg.Stores.Enable)
	for _, name := range enabled {
		if !supported[name] {
			problems = append(problems, fmt.Sprintf(
				"stores.enable.%s is on but the %s driver does not implement that store, so the feature would return NOT_IMPLEMENTED on the wire -- turn it off until the driver grows it",
				name, cfg.Stores.Driver))
		}
	}

	on := make(map[string]bool, len(enabled))
	for _, name := range enabled {
		on[name] = true
	}
	for _, required := range []string{"users", "sessions"} {
		if !on[required] {
			problems = append(problems, fmt.Sprintf(
				"stores.enable.%s is off, but the auth core requires it and would fall back to an in-process store that loses every write on the next cold start -- turn it on",
				required))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("config: refusing to start: %d problem(s) in stores.enable\n%s",
		len(problems), strings.Join(problems, "\n"))
}

// enabledStores returns the names of the stores.enable.<store> keys that are
// true, read reflectively from the struct's json tags rather than from a copy
// of the field list. A store added to config.StoreEnable is then covered here
// without anyone remembering to update this file — which is the same reason the
// config package generates its own env bindings from one table.
func enabledStores(e config.StoreEnable) []string {
	rv := reflect.ValueOf(e)
	rt := rv.Type()
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		if rv.Field(i).Kind() == reflect.Bool && rv.Field(i).Bool() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// knobGap is one configured knob this build validates but cannot act on,
// because the imported auth core exposes no way to set it.
//
// These are not phase gaps — internal/config/phases.go already refuses a whole
// domain that is not wired yet, and every knob below sits inside a domain that
// phases.go declares wired in P1. They are upstream gaps: the core's exported
// option set (awesome-go-auth auth.go) is narrower than its own Config struct,
// and *Auth cannot be built from a *Service, so there is no way to reach the
// remaining fields without forking the core, which this port does not do.
//
// They are warnings rather than refusals because refusing would make the
// product's own defaults unstartable — the shipped bcryptSaltRounds is 12 and
// the core is fixed at 10 — but every one of them is logged loudly at cold
// start, with the path, so nobody has to discover it from behaviour.
type knobGap struct {
	Path    string
	Problem string
	Remedy  string
}

// coreBcryptCost is bcrypt.DefaultCost, which awesome-go-auth hardcodes in
// hashPassword (security.go). Duplicated as a literal rather than imported so
// that this file does not pull in golang.org/x/crypto for one constant; the
// test that reads it against the core's behaviour is the guard.
const coreBcryptCost = 10

// unwiredKnobs reports every knob the operator set that the core cannot honour.
func unwiredKnobs(cfg *config.Config) []knobGap {
	defaults := config.Defaults()
	var gaps []knobGap

	if cfg.RefreshTokenSecret() != "" {
		gaps = append(gaps, knobGap{
			Path: "security.jwt.refreshTokenSecret",
			Problem: "the auth core signs access and refresh tokens with one HS256 secret and tells them apart by the typ claim, " +
				"so security.jwt.accessTokenSecret is the only secret in use and this one signs nothing",
			Remedy: "keep it set — RS-1 requires it and it becomes live as soon as the core takes a second secret — but do not " +
				"rely on rotating it to invalidate refresh tokens today",
		})
	}

	if cfg.Security.Password.BcryptSaltRounds != coreBcryptCost {
		gaps = append(gaps, knobGap{
			Path: "security.password.bcryptSaltRounds",
			Problem: fmt.Sprintf("the auth core hashes passwords at the fixed bcrypt cost %d and exposes no option for it, so the configured %d has no effect",
				coreBcryptCost, cfg.Security.Password.BcryptSaltRounds),
			Remedy: fmt.Sprintf("set it to %d to match what is actually applied, or leave it and accept that the deployed cost is %d",
				coreBcryptCost, coreBcryptCost),
		})
	}

	if cfg.Email.Verification.Mode != defaults.Email.Verification.Mode {
		gaps = append(gaps, knobGap{
			Path: "email.verification.mode",
			Problem: fmt.Sprintf("the auth core accepts this in its Config but exposes no functional option for it, so the deployed mode stays %q",
				defaults.Email.Verification.Mode),
			Remedy: "remove the override until the core exports an option for it",
		})
	}

	// The tokens.* lifetimes have core counterparts (ResetTokenTTL,
	// MagicLinkTTL, EmailVerificationTTL, EmailChangeTTL) whose defaults happen
	// to equal the product defaults, so only a deviation is a gap.
	for _, row := range []struct {
		path       string
		configured int
		coreValue  int
	}{
		{"tokens.passwordResetTtlMinutes", cfg.Tokens.PasswordResetTTLMinutes, defaults.Tokens.PasswordResetTTLMinutes},
		{"tokens.emailVerificationTtlMinutes", cfg.Tokens.EmailVerificationTTLMinutes, defaults.Tokens.EmailVerificationTTLMinutes},
		{"tokens.emailChangeTtlMinutes", cfg.Tokens.EmailChangeTTLMinutes, defaults.Tokens.EmailChangeTTLMinutes},
		{"tokens.magicLinkTtlMinutes", cfg.Tokens.MagicLinkTTLMinutes, defaults.Tokens.MagicLinkTTLMinutes},
	} {
		if row.configured == row.coreValue {
			continue
		}
		gaps = append(gaps, knobGap{
			Path: row.path,
			Problem: fmt.Sprintf("the auth core exposes no functional option for this lifetime, so the deployed value stays %d minutes and not the configured %d",
				row.coreValue, row.configured),
			Remedy: "remove the override until the core exports an option for it",
		})
	}

	gaps = append(gaps, deliveryKnobGaps(cfg)...)

	sort.Slice(gaps, func(i, j int) bool { return gaps[i].Path < gaps[j].Path })
	return gaps
}

// deliveryKnobGaps reports the knobs of email.mailer and sms that this build's
// transports cannot honour.
//
// Both blocks describe the reference's transports, which are HTTP gateways: a
// mailer is an endpoint you POST to with an X-API-Key, and an SMS gateway is a
// URL you GET with the credentials in the query string. This port sends through
// SES and SNS instead, which are reached by AWS API and authorised by the
// execution role, so those knobs address nothing and authenticate nothing.
//
// They are reported rather than refused, and rather than ignored. Refusing
// would make a document that is valid for every other port in the family
// unstartable here, for knobs that are required by the schema. Ignoring them is
// the failure mode this whole mechanism exists to prevent — an operator who
// rotates an SMS gateway password and sees nothing change has no way to learn
// from the outside that the password was never used. So each one is named, with
// its path, in the cold-start log.
//
// Note in particular what happens to sms.username and sms.password. The schema
// models them as secrets and its own comment says the transport "must move them
// off the URL" because the reference appends them as query parameters on a GET,
// writing credentials into every access log between here and the gateway. An
// SNS sender does not move them off the URL — it has no URL. The credentials-in-
// URL hazard is gone, and so is any use for the credentials.
//
// The gaps are reported whether or not the block they belong to is switched on,
// and the second case is the one that needs saying out loud. A credential is the
// part of these blocks that lives in Secrets Manager, so it is the part an
// operator sets first and the part a stack template carries; the switch — a from
// address for mail, an endpoint for SMS — is the part that is easy to forget.
// Set the credential alone and internal/config sees nothing to validate (a
// Secret resolved from its plain environment variable leaves no reference in the
// tree for validateSMS's `configured` to find), mailConfigured and smsConfigured
// are both false, and delivery is off. Before this port wired the two blocks
// that combination was refused outright by the phase gap, whose secretPrefix
// covered exactly these paths. Removing the domains removed that cover too, so
// the report has to replace it, or an SMS gateway password in the environment
// buys total silence: no mail, no text, no warning, and a 500 on the first
// /sms/send that nothing in the log accounts for.
func deliveryKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap

	// The credentials, reported wherever they appear. Each one names the switch
	// its block is missing when the block is off, because "this key is unused"
	// and "no mail is sent at all" are different things for an operator to read.
	mailOn, smsOn := mailConfigured(cfg), smsConfigured(cfg)
	const (
		portable = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it. "
		// The hazard config-schema.md §1.6 records against the SMS gateway
		// credentials: the reference appends them as query parameters on a GET,
		// writing them into every access log on the way. An SNS publish has no URL
		// to move them off, so the hazard retires with the credential.
		smsHazard = " — which also retires the credentials-in-URL hazard the schema records for it, since there is no URL"
	)
	smsOff := "sms.endpoint is unset, so no SMS transport is wired at all and POST /sms/send answers 500 SMS_NOT_CONFIGURED: set it to turn SMS delivery on, or delete the credential"
	for _, row := range []struct{ path, service, action, hazard, on, off string }{
		{
			path: "email.mailer.apiKey", service: "SES", action: "ses:SendEmail",
			on:  "Deleting the secret it points at costs nothing here, and removes one credential from the blast radius",
			off: "email.mailer.from is unset, so no mail transport is wired at all and no mail is sent: set it to turn mail delivery on, or delete the key",
		},
		{
			path: "sms.apiKey", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
		{
			path: "sms.username", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
		{
			path: "sms.password", service: "SNS", action: "sns:Publish", hazard: smsHazard,
			on:  "Retiring the gateway credential removes it from the blast radius entirely",
			off: smsOff,
		},
	} {
		if cfg.SecretValue(row.path) == "" {
			continue
		}
		blockOn := smsOn
		if strings.HasPrefix(row.path, "email.") {
			blockOn = mailOn
		}
		problem := fmt.Sprintf(
			"%s authorises the call with the Lambda execution role's %s permission, so this credential is never presented to anything",
			row.service, row.action) + row.hazard
		remedy := portable + row.on
		if !blockOn {
			problem += ", and this deployment sends nothing through that half at all"
			remedy = row.off
		}
		gaps = append(gaps, knobGap{Path: row.path, Problem: problem, Remedy: remedy})
	}

	if mailOn {
		const sesRemedy = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it"

		// Always present when the mailer is on: validate.go requires an endpoint
		// for any configured mailer block, and SES never has one.
		gaps = append(gaps, knobGap{
			Path:    "email.mailer.endpoint",
			Problem: "this build delivers mail through Amazon SES, which is called through the AWS API and not by posting to a URL, so no request is ever made to this endpoint",
			Remedy:  sesRemedy + ". The schema requires it, which is why configuring a mailer at all means configuring one",
		})
		// provider is free-form in the schema and the reference passes it to its
		// gateway to select a backend. Naming ses is honoured — it is what this
		// build does — so only a different value is a gap.
		if p := strings.TrimSpace(cfg.Email.Mailer.Provider); p != "" && !strings.EqualFold(p, "ses") {
			gaps = append(gaps, knobGap{
				Path:    "email.mailer.provider",
				Problem: fmt.Sprintf("mail is delivered through Amazon SES and there is no second transport to select, so the configured provider %q selects nothing", p),
				Remedy:  `set it to "ses" to describe what is actually deployed, or remove it`,
			})
		}
	}

	if smsOn {
		const snsRemedy = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it"

		gaps = append(gaps, knobGap{
			Path:    "sms.endpoint",
			Problem: "this build sends text messages with an SNS Publish to the recipient's number, so no request is ever made to this gateway; the knob's only remaining job is to say that SMS delivery should be wired at all",
			Remedy:  snsRemedy + ", and keep it set: an empty sms block leaves POST /sms/send answering 500 SMS_NOT_CONFIGURED",
		})
	}

	return gaps
}

// fatal reports a cold-start failure as structured JSON and aborts the init.
//
// A *ValidationError is expanded into one line per diagnostic: each line is
// self-contained by design, so whichever one an operator happens to see in
// CloudWatch is actionable on its own.
func fatal(log *slog.Logger, err error) {
	var verr *config.ValidationError
	if errors.As(err, &verr) {
		for _, d := range verr.Diagnostics {
			log.Error("configuration error",
				slog.String("rule", d.Rule),
				slog.String("path", d.Path),
				slog.String("source", d.Source),
				slog.String("problem", d.Problem),
				slog.String("remedy", d.Remedy))
		}
	}
	log.Error("cold start failed, refusing to serve", slog.String("error", err.Error()))

	// slog's handler writes synchronously to the underlying io.Writer, but the
	// runtime may still exit before a buffered stdout drains on some hosts.
	_ = os.Stdout.Sync()
	os.Exit(1)
}

// startTimeout bounds the cold-start work. The Lambda init phase gets 10
// seconds before the runtime restarts it, so a hung SSM or STS call must fail
// inside that window with a message rather than be killed without one.
const startTimeout = 8 * time.Second
