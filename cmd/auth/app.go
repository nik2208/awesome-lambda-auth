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

	// IDPKeySource injects the identity provider's signing key, for the same
	// reason Mail and SMS are injectable: a composition that signs with a key
	// held in AWS has to be provable without an AWS account. Nil builds the real
	// KMS-backed one (awsintegration.NewKMSKeySource), lazily. Injecting it
	// switches nothing on — whether an RS256 signer is built at all is a
	// question about idProvider.kmsKeyId (idp.go).
	//
	// It is a factory of a crypto.Signer, and deliberately not the KMS client
	// itself: awsintegration.KMSAPI speaks the AWS SDK's types, and the product
	// rule is that the SDK appears only under internal/integration/aws and
	// internal/store/dynamodb. A seam typed in SDK terms would export that
	// dependency to every implementor, this package's tests included — which is
	// why Mail and SMS are auth.MailerTransport and auth.SMSTransport rather
	// than SESAPI and SNSAPI, and why this one is IDPKeySource.
	IDPKeySource IDPKeySourceFactory

	// HTTPClient issues every outbound HTTP request this binary makes on a
	// route's behalf: the delivery webhook, the claims webhook, and the JWKS
	// fetch of resource-server mode. Nil, the zero value, is http.DefaultClient.
	// Injected so a test can point any of them at a TLS httptest server it
	// trusts; like Mail and SMS, injecting it switches nothing on.
	HTTPClient *http.Client
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

	// ResourceServerGuard verifies an RS256 bearer token against the issuer's
	// JWKS — or this instance's own access-token cookie — and puts the principal
	// on the request context. Nil unless resourceServer.enabled.
	//
	// NOTHING IN THIS ARTIFACT MOUNTS IT. It guards the routes of whatever
	// serves alongside it, and this binary has none of those: every route under
	// the api prefix belongs to the imported adapter, which verifies the local
	// HS256 session, and the commonest resource-server deployment is the hybrid
	// that keeps doing exactly that. So the guard is an export — for a host that
	// embeds this package, or for a future authorizer binary — and not a
	// middleware this cold start installs. See the header of idp.go.
	//
	// What resource-server mode does do to the deployed artifact is subtract:
	// HTTPConfig.ResourceServer unmounts all nineteen credential routes. That is
	// immediate and total, and it is the whole of the knob's effect here.
	ResourceServerGuard func(http.Handler) http.Handler

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
	// Before the core is built, because the core is what would otherwise fail,
	// with a message about a knob resource-server mode told the operator to
	// leave unset. See checkResourceServerSupport.
	if err := checkResourceServerSupport(cfg); err != nil {
		return nil, err
	}

	users, sessions, err := newStores(ctx, cfg, log)
	if err != nil {
		return nil, err
	}

	// Credential delivery. Built before the core because every sender option is
	// derived from it, and it performs no I/O: both AWS clients are deferred to
	// the first message actually sent (delivery.go).
	deliver, err := newDelivery(cfg, opts.Mail, opts.SMS, opts.HTTPClient, log)
	if err != nil {
		return nil, err
	}

	coreOpts := coreOptions(cfg, users, sessions, log)
	coreOpts = append(coreOpts, deliveryOptions(deliver, log)...)
	// The email flows: site URLs and the template store, seeded from the
	// artifact. This is the one option set that can do I/O at cold start —
	// reading email.templatesDir — and the one that can refuse for a store
	// the driver lacks.
	emailOpts, err := emailOptions(ctx, cfg, users, deliver, log)
	if err != nil {
		return nil, err
	}
	coreOpts = append(coreOpts, emailOpts...)
	coreOpts = append(coreOpts, twoFactorOptions(cfg)...)
	// Token claims. Like emailOptions this one can refuse: a claim mapped from
	// a field the core does not expose, or named after a reserved session
	// claim, is a document fault and has to stop the deployment rather than
	// turn every login into a 500.
	claimsOpts, err := claimsOptions(cfg, opts.HTTPClient, log)
	if err != nil {
		return nil, err
	}
	coreOpts = append(coreOpts, claimsOpts...)
	// OAuth: the provider registry and the provisioning policy. It refuses for
	// a profileMap or a fieldMap that does not compile, so a mapping expression
	// is a failed deployment rather than a provider that 500s on its first
	// callback.
	oauthOpts, err := oauthOptions(cfg, users, deliver, log)
	if err != nil {
		return nil, err
	}
	coreOpts = append(coreOpts, oauthOpts...)
	// Identity-provider mode. The second option set that can do I/O at cold
	// start — a KMS signer fetches its public key here — and it refuses for a
	// driver with no authorization-code store, for the same reason emailOptions
	// refuses for one with no template store.
	idpOpts, err := idpOptions(ctx, cfg, users, opts.IDPKeySource, log)
	if err != nil {
		return nil, err
	}
	coreOpts = append(coreOpts, idpOpts...)

	core, err := auth.New(coreOpts...)
	if err != nil {
		return nil, fmt.Errorf("auth core: %w", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz)
	// The auth surface comes entirely from the imported adapter. Nothing in this
	// binary may add a route under the api prefix: a route that exists here and
	// not in the other family ports is a wire divergence by construction.
	// In identity-provider mode the adapter mounts the OIDC surface too, all
	// five endpoints of it, as of awesome-go-auth v0.7.0; this binary used to
	// mount four of them itself and no longer does. What is left here is the
	// guard: mountAuthSurface returns an error rather than panicking on the one
	// configuration that can still register a pattern twice, an
	// idProvider.jwksPath pointed at a route the adapter already serves (idp.go).
	if err := mountAuthSurface(mux, core, cfg); err != nil {
		return nil, err
	}

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

	// Resource-server mode. Built after the core because the verifier's cookie
	// path needs it, and built at cold start so a JWKS endpoint the client
	// cannot use is a failed deployment rather than a 401 per request.
	if cfg.ResourceServer.Enabled {
		guard, err := newResourceServerGuard(core, resourceServerConfig(cfg, opts.HTTPClient), log)
		if err != nil {
			return nil, err
		}
		app.ResourceServerGuard = guard
	}

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
		slog.String("sessionCheckOn", cfg.Sessions.CheckOn),
		slog.Bool("identityProvider", core.IDP() != nil),
		slog.Bool("resourceServer", cfg.ResourceServer.Enabled))

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
		// The cost every password this deployment hashes is written at. It
		// cannot fail here: WithBcryptCost refuses anything outside bcrypt's
		// 4..31, and validate.go has already refused anything outside 10..15,
		// which is the narrower range — so the option and the schema cannot
		// disagree about a value that loaded.
		auth.WithBcryptCost(cfg.Security.Password.BcryptSaltRounds),
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

// httpConfig maps the cookie, CSRF and prefix knobs onto the shared wire layer.
//
// Cookie Max-Age is deliberately left at zero: HTTPConfig.resolve derives it
// from the token TTLs, which is what keeps a cookie from outliving the token it
// carries when an operator changes security.jwt.accessTokenTtl. The cookie
// *name* prefix is likewise derived by the core (CookieOptions.CookieName) and
// is not a knob in either layer.
//
// UIEnabled is the one field that reaches an emailed link: with it set, the
// core's UILink points a link at <site><prefix>/ui/<path> — the hosted UI's
// page for it — instead of at the bare API route (buildUiLink,
// auth.router.ts:261-271). It follows ui.enabled, which phases.go still refuses
// as a P6 domain, so today it is always false and every link points at the API
// route; wiring it now means the link shape and the UI switch cannot drift
// apart when the UI lands.
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
		CSRF:      auth.CSRFConfig{Enabled: cfg.Security.CSRF.Enabled},
		UIEnabled: cfg.UI.Enabled,
		// Resource-server mode: the adapter registers none of the nineteen
		// routes that create, prove, deliver or change a credential, so each of
		// them answers 404 rather than reaching a handler with no issuer behind
		// it (auth.ResourceServerGatedRoutes). This is the half of the knob that
		// changes the mounted surface; the verifier is App.ResourceServerGuard.
		ResourceServer: cfg.ResourceServer.Enabled,
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
		// Every register is logged once, at cold start, so the deviations show up
		// in the deployment log rather than being discovered from a client's bug
		// report. The memory driver announces the product and core registers only.
		logDeviations(log, store.CompatibilityNotes())
		return store, store, nil

	case config.StoreDriverMemory:
		// RS-12 already refuses this driver in production, so reaching it means
		// a development stack. Each cold start gets its own empty store, and
		// concurrent execution environments do not share one.
		log.Warn("using the in-memory store: state is per execution environment and is lost on every cold start",
			slog.String("path", "stores.driver"))
		logDeviations(log, nil)
		return newMemoryStoreBundle(), auth.NewMemorySessionStore(), nil

	default:
		return nil, nil, fmt.Errorf("stores.driver: %q is not implemented in this build; use %q or %q",
			cfg.Stores.Driver, config.StoreDriverDynamoDB, config.StoreDriverMemory)
	}
}

// memoryStoreBundle is the in-memory user store plus the stores the core cannot
// find by type assertion — the two OAuth stores and the template store — so
// that the development driver reaches the account-linking routes and the
// stored templates the same way the DynamoDB one does.
//
// The embedded pointer is what keeps the rest working: every optional interface
// the core *does* discover on the user store — MagicLinkStore, SMSStore,
// TOTPStore and the rest — is satisfied by method promotion, so wrapping it
// cannot quietly narrow the feature set.
type memoryStoreBundle struct {
	*auth.MemoryUserStore
	links     auth.LinkedAccountStore
	pending   auth.PendingLinkStore
	templates auth.TemplateStore
	codes     auth.AuthCodeStore
}

// newMemoryStoreBundle is the one place the development driver's bundle is
// assembled, shared by defaultStoreFactory and the test harness so the two
// cannot drift into different compositions.
func newMemoryStoreBundle() memoryStoreBundle {
	return memoryStoreBundle{
		MemoryUserStore: auth.NewMemoryUserStore(),
		links:           auth.NewMemoryLinkedAccounts(),
		pending:         auth.NewMemoryPendingLinks(),
		templates:       auth.NewMemoryTemplateStore(),
		// Per execution environment, like everything else on this driver, and
		// with a consequence worth knowing on Lambda even in development: an
		// authorization code minted by one environment is unknown to the next,
		// so an OIDC round trip only completes when /authorize and /token land
		// on the same one. RS-12 already refuses this driver in production; the
		// dynamodb store (internal/store/dynamodb/auth_codes.go) is what makes
		// the flow work across instances.
		codes: auth.NewMemoryAuthCodeStore(),
	}
}

func (m memoryStoreBundle) LinkedAccounts() auth.LinkedAccountStore { return m.links }
func (m memoryStoreBundle) PendingLinks() auth.PendingLinkStore     { return m.pending }
func (m memoryStoreBundle) Templates() auth.TemplateStore           { return m.templates }
func (m memoryStoreBundle) AuthCodes() auth.AuthCodeStore           { return m.codes }

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
		//
		// "templates" joined the set when the store gained its TEMPLATES
		// partition: mail templates and UI translations are readable and
		// patchable on this driver, so email.templatesDir seeds a store that
		// outlives the execution environment.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true, "templates": true,
		}, true
	case config.StoreDriverMemory:
		// awesome-go-auth ships MemoryLinkedAccounts, MemoryPendingLinks and
		// MemoryTemplateStore, and newMemoryStoreBundle hangs all three off the
		// user store, so the development driver backs the same set as the
		// production one. A driver that backs fewer is still refused by name in
		// emailOptions, which is why that refusal exists.
		return map[string]bool{
			"users": true, "sessions": true, "tokens": true,
			"linkedAccounts": true, "pendingLinks": true, "templates": true,
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

// unwiredKnobs reports every knob the operator set that the core cannot honour.
//
// security.password.bcryptSaltRounds used to head this list, because the core
// hashed at a fixed cost and exposed no option for it. v0.6.0 exports
// WithBcryptCost, coreOptions passes it, and the gap is gone — the configured
// cost is now the deployed cost. Nothing replaced it: the only other candidate
// P3 looked at was the iss claim, and there is no knob in a wired domain that
// asks for one, so there is nothing being ignored to report (twofactor.go).
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
	gaps = append(gaps, oauthKnobGaps(cfg)...)
	gaps = append(gaps, idpKnobGaps(cfg)...)

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
//
// Every one of those sentences changes when email.deliveryWebhook.url is set,
// so each message that asserts something about what does or does not get
// delivered branches on webhookConfigured. Under a webhook the five credential
// seams are the webhook's (deliveryOptions), SES carries at most the
// email-changed notice and the account-linking mail, and SNS carries nothing at
// all — so "no mail is sent" and "POST /sms/send answers 500
// SMS_NOT_CONFIGURED" would both be false. A wrong line here is worse than no
// line: this report is the product's own anti-silent-misconfiguration
// mechanism, and an operator who acts on it has no second source.
func deliveryKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap
	hook := webhookConfigured(cfg)

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
	// The "the block is off" texts, in the two postures. Without a webhook,
	// switching the block off means the credential is not delivered at all and
	// the route answers a coded 500; with one, the webhook already carries every
	// credential and the block is genuinely optional, so telling an operator to
	// set the switch would be telling them to wire a transport they do not need.
	smsOff := "sms.endpoint is unset, so no SMS transport is wired at all and POST /sms/send answers 500 SMS_NOT_CONFIGURED: set it to turn SMS delivery on, or delete the credential"
	mailOff := "email.mailer.from is unset, so no mail transport is wired at all and no mail is sent: set it to turn mail delivery on, or delete the key"
	if hook {
		smsOff = "sms.endpoint is unset, so no SNS transport is wired, but the delivery webhook carries the SMS code instead and POST /sms/send works: delete the credential, or set sms.endpoint only if you want the email-changed half of this document to be portable to a port that has no webhook"
		mailOff = "email.mailer.from is unset, so no SES transport is wired, but the delivery webhook carries all five credential deliveries instead: delete the key, or set email.mailer.from only to turn on the two mails the webhook has no seam for — the email-changed notice and the account-linking mail"
	}
	for _, row := range []struct{ path, service, action, hazard, on, off string }{
		{
			path: "email.mailer.apiKey", service: "SES", action: "ses:SendEmail",
			on:  "Deleting the secret it points at costs nothing here, and removes one credential from the blast radius",
			off: mailOff,
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

		// What SES actually carries, which is the whole mailer only without a
		// webhook. Under one it carries the two mails auth.DeliveryWebhook has no
		// seam for, and saying "this build delivers mail through Amazon SES"
		// would tell an operator the reset mail went out by mail when it did not.
		sesCarries := "this build delivers mail through Amazon SES"
		if hook {
			sesCarries = "email.deliveryWebhook.url is set, so the five credential deliveries are POSTed to that receiver and Amazon SES carries only the email-changed notice and the account-linking mail"
		}

		// Always present when the mailer is on: validate.go requires an endpoint
		// for any configured mailer block, and SES never has one.
		gaps = append(gaps, knobGap{
			Path:    "email.mailer.endpoint",
			Problem: sesCarries + "; either way SES is called through the AWS API and not by posting to a URL, so no request is ever made to this endpoint",
			Remedy:  sesRemedy + ". The schema requires it, which is why configuring a mailer at all means configuring one",
		})
		// provider is free-form in the schema and the reference passes it to its
		// gateway to select a backend. Naming ses is honoured — it is what this
		// build does — so only a different value is a gap.
		if p := strings.TrimSpace(cfg.Email.Mailer.Provider); p != "" && !strings.EqualFold(p, "ses") {
			gaps = append(gaps, knobGap{
				Path:    "email.mailer.provider",
				Problem: fmt.Sprintf("%s, and there is no second mail transport to select, so the configured provider %q selects nothing", sesCarries, p),
				Remedy:  `set it to "ses" to describe what is actually deployed, or remove it`,
			})
		}
	}

	if smsOn {
		const snsRemedy = "leave it set if the same document is deployed to another port in the family; nothing in this build reads it"

		// Without a webhook the knob still has one job — it is the switch that
		// wires SNS at all. With one it has none: the SMS code is POSTed to the
		// receiver whether or not this block is configured, and SNS publishes
		// nothing.
		problem := "this build sends text messages with an SNS Publish to the recipient's number, so no request is ever made to this gateway; the knob's only remaining job is to say that SMS delivery should be wired at all"
		remedy := snsRemedy + ", and keep it set: an empty sms block leaves POST /sms/send answering 500 SMS_NOT_CONFIGURED"
		if hook {
			problem = "email.deliveryWebhook.url is set, so the SMS code is POSTed to that receiver and nothing is published through SNS: no request is made to this gateway either, and the knob has no remaining job in this deployment"
			remedy = snsRemedy + ". Removing the whole sms block changes nothing here — POST /sms/send keeps working through the webhook — so keep it only for a document that is also deployed without one"
		}
		gaps = append(gaps, knobGap{Path: "sms.endpoint", Problem: problem, Remedy: remedy})
	}

	// The delivery webhook's secret is the same shape of hazard as the four
	// credentials above: a Secrets Manager entry the template carries, whose
	// switch — the url — is the part that gets forgotten. A secret *referenced*
	// from the document without a url is refused by validate.go; a value that
	// arrived through its plain environment variable leaves no reference to
	// refuse, so it is reported here instead of being silently unused.
	if cfg.SecretValue("email.deliveryWebhook.secret") != "" && strings.TrimSpace(cfg.Email.DeliveryWebhook.URL) == "" {
		gaps = append(gaps, knobGap{
			Path:    "email.deliveryWebhook.secret",
			Problem: "the delivery webhook's signing secret resolves to a value, but email.deliveryWebhook.url is unset, so no webhook is wired and the secret signs nothing; credentials go through SES and SNS as if it were absent",
			Remedy:  "set email.deliveryWebhook.url to the https receiver that should get every delivery, or delete the secret",
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
