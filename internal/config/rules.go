package config

import (
	"fmt"
	"net/url"
	"strings"
)

// minHS256SecretLength is the product floor for an HS256 signing secret.
//
// The reference has no floor at all — it never validates the secret and an empty
// one surfaces as a 500 inside the first jwt.sign
// (src/services/token.service.ts:22,145). 32 bytes matches the HMAC-SHA256 block
// output: below that, the secret is the weakest part of the construction.
const minHS256SecretLength = 32

// checkRules evaluates the refuse-to-start table of spec §2.
//
// Every rule reports with its §2 identifier, because the identifier is how an
// operator gets from a log line to the documentation. Rules are evaluated
// independently and all of them run: a deployment with three problems should
// name three problems.
//
// RS-7 has no function of its own. The spec folds it into RS-1: the admin guard
// reuses security.jwt.accessTokenSecret, so "accessPolicy is not open and there
// is no usable JWT secret" is the same condition as "the access secret is
// missing", and reporting it twice would just be noise.
func checkRules(c *Config, capabilities func(string) StoreCapabilities, d *diagnostics) {
	checkRS1Secrets(c, d)
	checkRS2InsecureCookieMode(c, d)
	checkRS3CSRF(c, d)
	checkRS4IDProviderKeys(c, d)
	checkRS5SameSite(c, d)
	checkRS6AdminGuard(c, d)
	checkRS8ResourceServerJWKS(c, d)
	checkRS10FirstUser(c, capabilities, d)
	checkRS11OAuthProviders(c, d)
	checkRS12MemoryStore(c, d)
	checkStoreRequirements(c, d)
}

// checkRS1Secrets: the HS256 signing secrets must exist, be long enough, and
// differ from one another.
//
// Resource-server mode exempts them because it never mints a token: it only
// validates tokens signed elsewhere, against a JWKS. The one thing it does not
// exempt is the admin guard, which verifies the access token with
// security.jwt.accessTokenSecret — that is RS-7, which the spec folds in here
// precisely because the two knobs are one knob. Without the carve-out an admin
// surface in resource-server mode comes up authenticating nobody, which is the
// silent failure §2 records against the reference.
func checkRS1Secrets(c *Config, d *diagnostics) {
	paths := []string{"security.jwt.accessTokenSecret", "security.jwt.refreshTokenSecret"}
	if c.ResourceServer.Enabled {
		if !c.adminGuardVerifiesTokens() {
			return
		}
		// Only the access secret is needed: nothing in this deployment mints or
		// verifies a refresh token, so demanding a second one would be noise.
		paths = paths[:1]
	}

	access := c.SecretValue("security.jwt.accessTokenSecret")
	refresh := c.SecretValue("security.jwt.refreshTokenSecret")

	for _, path := range paths {
		if c.secretFailed(path) {
			// The resolution failure has already been reported against this knob;
			// adding "and it is missing" would bury the cause.
			continue
		}
		value := c.SecretValue(path)
		switch {
		case value == "":
			d.errf(RuleSecrets, path,
				"the HS256 signing secret is missing, so the first login would fail with a 500 instead of signing a token",
				"reference it from a store -- "+path+": {secretsManager: <id>} -- or set "+envNameFor(path)+" for development")
		case len(value) < minHS256SecretLength:
			d.errf(RuleSecrets, path,
				fmt.Sprintf("the HS256 signing secret is %d characters, below the %d-character minimum", len(value), minHS256SecretLength),
				fmt.Sprintf("generate one with: openssl rand -base64 %d", minHS256SecretLength+16))
		}
	}

	if len(paths) == 2 && access != "" && access == refresh {
		d.errf(RuleSecrets, "security.jwt.refreshTokenSecret",
			"the access and refresh signing secrets are identical, which makes a refresh token accepted anywhere an access token is",
			"generate a second, independent secret for security.jwt.refreshTokenSecret")
	}
}

// checkRS2InsecureCookieMode: cookies on a shared AWS domain.
//
// __Host- and __Secure- prefixes, the Path-scoped refresh cookie and the CSRF
// double-submit all assume the deployment controls its own host. On
// <id>.execute-api.<region>.amazonaws.com or <id>.lambda-url.<region>.on.aws it
// does not: the stage segment breaks Path scoping, and every other AWS account's
// API shares the registrable domain, so a cookie without a Domain attribute is
// still host-only but the surrounding assumptions no longer hold. The spec names
// execute-api; lambda-url is included because the hazard is identical.
func checkRS2InsecureCookieMode(c *Config, d *diagnostics) {
	if !c.CookieDeliveryActive() || c.Cookies.AllowInsecureCookieMode {
		return
	}

	if c.Deployment.PublicURL == "" {
		d.errf(RuleInsecureCookieMode, "deployment.publicUrl",
			"cookie delivery is active but the deployment does not declare its public URL, so it cannot be checked for a custom domain",
			"set deployment.publicUrl to the origin clients reach; set cookies.allowInsecureCookieMode: true only for a dev stage")
		return
	}

	host := hostOf(c.Deployment.PublicURL)
	if !isSharedAWSDomain(host) {
		return
	}
	d.errf(RuleInsecureCookieMode, "deployment.publicUrl",
		fmt.Sprintf("cookie delivery is active on the shared AWS domain %q, where cookie scoping, the __Host- prefix and the CSRF double-submit assumptions break", host),
		"attach a custom domain and set deployment.publicUrl to it; for a dev stage set cookies.allowInsecureCookieMode: true")
}

// checkRS3CSRF: CSRF cannot be off while cookies are being issued.
//
// The reference defaults CSRF off (src/middleware/auth.middleware.ts:35); the
// product default is on and this rule refuses the reference's default outright.
// A cookie-authenticated, state-changing endpoint with no double-submit token is
// cross-site forgeable, and the whole point of shipping this as a product is
// that the operator does not get to make that mistake by omission.
func checkRS3CSRF(c *Config, d *diagnostics) {
	if !c.CookieDeliveryActive() || c.Security.CSRF.Enabled {
		return
	}
	d.errf(RuleCSRFDisabled, "security.csrf.enabled",
		"CSRF protection is disabled while auth cookies are being issued, which leaves every state-changing endpoint cross-site forgeable",
		"remove the override so it stays true; bearer clients (X-Auth-Strategy: bearer) already bypass the check and need nothing here")
}

// checkRS4IDProviderKeys: identity-provider mode needs externally supplied key
// material in production.
//
// The reference generates an ephemeral RSA keypair and warns that "all tokens
// will be invalidated on restart"
// (src/services/token.service.ts:50-63). Under Lambda a restart is every cold
// start, and there are many concurrently, so the warning describes a service that
// does not work rather than one that is inconvenient.
func checkRS4IDProviderKeys(c *Config, d *diagnostics) {
	if !c.IDProvider.active() {
		return
	}
	if c.SecretValue("idProvider.privateKey") != "" {
		return
	}
	if !c.IsProduction() {
		return
	}
	d.errf(RuleIDProviderKeys, "idProvider.privateKey",
		"identity-provider mode is active in production with no signing key supplied, and generating an ephemeral one would invalidate every token on each cold start",
		"reference a stored RSA private key -- idProvider.privateKey: {secretsManager: <id>} -- or turn idProvider.enabled off")
}

// checkRS5SameSite: SameSite=None requires Secure.
//
// Browsers reject a SameSite=None cookie that is not Secure, so the reference's
// silence here means an entire login succeeds server-side and sets nothing
// client-side (no check exists anywhere in
// src/services/token.service.ts:174-210).
func checkRS5SameSite(c *Config, d *diagnostics) {
	if c.Cookies.SameSite != SameSiteNone || c.Cookies.Secure {
		return
	}
	d.errf(RuleSameSiteNone, "cookies.sameSite",
		"sameSite is none without secure, and every browser rejects such a cookie outright, so login would appear to succeed and set nothing",
		"set cookies.secure: true, or use sameSite: lax if the clients are same-site")
}

// checkRS6AdminGuard: a deployed admin surface must have a guard.
//
// With neither an access policy nor a bootstrap secret, the reference logs to
// stderr and leaves the admin routes fully open
// (src/router/admin.router.ts:516-537). Operators of a deployed product do not
// read stderr, so the same situation refuses to start.
func checkRS6AdminGuard(c *Config, d *diagnostics) {
	if !c.Admin.Enabled {
		return
	}
	if c.Admin.AccessPolicy != "" || c.SecretValue("admin.bootstrapSecret") != "" {
		return
	}
	d.errf(RuleAdminUnguarded, "admin.accessPolicy",
		"the admin surface is enabled with neither an access policy nor a bootstrap secret, which would leave every admin endpoint open to anyone",
		"set admin.accessPolicy (first-user, is-admin-flag, rbac:<role>, permission:<perm>) or reference admin.bootstrapSecret from a store")
}

// checkRS8ResourceServerJWKS: resource-server mode needs a well-formed https
// JWKS URL at startup.
//
// The reference only discovers a bad URL at the first token verification
// (src/services/jwks.service.ts:111), which turns a deployment-time typo into a
// production 500. Reachability is deliberately not probed: the identity provider
// may legitimately come up after this stack.
func checkRS8ResourceServerJWKS(c *Config, d *diagnostics) {
	if !c.ResourceServer.Enabled {
		return
	}
	raw := c.ResourceServer.JWKSURL
	if raw == "" {
		d.errf(RuleResourceServerJWKS, "resourceServer.jwksUrl",
			"resource-server mode is on with no JWKS URL, so every token verification would fail at request time",
			"set resourceServer.jwksUrl to the https JWKS endpoint of the identity provider")
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		d.errf(RuleResourceServerJWKS, "resourceServer.jwksUrl",
			fmt.Sprintf("%q is not a well-formed https URL, and the reference would only discover that at the first token verification", raw),
			"use the full https URL, e.g. https://idp.example.com/.well-known/jwks.json")
	}
}

// checkRS10FirstUser: the first-user policy needs a driver that can list users.
//
// The reference fails at request time with a 500 saying exactly this
// (src/router/admin.router.ts:372-379). The capability comes from the store
// layer, which owns the truth about what each driver implements.
func checkRS10FirstUser(c *Config, capabilities func(string) StoreCapabilities, d *diagnostics) {
	if c.Admin.AccessPolicy != AdminAccessPolicyFirstUser {
		return
	}
	if capabilities(c.Stores.Driver).ListUsers {
		return
	}
	d.errf(RuleFirstUserListUsers, "admin.accessPolicy",
		fmt.Sprintf("accessPolicy first-user needs to enumerate users, and the %q store driver cannot", c.Stores.Driver),
		"use is-admin-flag or rbac:<role>, or select a driver that supports listing users")
}

// checkRS11OAuthProviders: a provider block must be complete.
//
// This is the one misconfiguration the reference already fails fast on, throwing
// OAUTH_NOT_CONFIGURED from the strategy constructor
// (src/strategies/oauth/google.strategy.ts:15-17).
func checkRS11OAuthProviders(c *Config, d *diagnostics) {
	for _, name := range sortedKeys(c.OAuth.Providers) {
		p := c.OAuth.Providers[name]
		base := "oauth.providers." + name
		secretPath := base + ".clientSecret"
		missing := make([]string, 0, 3)
		if p.ClientID == "" {
			missing = append(missing, "clientId")
		}
		if c.SecretValue(secretPath) == "" {
			missing = append(missing, "clientSecret")
		}
		if p.CallbackURL == "" {
			missing = append(missing, "callbackUrl")
		}
		if len(missing) == 0 {
			continue
		}
		d.errf(RuleOAuthIncomplete, base,
			fmt.Sprintf("the %q provider block is present but incomplete: %s missing", name, strings.Join(missing, ", ")),
			"supply the missing values, or remove the whole "+base+" block to disable the provider")
	}
}

// checkRS12MemoryStore: no in-memory store in production.
//
// Every Lambda execution environment would get its own copy, so sessions, tokens
// and rate-limit counters would depend on which one happened to serve the
// request.
func checkRS12MemoryStore(c *Config, d *diagnostics) {
	if c.Stores.Driver != StoreDriverMemory || !c.IsProduction() {
		return
	}
	d.errf(RuleMemoryStore, "stores.driver",
		"the memory driver is selected in a production deployment, and each execution environment would hold its own disconnected copy of every session",
		"use dynamodb or postgres, or set deployment.environment: development if this really is a throwaway stage")
}

// checkStoreRequirements enforces the cross-store requirements of spec §1.17: a
// feature switched on whose backing store is disabled would fail at request
// time, which is exactly the class of silent misconfiguration the product is
// meant to eliminate.
func checkStoreRequirements(c *Config, d *diagnostics) {
	requireStore := func(enabled bool, storePath string, storeEnabled bool, because, remedy string) {
		if !enabled || storeEnabled {
			return
		}
		d.errf(RuleStoreRequired, storePath,
			"the "+storePath+" store is disabled but "+because,
			remedy)
	}

	requireStore(c.Sessions.CheckOn != SessionCheckOnNone, "stores.enable.sessions", c.Stores.Enable.Sessions,
		fmt.Sprintf("sessions.checkOn is %q, which needs to read session state", c.Sessions.CheckOn),
		"enable stores.enable.sessions, or set sessions.checkOn: none")

	rbacPolicy := strings.HasPrefix(c.Admin.AccessPolicy, AdminAccessPolicyRBACPrefix) ||
		strings.HasPrefix(c.Admin.AccessPolicy, AdminAccessPolicyPermPrefix)
	requireStore(rbacPolicy, "stores.enable.rbac", c.Stores.Enable.RBAC,
		fmt.Sprintf("admin.accessPolicy is %q, which is evaluated against roles and permissions", c.Admin.AccessPolicy),
		"enable stores.enable.rbac, or use the is-admin-flag policy")

	requireStore(c.Tools.Enabled && c.Tools.InboundWebhooks.Enabled, "stores.enable.webhooks", c.Stores.Enable.Webhooks,
		"inbound webhooks are enabled and their per-provider rows and mapping scripts live in that store",
		"enable stores.enable.webhooks, or set tools.inboundWebhooks.enabled: false")

	requireStore(c.RuntimeSettings.Require2FA || len(c.RuntimeSettings.EnabledWebhookActions) > 0,
		"stores.enable.settings", c.Stores.Enable.Settings,
		"runtimeSettings seeds are configured and the runtime-mutable layer has nowhere to live",
		"enable stores.enable.settings, or remove the runtimeSettings block")

	requireStore(c.Tools.Enabled && c.Tools.Telemetry.Enabled, "stores.enable.telemetry", c.Stores.Enable.Telemetry,
		"the telemetry query endpoint is enabled and has no store to query",
		"enable stores.enable.telemetry, or set tools.telemetry.enabled: false")
}

// sharedAWSHostSuffixes are the AWS-owned domains where several accounts' APIs
// share a registrable domain and the path carries a stage segment.
var sharedAWSHostSuffixes = []string{
	".amazonaws.com",
	".on.aws",
}

// isSharedAWSDomain reports whether a host is a default AWS-issued endpoint
// rather than a domain the deployment controls.
func isSharedAWSDomain(host string) bool {
	host = strings.ToLower(host)
	for _, suffix := range sharedAWSHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

func hostOf(raw string) string {
	host := ""
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		host = u.Hostname()
	} else {
		// A bare host with no scheme parses with an empty Host; deployment.publicUrl
		// is validated separately, so treat the whole value as the host here rather
		// than silently passing the check.
		host = strings.SplitN(raw, "/", 2)[0]
	}
	// A fully-qualified name may carry the root label as a trailing dot, which
	// names the same host and which every browser and API Gateway accepts. Left in
	// place it would slip straight past the suffix match and turn RS-2 off.
	return strings.TrimSuffix(host, ".")
}

// envNameFor returns the documented AWESOME_AUTH_* variable for a secret path, so
// a diagnostic can tell the operator exactly what to set in development.
func envNameFor(path string) string {
	for _, slot := range secretSlots(Defaults()) {
		if slot.path == path {
			return slot.env
		}
	}
	return "the documented AWESOME_AUTH_* variable"
}
