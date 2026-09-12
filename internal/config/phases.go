package config

import (
	"reflect"
	"sort"
	"strings"
)

// A domain is one top-level block of the schema, paired with the phase that
// wires it up. The whole schema is defined and validated from P1 onwards, but
// only part of it is connected to anything, and a knob that validates cleanly
// and then does nothing is worse than one that does not exist: the operator has
// no way to tell the difference from the outside.
//
// So every domain that is not yet wired is enumerated here, and configuring it
// refuses the deployment with the phase it lands in. That is the whole mechanism:
// there is no code path in which a configured-but-inert block is silently
// accepted.
type domain struct {
	// path is the top-level dotted key, e.g. "idProvider".
	path string

	// phase names the phase that wires the domain, for the error message.
	phase string

	// get selects the domain's sub-tree out of a Config, so a configured domain
	// can be detected by comparing it against the same sub-tree of Defaults.
	get func(*Config) any

	// secretPrefix, when set, also treats a resolved secret under that dotted
	// prefix as evidence the domain was configured. Needed because a secret
	// supplied through its documented environment variable leaves no trace in
	// the Config tree.
	secretPrefix string
}

// unwiredDomains lists every domain whose types and validation exist but whose
// behaviour does not.
//
// P1 wires: schemaVersion, deployment, security.jwt secrets and TTLs,
// security.password, security.csrf, tokens, cookies, sessions,
// email.verification.mode, stores, http.
//
// Credential delivery added `email.mailer` and `sms`: they select and configure
// the transports the five credential-minting routes send through (cmd/auth
// delivery.go, internal/integration/aws ses.go and sns.go).
//
// The email flows (P2) closed the rest of the email block. `email.siteUrls` is
// the canonical base of every emailed link and, merged with http.cors.origins,
// the allowlist a request's Origin or Referer is matched against;
// `email.templatesDir` seeds the template store at cold start; and
// `email.deliveryWebhook` selects a signed https receiver as the sender for
// every credential seam in place of SES and SNS (cmd/auth email.go and
// delivery.go). None of the three is refused any more.
//
// Token claims and the TOTP issuer (P3) closed three more. `twoFactor.appName`
// is the issuer an authenticator app labels an enrolment with, handed to the
// core as WithTwoFactorAppName (cmd/auth twofactor.go).
// `security.jwt.extraClaims` is the declarative form of the reference's
// buildTokenPayload callback and `security.jwt.claimsWebhook` the escape hatch
// for a claim that has to be computed; both become one TokenClaimsBuilder built
// out of the core's own StaticClaims, UserFieldClaims, ChainClaims and
// ClaimsWebhook (cmd/auth claims.go). The claims webhook gained a required
// signing secret with the wiring, for the reason the Webhook type gives.
//
// A knob inside a wired domain that the imported core cannot honour is a
// different thing again, and is reported by cmd/auth's unwiredKnobs at cold
// start rather than refused here — which is where the mailer's endpoint and API
// key end up, since SES is reached by API and not by URL.
//
// Everything below is defined, validated and refused.
func unwiredDomains() []domain {
	return []domain{
		{
			path:         "oauth",
			phase:        "P4 (OAuth and account linking)",
			get:          func(c *Config) any { return c.OAuth },
			secretPrefix: "oauth.",
		},
		{
			path:         "idProvider",
			phase:        "P5 (identity provider and JWKS)",
			get:          func(c *Config) any { return c.IDProvider },
			secretPrefix: "idProvider.",
		},
		{
			path:  "resourceServer",
			phase: "P5 (identity provider and JWKS)",
			get:   func(c *Config) any { return c.ResourceServer },
		},
		{
			path:  "ui",
			phase: "P6 (hosted UI)",
			get:   func(c *Config) any { return c.UI },
		},
		{
			path:         "admin",
			phase:        "P6 (admin surface)",
			get:          func(c *Config) any { return c.Admin },
			secretPrefix: "admin.",
		},
		{
			path:         "tools",
			phase:        "P7 (tools, telemetry, SSE, webhooks)",
			get:          func(c *Config) any { return c.Tools },
			secretPrefix: "tools.",
		},
		{
			path:  "rateLimit",
			phase: "P7 (rate limiting)",
			get:   func(c *Config) any { return c.RateLimit },
		},
		{
			path:  "docs",
			phase: "P6 (OpenAPI surface)",
			get:   func(c *Config) any { return c.Docs },
		},
		{
			path:  "runtimeSettings",
			phase: "P6 (runtime settings store)",
			get:   func(c *Config) any { return c.RuntimeSettings },
		},
	}
}

// UnwiredDomains returns the dotted paths of the domains this build validates but
// does not act on, with the phase that wires each. Exported so the deployment
// tooling can warn about them before an upload rather than after a rollback.
func UnwiredDomains() map[string]string {
	out := make(map[string]string)
	for _, dom := range unwiredDomains() {
		out[dom.path] = dom.phase
	}
	return out
}

// checkPhaseGaps reports every unwired domain the operator has actually
// configured. allow downgrades the report to a warning, for tests that need to
// exercise a later phase's validation and for a staged rollout where the operator
// has accepted the gap.
func checkPhaseGaps(c *Config, allow bool, d *diagnostics) {
	defaults := Defaults()
	// derive() has already run on the real Config, so the baseline has to go
	// through it too or every derived value would read as operator intent. It
	// also inherits the wired http block, because docs.basePath derives from
	// http.apiPrefix: without this, customising the api prefix — which P1 does
	// wire — would report the docs domain as configured.
	defaults.HTTP = c.HTTP
	derive(defaults)

	for _, dom := range unwiredDomains() {
		if !domainConfigured(c, defaults, dom) {
			continue
		}
		problem := "this block is validated but not yet wired to anything, so configuring it has no effect at runtime"
		remedy := "remove it until " + dom.phase + " lands; it is accepted by the schema so that a document written today keeps working"
		if allow {
			c.warn(dom.path, problem, remedy)
			continue
		}
		d.errf(RuleUnimplemented, dom.path, problem, remedy+", or set AllowUnimplemented to accept the gap deliberately")
	}
}

// domainConfigured reports whether the operator moved a domain away from its
// defaults, through the document, an environment override or a secret.
//
// Comparing sub-trees rather than tracking per-knob writes means a knob added to
// a domain in future is covered without anyone remembering to update this file.
func domainConfigured(c, defaults *Config, dom domain) bool {
	if !reflect.DeepEqual(dom.get(c), dom.get(defaults)) {
		return true
	}
	if dom.secretPrefix == "" {
		return false
	}
	for path, resolved := range c.secrets {
		if strings.HasPrefix(path, dom.secretPrefix) && resolved.value != "" {
			return true
		}
	}
	return false
}

// sortedDomains is used by the tests to keep their expectations stable.
func sortedDomainPaths() []string {
	out := make([]string, 0, len(unwiredDomains()))
	for _, dom := range unwiredDomains() {
		out = append(out, dom.path)
	}
	sort.Strings(out)
	return out
}
