package main

import (
	"fmt"
	"log/slog"
	"sort"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The OAuth block: which identity providers this deployment accepts a login
// from, and what the callback is allowed to do with the person it authenticated.
// Together these are the P4 block of the schema — `oauth.providers` and
// `oauth.provisioning` — which internal/config/phases.go no longer refuses.
//
// ── the registry ─────────────────────────────────────────────────────────────
//
// Each entry of oauth.providers becomes one auth.OAuthProvider. "google" and
// "github" are the reference's two hard-coded strategies and arrive as the
// core's presets (auth.GoogleProvider, auth.GitHubProvider), which carry the
// endpoints, the scopes and — for Google — the access_type=offline the
// reference's strategy sends (google.strategy.ts:29). A document may not point
// either of them somewhere else: validate.go refuses an endpoint override on a
// built-in name, because "google" silently addressing somebody else's
// authorization server is the one misconfiguration nobody would catch by
// reading the document. Any other name is a generic provider and brings its own
// authorizationUrl, tokenUrl and userInfoUrl, which validate.go requires.
//
// clientSecret never travels in the document. It is a secret-tagged knob like
// the signing secrets, resolved through Secrets Manager → SSM → environment, and
// read here by path (cfg.SecretValue); RS-11 refuses a provider that has none.
//
// ── the provisioning policy ──────────────────────────────────────────────────
//
// The reference has no policy: GenericOAuthStrategy.findOrCreateUser is abstract
// (generic-oauth.strategy.ts:169-172) and every integrator writes the function.
// A deployable product cannot ask for a function, so the core made the same
// decision declarative (auth.OAuthProvisioning, registered upstream as
// `oauth-provisioning-is-a-policy-not-a-function`) and this file fills it in
// from oauth.provisioning.
//
// One term of that policy has no knob in the extracted schema, and it is the
// consequential one: what happens when the provider account is unknown but some
// account already holds the address it asserts. The core's default links them,
// which is the account-takeover shape the reference's own store interface warns
// about — two providers can assert one address without representing one person
// (user-store.interface.ts:105-119). Hardcoding either answer would put a
// security posture in a binary where no operator could see it, so
// oauth.provisioning.onEmailMatch is a knob: link (the default, the core's and
// the reference-compatible one), conflict (the reference's own
// OAUTH_ACCOUNT_CONFLICT flow, where the link is made only after an emailed
// token proves the address) or reject. docs/spec/decisions.md D-20 argues the
// default.
//
// ── what the callback does not do ────────────────────────────────────────────
//
// The reference's callback has a second-factor branch: a user with 2FA enabled
// is 302'd to `${redirectTo}/auth/2fa?tempToken=…&methods=…` instead of being
// handed a session (auth.router.ts:1298-1313). The imported core has no such
// branch — OAuthComplete issues a session for every account it resolves — and
// this product does not fork the core, so a 2FA-enabled account that signs in
// through a provider is signed in without presenting its second factor. It is
// pinned by TestOAuthCallbackIssuesASessionEvenForATwoFactorAccount so the day
// upstream grows the branch, that test fails and this paragraph comes out.
//
// ── the shared origin list ───────────────────────────────────────────────────
//
// The redirect allowlist and the canonical site are not OAuth's own: they are
// the same two values every emailed link is built from (siteURLs in email.go,
// config.RedirectOrigins). That is how the reference arranges it too — one
// allowedOrigins, one getDefaultSiteUrl — and it is what makes RS-11's demand
// for a non-empty allowlist meaningful: with an empty one the core reproduces
// the reference's behaviour of honouring whatever origin the state carries
// (reference-issues N1).

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

// oauthOptions wires the OAuth side of the core: the provider registry, the
// provisioning policy, the site URL and origin allowlist its redirects resolve
// against, and the two account-linking stores when the driver has them and the
// operator asked for them.
//
// The wiring is always present, because two of its fields are not about OAuth
// at all. OAuthWiring.SiteURL is the core's override for the default site URL
// and OAuthWiring.AllowedOrigins joins Config.SiteURLs in its origin allowlist
// (Auth.ResolveSiteURL, wire.go) — the same two values every emailed link is
// built from. Both come from siteURLs in email.go, so an emailed link and an
// OAuth redirect cannot resolve a request's origin differently, which is how
// the reference arranges it too (one allowedOrigins, one getDefaultSiteUrl).
// Setting SiteURL here is also what makes the canonical fallback
// deployment.publicUrl when email.siteUrls is empty: the core's own default is
// the first allowlisted entry, and the auth service's origin is not one.
//
// The stores are each gated on their own stores.enable key, which is the
// mechanism the schema already defines for exactly this: "a disabled store
// makes its feature routes and admin tabs absent, exactly as an absent injected
// store does in the reference" (config.StoreEnable). With a key off, or with a
// driver that has no view for it, the store is nil and its routes answer
// NOT_IMPLEMENTED, which is the truth rather than a silent 500.
//
// That truth is only bearable for a route nobody was sent to. The OAuth
// callback is not such a route: it is reached after the browser has already
// been 302'd to the provider and the person has already consented, so a 501
// there is a login that cannot be completed by anybody. So RS-11 refuses a
// configured provider with stores.enable.linkedAccounts off, and by the time
// this function runs, a non-empty registry implies a non-nil LinkedAccounts on
// every driver that has one. pendingLinks is demanded only by onEmailMatch:
// conflict, and its other half — the single-use state nonce — is reported by
// oauthKnobGaps when a provider is configured without it.
//
// The enable signal for the registry is derived rather than added: a provider
// entry exists, and RS-11 already guarantees that any entry which exists is
// complete. With none, OAuthWiring.Service stays nil and GET /oauth/{provider}
// answers the reference's "<Provider> OAuth not configured" 404 stub, while the
// four account-linking routes keep working — they need no registry.
//
// The service is built with auth.NewOAuthServiceWithConfig rather than
// auth.NewOAuthService so that a profileMap which does not compile is a
// cold-start failure naming the provider and the field, instead of a provider
// that 500s on its first callback. The provisioning policy is validated here
// for the same reason, before auth.New would validate it without a path to
// blame.
func oauthOptions(cfg *config.Config, users auth.UserStore, deliver *delivery, log *slog.Logger) ([]auth.Option, error) {
	canonical, allowlist := siteURLs(cfg)
	wiring := auth.OAuthWiring{
		AllowedOrigins: allowlist,
		SiteURL:        canonical,
	}
	if provider, ok := users.(oauthStoreProvider); ok {
		if cfg.Stores.Enable.LinkedAccounts {
			wiring.LinkedAccounts = provider.LinkedAccounts()
		}
		if cfg.Stores.Enable.PendingLinks {
			wiring.PendingLinks = provider.PendingLinks()
		}
	}
	// DeliverLinkToken is wired whenever a mail transport exists, so POST
	// /link-request sends the verification mail instead of storing a token
	// nobody receives. With no mailer it is nil, and the route still answers
	// success without sending anything — which is what the reference does with
	// no transport configured, so the fallback is not a degradation but the
	// unconfigured behaviour. The delivery webhook has no seam for this mail
	// (auth.DeliveryWebhook posts the five credential kinds and nothing else),
	// so a webhook-only deployment is in the "none" branch here.
	delivery := "none — POST /link-request stores the token and answers success without sending mail"
	if deliver != nil && deliver.mail != nil {
		wiring.DeliverLinkToken = deliver.deliverLinkToken
		delivery = "ses"
	}

	// The policy is attached whether or not a provider is configured. It governs
	// nothing without one, but validating it either way means a fieldMap typo is
	// a cold-start failure with a path rather than something the first federated
	// login discovers.
	provisioning := oauthProvisioning(cfg)
	if err := provisioning.Validate(); err != nil {
		return nil, fmt.Errorf("config: refusing to start: oauth.provisioning: %w", err)
	}
	wiring.Provisioning = &provisioning

	providers := oauthProviders(cfg)
	if len(providers) > 0 {
		svc, err := auth.NewOAuthServiceWithConfig(providers...)
		if err != nil {
			return nil, fmt.Errorf(
				"config: refusing to start: oauth.providers: %w -- fix the expression under that provider's profileMap; "+
					"the grammar is $.path segments joined by ?? with an optional quoted literal last", err)
		}
		wiring.Service = svc
	}

	log.Info("oauth wiring",
		slog.String("siteUrl", canonical),
		slog.Int("allowedOrigins", len(allowlist)),
		slog.String("providers", strings.Join(providerNames(providers), ",")),
		slog.Bool("autoCreate", provisioning.AutoCreate),
		slog.String("onEmailMatch", provisioning.OnEmailMatch),
		slog.Bool("requireVerifiedEmail", provisioning.RequireVerifiedEmail),
		slog.Int("allowedEmailDomains", len(provisioning.AllowedEmailDomains)),
		slog.Bool("linkedAccounts", wiring.LinkedAccounts != nil),
		slog.Bool("pendingLinks", wiring.PendingLinks != nil),
		slog.String("linkTokenDelivery", delivery))

	return []auth.Option{auth.WithOAuth(wiring)}, nil
}

// oauthProviders maps oauth.providers onto the core's registry, in name order
// so that the cold-start log and any error the service reports are stable.
//
// The built-in names start from the core's preset and the document may add to
// it, never replace it: scope, additionalAuthParams and profileMap are the
// three fields that are not an endpoint, so they are the three a document can
// still set on "google" or "github" without repointing the provider at another
// authorization server. That is a deliberate widening of the reference, which
// hardcodes the scopes: a deployment that needs Google to consent to one more
// scope should not have to fork a strategy for it, and the value is visible in
// the document either way.
func oauthProviders(cfg *config.Config) []auth.OAuthProvider {
	names := make([]string, 0, len(cfg.OAuth.Providers))
	for name := range cfg.OAuth.Providers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]auth.OAuthProvider, 0, len(names))
	for _, name := range names {
		p := cfg.OAuth.Providers[name]
		secret := cfg.SecretValue("oauth.providers." + name + ".clientSecret")

		var provider auth.OAuthProvider
		switch name {
		case oauthProviderGoogle:
			provider = auth.GoogleProvider(p.ClientID, secret, p.CallbackURL)
		case oauthProviderGitHub:
			provider = auth.GitHubProvider(p.ClientID, secret, p.CallbackURL)
		default:
			provider = auth.OAuthProvider{
				Name:         name,
				ClientID:     p.ClientID,
				ClientSecret: secret,
				RedirectURL:  p.CallbackURL,
				AuthURL:      p.AuthorizationURL,
				TokenURL:     p.TokenURL,
				UserInfoURL:  p.UserInfoURL,
			}
		}

		if scopes := scopeList(p.Scope); len(scopes) > 0 {
			provider.Scopes = scopes
		}
		provider.AdditionalAuthParams = mergeAuthParams(provider.AdditionalAuthParams, p.AdditionalAuthParams)
		if len(p.ProfileMap) > 0 {
			provider.ProfileMap = p.ProfileMap
		}
		out = append(out, provider)
	}
	return out
}

// The two provider names the reference hard-codes and the core ships presets
// for. Everything else is a generic provider.
const (
	oauthProviderGoogle = "google"
	oauthProviderGitHub = "github"
)

// oauthProvisioning maps oauth.provisioning onto the core's policy.
//
// Every field is passed as written. The core takes an explicit policy at its
// word — AutoCreate false means false — which is exactly why config.Defaults
// spells out the permissive default rather than leaving Go's zero value to
// decide that a deployment which configured nothing refuses every first login.
func oauthProvisioning(cfg *config.Config) auth.OAuthProvisioning {
	p := cfg.OAuth.Provisioning
	return auth.OAuthProvisioning{
		AutoCreate:           p.AutoCreate,
		AllowedEmailDomains:  p.AllowedEmailDomains,
		RequireVerifiedEmail: p.RequireVerifiedEmail,
		OnEmailMatch:         p.OnEmailMatch,
		FieldMap:             p.FieldMap,
	}
}

// scopeList splits a scope string the way an OAuth authorization request means
// it: whitespace-separated values, which the core joins back with a single
// space. Splitting on whitespace alone and not on commas is deliberate — a
// provider that wants a comma-joined scope gets that string through as one
// value, exactly as the reference passes its `scope` string through untouched
// (generic-oauth.strategy.ts:108-116).
func scopeList(scope string) []string {
	return strings.Fields(scope)
}

// mergeAuthParams layers the document's additionalAuthParams over a preset's.
//
// A copy, never a mutation: the preset map comes from the core's constructor
// and the document's map is owned by the Config, so writing into either would
// make one provider's wiring depend on another's. An entry in the document
// replaces the preset's entry of the same key, which is the only way to turn
// Google's access_type=offline off; the core then applies the whole map with
// the reference's precedence (an entry overrides client_id, redirect_uri,
// response_type and scope, and state overrides an entry).
func mergeAuthParams(preset, configured map[string]string) map[string]string {
	if len(preset) == 0 && len(configured) == 0 {
		return nil
	}
	out := make(map[string]string, len(preset)+len(configured))
	for k, v := range preset {
		out[k] = v
	}
	for k, v := range configured {
		out[k] = v
	}
	return out
}

func providerNames(providers []auth.OAuthProvider) []string {
	out := make([]string, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.Name)
	}
	return out
}

// oauthKnobGaps reports the oauth knobs this build validates but cannot act on,
// and the one defence a configured deployment silently gives up.
//
// projectId: the reference carries it for Google because its own documentation
// does (config-schema.md §1.7), and nothing in the flow reads it — not the
// reference's strategy, and not the core's provider, which has no field for it.
// It is reported rather than refused for the reason every entry of unwiredKnobs
// is: a document written for another port in the family must stay deployable
// here, and an operator who set a value must not have to learn from behaviour
// that nothing consumed it.
//
// stores.enable.pendingLinks: the same store that backs the conflict flow is
// where OAuthBegin records the state nonce, and where OAuthComplete consumes it
// — which is what makes a state single-use rather than replayable for the whole
// of its TTL (oauth_wire.go). With the store off the core skips both halves and
// falls back to the reference's own behaviour: signed, time-bounded, replayable.
// That is not a broken deployment, so RS-11 only refuses it for onEmailMatch:
// conflict, where nothing would work at all; here it is said out loud, because a
// defence that disappears when an unrelated-looking store key is left at its
// default is exactly the kind of thing nobody discovers from behaviour.
func oauthKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap
	if len(cfg.OAuth.Providers) > 0 && !cfg.Stores.Enable.PendingLinks {
		gaps = append(gaps, knobGap{
			Path: "stores.enable.pendingLinks",
			Problem: "the pending-links store is off, so the OAuth state nonce is neither recorded at /oauth/{provider} nor " +
				"consumed at the callback, and a captured state stays replayable for the whole of its TTL instead of exactly once",
			Remedy: "enable stores.enable.pendingLinks (AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS=true) to get the single-use " +
				"nonce; leaving it off keeps the reference's behaviour, where the signature and the TTL are the only defences",
		})
	}
	for _, name := range sortedProviderNames(cfg) {
		if strings.TrimSpace(cfg.OAuth.Providers[name].ProjectID) == "" {
			continue
		}
		gaps = append(gaps, knobGap{
			Path: "oauth.providers." + name + ".projectId",
			Problem: "the OAuth flow never sends a project id — the authorization request carries client_id, redirect_uri, " +
				"response_type, scope and state, and the token exchange the client credentials — so this value reaches nothing",
			Remedy: "leave it set if the same document is deployed to another port in the family; nothing in this build reads it",
		})
	}
	return gaps
}

func sortedProviderNames(cfg *config.Config) []string {
	names := make([]string, 0, len(cfg.OAuth.Providers))
	for name := range cfg.OAuth.Providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
