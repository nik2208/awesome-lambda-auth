package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// Token claims: what this deployment puts in a token besides the six claims
// every port writes. Together with the TOTP issuer in twofactor.go this is the
// P3 block of the schema — security.jwt.extraClaims and
// security.jwt.claimsWebhook — which internal/config/phases.go no longer
// refuses.
//
// ── what the reference has instead ───────────────────────────────────────────
//
// One mechanism, and it is code: config.buildTokenPayload(user), an in-process
// function whose result is spread over the base payload
// (auth-config.model.ts:316, auth.router.ts:378-384). A configuration document
// cannot carry a function, so the schema splits that one hook in two
// (config-schema.md §3.1): a declarative mapping table for the common case —
// copy a user field, or write a constant — and a webhook for the rest, because
// arbitrary computation is irreducibly code and the only way to reach code from
// a document is to call it.
//
// ── none of the mechanics are here ───────────────────────────────────────────
//
// The core ships all four pieces: auth.StaticClaims for {const: …},
// auth.UserFieldClaims for {fromUserField: …}, auth.ChainClaims to compose them
// and auth.ClaimsWebhook for the HTTP escape hatch. This file decodes the
// document onto them and does nothing else — no claim is read out of a User
// here, no request is built here, no field allowlist is written down here. That
// is the same rule the delivery seam follows with the ready-made mailers, and
// for the same reason: a second definition of a wire detail is free to diverge
// from the first, and the first is upstream's.
//
// ── the order, and why the webhook is last ───────────────────────────────────
//
// ChainClaims merges in order and the later builder wins a shared name, so the
// chain is: mapped user fields, then constants, then the webhook. The first two
// can never collide — a claim name is one key of one map and validate.go
// refuses an entry that is both fromUserField and const — so their order is
// arbitrary and only the webhook's position is a decision. It goes last because
// it is the one that computed its answer for this user at this moment, while
// the table says the same thing for everybody; a deployment that configures
// both wants the computed value to win, or it would not be paying for the round
// trip.
//
// Nothing in the chain can touch the session claims. issueToken writes sid,
// tid, jti, typ, iss, iat and exp *after* the merge, so a builder cannot retype
// a token or rebind its session (token.go) — which is what makes it safe to let
// an endpoint on somebody else's network contribute to a credential at all.
//
// ── failing closed (decision D-10) ───────────────────────────────────────────
//
// D-10 says a claims-webhook failure fails closed, and the core already does
// it, so this file implements none of it and the tests verify it instead. A
// builder error aborts the mint (token.go), which surfaces as the generic 500
// the core writes for a broken host hook — HTTPErrInternal, message "Internal
// server error", deliberately code-less. D-10's own text predicted a
// CLAIMS_WEBHOOK_FAILED code; there is none, because the envelope an adapter
// writes is not this product's to add to, and the decision has been amended to
// say so rather than the port inventing a code no other member of the family
// emits.
//
// One place deliberately does NOT fail closed, and it is worth knowing before
// reading a log: GET /me runs the builder too — its body is the profile, and
// customClaims is rendered in it — but Service.Me logs a builder failure and
// leaves customClaims empty rather than failing the read (service.go). So a
// receiver that is down takes logins and refreshes with it and leaves /me
// answering, minus the claims. The authenticated middleware path runs the
// builder zero times: Service.Authenticate never calls it, because what the
// hook computed is already inside the token the request carried. One login is
// one request to the receiver; a protected route is none.

// claimsConfigured is the enable signal, and like every other one in this
// binary it is derived from what validation already requires rather than from a
// new knob: a table with entries in it, or a url that passed validateJWT —
// which refuses a url without its signing secret, so a non-empty url is exactly
// "the operator configured a signed receiver and it validated".
func claimsConfigured(cfg *config.Config) bool {
	return len(cfg.Security.JWT.ExtraClaims) > 0 || strings.TrimSpace(cfg.Security.JWT.ClaimsWebhook.URL) != ""
}

// claimsOptions builds the token claims hook, or returns nothing at all when
// neither half is configured — which leaves Config.BuildTokenClaims nil and
// every token carrying exactly the six base claims.
//
// client is the same injected *http.Client the delivery webhook takes, for the
// same reason: the receiver has to be https, so a test needs one it trusts. Nil
// is http.DefaultClient and is what the binary passes.
//
// The error is a refuse-to-start. Both of its causes are documents rather than
// outages — a claim mapped from a field that does not exist, a claim named
// after a reserved session claim, a url the core will not take — and a document
// fault has to stop the deployment where an operator can see it, not turn every
// login into a 500.
func claimsOptions(cfg *config.Config, client *http.Client, log *slog.Logger) ([]auth.Option, error) {
	if !claimsConfigured(cfg) {
		return nil, nil
	}

	fields, static, err := splitExtraClaims(cfg)
	if err != nil {
		return nil, err
	}

	var builders []auth.TokenClaimsBuilder
	if len(fields) > 0 {
		// Built once over the whole table. The per-entry pass above has already
		// located every bad mapping by path, so this call cannot fail for a
		// reason the operator has not already been told about.
		mapped, err := auth.UserFieldClaims(fields)
		if err != nil {
			return nil, fmt.Errorf("config: refusing to start: security.jwt.extraClaims: %w", err)
		}
		builders = append(builders, mapped)
	}
	if len(static) > 0 {
		builders = append(builders, auth.StaticClaims(static))
	}

	webhook := "none"
	hook, err := newClaimsWebhook(cfg, client)
	if err != nil {
		return nil, err
	}
	if hook != nil {
		// hook.Build is not appended directly: its error carries the receiver's
		// whole URL and Service.Me writes that error to the log on every GET
		// /me while the receiver is unwell. See claimsBuilder.
		builders = append(builders, claimsBuilder(hook))
		webhook = webhookOrigin(hook.URL)
	}

	log.Info("token claims wired",
		slog.Int("mappedClaims", len(fields)),
		slog.Int("constantClaims", len(static)),
		slog.String("claimsWebhook", webhook),
		slog.Int("claimsWebhookTimeoutMs", cfg.Security.JWT.ClaimsWebhook.TimeoutMs),
		slog.String("onWebhookFailure", "the mint fails and login, refresh and 2FA step-up answer 500; GET /me answers without customClaims"))

	return []auth.Option{auth.WithTokenClaimsBuilder(auth.ChainClaims(builders...))}, nil
}

// newClaimsWebhook builds the receiver security.jwt.claimsWebhook.url names, or
// returns nil when the block is off.
//
// Separate from claimsOptions for the reason newDelivery hands back its own
// *auth.DeliveryWebhook: the deadline is the one property of this thing that a
// test has to be able to observe without going through a login, because a login
// also hashes a password and the assertion "the configured timeout is what
// bounds the request" cannot be made against a measurement that includes bcrypt.
func newClaimsWebhook(cfg *config.Config, client *http.Client) (*auth.ClaimsWebhook, error) {
	url := strings.TrimSpace(cfg.Security.JWT.ClaimsWebhook.URL)
	if url == "" {
		return nil, nil
	}
	hook, err := auth.NewClaimsWebhook(url, cfg.SecretValue("security.jwt.claimsWebhook.secret"))
	if err != nil {
		// Unreachable in practice — validate.go has already refused everything
		// the core's parser would — but scrubbed anyway, because the core's
		// message quotes the url it rejected and this one goes to CloudWatch
		// like any other cold-start failure. The path names the knob; the value
		// is not what the operator is missing.
		return nil, fmt.Errorf("config: refusing to start: security.jwt.claimsWebhook.url: %w", scrubbedWebhookError(err, url))
	}
	// timeoutMs bounds one request, connect to last byte, through the request
	// context; validate.go guarantees it is positive and no larger than its
	// ceiling — a deadline past the function's own Timeout would bound nothing.
	// A login is waiting on the answer inside a Lambda invocation, so this is
	// what keeps a slow receiver from turning every login into a function
	// timeout — and the core's own 2 second default is not necessarily this
	// deployment's idea of slow.
	hook.Timeout = time.Duration(cfg.Security.JWT.ClaimsWebhook.TimeoutMs) * time.Millisecond
	hook.Client = client
	return hook, nil
}

// claimsBuilder is hook.Build with the receiver's URL taken out of its errors.
//
// It exists because this half of the binary is the one that logs on failure
// rather than refusing. A failing mint answers 500 and the error reaches no
// log; GET /me does not fail closed — Service.Me logs the builder's error and
// answers without customClaims — and that log line is written through
// Config.Logger into CloudWatch. The core's error wraps the *url.Error from
// net/http, which prints the whole URL including its path, and the path of a
// webhook is where an operator puts a capability token when the receiver cannot
// verify an HMAC itself. That is the same value the cold-start line above
// reduces to its origin and internal/config refuses without quoting
// (absoluteURLOrigin); a per-request leak would undo both.
//
// The scrubbing is delivery.go's, shared with the delivery webhook, which has
// the identical shape for the identical reason.
func claimsBuilder(hook *auth.ClaimsWebhook) auth.TokenClaimsBuilder {
	return func(ctx context.Context, user auth.User) (map[string]any, error) {
		claims, err := hook.Build(ctx, user)
		if err != nil {
			return nil, scrubbedWebhookError(err, hook.URL)
		}
		return claims, nil
	}
}

// splitExtraClaims decodes security.jwt.extraClaims into the two shapes the
// core's constructors take, refusing every entry neither of them would honour.
//
// Both refusals name the entry's own dotted path, which is the whole reason for
// the per-entry pass: the core's errors name the claim but not the knob, and an
// operator reading a cold-start failure needs the line of the document to edit.
// Every entry is checked before any is reported, following the config layer's
// convention — a document with three bad mappings is fixed in one edit rather
// than in three deployments.
//
// The reserved-name check is auth.UserFieldClaims itself, applied to a
// one-entry table, and it is deliberately not a list of names copied into this
// file. sid, tid, jti, typ, iss, iat and exp are reserved because issueToken
// writes them after the merge; that list belongs to the core and changes with
// it, and a copy here would keep accepting a name the day the core reserved it
// — which is precisely the failure it exists to prevent, since issueToken
// discards such a claim silently on every mint. A constant is run through the
// same check with a field that is known-good, so that only the *name* can be
// what the call refuses. validate.go already refuses the six base claims, which
// are a different thing: those a builder may legitimately override, and the
// product refuses them because the family's clients read them.
func splitExtraClaims(cfg *config.Config) (fields map[string]string, static map[string]any, err error) {
	fields = make(map[string]string)
	static = make(map[string]any)

	names := make([]string, 0, len(cfg.Security.JWT.ExtraClaims))
	for name := range cfg.Security.JWT.ExtraClaims {
		names = append(names, name)
	}
	sort.Strings(names)

	var problems []error
	for _, name := range names {
		claim := cfg.Security.JWT.ExtraClaims[name]
		path := "security.jwt.extraClaims." + name

		field := claim.FromUserField
		if field == "" {
			// A constant: only the name is under test, so the field is one the
			// allowlist certainly holds.
			field = "id"
		}
		if _, nameErr := auth.UserFieldClaims(map[string]string{name: field}); nameErr != nil {
			problems = append(problems, fmt.Errorf("config: refusing to start: %s: %w", path, nameErr))
			continue
		}

		if claim.FromUserField != "" {
			fields[name] = claim.FromUserField
			continue
		}
		static[name] = claim.Const
	}
	if len(problems) > 0 {
		return nil, nil, errors.Join(problems...)
	}
	return fields, static, nil
}
