package main

import (
	"log/slog"

	auth "github.com/nik2208/awesome-go-auth"
)

// WireDeviation is one place this product knowingly answers differently from
// the reference at the configuration layer: a default, a refusal or a policy
// that no store and no core route owns, and that a client can observe.
//
// The other two registers live where their behaviour lives — the imported core
// publishes auth.CompatibilityNotes() and the DynamoDB store publishes
// (*Store).CompatibilityNotes() — and docs/deviations.md indexes all three.
// deviations_test.go fails when an entry of any register is missing from that
// index, so a deviation cannot quietly stop being documented.
type WireDeviation struct {
	// ID is the stable handle. It never changes once published.
	ID string
	// Surface is the knob or route affected.
	Surface string
	// Behaviour is what this product does.
	Behaviour string
	// Reference is what awesome-node-auth does instead.
	Reference string
	// Why is the reason the reproduce-the-reference rule was set aside.
	Why string
	// Spec names the document and section that argues the decision.
	Spec string
}

// WireDeviations returns the product-level register, freshly built on every
// call.
func WireDeviations() []WireDeviation {
	return []WireDeviation{
		{
			ID:      "csrf-enabled-by-default",
			Surface: "security.csrf.enabled, every cookie-authenticated unsafe request",
			Behaviour: "Double-submit CSRF is enforced unless the operator turns it off, " +
				"and turning it off in production is refused (RS-3).",
			Reference: "csrf.enabled defaults to false (src/middleware/auth.middleware.ts:35), " +
				"so a deployment that never mentions CSRF runs without it.",
			Why: "A deployable product has to be safe with an empty configuration; a " +
				"library can leave the choice to the integrator.",
			Spec: "docs/spec/config-schema.md §1.3 and §2 RS-3",
		},
		{
			ID:      "production-by-default",
			Surface: "deployment.environment",
			Behaviour: "The environment defaults to production, which is the strict side of " +
				"every rule that distinguishes the two: memory stores are refused, " +
				"env-sourced secrets are warned about, swagger is off.",
			Reference: "There is no environment knob; behaviour that depends on one reads " +
				"NODE_ENV, which is unset in a fresh process and therefore not production.",
			Why: "A stack deployed by someone who forgot to say which environment it is " +
				"should get the stricter rules, not the looser ones.",
			Spec: "docs/spec/config-schema.md §1 (deployment) and §2",
		},
		{
			ID:      "refresh-token-families",
			Surface: "POST <prefix>/refresh",
			Behaviour: "Refresh tokens form a family per session: a replayed refresh token " +
				"revokes the whole session, and every later refresh on it answers 401 " +
				"SESSION_REVOKED.",
			Reference: "Rotation replaces the token; a replay fails as an invalid token and " +
				"the session stays alive.",
			Why: "A replay is the signature of a stolen refresh token, and on a serverless " +
				"stack the store is the only place the theft can be acted on.",
			Spec: "docs/spec/data-model.md §4.3; docs/spec/decisions.md D-7 (signed off 2026-09-11)",
		},
		{
			ID:      "templates-dir-only-seeds-absent-ids",
			Surface: "email.templatesDir, and the body and subject of every mail rendered from a stored template",
			Behaviour: "The directory is read once, at cold start, and writes only the template ids " +
				"and UI pages the template store does not already hold; a template saved " +
				"through the store wins over the file of the same id, on every cold start.",
			Reference: "There is no templates directory: config.templateStore is the only " +
				"override source and its contents come from whoever writes to it " +
				"(src/interfaces/template-store.interface.ts:13-43, memory-template.store.ts).",
			Why: "A Lambda has no writable filesystem and no deploy step that runs code, so " +
				"the artifact is the only place a shipped template can live and cold start " +
				"the only moment it can be read; and a runtime edit must survive the next " +
				"redeploy, or the admin API would be undone by every cold start.",
			Spec: "docs/spec/config-schema.md §1.5, §3.8 and §3.10; docs/spec/decisions.md D-17",
		},
	}
}

// logDeviations writes every register to the cold-start log, so a deployment
// announces the ways it differs from the reference instead of leaving them to
// be discovered from a client's bug report. storeNotes is nil for a driver
// that publishes none.
func logDeviations(log *slog.Logger, storeNotes []string) {
	for _, d := range WireDeviations() {
		log.Info("wire deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, d := range auth.CompatibilityNotes().KnownDeviations {
		log.Info("core deviation", slog.String("id", d.ID), slog.String("surface", d.Surface))
	}
	for _, note := range storeNotes {
		log.Info("store compatibility note", slog.String("note", note))
	}
}
