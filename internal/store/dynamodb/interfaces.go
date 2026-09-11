package dynamodb

import auth "github.com/nik2208/awesome-go-auth"

// The P1 subset, asserted at compile time. The auth core discovers the optional
// interfaces by type assertion on the concrete store, so a signature that drifts
// out of shape would otherwise fail silently — Service would simply stop offering
// the feature and return ErrFeatureNotSupported at runtime.
var (
	_ auth.UserStore          = (*Store)(nil)
	_ auth.UserAccountStore   = (*Store)(nil)
	_ auth.UserPasswordStore  = (*Store)(nil)
	_ auth.SessionStore       = (*Store)(nil)
	_ auth.SessionLookupStore = (*Store)(nil)
	_ auth.SessionAdminStore  = (*Store)(nil)

	// The four single-use token stores, plus TOTP. They are optional to the core
	// and therefore invisible to the compiler at the call site, which is exactly
	// why they are pinned here: a signature that drifts would turn into a 500 on
	// the wire ("store does not implement …") with nothing failing to build.
	_ auth.MagicLinkStore         = (*Store)(nil)
	_ auth.SMSStore               = (*Store)(nil)
	_ auth.EmailVerificationStore = (*Store)(nil)
	_ auth.EmailChangeStore       = (*Store)(nil)
	_ auth.TOTPStore              = (*Store)(nil)

	// UserPhoneStore is declared in account.go rather than store.go, beside the
	// POST /add-phone route that needs it, which is why a derivation that read
	// store.go, oauth.go, api_keys.go and telemetry.go missed it entirely. It was
	// found by driving the routes (cmd/auth's store sweep), not by reading, and it
	// is pinned here so it cannot be lost again.
	_ auth.UserPhoneStore = (*Store)(nil)

	// The two OAuth stores. They cannot be methods on *Store, because
	// auth.LinkedAccountStore and auth.PendingLinkStore both declare Save — with
	// different signatures — and both declare Delete(ctx, string) error, with two
	// different meanings. One type physically cannot satisfy both, so each gets a
	// view constructed from a Store: Store.LinkedAccounts() and
	// Store.PendingLinks().
	//
	// These two are also the only stores here the core does not discover by type
	// assertion. They are handed to it explicitly, through auth.WithOAuth
	// (oauth_wire.go:226-233), which is why the composition root has to pass them
	// and why cmd/auth tests that the routes above them work.
	_ auth.LinkedAccountStore = (*LinkedAccounts)(nil)
	_ auth.PendingLinkStore   = (*PendingLinks)(nil)

	// The template store (template_store.go) is on *Store directly. The view
	// pattern above exists for one reason — a method-name collision — and none
	// of TemplateStore's six names collides with anything here, so a view would
	// be a third type carrying nothing but an indirection. It shares one thing
	// with the two OAuth stores: the core does not discover it by type assertion
	// either, it is handed over explicitly through auth.WithTemplateStore, which
	// is what Store.Templates() exists for and why cmd/auth pins the shape.
	_ auth.TemplateStore = (*Store)(nil)
)

// Interfaces deliberately NOT implemented yet, listed so their absence reads as a
// decision rather than an omission: UserMetadataStore, RolesPermissionsStore,
// TenantStore, APIKeyStore, TelemetryStore. Every one of them has its item type
// designed in docs/spec/data-model.md §1.4-§1.5 and reuses the helpers here;
// stubbing them to return "not implemented" would be worse than leaving them out,
// because the core's type assertions would then advertise features that fail on
// the wire.
