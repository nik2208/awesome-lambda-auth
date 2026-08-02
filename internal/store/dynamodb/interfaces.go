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
)

// Interfaces deliberately NOT implemented yet, listed so their absence reads as a
// decision rather than an omission: MagicLinkStore, SMSStore, TOTPStore,
// EmailVerificationStore, EmailChangeStore, UserMetadataStore,
// RolesPermissionsStore, TenantStore, APIKeyStore, LinkedAccountStore,
// PendingLinkStore, TelemetryStore. Every one of them has its item type designed
// in docs/spec/data-model.md §1.3-§1.5 and reuses the helpers here; stubbing them
// to return "not implemented" would be worse than leaving them out, because the
// core's type assertions would then advertise features that fail on the wire.
