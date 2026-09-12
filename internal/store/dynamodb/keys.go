package dynamodb

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"
)

// Key attribute names. GSI1's are deliberately generic so their meaning can
// differ per item type and change without renaming the index (data-model.md §7).
const (
	attrPK     = "PK"
	attrSK     = "SK"
	attrGSI1PK = "GSI1PK"
	attrGSI1SK = "GSI1SK"
	attrType   = "_t"
	attrVer    = "_v"
	attrTTL    = "ttl"
)

// keySep separates the fixed prefix from the caller-supplied segments. It is the
// reason identifiers are validated: USER#a#b and USER#a + #b are the same
// string, so a tenant id containing '#' would let one tenant forge another
// tenant's partition key.
const keySep = "#"

// schemaVersion is stamped into _v on every item this build writes. Readers
// accept anything at or below it and must tolerate unknown attributes (§7).
const schemaVersion = 1

// Entity types, written to _t so a migration sweep can filter without inferring
// type from key prefixes (§7).
const (
	typeUser        = "user"
	typeEmail       = "email"
	typeSession     = "session"
	typeRefresh     = "refresh"
	typeToken       = "token"
	typeMember      = "member"
	typeLink        = "link"
	typeLinkID      = "linkid"
	typePendingLink = "plink"

	// The two template-directory item types (data-model.md §1.6). Distinct
	// values rather than one shared "template": they have different attribute
	// sets, and _t exists so a migration sweep can tell them apart without
	// inferring type from the sort-key prefix.
	typeMailTemplate  = "template"
	typeUITranslation = "uitranslation"

	// typeAuthCode is one OIDC authorization code (data-model.md §1.7). Its own
	// type rather than typeToken: a token pointer resolves a hash to a user and
	// is a hint the profile can outlive, while an authorization code IS the
	// record — it carries the client, the redirect URI and the PKCE challenge —
	// and a sweep over the two has nothing in common.
	typeAuthCode = "authcode"

	// typeSettings is the deployment's runtime settings document
	// (data-model.md §1.8). There is exactly one of them in the table, which is
	// a reason for _t rather than against it: the singleton is the item a
	// migration sweep is most likely to have to find, and finding it by type is
	// what stops that sweep from hardcoding the key.
	typeSettings = "settings"
)

// Sort keys and partition-key prefixes for the item types this package writes.
// The full catalogue is data-model.md §2.2.
const (
	pkUserPrefix    = "USER" + keySep
	pkEmailPrefix   = "EMAIL" + keySep
	pkSessionPrefix = "SESSION" + keySep
	pkRefreshPrefix = "REFRESH" + keySep
	pkTenantPrefix  = "TENANT" + keySep

	// pkOAuthPrefix keys the linked-account item by the provider account itself,
	// because FindByProvider(provider, providerID) is the primary lookup and
	// neither it nor ListForUser nor Delete carries a tenant (§2.3, "SK=LINK#").
	pkOAuthPrefix = "OAUTH" + keySep

	// pkLinkIDPrefix is the by-id pointer Delete(id) needs: the id is the only
	// thing that method carries and it is not part of the canonical key.
	pkLinkIDPrefix = "LINKID" + keySep

	// pkPendingLinkPrefix keys the OAuth stash by the opaque state string the
	// core composes (oauth_wire.go:417-426).
	pkPendingLinkPrefix = "PLINK" + keySep

	// pkOIDCPrefix keys an OIDC authorization code by the sha256 of the code the
	// client was handed. The hash is the core's own (AuthCode.CodeHash,
	// hashToken), so a dump of this table cannot be redeemed at /token — the
	// same property the refresh, reset and magic-link partitions have.
	pkOIDCPrefix = "OIDC" + keySep

	// gsi1UserIDPrefix keys the tenant-less by-owner fan-outs. It is distinct
	// from pkUserPrefix because the items that use it (memberships, linked
	// accounts) are reachable from methods that carry no tenant id.
	gsi1UserIDPrefix = "USERID" + keySep

	// templatesPK is the directory partition every mail template and UI
	// translation set lives in (data-model.md §1.6) — a constant, not a prefix,
	// the way TENANTS is. auth.TemplateStore carries no tenant and no owner: a
	// template is deployment-global in the reference too, and one partition is
	// what makes each of the two list methods a single Query.
	templatesPK = "TEMPLATES"

	// The two sort-key namespaces of that partition. Their tails are validated
	// against idPattern, so neither can be forged into the other.
	skMailTemplatePrefix  = "MAIL" + keySep
	skUITranslationPrefix = "UI" + keySep

	// settingsPK is the partition of the runtime settings document
	// (data-model.md §1.8). A constant with no separator and no caller-supplied
	// segment, like templatesPK: auth.SettingsStore carries no tenant, no owner
	// and no id — GetSettings takes a context and nothing else — because the
	// settings are deployment-global in the reference too, one object the admin
	// Control panel patches (settings-store.interface.ts:28-40).
	//
	// Its own partition rather than a second sort key under TEMPLATES, even
	// though both are deployment-global configuration. TEMPLATES is a
	// *directory*: its two list methods are single Queries over the whole
	// partition with a begins_with, and an item that is not a template sitting in
	// it would either have to be excluded by every one of them or be returned to
	// a caller expecting a MailTemplate. A partition that holds exactly one item
	// costs nothing extra — DynamoDB charges per item, not per partition — and
	// keeps both key spaces describable in one line each.
	settingsPK = "SETTINGS"

	// skSettings is the single sort key of that partition. The settings are a
	// singleton, so the sort key is a constant, as SESSION's and PLINK's are;
	// there is nothing to name because there is nothing to distinguish.
	skSettings = "SETTINGS"

	// skAuthCode is the single sort key of the OIDC partition. The partition
	// holds exactly one item — the code — so the sort key is a constant, as
	// SESSION's and PLINK's are.
	skAuthCode = "CODE"

	skProfile      = "PROFILE"
	skEmail        = "EMAIL"
	skSession      = "SESSION"
	skRefresh      = "REFRESH"
	skToken        = "TOKEN"
	skOAuth        = "OAUTH"
	skLinkID       = "LINKID"
	skPendingLink  = "PLINK"
	skMemberPrefix = "MEMBER" + keySep
)

// idPattern is the accepted shape of a tenant, user or session identifier. It
// admits everything awesome-go-auth generates ("usr_"/"ses_" + 32 hex chars,
// security.go:18-26) and excludes '#', which is what makes the composite keys
// unambiguous. An empty tenant id is handled separately, in checkTenant.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxEmailKeyLen bounds the email segment of EMAIL#<t>#<email>. DynamoDB's own
// limit is 2048 bytes for a partition key; 320 is the longest address RFC 5321
// permits, and rejecting longer input here turns a mysterious
// ValidationException into a typed error at the boundary.
const maxEmailKeyLen = 320

// Sentinel errors for input the store refuses to turn into a key. They are
// separate from the auth core's errors because they signal a caller bug, not an
// authentication outcome.
var (
	// ErrInvalidIdentifier means a caller-supplied key segment — a tenant, user
	// or session id, an OAuth provider or provider account id, a pending-link
	// state — would produce an ambiguous or malformed key.
	ErrInvalidIdentifier = errors.New("dynamodb: invalid identifier")

	// ErrTenantRequired means multi-tenancy is on and the caller passed the
	// empty tenant. It is a typed error rather than a silent default: both
	// substituting a configured tenant and treating "" as a wildcard would
	// merge or leak tenants (data-model.md §3).
	ErrTenantRequired = errors.New("dynamodb: tenant id is required in multi-tenant mode")

	// ErrInvalidEmail means an email address cannot be used as a key segment.
	ErrInvalidEmail = errors.New("dynamodb: invalid email address")
)

// checkTenant validates a tenant id. "" is a real, distinct tenant — the
// single-tenant deployment's tenant — and maps to the literal partition
// USER##<u>. It is only rejected when multi-tenancy is enabled, where an
// unkeyed write is a bug worth failing loudly (data-model.md §3).
func (s *Store) checkTenant(tenantID string) error {
	if tenantID == "" {
		if s.multiTenant {
			return ErrTenantRequired
		}
		return nil
	}
	if !idPattern.MatchString(tenantID) {
		return fmt.Errorf("%w: tenant %q", ErrInvalidIdentifier, tenantID)
	}
	return nil
}

func checkID(kind, id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%w: %s %q", ErrInvalidIdentifier, kind, id)
	}
	return nil
}

// checkHash guards the hash-keyed capability items. The value occupies the only
// variable segment of its partition key, so '#' inside it is unambiguous and
// need not be rejected; an empty hash, however, would build a key that any
// other empty-hash caller also builds, so it is refused.
func checkHash(kind, hash string) error {
	if hash == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidIdentifier, kind)
	}
	return nil
}

// normalizeEmail mirrors the core's normalization (service.go:58) so the key
// this store computes is the key the core expects. It is duplicated rather than
// imported because it is unexported there.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func checkEmail(email string) error {
	switch {
	case email == "":
		return fmt.Errorf("%w: empty", ErrInvalidEmail)
	case len(email) > maxEmailKeyLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidEmail, maxEmailKeyLen)
	case strings.ContainsAny(email, "\x00\n\r"):
		return fmt.Errorf("%w: contains a control character", ErrInvalidEmail)
	}
	return nil
}

// userPK is USER#<t>#<u>: the tenant is inside the partition key, which is what
// makes cross-tenant reads unwritable rather than merely wrong.
func userPK(tenantID, userID string) string {
	return pkUserPrefix + tenantID + keySep + userID
}

// emailPK is the uniqueness item. Because the tenant segment is '#'-free the
// split is unambiguous however odd the address is.
func emailPK(tenantID, email string) string {
	return pkEmailPrefix + tenantID + keySep + email
}

func sessionPK(sessionID string) string { return pkSessionPrefix + sessionID }

func refreshPK(hash string) string { return pkRefreshPrefix + hash }

func tenantPK(tenantID string) string { return pkTenantPrefix + tenantID }

func memberSK(userID string) string { return skMemberPrefix + userID }

func gsi1UserID(userID string) string { return gsi1UserIDPrefix + userID }

// sessionGSI1SK sorts a user's sessions by creation time. It relies on tsLayout
// being fixed-width: DynamoDB compares sort keys bytewise.
func sessionGSI1SK(createdAt, sessionID string) string {
	return skSession + keySep + createdAt + keySep + sessionID
}

// Bounds on the caller-supplied segments of the OAuth key space. DynamoDB's own
// limit is 2048 bytes for a partition key; rejecting longer input here turns a
// mysterious ValidationException into a typed error at the boundary, the same
// reason maxEmailKeyLen exists.
//
// maxProviderAccountIDLen is generous because a provider account id is whatever
// the provider says it is — a Google `sub`, a GitHub numeric id, or (on the
// account-link path, oauth_wire.go:776-779) an email address.
const (
	maxProviderAccountIDLen = 512
	maxStateKeyLen          = 1024
)

// checkProvider validates the provider name. It occupies a *middle* segment of
// OAUTH#<provider>#<providerId>, so a '#' inside it would make the split
// ambiguous and let one provider forge another's key — the same argument as for
// tenant ids, and idPattern is the same answer.
func checkProvider(provider string) error {
	if !idPattern.MatchString(provider) {
		return fmt.Errorf("%w: provider %q", ErrInvalidIdentifier, provider)
	}
	return nil
}

// checkProviderAccountID validates the provider's own account identifier. It is
// the trailing segment of its partition key, so '#' inside it is unambiguous and
// need not be rejected; empty is refused because OAUTH#google# is a key every
// other empty-id caller also builds, and a binding to "no account" is not a
// binding.
//
// MemoryLinkedAccounts would store one (oauth.go:380-399). This refuses instead:
// the only way to reach it is a provider that returned no account id, which
// HandleCallback should never have got past its profile check, and persisting it
// would make FindByProvider(provider, "") resolve to a real user.
func checkProviderAccountID(providerID string) error {
	switch {
	case providerID == "":
		return fmt.Errorf("%w: empty provider account id", ErrInvalidIdentifier)
	case len(providerID) > maxProviderAccountIDLen:
		return fmt.Errorf("%w: provider account id longer than %d bytes", ErrInvalidIdentifier, maxProviderAccountIDLen)
	case strings.ContainsAny(providerID, "\x00\n\r"):
		return fmt.Errorf("%w: provider account id contains a control character", ErrInvalidIdentifier)
	}
	return nil
}

// checkStateKey validates a PendingLinkStore key. The core composes it from a
// namespace and a nonce, a token hash or an (email, provider) pair
// (oauth_wire.go:417-426), so it is opaque here: it is the only variable segment
// of its partition key and may contain anything except the empty string, which
// every other empty-state caller would also build.
func checkStateKey(state string) error {
	switch {
	case state == "":
		return fmt.Errorf("%w: empty pending-link state", ErrInvalidIdentifier)
	case len(state) > maxStateKeyLen:
		return fmt.Errorf("%w: pending-link state longer than %d bytes", ErrInvalidIdentifier, maxStateKeyLen)
	case strings.ContainsAny(state, "\x00\n\r"):
		return fmt.Errorf("%w: pending-link state contains a control character", ErrInvalidIdentifier)
	}
	return nil
}

// oauthPK is the linked account's canonical key. The provider is '#'-free, so
// the split is unambiguous however odd the account id is.
func oauthPK(provider, providerID string) string {
	return pkOAuthPrefix + provider + keySep + providerID
}

// oauthGSI1SK sorts a user's links by provider then account, and carries both
// values in the index key so the by-owner query needs no extra projection.
func oauthGSI1SK(provider, providerID string) string {
	return skOAuth + keySep + provider + keySep + providerID
}

func linkIDPK(linkID string) string { return pkLinkIDPrefix + linkID }

func pendingLinkPK(state string) string { return pkPendingLinkPrefix + state }

// authCodePK keys an authorization code by its hash. The hash is the only
// variable segment of the partition key, so '#' inside it is unambiguous and
// need not be rejected; an empty one is refused by checkHash, because OIDC# is a
// key every other empty-hash caller would also build.
func authCodePK(codeHash string) string { return pkOIDCPrefix + codeHash }

// mailTemplateSK and uiTranslationSK key the two entries of the template
// directory under templatesPK. The id and the page are validated with checkID
// before either is called: the template ids the core defines (mailer.go:240-245,
// "password-reset" and its siblings) all satisfy idPattern, and '#' is excluded
// so MAIL#<id> cannot be made to read as anything else.
func mailTemplateSK(id string) string { return skMailTemplatePrefix + id }

func uiTranslationSK(page string) string { return skUITranslationPrefix + page }

// mailTemplateIDFromSK and uiTranslationPageFromSK are the inverses. Neither
// value is duplicated into an attribute of its own (data-model.md §5, "Mail
// template"), so the sort key is the one place it lives and these are the only
// decoders.
func mailTemplateIDFromSK(sk string) (string, bool) {
	return strings.CutPrefix(sk, skMailTemplatePrefix)
}

func uiTranslationPageFromSK(sk string) (string, bool) {
	return strings.CutPrefix(sk, skUITranslationPrefix)
}

// pendingLinkSingleUsePrefixes are the two PendingLinkStore namespaces whose
// entries are credentials spent exactly once, and are therefore consumed by the
// read that resolves them (see PendingLinks.Get).
//
// The core's own doc for the field says so — "It carries two kinds of entry,
// both keyed by an opaque string and both single-use: the in-flight OAuth state
// (so a nonce cannot be replayed) and the account-link token issued by
// /link-request" (oauth_wire.go:170-174) — and both are written by the core
// (oauth_wire.go:485, :710) and read exactly once (:530, :765).
//
// The third namespace the core knows about, "pending-link:", is deliberately not
// here. It is the host-written account-conflict stash, and LinkRequest *reads* it
// to resolve an identity (oauth_wire.go:689) while LinkVerify deletes it only
// after the link has been written (:804). Consuming it on read would make an
// ordinary retry of POST /link-request — a user whose mail never arrived, or a
// first attempt that failed its own GetUserByEmail — answer 401 UNAUTHORIZED
// instead of issuing a second token.
//
// Anything else is treated as re-readable, which is exactly MemoryPendingLinks'
// behaviour (oauth_wire.go:871-884). That is the safe default for an unknown
// namespace in one direction and the unsafe one in the other: failing to consume a
// new single-use kind loses an atomicity guarantee the reference never had, where
// consuming a new re-readable kind would silently break a working flow. The
// tie-breaker is that a broken flow is loud and a replayable credential is not — so
// the default stays "re-readable" and the silence is removed instead, by
// warnUnknownPendingLinkNamespace.
var pendingLinkSingleUsePrefixes = []string{"oauth-state:", "link-token:"}

// pendingLinkReReadablePrefixes are the namespaces this build positively knows are
// not credentials. Listing them is what makes an unrecognised namespace
// distinguishable from a deliberately re-readable one, and therefore reportable:
// this store's classification is a coupling to key builders the core does not
// export (oauth_wire.go:417-426), so a core upgrade that renames or adds one cannot
// be caught at compile time and must at least not pass in silence.
var pendingLinkReReadablePrefixes = []string{"pending-link:"}

// pendingLinkIsSingleUse reports whether a key names a credential rather than a
// stash entry.
func pendingLinkIsSingleUse(state string) bool {
	return hasAnyPrefix(state, pendingLinkSingleUsePrefixes)
}

// pendingLinkIsKnown reports whether this build recognises the key's namespace at
// all, either as a credential or as a stash entry.
func pendingLinkIsKnown(state string) bool {
	return pendingLinkIsSingleUse(state) || hasAnyPrefix(state, pendingLinkReReadablePrefixes)
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// pendingLinkNamespace is the part of a key that is safe to log: everything up to
// and including the first ':'.
//
// The remainder must never be logged. For "oauth-state:" it is the CSRF nonce
// itself, and for "link-token:" it is the sha256 of a live account-link token —
// both are the credential, not an identifier for it.
func pendingLinkNamespace(state string) string {
	if i := strings.Index(state, ":"); i >= 0 {
		return state[:i+1]
	}
	return "(no namespace)"
}

// tokenFamily is the parameterisation of the single-use token families
// (data-model.md §1.3). They differ only in a key prefix, two profile attribute
// names and — for email change — one extra attribute, so the flow is written
// once and each family is a value rather than a copy.
//
// That is deliberate beyond mere brevity: these five are the whole "issue a
// secret, consume it exactly once" surface, and a reviewer who has checked one
// conditional write has checked all of them. A fifth variant with its own
// hand-rolled condition would be the thing that quietly gets it wrong.
type tokenFamily struct {
	// name appears in error messages and in the pointer item's `family`
	// attribute, which is what makes a migration sweep over one family possible.
	name string

	// pkPrefix is the pointer item's partition-key prefix. Empty means the
	// family has no pointer item at all: GetUserBySMSCodeHash already carries
	// (userID, tenantID) (store.go:51), so the profile is directly addressable
	// and a pointer would cost a write per send and a read per verify to
	// resolve something the caller already knows (§2.3, "OTP# ephemeral item").
	pkPrefix string

	// hashAttr and expAttr are the two profile attributes that constrain each
	// other. They share one item because a DynamoDB condition is per-item: split
	// them and "the hash matches AND it has not expired" stops being expressible
	// as a single atomic check, which is the entire point of these stores.
	hashAttr string
	expAttr  string

	// extraIssueAttrs names the attributes issue writes beyond the hash and
	// expiry, for validation and documentation; the values come from the caller.
	extraIssueAttrs []string

	// extraClearAttrs are removed by Clear*Token alongside the hash and expiry,
	// and deliberately *not* by the consuming read. Email change is the reason:
	// ApplyEmailChange reads pendingEmail off the profile *after* the token has
	// been consumed (service.go:472-479), so consuming must leave it in place
	// while clearing must take it away, exactly as MemoryUserStore does
	// (memory_store.go:395).
	extraClearAttrs []string

	// invalidErr is what an unknown, already-consumed or expired value maps to.
	// SMS answers ErrInvalidCode where the token families answer ErrInvalidToken
	// (memory_store.go:238 versus :195), and the wire mapping is built on that
	// distinction, so it is a per-family property rather than a constant.
	invalidErr error
}

func (f tokenFamily) pk(hash string) string { return f.pkPrefix + hash }

// hasPointer reports whether a hash is resolved through a pointer item, i.e.
// whether the lookup method carries a tenant and user id of its own.
func (f tokenFamily) hasPointer() bool { return f.pkPrefix != "" }

// The five families. Four are pointer-backed because their lookup methods carry
// no tenant id and the profile lives under USER#<t>#<u>; SMS is not, because its
// lookup carries both.
var (
	familyReset = tokenFamily{
		name:       "reset",
		pkPrefix:   "RESET" + keySep,
		hashAttr:   "resetHash",
		expAttr:    "resetExp",
		invalidErr: auth.ErrInvalidToken,
	}

	familyMagic = tokenFamily{
		name:       "magic",
		pkPrefix:   "MAGIC" + keySep,
		hashAttr:   attrMagicHash,
		expAttr:    attrMagicExp,
		invalidErr: auth.ErrInvalidToken,
	}

	familyVerify = tokenFamily{
		name:       "verify",
		pkPrefix:   "VERIFY" + keySep,
		hashAttr:   attrVerifyHash,
		expAttr:    attrVerifyExp,
		invalidErr: auth.ErrInvalidToken,
	}

	// familyEchg carries the address the change is *to*. It is written with the
	// token and cleared with the token, so a stale token can never be the reason
	// a pending address survives.
	familyEchg = tokenFamily{
		name:            "echg",
		pkPrefix:        "ECHG" + keySep,
		hashAttr:        attrEchgHash,
		expAttr:         attrEchgExp,
		extraIssueAttrs: []string{attrPendingEmail},
		extraClearAttrs: []string{attrPendingEmail},
		invalidErr:      auth.ErrInvalidToken,
	}

	familySMS = tokenFamily{
		name:       "sms",
		hashAttr:   attrSMSHash,
		expAttr:    attrSMSExp,
		invalidErr: auth.ErrInvalidCode,
	}
)

// pointerFamilies is the set that writes a pointer item. DeleteUser sweeps them
// off the profile, and the family tests iterate it so a new family cannot be
// added without being covered.
var pointerFamilies = []tokenFamily{familyReset, familyMagic, familyVerify, familyEchg}
