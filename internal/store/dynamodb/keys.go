package dynamodb

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	typeUser    = "user"
	typeEmail   = "email"
	typeSession = "session"
	typeRefresh = "refresh"
	typeToken   = "token"
	typeMember  = "member"
)

// Sort keys and partition-key prefixes for the item types this package writes.
// The full catalogue is data-model.md §2.2.
const (
	pkUserPrefix    = "USER" + keySep
	pkEmailPrefix   = "EMAIL" + keySep
	pkSessionPrefix = "SESSION" + keySep
	pkRefreshPrefix = "REFRESH" + keySep
	pkTenantPrefix  = "TENANT" + keySep

	// gsi1UserIDPrefix keys the tenant-less by-owner fan-outs. It is distinct
	// from pkUserPrefix because the items that use it (memberships, linked
	// accounts) are reachable from methods that carry no tenant id.
	gsi1UserIDPrefix = "USERID" + keySep

	skProfile      = "PROFILE"
	skEmail        = "EMAIL"
	skSession      = "SESSION"
	skRefresh      = "REFRESH"
	skToken        = "TOKEN"
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
	// ErrInvalidIdentifier means a tenant, user or session id would produce an
	// ambiguous or malformed key.
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

// tokenFamily is the parameterisation of the four single-use token families
// (data-model.md §1.3). They differ only in a key prefix and two profile
// attribute names, so the flow is written once.
type tokenFamily struct {
	name     string
	pkPrefix string
	hashAttr string
	expAttr  string
}

func (f tokenFamily) pk(hash string) string { return f.pkPrefix + hash }

// familyReset is the only family in the P1 subset: UserPasswordStore is
// required, MagicLinkStore / EmailVerificationStore / EmailChangeStore are not.
// The other three are one tokenFamily value each and reuse every function below.
var familyReset = tokenFamily{
	name:     "reset",
	pkPrefix: "RESET" + keySep,
	hashAttr: "resetHash",
	expAttr:  "resetExp",
}
