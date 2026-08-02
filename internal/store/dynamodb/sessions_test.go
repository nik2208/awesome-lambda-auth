package dynamodb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

func sampleSession(u auth.User) auth.Session {
	now := time.Now().UTC()
	return auth.Session{
		ID:               uniqueID("ses"),
		UserID:           u.ID,
		TenantID:         u.TenantID,
		RefreshTokenHash: hashOf(uniqueID("refresh")),
		CreatedAt:        now,
		ExpiresAt:        now.Add(30 * 24 * time.Hour),
	}
}

func TestSessionRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	byHash, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash)
	if err != nil {
		t.Fatalf("get by refresh hash: %v", err)
	}
	byID, err := store.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	for name, got := range map[string]auth.Session{"byHash": byHash, "byID": byID} {
		if got.ID != sess.ID || got.UserID != sess.UserID || got.TenantID != sess.TenantID ||
			got.RefreshTokenHash != sess.RefreshTokenHash {
			t.Fatalf("%s: %+v, want %+v", name, got, sess)
		}
		if !got.CreatedAt.Equal(sess.CreatedAt) || !got.ExpiresAt.Equal(sess.ExpiresAt) {
			t.Fatalf("%s: timestamps %v/%v, want %v/%v", name, got.CreatedAt, got.ExpiresAt, sess.CreatedAt, sess.ExpiresAt)
		}
		if got.RevokedAt != nil {
			t.Fatalf("%s: revokedAt = %v, want nil", name, got.RevokedAt)
		}
	}

	if _, err := store.GetSessionByID(ctx, uniqueID("ses")); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("missing session by id: err = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.GetSessionByRefreshTokenHash(ctx, hashOf("nope")); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("missing session by hash: err = %v, want ErrSessionNotFound", err)
	}
}

// rotate performs the sequence Service.Refresh performs: read by the presented
// hash, then write the replacement, both on one context.
func rotateOnce(t *testing.T, store *Store, presented string, next auth.Session) error {
	t.Helper()
	ctx := WithRotationScope(context.Background())
	if _, err := store.GetSessionByRefreshTokenHash(ctx, presented); err != nil {
		return err
	}
	return store.UpdateSession(ctx, next)
}

func TestRotationAdvancesTheSession(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	old := sess.RefreshTokenHash

	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	next.ExpiresAt = sess.ExpiresAt.Add(time.Hour)
	if err := rotateOnce(t, store, old, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	got, err := store.GetSessionByRefreshTokenHash(ctx, next.RefreshTokenHash)
	if err != nil {
		t.Fatalf("get by new hash: %v", err)
	}
	if got.RevokedAt != nil {
		t.Fatalf("rotation revoked the session: %v", got.RevokedAt)
	}
	if !got.ExpiresAt.Equal(next.ExpiresAt) {
		t.Fatalf("expiresAt = %v, want %v", got.ExpiresAt, next.ExpiresAt)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if gen := getN(raw, attrGen); gen != firstGen+1 {
		t.Fatalf("gen = %d, want %d", gen, firstGen+1)
	}
}

func TestReplayedRefreshTokenRevokesTheFamily(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	old := sess.RefreshTokenHash
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := rotateOnce(t, store, old, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Replaying the rotated-out token must not merely fail: it must take the
	// whole family down, because the only explanation for someone holding a spent
	// generation is that it leaked.
	if _, err := store.GetSessionByRefreshTokenHash(ctx, old); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("replay: err = %v, want ErrSessionNotFound", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if getS(raw, attrRevokedAt) == "" {
		t.Fatal("family not revoked after replay")
	}
	if got := getS(raw, attrRevokedReason); got != reasonReplay {
		t.Fatalf("revokedReason = %q, want %q", got, reasonReplay)
	}

	// The current generation is dead too — that is what "family" means.
	after, err := store.GetSessionByRefreshTokenHash(ctx, next.RefreshTokenHash)
	if err != nil {
		t.Fatalf("get current generation after replay: %v", err)
	}
	if after.RevokedAt == nil {
		t.Fatal("current generation still live after the family was revoked")
	}
}

func TestRotationRefusesAStalePrecondition(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))

	// RotateSession is the shape the upstream optional interface should have; a
	// caller that supplies the wrong previous hash is presenting a spent token.
	err := store.RotateSession(ctx, sess.ID, hashOf("never-was-current"), next)
	if !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("err = %v, want ErrSessionNotFound", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if getS(raw, attrRevokedReason) != reasonReplay {
		t.Fatalf("revokedReason = %q, want %q", getS(raw, attrRevokedReason), reasonReplay)
	}
	// The transaction was cancelled as a whole, so no pointer for the rejected
	// token can exist.
	mustNotExist(t, client, store.table, refreshPK(next.RefreshTokenHash), skRefresh)
}

func TestRotationRefusesARevokedSession(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.RevokeSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.RotateSession(ctx, sess.ID, sess.RefreshTokenHash, next); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Fatalf("err = %v, want ErrSessionRevoked", err)
	}
}

func TestRotationOnMissingSession(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if err := store.RotateSession(ctx, sess.ID, hashOf("old"), sess); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("rotate: err = %v, want ErrSessionNotFound", err)
	}
	if err := store.UpdateSession(ctx, sess); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("degraded update: err = %v, want ErrSessionNotFound", err)
	}
}

func TestLogoutRevokesAndIsIdempotent(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	first := time.Now().UTC()
	revoked := sess
	revoked.RevokedAt = &first
	if err := store.UpdateSession(ctx, revoked); err != nil {
		t.Fatalf("logout: %v", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if got := getS(raw, attrRevokedReason); got != reasonLogout {
		t.Fatalf("revokedReason = %q, want %q", got, reasonLogout)
	}
	if got := getS(raw, attrRefreshHash); got != sess.RefreshTokenHash {
		t.Fatalf("logout changed the refresh hash to %q", got)
	}
	stamped := getS(raw, attrRevokedAt)

	// A second logout is a successful logout, and must not relabel the first.
	second := first.Add(time.Minute)
	revoked.RevokedAt = &second
	if err := store.UpdateSession(ctx, revoked); err != nil {
		t.Fatalf("second logout: %v", err)
	}
	raw = rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if getS(raw, attrRevokedAt) != stamped {
		t.Fatalf("revokedAt was overwritten: %q -> %q", stamped, getS(raw, attrRevokedAt))
	}

	// A revoked session is returned, not turned into an error: Service.Refresh
	// maps any error here to ErrSessionNotFound and would lose ErrSessionRevoked.
	got, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash)
	if err != nil {
		t.Fatalf("get revoked session: %v", err)
	}
	if got.RevokedAt == nil {
		t.Fatal("revokedAt not surfaced on the returned session")
	}
}

func TestRevokeSessionByID(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.RevokeSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if got := getS(raw, attrRevokedReason); got != reasonAdmin {
		t.Fatalf("revokedReason = %q, want %q", got, reasonAdmin)
	}
	first := getS(raw, attrRevokedAt)

	if err := store.RevokeSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("revoke twice: %v", err)
	}
	raw = rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if getS(raw, attrRevokedAt) != first {
		t.Fatal("second revoke overwrote the original revocation")
	}

	if err := store.RevokeSessionByID(ctx, uniqueID("ses")); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("revoke missing: err = %v, want ErrSessionNotFound", err)
	}
}

// TestAReplayRevocationSurvivesAnAdminRevoke keeps the audit trail honest: the
// reason a session died is the difference between a routine logout and an
// incident.
func TestAReplayRevocationSurvivesAnAdminRevoke(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := rotateOnce(t, store, sess.RefreshTokenHash, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("replay: %v", err)
	}
	if err := store.RevokeSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if got := getS(raw, attrRevokedReason); got != reasonReplay {
		t.Fatalf("revokedReason = %q, want %q", got, reasonReplay)
	}
}

func TestListSessionsForUser(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	other := newUser(t, store, "acme")

	base := time.Now().UTC().Add(-time.Hour)
	var want []string
	for i := range 3 {
		sess := sampleSession(u)
		sess.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		sess.ExpiresAt = sess.CreatedAt.Add(24 * time.Hour)
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
		want = append(want, sess.ID)
	}
	if _, err := store.CreateSession(ctx, sampleSession(other)); err != nil {
		t.Fatalf("create other user's session: %v", err)
	}
	// Same user id, different tenant: a different GSI1 partition, so it must not
	// appear.
	crossTenant := sampleSession(u)
	crossTenant.TenantID = "other-tenant"
	if _, err := store.CreateSession(ctx, crossTenant); err != nil {
		t.Fatalf("create cross-tenant session: %v", err)
	}

	got, err := store.ListSessionsForUser(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d sessions, want %d: %+v", len(got), len(want), got)
	}
	for i, sess := range got {
		if sess.ID != want[i] {
			t.Fatalf("position %d = %q, want %q (results must be oldest-first)", i, sess.ID, want[i])
		}
		if sess.UserID != u.ID || sess.TenantID != "acme" {
			t.Fatalf("leaked session: %+v", sess)
		}
		// The full item comes from the main table, not the index, so the secrets
		// the index does not project must still be present.
		if sess.RefreshTokenHash == "" {
			t.Fatalf("session %q has no refresh hash; the index projection was trusted", sess.ID)
		}
	}

	empty, err := store.ListSessionsForUser(ctx, uniqueID("usr"), "acme")
	if err != nil {
		t.Fatalf("list for unknown user: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("got %d sessions for an unknown user", len(empty))
	}
}

func TestListSessionsRefusesToExceedItsCap(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MaxSessionsPerUser = 2 })
	ctx := context.Background()
	u := newUser(t, store, "acme")

	for i := range 3 {
		sess := sampleSession(u)
		sess.CreatedAt = sess.CreatedAt.Add(time.Duration(i) * time.Second)
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session %d: %v", i, err)
		}
	}
	if _, err := store.ListSessionsForUser(ctx, u.ID, "acme"); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("err = %v, want ErrResultTooLarge", err)
	}
}

func TestDeleteExpiredSessionsIsANoOp(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	sess.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	// TTL owns expiry, so the cron route has nothing to count. The number is on
	// the wire, hence CompatibilityNotes.
	n, err := store.DeleteExpiredSessions(ctx, time.Now())
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if n != 0 {
		t.Fatalf("deleted = %d, want 0", n)
	}
	if _, err := store.GetSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("expired session must still be readable until TTL reaps it: %v", err)
	}
	notes := store.CompatibilityNotes()
	if len(notes) == 0 {
		t.Fatal("CompatibilityNotes must record the deleted:0 deviation")
	}
}

// TestRotationPreservesStoreSideAttributes guards the one thing a whole-struct
// PutItem would silently destroy: auth.Session has no fields for device metadata,
// so rotation must write an explicit attribute list.
func TestRotationPreservesStoreSideAttributes(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := client.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                 aws.String(store.table),
		Key:                       key(sessionPK(sess.ID), skSession),
		UpdateExpression:          aws.String("SET userAgent = :ua, ipAddress = :ip"),
		ExpressionAttributeValues: map[string]types.AttributeValue{":ua": avS("curl/8"), ":ip": avS("203.0.113.7")},
	}); err != nil {
		t.Fatalf("attach device metadata: %v", err)
	}

	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := rotateOnce(t, store, sess.RefreshTokenHash, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	raw := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
	if getS(raw, "userAgent") != "curl/8" || getS(raw, "ipAddress") != "203.0.113.7" {
		t.Fatalf("device metadata lost across rotation: %v", raw)
	}
}

func TestSessionValidationRejectsForgeableKeys(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	bad := sampleSession(u)
	bad.UserID = "usr#evil"
	if _, err := store.CreateSession(ctx, bad); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("err = %v, want ErrInvalidIdentifier", err)
	}
	bad = sampleSession(u)
	bad.RefreshTokenHash = ""
	if _, err := store.CreateSession(ctx, bad); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("empty refresh hash: err = %v, want ErrInvalidIdentifier", err)
	}
}
