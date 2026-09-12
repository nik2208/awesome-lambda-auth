package dynamodb

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// Session and refresh-pointer attributes.
const (
	attrSessionID     = "sessionId"
	attrRefreshHash   = "refreshHash"
	attrGen           = "gen"
	attrExpiresAt     = "expiresAt"
	attrRevokedAt     = "revokedAt"
	attrRevokedReason = "revokedReason"
	attrRevokedGen    = "revokedGen"
)

// Revocation reasons. They are stored, not derived, because the reason a session
// died is the difference between an audit line and a security incident.
const (
	reasonLogout = "logout"
	reasonAdmin  = "admin_revoke"
	reasonReplay = "refresh_replay"
)

// firstGen is the generation a freshly created session starts at. It counts
// rotations, and is pinned in the rotation condition so a replay cannot land on
// a generation that has already moved.
const firstGen int64 = 1

// sessionItem encodes an auth.Session. Device metadata the HTTP layer may have
// attached (userAgent, ipAddress, lastActiveAt) has no home on auth.Session, so
// rotation must never PutItem over a session — see rotate, which uses UpdateItem
// with an explicit attribute list precisely so those extras survive (§5).
func (s *Store) sessionItem(sess auth.Session, gen int64) item {
	createdAt := formatTime(sess.CreatedAt)
	it := item{}.
		sAlways(attrPK, sessionPK(sess.ID)).
		sAlways(attrSK, skSession).
		stamp(typeSession).
		sAlways(attrSessionID, sess.ID).
		sAlways(attrUserID, sess.UserID).
		sAlways(attrTenantID, sess.TenantID).
		sAlways(attrRefreshHash, sess.RefreshTokenHash).
		n(attrGen, gen).
		sAlways(attrCreatedAt, createdAt).
		sAlways(attrExpiresAt, formatTime(sess.ExpiresAt)).
		sAlways(attrGSI1PK, userPK(sess.TenantID, sess.UserID)).
		sAlways(attrGSI1SK, sessionGSI1SK(createdAt, sess.ID)).
		ttl(sess.ExpiresAt.Add(s.ttlGrace))
	it.tp(attrRevokedAt, sess.RevokedAt)
	return it
}

func sessionFromItem(m map[string]types.AttributeValue) (auth.Session, error) {
	if err := checkVersion(m, typeSession); err != nil {
		return auth.Session{}, err
	}
	sess := auth.Session{
		ID:               getS(m, attrSessionID),
		UserID:           getS(m, attrUserID),
		TenantID:         getS(m, attrTenantID),
		RefreshTokenHash: getS(m, attrRefreshHash),
	}
	var err error
	if sess.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.Session{}, err
	}
	if sess.ExpiresAt, err = getTime(m, attrExpiresAt); err != nil {
		return auth.Session{}, err
	}
	if sess.RevokedAt, err = getTimePtr(m, attrRevokedAt); err != nil {
		return auth.Session{}, err
	}
	return sess, nil
}

// refreshPointer maps a refresh-token hash back to its session. The hash is a
// capability: possession of the 256-bit value is the authorisation, so the item
// is global and carries the tenant id for the next access to key on (§3).
func (s *Store) refreshPointer(sess auth.Session, gen int64) item {
	return item{}.
		sAlways(attrPK, refreshPK(sess.RefreshTokenHash)).
		sAlways(attrSK, skRefresh).
		stamp(typeRefresh).
		sAlways(attrSessionID, sess.ID).
		sAlways(attrUserID, sess.UserID).
		sAlways(attrTenantID, sess.TenantID).
		n(attrGen, gen).
		ttl(sess.ExpiresAt.Add(s.ttlGrace))
}

func (s *Store) checkSession(sess auth.Session) error {
	if err := s.checkTenant(sess.TenantID); err != nil {
		return err
	}
	if err := checkID("session id", sess.ID); err != nil {
		return err
	}
	if err := checkID("user id", sess.UserID); err != nil {
		return err
	}
	return checkHash("refresh token hash", sess.RefreshTokenHash)
}

// The session interfaces. SessionStore is handed to the core by name
// (auth.WithSessionStore); the other two are discovered by type assertion, so a
// drifted signature there is a GET /sessions or a POST /sessions/cleanup that
// answers 501 from a binary that built cleanly. See interfaces.go for the
// convention.
var (
	_ auth.SessionStore       = (*Store)(nil)
	_ auth.SessionLookupStore = (*Store)(nil)
	_ auth.SessionAdminStore  = (*Store)(nil)
)

// CreateSession writes the session and its first refresh pointer in one
// transaction (data-model.md #10), so a session can never exist without a way to
// resolve it from the token that was already handed to the client.
func (s *Store) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	if err := s.checkSession(sess); err != nil {
		return auth.Session{}, err
	}
	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			// Unconditional, matching MemorySessionStore.CreateSession
			// (memory_store.go:414-420). Session ids are 128 bits of randomness,
			// so an overwrite is not a case that arises.
			{Put: &types.Put{TableName: aws.String(s.table), Item: s.sessionItem(sess, firstGen)}},
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item:      s.refreshPointer(sess, firstGen),
				// Tolerating the same session reclaiming its own pointer keeps a
				// retried login idempotent; a different session behind the same
				// hash would be a sha256 collision and stays loud.
				ConditionExpression:       aws.String("attribute_not_exists(#PK) OR #sessionId = :sid"),
				ExpressionAttributeNames:  exprNames(attrPK, attrSessionID),
				ExpressionAttributeValues: map[string]types.AttributeValue{":sid": avS(sess.ID)},
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			if _, failed := txFailedAt(reasons, 1); failed {
				return auth.Session{}, errors.New("dynamodb: refresh token hash already bound to another session")
			}
		}
		return auth.Session{}, wrap("create session", err)
	}
	return sess, nil
}

// GetSessionByRefreshTokenHash resolves the pointer, then the session, and
// decides whether the token presented is the current generation.
//
// A hash that resolves to a live session whose refreshHash has moved on can only
// be a generation that was already exchanged — a replay. The answer is immediate
// revocation of the whole family (the family *is* the session: Service.Refresh
// keeps session.ID across rotations and only replaces the hash, service.go:122-162).
// Writing inside a nominally read-only method is a deliberate deviation:
// deferring the response until the next request leaves the attacker a valid
// window.
//
// A session that is already revoked is returned rather than turned into an
// error, because Service.Refresh maps any error from this method to
// ErrSessionNotFound (service.go:129-131) and would therefore swallow
// ErrSessionRevoked; returning the populated struct is what puts the right status
// on the wire.
func (s *Store) GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (auth.Session, error) {
	if err := checkHash("refresh token hash", tokenHash); err != nil {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	ptr, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(refreshPK(tokenHash), skRefresh),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.Session{}, wrap("get refresh pointer", err)
	}
	if len(ptr.Item) == 0 {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	if err := checkVersion(ptr.Item, typeRefresh); err != nil {
		return auth.Session{}, err
	}
	pointerGen := getN(ptr.Item, attrGen)

	current, err := s.getSessionItem(ctx, getS(ptr.Item, attrSessionID))
	if err != nil {
		return auth.Session{}, err
	}
	sess, err := sessionFromItem(current)
	if err != nil {
		return auth.Session{}, err
	}
	if sess.RevokedAt != nil {
		return sess, nil
	}
	if getS(current, attrRefreshHash) != tokenHash {
		if err := s.revokeFamily(ctx, sess.ID, reasonReplay, pointerGen); err != nil {
			return auth.Session{}, err
		}
		return auth.Session{}, auth.ErrSessionNotFound
	}

	// Hand the precondition to UpdateSession, which the interface leaves no room
	// to pass it to. See rotation.go.
	if scope := rotationScopeFrom(ctx); scope != nil {
		scope.record(sess.ID, rotationPrecondition{
			oldHash: tokenHash,
			gen:     getN(current, attrGen),
			hasGen:  true,
		})
	}
	return sess, nil
}

// GetSessionByID implements SessionLookupStore. An expired-but-not-yet-reaped
// item is returned as-is: TTL is best effort, and the core owns the expiry
// decision (service.go:136).
func (s *Store) GetSessionByID(ctx context.Context, sessionID string) (auth.Session, error) {
	if err := checkID("session id", sessionID); err != nil {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	m, err := s.getSessionItem(ctx, sessionID)
	if err != nil {
		return auth.Session{}, err
	}
	return sessionFromItem(m)
}

func (s *Store) getSessionItem(ctx context.Context, sessionID string) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(sessionPK(sessionID), skSession),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get session", err)
	}
	if len(out.Item) == 0 {
		return nil, auth.ErrSessionNotFound
	}
	return out.Item, nil
}

// UpdateSession is the one interface method that means two different things. The
// core calls it to revoke (Logout sets RevokedAt, service.go:178-180) and to
// rotate (Refresh replaces the hash and expiry, service.go:157-159), and the two
// need opposite conditions, so they are split here on the only signal available.
func (s *Store) UpdateSession(ctx context.Context, sess auth.Session) error {
	if err := s.checkSession(sess); err != nil {
		return err
	}
	if sess.RevokedAt != nil {
		return s.revoke(ctx, sess)
	}
	pre, ok := rotationPreFor(ctx, sess.ID)
	if !ok {
		s.warnDegradedRotation()
	}
	return s.rotate(ctx, sess, pre, ok)
}

// RotateSession is the shape the upstream optional interface should have
// (data-model.md §4.3, resolution 1):
//
//	SessionRotationStore { RotateSession(ctx, sessionID, oldRefreshHash string, next Session) error }
//
// It is implemented from day one so that adopting the interface upstream is a
// no-op here, and so callers that hold the old hash can rotate correctly without
// the context-carried interim.
func (s *Store) RotateSession(ctx context.Context, sessionID, oldRefreshHash string, next auth.Session) error {
	next.ID = sessionID
	if err := s.checkSession(next); err != nil {
		return err
	}
	if err := checkHash("previous refresh token hash", oldRefreshHash); err != nil {
		return err
	}
	return s.rotate(ctx, next, rotationPrecondition{oldHash: oldRefreshHash}, true)
}

func rotationPreFor(ctx context.Context, sessionID string) (rotationPrecondition, bool) {
	scope := rotationScopeFrom(ctx)
	if scope == nil {
		return rotationPrecondition{}, false
	}
	return scope.take(sessionID)
}

// rotate writes the new refresh pointer and advances the session in one
// transaction (data-model.md #12).
//
// The condition on the session item is what makes concurrent refreshes resolve
// to exactly one winner: both callers read the same refreshHash, both attempt to
// replace it, and "#refreshHash = :old" can only hold for whichever transaction
// commits first. The loser learns that its token is now a rotated-out generation
// and revokes the family, which is the same conclusion replay detection reaches
// on the read path — just reached a request earlier.
//
// Without a precondition (havePre false) the condition degrades to
// attribute_not_exists(revokedAt), both callers succeed, and the loser's token
// becomes a stale generation that the next use will catch. That is the residual
// documented in §4.3.3, and it is why WithRotationScope exists.
func (s *Store) rotate(ctx context.Context, sess auth.Session, pre rotationPrecondition, havePre bool) error {
	cond := "attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"
	names := map[string]string{
		"#PK":          attrPK,
		"#revokedAt":   attrRevokedAt,
		"#refreshHash": attrRefreshHash,
		"#expiresAt":   attrExpiresAt,
		"#updatedAt":   attrUpdatedAt,
		"#gen":         attrGen,
		"#ttl":         attrTTL,
	}
	values := map[string]types.AttributeValue{
		":new": avS(sess.RefreshTokenHash),
		":exp": avS(formatTime(sess.ExpiresAt)),
		":now": avS(formatTime(s.nowUTC())),
		":ttl": avN(sess.ExpiresAt.Add(s.ttlGrace).Unix()),
		":one": avN(1),
	}
	if havePre {
		cond += " AND #refreshHash = :old"
		values[":old"] = avS(pre.oldHash)
		if pre.hasGen {
			cond += " AND #gen = :gen"
			values[":gen"] = avN(pre.gen)
		}
	}

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                 aws.String(s.table),
				Item:                      s.refreshPointer(sess, pre.gen+1),
				ConditionExpression:       aws.String("attribute_not_exists(#PK) OR #sessionId = :sid"),
				ExpressionAttributeNames:  exprNames(attrPK, attrSessionID),
				ExpressionAttributeValues: map[string]types.AttributeValue{":sid": avS(sess.ID)},
			}},
			{Update: &types.Update{
				TableName: aws.String(s.table),
				Key:       key(sessionPK(sess.ID), skSession),
				// An explicit attribute list, not a Put: whatever device metadata
				// the HTTP layer stored is not on auth.Session and must survive.
				// ADD on #gen avoids needing to know the current generation.
				UpdateExpression:                    aws.String("SET #refreshHash = :new, #expiresAt = :exp, #updatedAt = :now, #ttl = :ttl ADD #gen :one"),
				ConditionExpression:                 aws.String(cond),
				ExpressionAttributeNames:            names,
				ExpressionAttributeValues:           values,
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
		},
	})
	if err == nil {
		return nil
	}
	reasons, cancelled := txConditionFailures(err)
	if !cancelled {
		return wrap("rotate session", err)
	}
	if _, failed := txFailedAt(reasons, 0); failed {
		return errors.New("dynamodb: refresh token hash already bound to another session")
	}
	preImage, failed := txFailedAt(reasons, 1)
	if !failed {
		return wrap("rotate session", err)
	}
	return s.classifyRotationLoss(ctx, sess.ID, pre, havePre, preImage)
}

// classifyRotationLoss turns a failed rotation condition into the right answer.
// It may read the session again: DynamoDB only returns a pre-image when
// ReturnValuesOnConditionCheckFailure is honoured, and a read *after* a write has
// already been refused is not the read-then-write this store forbids.
func (s *Store) classifyRotationLoss(ctx context.Context, sessionID string, pre rotationPrecondition, havePre bool, preImage map[string]types.AttributeValue) error {
	if len(preImage) == 0 {
		out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
			TableName:      aws.String(s.table),
			Key:            key(sessionPK(sessionID), skSession),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return wrap("classify rotation failure", err)
		}
		if len(out.Item) == 0 {
			return auth.ErrSessionNotFound
		}
		preImage = out.Item
	}
	if getS(preImage, attrRevokedAt) != "" {
		return auth.ErrSessionRevoked
	}
	if !havePre {
		// No precondition was pinned, so the only condition that could have
		// failed was already handled above. Report the raw situation instead of
		// inventing a cause.
		return errors.New("dynamodb: session rotation refused with no revocation and no precondition")
	}
	// Someone else rotated first: this caller's token is a rotated-out
	// generation, which is exactly a replay. Kill the family.
	if err := s.revokeFamily(ctx, sessionID, reasonReplay, pre.gen); err != nil {
		return err
	}
	return auth.ErrSessionNotFound
}

// revoke is the logout path. It is idempotent by design: an already-revoked
// session is a successful logout, and the first revocation's timestamp and reason
// are kept, because overwriting them would erase the record of a replay with a
// routine logout.
func (s *Store) revoke(ctx context.Context, sess auth.Session) error {
	at := sess.RevokedAt
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(sessionPK(sess.ID), skSession),
		UpdateExpression:         aws.String("SET #revokedAt = :at, #revokedReason = :reason, #updatedAt = :at"),
		ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":at":     avS(formatTime(*at)),
			":reason": avS(reasonLogout),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return nil
	}
	if !isConditionFailed(err) {
		return wrap("revoke session", err)
	}
	// The condition covers two cases at once. An empty pre-image means the item
	// does not exist; anything else means it was already revoked.
	preImage, _ := conditionFailedItem(err)
	if len(preImage) > 0 {
		return nil
	}
	if _, err := s.getSessionItem(ctx, sess.ID); err != nil {
		return err
	}
	return nil
}

// revokeFamily kills every generation of a session at once. No pointer
// enumeration is needed: every refresh read resolves through the session item,
// so revoking it invalidates all outstanding generations.
func (s *Store) revokeFamily(ctx context.Context, sessionID, reason string, gen int64) error {
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(sessionPK(sessionID), skSession),
		UpdateExpression:         aws.String("SET #revokedAt = :now, #revokedReason = :reason, #revokedGen = :gen, #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrRevokedGen, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":    avS(formatTime(s.nowUTC())),
			":reason": avS(reason),
			":gen":    avN(gen),
		},
	})
	if err != nil && !isConditionFailed(err) {
		return wrap("revoke session family", err)
	}
	// A failed condition means someone already revoked it, which is the desired
	// end state.
	return nil
}

// ListSessionsForUser implements SessionAdminStore. It reads the sparse GSI —
// eventual consistency is acceptable for an admin/UI listing, and is the price
// of not indexing sessions under the user partition, where they would turn the
// hottest read in the system into a paginated scan of the user's history (§2.3).
//
// Results come back oldest-first, because GSI1SK embeds the creation timestamp.
// The reference iterates a map and returns them in no order at all.
func (s *Store) ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]auth.Session, error) {
	keys, err := s.sessionKeysForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return []auth.Session{}, nil
	}
	// GSI1 projects three attributes on purpose — no secret is ever in a second
	// physical copy (§5) — so the full items come from the main table.
	items, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("list sessions", err)
	}
	out := make([]auth.Session, 0, len(items))
	for _, m := range items {
		sess, err := sessionFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	// BatchGetItem does not preserve request order, so the ordering the index
	// gave us has to be restored here.
	slices.SortFunc(out, func(a, b auth.Session) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// sessionKeysForUser returns the main-table keys of a user's sessions.
func (s *Store) sessionKeysForUser(ctx context.Context, userID, tenantID string) ([]map[string]types.AttributeValue, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return nil, err
	}
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	// No ConsistentRead: a GSI does not support it.
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :owner AND begins_with(#GSI1SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrGSI1PK, attrGSI1SK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner":  avS(userPK(tenantID, userID)),
			":prefix": avS(skSession + keySep),
		},
	}, s.maxSessions)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query sessions for user", err)
	}
	keys := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		keys = append(keys, key(getS(m, attrPK), getS(m, attrSK)))
	}
	return keys, nil
}

// RevokeSessionByID implements SessionAdminStore.
func (s *Store) RevokeSessionByID(ctx context.Context, sessionID string) error {
	if err := checkID("session id", sessionID); err != nil {
		return auth.ErrSessionNotFound
	}
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key:       key(sessionPK(sessionID), skSession),
		// if_not_exists keeps an earlier revocation — a replay, say — from being
		// relabelled as an administrative one.
		UpdateExpression:         aws.String("SET #revokedAt = if_not_exists(#revokedAt, :now), #revokedReason = if_not_exists(#revokedReason, :reason), #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":    avS(formatTime(s.nowUTC())),
			":reason": avS(reasonAdmin),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return auth.ErrSessionNotFound
		}
		return wrap("revoke session by id", err)
	}
	return nil
}

// DeleteExpiredSessions implements SessionAdminStore as a no-op.
//
// Expiry is DynamoDB TTL (§4.5), so there is nothing for a cron to delete and no
// count to report. Producing a real number would need an EXPIRES#<bucket> index
// — an extra GSI plus a write on every session — to reproduce a figure whose only
// documented consumer is the cron job itself. POST /sessions/cleanup therefore
// answers deleted:0; see CompatibilityNotes.
func (s *Store) DeleteExpiredSessions(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}
