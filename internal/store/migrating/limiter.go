package migrating

import (
	"sync"
	"time"
)

// The limiter both outbound paths are bounded by.
//
// It exists because the upstream seam requires it in so many words: "whatever
// call survives the marker must still be bounded and rate-limited by the
// verifier itself" (awesome-go-auth/password_verifier.go). The same sentence
// applies word for word to the dual-read fall-through, which sits on the same
// unauthenticated routes and calls the same directory.
//
// Two things are bounded, and they are different threats:
//
//   - Per subject. One address, or one user id, may only cost so many calls to
//     the source per unit time. This is what stops a single account from being
//     used to drive Cognito's own lockout counters, which is the attack the
//     upstream doc names: an attacker who knows one real address can otherwise
//     spend POST /login to lock that person out of the system being migrated
//     away from.
//   - Globally. Every subject together may only cost so many calls. This is
//     what stops an attacker who names a million distinct addresses, for whom
//     the per-subject bucket is no constraint at all, from turning this function
//     into a load generator aimed at somebody else's API quota — and, with it,
//     from turning a credential-stuffing run into a bill.
//
// What "refused" means is deliberate, and it is not an error. Over budget, the
// caller behaves as though the source had said no: a dual-read miss stays a
// miss, and the verifier answers (false, false, nil). Both are answers the route
// already produces in quantity, so nothing a client can see changes when the
// limiter engages — which is the property the whole seam is required to have.
// Answering an error instead would have turned throttling into a 500 that a
// client could use to detect that a verifier is configured at all.
//
// Scope is one execution environment, and that is stated rather than papered
// over. A Lambda under load runs many, each with its own buckets, so the global
// bound is per environment and the aggregate is that bound times the concurrency
// AWS chose. A shared counter would need a store round trip on the path whose
// cost this is trying to contain, which is a strictly worse trade: the point is
// not to enforce a quota to the digit, it is to remove the unbounded multiplier
// between "requests an attacker sends" and "calls somebody else's directory
// receives". Per environment, that multiplier is a constant.
type limiter struct {
	mu sync.Mutex

	// burst and refill describe every per-subject bucket. refill is tokens per
	// second, held as a rate rather than an interval so a sub-per-second refill
	// is expressible without integer division.
	burst  float64
	refill float64

	global   bucket
	subjects map[string]*bucket

	// maxSubjects caps the table. Without it the map is an
	// attacker-controlled allocation on an unauthenticated route: one entry per
	// distinct address named, held for as long as the execution environment
	// lives, which is the classic way a rate limiter becomes the outage.
	maxSubjects int

	now func() time.Time
}

// bucket is one token bucket. Zero value is unusable; newLimiter fills them.
type bucket struct {
	tokens float64
	last   time.Time
	burst  float64
	refill float64
}

func (b *bucket) take(now time.Time) bool {
	if !b.last.IsZero() {
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			b.tokens += elapsed * b.refill
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
		}
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// full reports a bucket that has nothing to remember: it is back at its burst
// size, so evicting it loses no state a caller could observe. This is what makes
// eviction safe rather than a way to reset an attacker's budget.
func (b *bucket) full() bool { return b.tokens >= b.burst }

// newLimiter builds a limiter. Any non-positive parameter falls back to the
// package default beside it, so a caller may configure one bound and inherit the
// rest.
func newLimiter(perSubjectBurst, perSubjectPerMinute, globalBurst, globalPerSecond float64, maxSubjects int, now func() time.Time) *limiter {
	if perSubjectBurst <= 0 {
		perSubjectBurst = defaultSubjectBurst
	}
	if perSubjectPerMinute <= 0 {
		perSubjectPerMinute = defaultSubjectPerMinute
	}
	if globalBurst <= 0 {
		globalBurst = defaultGlobalBurst
	}
	if globalPerSecond <= 0 {
		globalPerSecond = defaultGlobalPerSecond
	}
	if maxSubjects <= 0 {
		maxSubjects = defaultMaxSubjects
	}
	if now == nil {
		now = time.Now
	}
	return &limiter{
		burst:       perSubjectBurst,
		refill:      perSubjectPerMinute / 60,
		global:      bucket{tokens: globalBurst, burst: globalBurst, refill: globalPerSecond},
		subjects:    make(map[string]*bucket),
		maxSubjects: maxSubjects,
		now:         now,
	}
}

// The defaults. They are deliberately low: the calls being bounded are not part
// of normal operation even during a migration — one per account, once, and never
// again after adoption — so a bound that a real person can notice would have to
// be reached by the same person failing repeatedly within a minute.
const (
	// defaultSubjectBurst: five attempts on one address before the refill rate
	// takes over. Enough for a person who mistypes their password a few times.
	defaultSubjectBurst = 5

	// defaultSubjectPerMinute: one attempt per minute sustained.
	defaultSubjectPerMinute = 1

	// defaultGlobalBurst / defaultGlobalPerSecond: 50 calls immediately, then 5
	// a second, per execution environment. A bulk migration goes through
	// cmd/migrate and not through here, so this only has to absorb the arrival
	// rate of real people logging in for the first time after a cutover.
	defaultGlobalBurst     = 50
	defaultGlobalPerSecond = 5

	// defaultMaxSubjects: ten thousand tracked subjects, which at a few dozen
	// bytes each is noise against a Lambda's smallest memory size and is far
	// more distinct addresses than a migration window sees.
	defaultMaxSubjects = 10_000
)

// allow reports whether one call to the source may be made for subject.
//
// The global bucket is taken first and is not refunded if the per-subject bucket
// then refuses. That is the conservative direction and it is intended: the
// global bucket is the bound on what this function can do to somebody else's
// API, and a refusal that still consumed a token means a flood of refused
// requests cannot be used to hold the global budget open for the one request the
// attacker actually wants through.
func (l *limiter) allow(subject string) bool {
	if subject == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if !l.global.take(now) {
		return false
	}

	b, ok := l.subjects[subject]
	if !ok {
		if len(l.subjects) >= l.maxSubjects && !l.evictLocked() {
			// The table is full of subjects that all still owe tokens, which is
			// what a distributed guessing run looks like. Refusing is the safe
			// direction: the caller degrades to "the source said no", which is an
			// answer the route already gives, rather than to an unbounded map.
			return false
		}
		b = &bucket{tokens: l.burst, burst: l.burst, refill: l.refill}
		l.subjects[subject] = b
	}
	return b.take(now)
}

// evictLocked drops every subject whose bucket has refilled completely, and
// reports whether it freed anything. Called with the mutex held.
//
// Only full buckets go: an entry still owing tokens is the only kind that means
// anything, and evicting one would hand its subject a fresh budget, which is the
// one thing a keyspace-flooding attacker would be trying to buy.
func (l *limiter) evictLocked() bool {
	now := l.now()
	freed := false
	for k, b := range l.subjects {
		// take() is what applies the refill, so the bucket has to be brought up
		// to date before "full" means anything. Reading b.tokens directly would
		// only ever evict subjects that never spent a token.
		if !b.last.IsZero() {
			if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
				b.tokens += elapsed * b.refill
				if b.tokens > b.burst {
					b.tokens = b.burst
				}
				b.last = now
			}
		}
		if b.full() {
			delete(l.subjects, k)
			freed = true
		}
	}
	return freed
}
