package aws

import (
	"context"
	"sync"
)

// lazyClient defers building one SDK client until the first call that actually
// needs it, and then builds it at most once.
//
// This is the same bargain lazyConfig strikes for the credential chain, one
// level up, and it exists for the cold-start budget: cmd/auth bounds the whole
// init phase at startTimeout (8s), and a deployment that configures mail or SMS
// must not pay for a client — or, on a host where the credential chain reaches
// IMDS, a network round trip — during init for a capability most invocations
// never use. A magic-link mail is sent by one route out of thirty.
//
// Building at most once is the other half. Rebuilding per send would throw away
// the HTTP connection pool and turn every message into a fresh TLS handshake,
// which is the same mistake NewDynamoDBClient's comment warns about for the
// store.
//
// The error is memoised with the client on purpose: build failures here are
// configuration failures (no region, no credentials), not transient ones, so
// retrying them per request buys nothing and costs a credential-chain walk each
// time. A transient failure belongs to the API call itself, which is not cached.
type lazyClient[T any] struct {
	build func(context.Context) (T, error)

	once sync.Once
	v    T
	err  error
}

func (l *lazyClient[T]) get(ctx context.Context) (T, error) {
	l.once.Do(func() { l.v, l.err = l.build(ctx) })
	return l.v, l.err
}
