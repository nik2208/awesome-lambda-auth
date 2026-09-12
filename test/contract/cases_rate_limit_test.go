package contract

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
)

// ── rate limiting, and the only honest way to probe one ──────────────────────
//
// The built-in limiter is net-new to this product: the reference ships none at
// all, so this is the one capability here with no reference wire to compare
// against and the one whose absence is not merely unfalsifiable but *expensive*
// to falsify.
//
// **A limiter cannot be probed.** Every other capability in this suite answers a
// single harmless request: a route is mounted or it is not, a store is wired or
// it declares itself absent. A limiter answers nothing until it refuses, and
// making it refuse means spending the budget it exists to protect. A probe that
// did that would be wrong twice over — it would flake, because the budget it
// needs may already have been spent by real traffic or by a parallel run, and it
// would leave the deployment throttled for whoever called next, which on an
// account-keyed limiter means a real person unable to log in.
//
// So this capability is **declared, not discovered**, and declaring it is
// opt-in. RateLimitEnv carries both halves of what the case needs to be safe:
// which key the deployment limits by, and what the budget is.
//
// **And the case asserts the shape, not the timing.** It does not assert that
// the refusal arrives on request max+1 — a fixed window can roll mid-run and
// hand back a fresh budget, and another caller may have spent some of it first —
// only that a refusal arrives within a bounded number of attempts and that when
// it does, its body and headers are exactly what the deviation register
// promises. Everything about *when* is the deployment's business; everything
// about *what* is the contract.

// CapRateLimit is a deployment that rate limits, as the operator declares it.
const CapRateLimit Capability = "rate-limit"

// RateLimitEnv is the declaration. Its value is `<keyBy>:<max>` — the deployment's
// rateLimit.keyBy and rateLimit.max — for example:
//
//	AWESOME_AUTH_CONTRACT_RATE_LIMIT=email:10
//
// Only `email:` is honoured, and `ip:` is recorded as absent rather than as a
// fault. That is not fastidiousness about spelling: under an account-keyed
// limiter the case can spend the budget of one random address under
// @contract.invalid that nothing will ever use again, so the deployment is left
// exactly as it was found. Under an address-keyed one the budget it would spend
// is the suite's own source address, shared with every other caller behind the
// same egress — which is precisely the state this case must not leave behind.
// An operator with an address-keyed deployment has nothing to declare here, and
// saying so is better than offering them a switch that quietly throttles their
// stack.
const RateLimitEnv = "AWESOME_AUTH_CONTRACT_RATE_LIMIT"

// maxProbeableRateLimit caps the budget this case will try to exhaust.
//
// The case sends up to 2×max+2 requests, so a generous limit turns a contract
// suite into a load generator aimed at somebody's login route. Past this the
// case skips with that reason: the shape of a refusal is the same at any budget,
// and there is no assertion here worth several hundred requests.
const maxProbeableRateLimit = 50

func init() {
	registerCapability(capabilityDecl{
		Name: CapRateLimit,
		// stageAnonymous because the probe depends on nothing: it makes no
		// request at all, of either client, and needs no account. It is the
		// stage for a probe with no prerequisites, and this one has none by
		// construction — see the header for why it cannot have any.
		Stage: stageAnonymous,
		Probe: func(t *testing.T, p *probeRun) {
			p.Set(CapRateLimit, probeRateLimit(os.Getenv(RateLimitEnv)))
		},
	})
}

// probeRateLimit reads the declaration. It is a pure function of the string so
// that its three answers can be tested without a deployment.
func probeRateLimit(raw string) capability {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return capability{
			state: capAbsent,
			why: RateLimitEnv + " is unset, so no rate limiter is declared — this suite will not spend a live budget to " +
				"discover one, because doing so would leave the deployment throttled for the next caller",
		}
	}
	keyBy, budget, ok := strings.Cut(raw, ":")
	max, err := strconv.Atoi(strings.TrimSpace(budget))
	switch {
	case !ok || err != nil || max < 1:
		return capability{
			state: capBroken,
			why: RateLimitEnv + "=" + strconv.Quote(raw) + " is not <keyBy>:<max> with a positive max, e.g. \"email:10\" — " +
				"a declaration nobody can parse is a fault, not a deployment without a limiter",
		}
	case strings.TrimSpace(keyBy) == "ip":
		return capability{
			state: capAbsent,
			why: RateLimitEnv + " declares an address-keyed limiter; the case is not run against one, because exhausting it " +
				"would throttle this suite's own source address for everyone behind it",
		}
	case strings.TrimSpace(keyBy) != "email":
		return capability{
			state: capBroken,
			why:   RateLimitEnv + " names keyBy " + strconv.Quote(keyBy) + "; the schema has only \"ip\" and \"email\"",
		}
	case max > maxProbeableRateLimit:
		return capability{
			state: capAbsent,
			why: RateLimitEnv + " declares a budget of " + strconv.Itoa(max) + ", above the " +
				strconv.Itoa(maxProbeableRateLimit) + " this case will try to exhaust; the shape of a refusal is the same " +
				"at any budget and is not worth several hundred requests",
		}
	}
	return capability{
		state: capOn,
		why:   RateLimitEnv + " declares an account-keyed limiter at " + strconv.Itoa(max) + " per window",
	}
}

// declaredRateLimitBudget re-reads the declared budget for the case. The probe
// has already validated it, so this cannot fail by the time a case runs.
func declaredRateLimitBudget() int {
	_, budget, _ := strings.Cut(strings.TrimSpace(os.Getenv(RateLimitEnv)), ":")
	max, _ := strconv.Atoi(strings.TrimSpace(budget))
	return max
}

func init() {
	register(Case{
		Name: "rate-limit/refusal-shape",
		Doc: "the product's own surface — awesome-node-auth has no limiter (RouterOptions.rateLimiter is an empty slot, " +
			"auth.router.ts:46, and absent it rl = [], :468) — so this pins the deviation register's " +
			"rate-limited-routes-answer-429 rather than a clause of the wire contract",
		Needs: []Capability{CapRateLimit},
		Run: func(t *testing.T, e *Env) {
			max := declaredRateLimitBudget()

			// One random address under @contract.invalid, never registered and
			// never used again. That is what makes this case safe to run against
			// a live deployment: the budget it spends belongs to an account that
			// does not exist and that nobody will ever try to log into, so the
			// stack is left exactly as it was found. It is also why the case
			// needs an account-keyed limiter and refuses to run against an
			// address-keyed one.
			victim := randomAccount()
			c := e.NewClient()

			// Up to 2×max+2 attempts, and the bound is the fixed window rather
			// than slack. The budget resets on a window boundary, so a run that
			// straddles one legitimately needs a second budget's worth of
			// requests before the counter can reach its limit; +2 covers the
			// request that crosses the boundary and the one that refuses. Any
			// more than that and the declared budget is not the deployment's.
			var refusal *Resp
			var lastAllowed *Resp
			attempts := 2*max + 2
			for i := 0; i < attempts && refusal == nil; i++ {
				r := c.POST(t, "/login", body{"email": victim.Email, "password": "not-the-password"})
				if r.Status == http.StatusTooManyRequests {
					refusal = r
					break
				}
				lastAllowed = r
			}
			if refusal == nil {
				t.Fatalf("%s declares a budget of %d and %d requests to POST %s/login were all allowed; "+
					"either the limiter is not on, or its scope does not cover login, or the declared budget is not this deployment's",
					RateLimitEnv, max, attempts, e.Prefix)
			}

			// ── the shape, which is the whole assertion ──────────────────────
			//
			// Every literal here is written out rather than imported, as
			// everywhere else in this suite: the failure worth catching is a
			// change in the literal, and importing the constant would make the
			// test agree with the change.
			if got := string(refusal.Body); got != `{"error":"Too many requests","code":"RATE_LIMITED"}` {
				t.Errorf("the refusal body is %s, want {\"error\":\"Too many requests\",\"code\":\"RATE_LIMITED\"}\n  %s",
					got, refusal.where())
			}
			if got := refusal.str(t, "code"); got != "RATE_LIMITED" {
				t.Errorf("code = %q, want RATE_LIMITED: a client that backs off switches on this and not on the sentence", got)
			}
			if ct := refusal.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Retry-After is the one header the refusal carries, in the
			// delta-seconds form of RFC 9110 §10.2.3. Zero would be an
			// invitation to retry immediately, which is what the header exists
			// to prevent.
			retry := refusal.Header.Get("Retry-After")
			secs, err := strconv.Atoi(strings.TrimSpace(retry))
			if err != nil || secs < 1 {
				t.Errorf("Retry-After = %q, want a positive integer number of seconds\n  %s", retry, refusal.where())
			}

			// A refusal must cost nothing downstream, and the observable half of
			// that is the cookie jar: the limiter is outermost, ahead of the
			// middleware that distributes the CSRF auto-init cookie, so a
			// refused request has reached nothing that sets one.
			if len(refusal.SetCookie) != 0 {
				t.Errorf("the refusal carries %d Set-Cookie header(s) (%v); a refused request reached something that sets cookies, "+
					"so it did not cost nothing downstream", len(refusal.SetCookie), refusal.SetCookie)
			}

			// The RateLimit-* family is deliberately not sent, on the refusal or
			// on a successful response. Under an account-keyed counter
			// RateLimit-Remaining on a 200 is an oracle about somebody else's
			// traffic: whoever can name an address could read from it whether
			// that person has been logging in.
			for _, name := range []string{
				"RateLimit", "RateLimit-Limit", "RateLimit-Remaining", "RateLimit-Reset", "RateLimit-Policy",
				"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
			} {
				if v := refusal.Header.Get(name); v != "" {
					t.Errorf("the refusal carries %s: %q; this deployment leaks its budget", name, v)
				}
				if lastAllowed != nil {
					if v := lastAllowed.Header.Get(name); v != "" {
						t.Errorf("an allowed response carries %s: %q, which is an oracle about the subject's other traffic", name, v)
					}
				}
			}
		},
	})
}

// TestProbeRateLimitReadsTheDeclaration runs without a deployment, like
// TestCapabilityRegistryIsWellFormed, because the three answers this probe can
// give are the whole of its behaviour and none of them needs a stack.
//
// The distinction that matters is absent versus broken. An undeclared limiter
// and an address-keyed one are configurations, and the case skips; a
// declaration nobody can parse is a fault, and the suite must fail rather than
// quietly report a green run over a check that never happened.
func TestProbeRateLimitReadsTheDeclaration(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		raw  string
		want capState
	}{
		{"", capAbsent},
		{"   ", capAbsent},
		{"ip:10", capAbsent},
		{" ip : 10 ", capAbsent},
		{"email:" + strconv.Itoa(maxProbeableRateLimit+1), capAbsent},
		{"email:10", capOn},
		{"email:1", capOn},
		{" email : 10 ", capOn},
		{"email", capBroken},
		{"email:", capBroken},
		{"email:0", capBroken},
		{"email:-1", capBroken},
		{"email:many", capBroken},
		{"session:10", capBroken},
		{"10", capBroken},
	} {
		t.Run(strconv.Quote(tc.raw), func(t *testing.T) {
			got := probeRateLimit(tc.raw)
			if got.state != tc.want {
				t.Errorf("probeRateLimit(%q) = %s (%s), want %s", tc.raw, got.state, got.why, tc.want)
			}
			if strings.TrimSpace(got.why) == "" {
				t.Errorf("probeRateLimit(%q) recorded no reason; the report prints one for every capability", tc.raw)
			}
		})
	}
}
