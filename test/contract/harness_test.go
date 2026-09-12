// Package contract is the black-box wire-contract suite for awesome-lambda-auth.
//
// It talks HTTP to a running stack and nothing else: no import of the auth core,
// no import of this repository's internals, no database handle, no AWS call. The
// correctness claim it exists to check is "the family's shipped clients work
// against this deployment with only a base-URL change", and a claim about a
// deployment can only be checked against a deployment.
//
// Everything lives in _test.go files on purpose. Nothing here is compiled into
// the deployable, and nothing here can be imported by it.
//
// Point it at a stack with AWESOME_AUTH_CONTRACT_BASE_URL; see README.md.
package contract

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	// BaseURLEnv names the stack under test, scheme and host, no trailing
	// slash: https://example.execute-api.eu-west-1.amazonaws.com, or
	// http://localhost:3000 for the reference Express app. Unset means "no
	// deployment to talk to", which is a skip and not a failure — a plain
	// checkout must stay green under `go test ./...`.
	BaseURLEnv = "AWESOME_AUTH_CONTRACT_BASE_URL"

	// PrefixEnv overrides the router mount point. The reference calls it
	// apiPrefix and defaults it to /auth (wire-contract.md §1, auth.router.ts
	// :253-255); so does this suite.
	PrefixEnv = "AWESOME_AUTH_CONTRACT_API_PREFIX"

	// RequireEnv lists the capabilities this deployment claims to offer, comma
	// separated, or the word "all". A listed capability that is missing is a
	// failure instead of a skip.
	//
	// It exists because "absent" is unfalsifiable from outside: a store the
	// operator never wired and a store that regressed into answering
	// NOT_IMPLEMENTED look identical on the wire, and the skip that is correct
	// for the first is a silent green run for the second. Nobody but the
	// operator knows which deployment they pointed the suite at, so the
	// operator says. Set it for a stack that is supposed to be complete; leave
	// it unset for the reference demo, which really does run without CSRF.
	RequireEnv = "AWESOME_AUTH_CONTRACT_REQUIRE"

	defaultPrefix = "/auth"
)

// Capability is one thing a deployment either offers or does not. It is probed,
// never assumed: a route gated on a store the operator did not configure is a
// deployment difference, not a contract break, and a suite that fails on it is
// a broken suite.
type Capability string

const (
	CapRegister       Capability = "register"
	CapCSRF           Capability = "csrf"
	CapSessions       Capability = "sessions"
	CapTOTP           Capability = "totp"
	CapLinkedAccounts Capability = "linked-accounts"
	CapCookieSecure   Capability = "secure-cookies"
	CapOAuthGoogle    Capability = "oauth-google"
)

// capState is the three-way answer a probe can get, and the distinction the
// suite turns on. "Off" is not one state but two, and collapsing them is how a
// contract suite goes green against a broken deployment: a store the operator
// did not wire is a deployment difference and a legitimate skip, while a route
// that answers 500 — or 403, or a 501 without the documented code — is a
// deployment that is broken, and a broken deployment must never be able to
// switch a case off.
type capState int

const (
	capOn     capState = iota // the feature answered
	capAbsent                 // the deployment declared, in the documented way, that it has no such store
	capBroken                 // neither: this is a fault, not a configuration
)

func (s capState) String() string {
	switch s {
	case capOn:
		return "on"
	case capAbsent:
		return "absent"
	default:
		return "BROKEN"
	}
}

type capability struct {
	state capState
	why   string // what was observed
}

// classify reads one probe answer. 200 is the feature. The two documented ways
// for a deployment to say "no store is wired" are the reference's Express 404
// fall-through for an unmounted route (§4, auth.router.ts:1456 — the route is
// simply not registered) and this port's 5xx with code NOT_IMPLEMENTED. There
// is no third way, so everything else is capBroken.
func classify(r *Resp) capability {
	switch {
	case r.Status == 200:
		return capability{state: capOn, why: fmt.Sprintf("%s answered 200", r.Target)}
	case r.Status == 404:
		return capability{state: capAbsent, why: fmt.Sprintf("%s answered 404 — the route is not mounted, so no store is wired", r.Target)}
	case r.Status >= 500:
		var m map[string]any
		if json.Unmarshal(r.Body, &m) == nil && m["code"] == "NOT_IMPLEMENTED" {
			return capability{state: capAbsent, why: fmt.Sprintf("%s answered %d NOT_IMPLEMENTED — the store is switched off", r.Target, r.Status)}
		}
	}
	return capability{state: capBroken, why: fmt.Sprintf("%s answered %d %s, which is neither the feature nor a declared absence", r.Target, r.Status, r.snippet())}
}

// classifyOAuth reads the probe answer for GET <prefix>/oauth/google, whose two
// documented shapes are not the two classify knows about.
//
// "On" is a 302 to the provider carrying a state — the route answers a redirect,
// never a 200 — and the documented absence is the reference's own stub for a
// strategy the host app never passed: 404 {"error":"Google OAuth not
// configured"} (auth.router.ts:1361), which is a JSON body rather than an
// unmounted route's fall-through. Anything else is a fault: a 500 from a
// half-wired provider must not read as "nobody configured Google".
func classifyOAuth(r *Resp) capability {
	switch r.Status {
	case 302:
		loc := r.Header.Get("Location")
		if loc == "" {
			return capability{state: capBroken, why: fmt.Sprintf("%s answered 302 with no Location", r.Target)}
		}
		u, err := url.Parse(loc)
		if err != nil || u.Query().Get("state") == "" {
			return capability{state: capBroken, why: fmt.Sprintf("%s answered 302 to %q, which carries no state parameter", r.Target, loc)}
		}
		return capability{state: capOn, why: fmt.Sprintf("%s answered 302 to %s with a state", r.Target, u.Host)}
	case 404:
		var m map[string]any
		if json.Unmarshal(r.Body, &m) == nil && m["error"] == "Google OAuth not configured" {
			return capability{state: capAbsent, why: fmt.Sprintf("%s answered the reference's 404 stub — no Google provider is configured", r.Target)}
		}
	}
	return capability{state: capBroken, why: fmt.Sprintf("%s answered %d %s, which is neither a provider redirect nor the documented 404 stub", r.Target, r.Status, r.snippet())}
}

// Case is one assertion about the wire. Adding a route to the covered surface is
// adding a Case in a cases_*.go file; the harness never has to change.
type Case struct {
	// Name is the subtest name. Slash-separated, area first, so `go test -run`
	// can select a whole area.
	Name string

	// Doc cites the clause of docs/spec/wire-contract.md this case pins. It is
	// logged before the case runs, so a failure report says which clause broke
	// without anyone opening the spec.
	Doc string

	// Needs lists the deployment capabilities the case requires. A case whose
	// needs are not met is skipped with the reason the probe recorded.
	Needs []Capability

	Run func(t *testing.T, e *Env)
}

var registry []Case

// register is what a cases_*.go file calls from its init.
func register(cs ...Case) { registry = append(registry, cs...) }

// Env is the probed deployment: where it is, and what it turned out to offer.
type Env struct {
	BaseURL string
	Prefix  string
	Caps    map[Capability]capability
}

// URL builds an absolute URL for a path relative to the router mount point.
// A path starting with "!" is taken as absolute (outside the prefix).
func (e *Env) URL(path string) string {
	if strings.HasPrefix(path, "!") {
		return e.BaseURL + path[1:]
	}
	return e.BaseURL + e.Prefix + path
}

func (e *Env) can(c Capability) bool { return e.Caps[c].state == capOn }

// required is the set named by RequireEnv. `all` means every capability the
// probe knows about.
type required struct {
	all  bool
	set  map[Capability]bool
	spec string
}

func readRequired(t *testing.T) required {
	raw := strings.TrimSpace(os.Getenv(RequireEnv))
	req := required{set: map[Capability]bool{}, spec: raw}
	if raw == "" {
		return req
	}
	known := map[Capability]bool{
		CapRegister: true, CapCSRF: true, CapSessions: true,
		CapTOTP: true, CapLinkedAccounts: true, CapCookieSecure: true,
		CapOAuthGoogle: true,
	}
	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f == "all" {
			req.all = true
			continue
		}
		if !known[Capability(f)] {
			t.Fatalf("%s names an unknown capability %q; known: register, csrf, sessions, totp, linked-accounts, secure-cookies, oauth-google, all",
				RequireEnv, f)
		}
		req.set[Capability(f)] = true
	}
	return req
}

func (r required) wants(c Capability) bool { return r.all || r.set[c] }

// TestContract is the whole suite: one subtest per registered case.
func TestContract(t *testing.T) {
	base := strings.TrimSpace(os.Getenv(BaseURLEnv))
	if base == "" {
		// A caller who named the capabilities to verify has told us they meant
		// to run this against something. Skipping that quietly is the one shape
		// of "green forever" the exit code can still catch: a CI job whose
		// base URL arrived empty keeps its %s and goes red.
		if spec := strings.TrimSpace(os.Getenv(RequireEnv)); spec != "" {
			t.Fatalf(`%s=%q asks this suite to verify a deployment offers those capabilities, and %s is empty.

There is nothing to verify them against. This is a misconfigured run, not an
offline one — skipping it would report success for checks that never happened.`,
				RequireEnv, spec, BaseURLEnv)
		}
		announce("SKIPPED: %s is not set, so the wire contract was checked against nothing.\n"+
			"Nothing below this line was executed. See test/contract/README.md.", BaseURLEnv)
		t.Skipf(`%s is not set, so there is no deployment to check the wire contract against.

Set it to the origin of a running stack and re-run, for example:

    %s=https://<api-id>.execute-api.<region>.amazonaws.com ./scripts/toolchain.sh go test ./test/contract/...
    %s=http://localhost:3000 go test ./test/contract/...        # the reference Express app

Override the router mount point with %s (default %q). See test/contract/README.md.`,
			BaseURLEnv, BaseURLEnv, BaseURLEnv, PrefixEnv, defaultPrefix)
	}

	prefix := strings.TrimSpace(os.Getenv(PrefixEnv))
	if prefix == "" {
		prefix = defaultPrefix
	}
	env := &Env{
		BaseURL: strings.TrimSuffix(base, "/"),
		Prefix:  strings.TrimSuffix(prefix, "/"),
	}
	req := readRequired(t)
	probe(t, env, req)

	cases := append([]Case(nil), registry...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })

	var skipped []string
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			for _, need := range c.Needs {
				st := env.Caps[need]
				switch {
				case st.state == capOn:
					// nothing to gate on
				case st.state == capBroken:
					t.Fatalf(`this case needs %q, and this deployment neither offers it nor declares it absent — it is broken.
A fault is not a configuration, and the suite will not let one switch a case off.
  %s`, need, st.why)
				case req.wants(need):
					t.Fatalf(`%s=%q names %q as a capability this deployment offers, and it does not.
  %s`, RequireEnv, req.spec, need, st.why)
				default:
					skipped = append(skipped, fmt.Sprintf("%-58s needs %q: %s", c.Name, need, st.why))
					t.Skipf(`deployment does not offer %q: %s

If this deployment is supposed to offer it, say so with %s and the skip becomes a failure.`,
						need, st.why, RequireEnv)
				}
			}
			if c.Doc != "" {
				t.Logf("contract: %s", c.Doc)
			}
			c.Run(t, env)
		})
	}

	// A skip is invisible without -v and costs nothing in the exit code, so a
	// suite that quietly stopped checking half the contract reads exactly like
	// one that checked all of it. Say it on stdout, where a non-verbose CI log
	// still shows it.
	if len(skipped) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d of %d contract cases did NOT run against %s:\n", len(skipped), len(cases), env.BaseURL)
		for _, s := range skipped {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
		fmt.Fprintf(&b, "Set %s (comma-separated, or \"all\") to turn these skips into failures.", RequireEnv)
		announce("%s", b.String())
	}
}

// announce puts a skip where a reader will trip over it under `go test -v`,
// which is how every invocation in the README runs.
//
// It cannot do better than that: cmd/go buffers a passing package's stdout and
// stderr alike and prints neither, so nothing a green test binary writes
// survives a non-verbose run. The exit code is the only channel that does, and
// the two things that use it are RequireEnv (an absent capability the operator
// said would be there) and the BaseURLEnv-empty-but-RequireEnv-set check above.
func announce(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "\n[contract] "+format+"\n\n", args...)
}

// probe reads the deployment. Every answer here is an observation about this
// stack, never a decision about the contract: the contract is the same
// everywhere, and what changes between deployments is which parts of it are
// reachable.
func probe(t *testing.T, e *Env, req required) {
	t.Helper()
	e.Caps = map[Capability]capability{}

	// CSRF: the cookie is distributed solely by the router's auto-init
	// middleware (§0.6), so any request through the router reveals whether the
	// feature is on. An unauthenticated GET /me is the cheapest one.
	//
	// This is the one capability with no status to classify — a router with
	// csrf.enabled off and a router that stopped setting the cookie look the
	// same from outside — so absence here is exactly what RequireEnv is for.
	anon := e.NewClient()
	r := anon.GET(t, "/me")
	if c := r.cookie("csrf-token"); c != nil {
		e.Caps[CapCSRF] = capability{state: capOn, why: fmt.Sprintf("auto-init cookie %q observed", c.Name)}
		secure := capAbsent
		if c.Secure {
			secure = capOn
		}
		e.Caps[CapCookieSecure] = capability{state: secure, why: fmt.Sprintf("csrf cookie Secure=%v", c.Secure)}
	} else {
		e.Caps[CapCSRF] = capability{state: capAbsent, why: "no csrf-token cookie is auto-initialised, so config.csrf.enabled is off"}
		e.Caps[CapCookieSecure] = capability{state: capAbsent, why: "no cookie observed during the probe"}
	}

	// Registration, without which the suite cannot provision anything: it
	// cannot seed a store it is not allowed to reach.
	//
	// Only the reference's documented absence — Express's 404 fall-through for
	// a route mounted only when the host app passes onRegister (§3.7,
	// auth.router.ts:713) — is a reason to stand down. A 500 here used to skip
	// the entire suite and exit 0, which meant a deployment answering 500 to
	// every request produced the same green `ok` as a healthy one.
	acct := randomAccount()
	reg := anon.POST(t, "/register", body{"email": acct.Email, "password": acct.Password})
	switch {
	case reg.Status == 200 || reg.Status == 201:
		e.Caps[CapRegister] = capability{state: capOn, why: fmt.Sprintf("POST %s/register answered %d", e.Prefix, reg.Status)}
	case reg.Status == 404 && !req.wants(CapRegister):
		e.Caps[CapRegister] = capability{state: capAbsent, why: fmt.Sprintf("POST %s/register answered 404 — the route is not mounted", e.Prefix)}
		announce("SKIPPED: %s does not mount POST %s/register, so the suite could not provision an account.\n"+
			"None of the %d contract cases ran. Set %s=register to make this a failure.",
			e.BaseURL, e.Prefix, len(registry), RequireEnv)
		t.Skipf(`this deployment does not mount registration: POST %s/register answered 404.

The suite is black-box and self-provisioning — it registers the accounts it
needs because it cannot seed a store it cannot reach — so it cannot run against
a stack with the route unmounted (the reference mounts it only when the host app
passes onRegister; wire-contract.md §3.7).`, e.Prefix)
	default:
		t.Fatalf(`probe: POST %s/register answered %d %s

That is a broken deployment, not an unconfigured one: the documented absence of
this route is Express's 404 fall-through (§3.7), and nothing else. The suite
refuses to treat a fault as a reason to stand down — this used to be a skip, and
a stack answering 500 to every route exited 0.`, e.Prefix, reg.Status, reg.snippet())
	}

	// A logged-in client for the store-gated probes below.
	cli := e.NewClient()
	login := cli.POST(t, "/login", body{"email": acct.Email, "password": acct.Password})
	if login.Status != 200 {
		t.Fatalf("probe: cannot log the freshly registered account in: POST %s/login -> %d %s",
			e.Prefix, login.Status, login.snippet())
	}

	e.Caps[CapSessions] = classify(cli.GET(t, "/sessions"))
	e.Caps[CapLinkedAccounts] = classify(cli.GET(t, "/linked-accounts"))
	e.Caps[CapTOTP] = classify(cli.POST(t, "/2fa/setup", nil, CSRF()))
	// The OAuth entry point reads no credential (§4: "Auth gate: none"), so the
	// anonymous client is the honest probe for it.
	e.Caps[CapOAuthGoogle] = classifyOAuth(anon.GET(t, "/oauth/google"))

	names := make([]string, 0, len(e.Caps))
	for k := range e.Caps {
		names = append(names, string(k))
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "deployment under test: %s (router mounted at %s)\n", e.BaseURL, e.Prefix)
	if req.spec != "" {
		fmt.Fprintf(&b, "  %s=%s\n", RequireEnv, req.spec)
	}
	for _, n := range names {
		st := e.Caps[Capability(n)]
		fmt.Fprintf(&b, "  %-16s %-7s %s\n", n, st.state, st.why)
	}
	t.Log(b.String())

	// Report every fault once, loudly, even for a capability no case happens to
	// need: linked-accounts gates nothing, so a linked-accounts route that
	// started answering 500 would otherwise be recorded and never mentioned.
	for _, n := range names {
		c := Capability(n)
		st := e.Caps[c]
		if st.state == capBroken {
			t.Errorf(`capability %q is broken, not absent — this deployment is faulty.
  %s`, c, st.why)
		}
		if st.state == capAbsent && req.wants(c) {
			t.Errorf(`%s=%q names %q as a capability this deployment offers, and the probe could not find it.
  %s`, RequireEnv, req.spec, c, st.why)
		}
	}
}
