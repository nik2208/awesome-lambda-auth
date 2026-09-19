package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
	"golang.org/x/crypto/bcrypt"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The admin console, driven the way the binary builds it: a Config loaded from
// the same environment the stack would set, the same core buildCore assembles
// for New, and the same mount mountAuthSurface performs — with the `admin`
// domain loaded under AllowUnimplemented, so that these tests say the same
// thing on both sides of the phase gate's removal (the gate comes down in its
// own last commit, by convention).
//
// Every request here goes through the adapter's mux, because the claim is
// not that adminHTTPOptions computes a value but that the imported adapter
// mounts the console from it, guards it, and serves the routes the vendored
// SPA calls.

const (
	testAdminRootEmail    = "root@example.test"
	testAdminRootPassword = "root-passw0rd-for-the-console"
	testBootstrapSecret   = "bootstrap-secret-0123456789abcdefghij"
)

// testRootHash is one bcrypt hash for the whole package, at MinCost: the
// console's login verifies it on every test that logs the root user in, and
// the cost is orthogonal to everything asserted.
var testRootHash = func() string {
	h, err := bcrypt.GenerateFromPassword([]byte(testAdminRootPassword), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	return string(h)
}()

// adminEnv is baseEnv plus a mounted console under the given policy, with
// every console store switched on so the tabs have something behind them, and
// the root user configured so the suite can log in without first promoting
// anybody.
func adminEnv(policy string, kv ...string) map[string]string {
	env := with(baseEnv(),
		"AWESOME_AUTH_ADMIN_ENABLED", "true",
		"AWESOME_AUTH_ADMIN_ACCESS_POLICY", policy,
		"AWESOME_AUTH_ADMIN_ROOT_EMAIL", testAdminRootEmail,
		"AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH", testRootHash,
		"AWESOME_AUTH_STORES_ENABLE_METADATA", "true",
		"AWESOME_AUTH_STORES_ENABLE_RBAC", "true",
		"AWESOME_AUTH_STORES_ENABLE_TENANTS", "true",
		"AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true",
		"AWESOME_AUTH_STORES_ENABLE_WEBHOOKS", "true",
		"AWESOME_AUTH_STORES_ENABLE_SETTINGS", "true",
		// The auth router's limiter would otherwise count the logins these
		// tests make against one address; the promote route's own limiter is
		// exercised by name in TestAdminPromoteRouteIsRateLimited.
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "false",
	)
	return with(env, kv...)
}

func loadAdmin(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(context.Background(), config.Options{
		Getenv:             envFunc(env),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// adminSurface is the deployment's whole HTTP handler for cfg, built exactly
// as New builds it minus the loader and the Lambda event layer, plus the
// memory bundle the core was handed, so a test can reach the stores directly
// where the wire offers no route (assigning a role, seeding an upload).
type adminSurface struct {
	handler http.Handler
	stores  memoryStoreBundle
	core    *auth.Auth
}

func newAdminSurface(t *testing.T, cfg *config.Config, opts Options, counter rateLimitCounter) *adminSurface {
	t.Helper()
	log := discardLogger()
	opts.Logger = log
	users := newMemoryStoreBundle()
	deliver, err := newDelivery(cfg, opts.Mail, opts.SMS, opts.HTTPClient, log)
	if err != nil {
		t.Fatalf("newDelivery: %v", err)
	}
	core, err := buildCore(context.Background(), cfg, opts, users, auth.NewMemorySessionStore(), deliver, log)
	if err != nil {
		t.Fatalf("buildCore: %v", err)
	}
	if err := checkAdminMounted(cfg, httpConfig(cfg)); err != nil {
		t.Fatalf("checkAdminMounted: %v", err)
	}
	mux := http.NewServeMux()
	if err := mountAuthSurface(mux, core, cfg, newRateLimiter(cfg, counter, log), newAdminPromoteLimiter(cfg, counter, log)); err != nil {
		t.Fatalf("mountAuthSurface: %v", err)
	}
	return &adminSurface{handler: docsSecurityHeaders(cfg)(mux), stores: users, core: core}
}

// call issues one request against the surface. body is JSON when non-nil.
func (s *adminSurface) call(t *testing.T, method, path string, body any, decorate ...func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	req.RemoteAddr = "203.0.113.7:4242"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, d := range decorate {
		d(req)
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func withBearer(token string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+token) }
}

func acceptHTML(r *http.Request) { r.Header.Set("Accept", "text/html") }

// rootLogin logs the configured root user in and returns the admin cookie.
func (s *adminSurface) rootLogin(t *testing.T) *http.Cookie {
	t.Helper()
	rec := s.call(t, http.MethodPost, "/admin/login", map[string]string{"email": testAdminRootEmail, "password": testAdminRootPassword})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/login as root answered %d: %s", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if strings.HasSuffix(c.Name, "accessToken") && c.Value != "" {
			return c
		}
	}
	t.Fatalf("the admin login set no accessToken cookie: %v", rec.Result().Cookies())
	return nil
}

// registerAndLogin provisions an ordinary account through the auth router and
// returns its id and a bearer access token — the credential the policy judges.
func (s *adminSurface) registerAndLogin(t *testing.T, email string) (id, token string) {
	t.Helper()
	reg := s.call(t, http.MethodPost, "/auth/register", map[string]string{"email": email, "password": testPassword})
	if reg.Code != http.StatusCreated && reg.Code != http.StatusOK {
		t.Fatalf("register %s: %d %s", email, reg.Code, reg.Body.String())
	}
	var regBody struct {
		UserID string `json:"userId"`
	}
	_ = json.Unmarshal(reg.Body.Bytes(), &regBody)
	login := s.call(t, http.MethodPost, "/auth/login", map[string]string{"email": email, "password": testPassword},
		func(r *http.Request) { r.Header.Set("X-Auth-Strategy", "bearer") })
	if login.Code != http.StatusOK {
		t.Fatalf("login %s: %d %s", email, login.Code, login.Body.String())
	}
	var tokens struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal(login.Body.Bytes(), &tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("login answered no accessToken: %s", login.Body.String())
	}
	return regBody.UserID, tokens.AccessToken
}

func decodeJSON(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("body is not a JSON object (%v): %s", err, rec.Body.String())
	}
	return m
}

// ── the mapping ──────────────────────────────────────────────────────────────

// TestAdminHTTPOptionsCarryTheWholeBlock pins the map from `admin.*` onto
// auth.AdminOptions knob by knob, for the reason TestUIOptionsCarryTheWholeBlock
// gives: once the domain is wired, this is what stands between a knob and
// reaching nothing.
func TestAdminHTTPOptionsCarryTheWholeBlock(t *testing.T) {
	t.Parallel()

	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_BASE_PATH", "/console",
		"AWESOME_AUTH_ADMIN_LOGIN_PATH", "/signin",
		"AWESOME_AUTH_ADMIN_COOKIE_PREFIX", "__Secure-",
		"AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET", testBootstrapSecret,
	))
	got := adminHTTPOptions(cfg)

	if !got.Enabled || got.Path != "/console" || got.LoginPath != "/signin" {
		t.Errorf("Enabled=%v Path=%q LoginPath=%q", got.Enabled, got.Path, got.LoginPath)
	}
	if got.AccessPolicy == nil || got.AccessPolicy.Kind != auth.AdminPolicyIsAdminFlag || got.AccessPolicy.Predicate != nil {
		t.Errorf("AccessPolicy = %+v, want the is-admin-flag kind", got.AccessPolicy)
	}
	if got.Secret != testBootstrapSecret {
		t.Errorf("Secret = %q, want the resolved bootstrap secret", got.Secret)
	}
	// The integration, and the inherited fix: empty means Config.Secret, i.e.
	// the access-token secret, and the core then accepts typ:"access" and
	// typ:"admin" and nothing else. A value here would sever the first
	// without buying the second.
	if got.JWTSecret != "" {
		t.Errorf("JWTSecret = %q, want empty so the core verifies with the access-token secret", got.JWTSecret)
	}
	if got.CookiePrefix == nil || *got.CookiePrefix != "__Secure-" {
		t.Errorf("CookiePrefix = %v, want the explicit override", got.CookiePrefix)
	}
	if got.RootUser == nil || got.RootUser.Email != testAdminRootEmail || got.RootUser.PasswordHash != testRootHash {
		t.Errorf("RootUser = %+v", got.RootUser)
	}
	if got.AuthAPIPrefix != "" || got.UploadBaseURL != "" || got.Docs.BasePath != "" {
		t.Errorf("AuthAPIPrefix=%q UploadBaseURL=%q Docs.BasePath=%q; all three are derived by the core from the mounts and must stay empty",
			got.AuthAPIPrefix, got.UploadBaseURL, got.Docs.BasePath)
	}
	// development, and docs.swagger at its default of auto: on, the way the
	// auth router's pair is on.
	if !got.Docs.Enabled || got.Docs.Enabled != docsEnabled(cfg) {
		t.Errorf("Docs.Enabled = %v, want it to follow docs.swagger through docsEnabled (%v)", got.Docs.Enabled, docsEnabled(cfg))
	}
	if got.RateLimiter != nil {
		t.Error("RateLimiter is set by httpConfig; it must be left to mountAuthSurface, which holds the counter")
	}

	// "unset" is spelled as the empty string and reaches the core as nil, so
	// the admin cookie's name is derived from the same cookie options the
	// session cookies use.
	plain := adminHTTPOptions(loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)))
	if plain.CookiePrefix != nil {
		t.Errorf("CookiePrefix = %q for an unset knob, want nil", *plain.CookiePrefix)
	}
}

func TestAdminAccessPolicyMapsEverySpelling(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		policy string
		kind   auth.AdminPolicyKind
		pred   bool
	}{
		{config.AdminAccessPolicyOpen, auth.AdminPolicyOpen, false},
		{config.AdminAccessPolicyFirstUser, auth.AdminPolicyFirstUser, false},
		{config.AdminAccessPolicyIsAdmin, auth.AdminPolicyIsAdminFlag, false},
		{"rbac:operators", "", true},
		{"permission:console:use", "", true},
	} {
		var cfg *config.Config
		if tc.policy == config.AdminAccessPolicyFirstUser {
			// RS-18 refuses first-user at load on every driver, so the only
			// Config that reaches this arm is one that bypassed the loader;
			// the mapping is kept for it and pinned here the same way.
			cfg = loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin))
			cfg.Admin.AccessPolicy = tc.policy
			if _, err := config.Load(context.Background(), config.Options{Getenv: envFunc(adminEnv(tc.policy)), AllowUnimplemented: true}); err == nil ||
				!strings.Contains(err.Error(), "[RS-18]") {
				t.Errorf("first-user loaded, or was refused by something other than RS-18: %v", err)
			}
		} else {
			cfg = loadAdmin(t, adminEnv(tc.policy))
		}
		got := adminAccessPolicy(cfg)
		if got == nil {
			t.Errorf("%s: nil policy", tc.policy)
			continue
		}
		if got.Kind != tc.kind || (got.Predicate != nil) != tc.pred {
			t.Errorf("%s: Kind=%q Predicate=%v, want Kind=%q Predicate=%v", tc.policy, got.Kind, got.Predicate != nil, tc.kind, tc.pred)
		}
	}

	// No policy at all is nil, which the core reads as the legacy bearer
	// guard — RS-6 only lets that load beside a bootstrap secret.
	legacy := loadAdmin(t, with(adminEnv(""), "AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET", testBootstrapSecret))
	if adminAccessPolicy(legacy) != nil {
		t.Error("an empty admin.accessPolicy mapped to a policy; it must be nil so the bootstrap secret is the guard")
	}
}

// failingRBAC is a RolesPermissionsStore whose reads fail, for the one branch
// of the predicate that matters most: a store error is a denial, not a 500 and
// not a grant.
type failingRBAC struct{ auth.RolesPermissionsStore }

func (failingRBAC) GetRolesForUser(context.Context, string, string) ([]string, error) {
	return nil, errors.New("dynamodb is on fire")
}

func (failingRBAC) UserHasPermission(context.Context, string, string, string) (bool, error) {
	return false, errors.New("dynamodb is on fire")
}

func TestAdminRBACPredicateGrantsByRoleOrPermissionAndDeniesOnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rbac := auth.NewMemoryRolesPermissionsStore()
	if err := rbac.CreateRole(ctx, "operators", []string{"console:use"}); err != nil {
		t.Fatal(err)
	}
	if err := rbac.AddRoleToUser(ctx, "u1", "operators", "acme"); err != nil {
		t.Fatal(err)
	}
	holder := auth.User{ID: "u1", TenantID: "acme"}
	stranger := auth.User{ID: "u2", TenantID: "acme"}
	// Same id, other tenant: a role is a tenant-scoped assignment and the
	// predicate asks in the user's own.
	elsewhere := auth.User{ID: "u1", TenantID: "globex"}

	byRole := adminRBACPredicate(adminPredicateRole, "operators")
	byPerm := adminRBACPredicate(adminPredicatePermission, "console:use")
	for name, tc := range map[string]struct {
		pred auth.AdminPolicyFunc
		user auth.User
		want bool
	}{
		"role held":            {byRole, holder, true},
		"role not held":        {byRole, stranger, false},
		"role in other tenant": {byRole, elsewhere, false},
		"permission held":      {byPerm, holder, true},
		"permission not held":  {byPerm, stranger, false},
	} {
		got, err := tc.pred(ctx, tc.user, rbac)
		if err != nil || got != tc.want {
			t.Errorf("%s: (%v, %v), want (%v, nil)", name, got, err, tc.want)
		}
	}

	// The denial branches. Both answer (false, error), which the core reads as
	// granted = false — the reference's catch { granted = false } — and never
	// as a 500.
	for name, pred := range map[string]auth.AdminPolicyFunc{"role": byRole, "permission": byPerm} {
		if got, err := pred(ctx, holder, nil); got || err == nil {
			t.Errorf("%s with no store: (%v, %v), want a denial with an error", name, got, err)
		}
		if got, err := pred(ctx, holder, failingRBAC{}); got || err == nil {
			t.Errorf("%s with a failing store: (%v, %v), want a denial with an error", name, got, err)
		}
	}
}

// ── the surface ──────────────────────────────────────────────────────────────

// TestAdminConsoleIsMountedGuardedAndServed is the block end to end on the
// memory driver: the adapter mounts the console beside the api prefix, the
// guard refuses an anonymous caller, the shell serves the login form, the root
// login mints a session, and behind it the users, settings and promote routes
// answer — and an ordinary account is judged by the policy on its own access
// token, which is the integration the empty JWTSecret buys.
func TestAdminConsoleIsMountedGuardedAndServed(t *testing.T) {
	t.Parallel()
	s := newAdminSurface(t, loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)), Options{}, nil)

	// Anonymous: 401 on the API, the login shell on an HTML GET of the root,
	// and 401 — not the shell — on an HTML GET of a guarded route, which is
	// the upstream narrowing this product inherits.
	if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous GET /admin/api/ping answered %d, want 401: %s", rec.Code, rec.Body.String())
	} else if m := decodeJSON(t, rec); m["error"] != "Unauthorized" {
		t.Errorf("anonymous ping body = %v, want the admin envelope {\"error\":\"Unauthorized\"}", m)
	}
	if rec := s.call(t, http.MethodGet, "/admin/", nil, acceptHTML); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), "window.__ADMIN_CONFIG__") ||
		!strings.Contains(rec.Body.String(), `"sessionBased":true`) ||
		!strings.Contains(rec.Body.String(), `id="login"`) {
		t.Errorf("anonymous HTML GET /admin/ answered %d and did not render the login shell:\n%s", rec.Code, rec.Body.String())
	}
	if rec := s.call(t, http.MethodGet, "/admin/api/users", nil, acceptHTML); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous HTML GET /admin/api/users answered %d, want 401: the reference serves the user table here", rec.Code)
	}

	// The root login, and what a session buys.
	cookie := s.rootLogin(t)
	rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withCookie(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("ping with the admin cookie answered %d: %s", rec.Code, rec.Body.String())
	}
	features, _ := decodeJSON(t, rec)["features"].(map[string]any)
	for name, want := range map[string]bool{
		"roles": true, "tenants": true, "metadata": true, "apiKeys": true, "webhooks": true,
		"control": true, "sessions": true, "templates": false, "upload": false,
	} {
		if features[name] != want {
			t.Errorf("features.%s = %v, want %v (the flag follows the store the admin slot handed over): %v", name, features[name], want, features)
		}
	}

	// The users tab reads the lister; the account registered a moment ago is
	// in it.
	id, token := s.registerAndLogin(t, "operator@example.test")
	rec = s.call(t, http.MethodGet, "/admin/api/users", nil, withCookie(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/users answered %d: %s", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, `"operator@example.test"`) || !strings.Contains(body, `"total":`) {
		t.Errorf("the users listing does not carry the registered account and a total: %s", body)
	}

	// Settings round trip through the store the `settings` slot handed over.
	rec = s.call(t, http.MethodGet, "/admin/api/settings", nil, withCookie(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/api/settings answered %d: %s", rec.Code, rec.Body.String())
	}
	rec = s.call(t, http.MethodPut, "/admin/api/settings", map[string]any{"require2FA": true}, withCookie(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/api/settings answered %d: %s", rec.Code, rec.Body.String())
	}
	if m := decodeJSON(t, s.call(t, http.MethodGet, "/admin/api/settings", nil, withCookie(cookie))); m["require2FA"] != true {
		t.Errorf("settings after the PUT = %v, want require2FA true", m)
	}

	// An ordinary account's access token is a credential the policy judges:
	// refused while the flag is off, admitted once the console's own promote
	// route sets it — through the writer the memory bundle promotes, exactly
	// as the DynamoDB store's UpdateIsAdmin would be.
	if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(token)); rec.Code != http.StatusForbidden {
		t.Fatalf("an unflagged user's access token answered %d on ping, want 403 Forbidden", rec.Code)
	}
	rec = s.call(t, http.MethodPost, "/admin/users/"+id+"/promote", map[string]string{"method": "flag"}, withCookie(cookie))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/users/{id}/promote answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(token)); rec.Code != http.StatusOK {
		t.Errorf("the promoted user's access token answered %d on ping, want 200: an access token is an admin credential under the policy", rec.Code)
	}

	// And the thing the typed-token deviation closes: a 2FA step-up token is
	// not an admin credential. There is no enrolment here to mint one, so the
	// nearest observable is that a refresh token — also signed by the shared
	// secret, and never typ:"access" — is refused.
	login := s.call(t, http.MethodPost, "/auth/login", map[string]string{"email": "operator@example.test", "password": testPassword},
		func(r *http.Request) { r.Header.Set("X-Auth-Strategy", "bearer") })
	var pair struct {
		RefreshToken string `json:"refreshToken"`
	}
	_ = json.Unmarshal(login.Body.Bytes(), &pair)
	if pair.RefreshToken == "" {
		t.Fatalf("bearer login answered no refreshToken: %s", login.Body.String())
	}
	if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(pair.RefreshToken)); rec.Code != http.StatusUnauthorized {
		t.Errorf("a refresh token answered %d on ping, want 401: the guard accepts typ admin and typ access and nothing else", rec.Code)
	}
}

func TestAdminConsoleIsNotMountedWhenTheBlockIsOff(t *testing.T) {
	t.Parallel()
	s := newAdminSurface(t, mustLoad(t, baseEnv()), Options{}, nil)
	for _, path := range []string{"/admin", "/admin/", "/admin/api/ping", "/admin/login"} {
		if rec := s.call(t, http.MethodGet, path, nil); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s answered %d with admin.enabled off, want 404", path, rec.Code)
		}
	}
}

func TestAdminStoresFollowTheirFlags(t *testing.T) {
	t.Parallel()
	env := adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_STORES_ENABLE_METADATA", "false",
		"AWESOME_AUTH_STORES_ENABLE_RBAC", "false",
		"AWESOME_AUTH_STORES_ENABLE_TENANTS", "false",
		"AWESOME_AUTH_STORES_ENABLE_API_KEYS", "false",
		"AWESOME_AUTH_STORES_ENABLE_WEBHOOKS", "false",
	)
	s := newAdminSurface(t, loadAdmin(t, env), Options{}, nil)
	cookie := s.rootLogin(t)
	features, _ := decodeJSON(t, s.call(t, http.MethodGet, "/admin/api/ping", nil, withCookie(cookie)))["features"].(map[string]any)
	for _, name := range []string{"roles", "tenants", "metadata", "apiKeys", "webhooks"} {
		if features[name] != false {
			t.Errorf("features.%s = %v with its flag off, want false: a flag that is off must hand nothing over", name, features[name])
		}
	}
	// The routes behind those tabs answer the reference's own absence.
	if rec := s.call(t, http.MethodGet, "/admin/api/api-keys", nil, withCookie(cookie)); rec.Code != http.StatusNotFound {
		t.Errorf("GET /admin/api/api-keys with no store answered %d, want the reference's 404", rec.Code)
	}
}

// TestAdminRBACPolicyThroughTheSurface drives the two string forms against
// the mounted console: an access token is refused until the role, or the
// permission, is assigned in the RBAC store the `admin` slot handed over.
func TestAdminRBACPolicyThroughTheSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		policy string
		grant  func(ctx context.Context, rbac auth.RolesPermissionsStore, userID string) error
	}{
		{"rbac:operators", func(ctx context.Context, rbac auth.RolesPermissionsStore, userID string) error {
			if err := rbac.CreateRole(ctx, "operators", nil); err != nil {
				return err
			}
			return rbac.AddRoleToUser(ctx, userID, "operators", "")
		}},
		{"permission:console:use", func(ctx context.Context, rbac auth.RolesPermissionsStore, userID string) error {
			if err := rbac.CreateRole(ctx, "support", []string{"console:use"}); err != nil {
				return err
			}
			return rbac.AddRoleToUser(ctx, userID, "support", "")
		}},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			t.Parallel()
			s := newAdminSurface(t, loadAdmin(t, adminEnv(tc.policy)), Options{}, nil)
			id, token := s.registerAndLogin(t, "rbac-"+strings.ReplaceAll(tc.policy, ":", "-")+"@example.test")

			if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(token)); rec.Code != http.StatusForbidden {
				t.Fatalf("before the grant, ping answered %d, want 403", rec.Code)
			}
			if err := tc.grant(context.Background(), s.stores.rbac, id); err != nil {
				t.Fatalf("grant: %v", err)
			}
			if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(token)); rec.Code != http.StatusOK {
				t.Errorf("after the grant, ping answered %d, want 200: %s", rec.Code, rec.Body.String())
			}
			// The root user bypasses the policy on either form, as there.
			if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withCookie(s.rootLogin(t))); rec.Code != http.StatusOK {
				t.Errorf("root answered %d under %s, want 200", rec.Code, tc.policy)
			}
		})
	}
}

// ── uploads ──────────────────────────────────────────────────────────────────

// TestUploadedAssetsAreServedFromTheUploadStore is the retired deviation
// driven the other way: with ui.uploadDir naming an S3 location, the console
// uploads through the store and the hosted UI serves the object back — from
// the same store, through the core's own composition, with UIOptions.Uploads
// left nil.
func TestUploadedAssetsAreServedFromTheUploadStore(t *testing.T) {
	t.Parallel()
	uploads := auth.NewMemoryUploadStore()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_UI_ENABLED", "true",
		"AWESOME_AUTH_UI_UPLOAD_DIR", "s3://logos-bucket/uploads",
	))
	s := newAdminSurface(t, cfg, Options{UploadStore: uploads}, nil)
	cookie := s.rootLogin(t)

	features, _ := decodeJSON(t, s.call(t, http.MethodGet, "/admin/api/ping", nil, withCookie(cookie)))["features"].(map[string]any)
	if features["upload"] != true {
		t.Fatalf("features.upload = %v, want true with an upload store configured", features["upload"])
	}

	// Through the console's route, as the SPA sends it: one multipart part
	// named "file".
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", "brand.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = part.Write([]byte("\x89PNG-not-really"))
	_ = mw.Close()
	req := httptest.NewRequest(http.MethodPost, "/admin/api/upload/logo", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /admin/api/upload/logo answered %d: %s", rec.Code, rec.Body.String())
	}
	answer := decodeJSON(t, rec)
	filename, _ := answer["filename"].(string)
	url, _ := answer["url"].(string)
	if filename == "" || !strings.HasPrefix(url, "/auth/ui/assets/uploads/") {
		t.Fatalf("upload answered %v, want a filename and a url under the UI's asset mount", answer)
	}

	// And back out through the hosted UI, anonymously, as a browser fetches a
	// logo.
	got := s.call(t, http.MethodGet, url, nil)
	if got.Code != http.StatusOK || got.Body.String() != "\x89PNG-not-really" {
		t.Errorf("GET %s answered %d %q, want the uploaded bytes", url, got.Code, got.Body.String())
	}
	if ct := got.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/png") {
		t.Errorf("GET %s Content-Type = %q, want image/png", url, ct)
	}
	// Both legacy and unified paths, as the reference mounts both.
	if got := s.call(t, http.MethodGet, "/auth/ui/assets/logo/"+filename, nil); got.Code != http.StatusOK {
		t.Errorf("GET /auth/ui/assets/logo/%s answered %d, want 200", filename, got.Code)
	}
	if got := s.call(t, http.MethodGet, "/auth/ui/assets/uploads/nope.png", nil); got.Code != http.StatusNotFound {
		t.Errorf("a missing upload answered %d, want 404 — ErrUploadNotFound must survive UploadFS", got.Code)
	}
	// The listing and the delete, so the four routes are all seen to reach the
	// store.
	if rec := s.call(t, http.MethodGet, "/admin/api/upload/files", nil, withCookie(cookie)); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), filename) {
		t.Errorf("GET /admin/api/upload/files answered %d %s", rec.Code, rec.Body.String())
	}
	if rec := s.call(t, http.MethodDelete, "/admin/api/upload/"+filename, nil, withCookie(cookie)); rec.Code != http.StatusOK {
		t.Errorf("DELETE /admin/api/upload/%s answered %d %s", filename, rec.Code, rec.Body.String())
	}
	if got := s.call(t, http.MethodGet, url, nil); got.Code != http.StatusNotFound {
		t.Errorf("after the delete, GET %s answered %d, want 404", url, got.Code)
	}
}

func TestAPlainUploadPathBuildsNoStoreAndIsReported(t *testing.T) {
	t.Parallel()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_UI_ENABLED", "true",
		"AWESOME_AUTH_UI_UPLOAD_DIR", "/var/uploads",
	))
	// An injected store must not be picked up: the seam switches nothing on.
	s := newAdminSurface(t, cfg, Options{UploadStore: auth.NewMemoryUploadStore()}, nil)
	cookie := s.rootLogin(t)
	features, _ := decodeJSON(t, s.call(t, http.MethodGet, "/admin/api/ping", nil, withCookie(cookie)))["features"].(map[string]any)
	if features["upload"] != false {
		t.Errorf("features.upload = %v for a filesystem path, want false", features["upload"])
	}
	if rec := s.call(t, http.MethodGet, "/auth/ui/assets/uploads/x.png", nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /auth/ui/assets/uploads/x.png answered %d with no store, want the reference's 404", rec.Code)
	}

	gaps := map[string]knobGap{}
	for _, g := range unwiredKnobs(cfg) {
		gaps[g.Path] = g
	}
	g, ok := gaps["ui.uploadDir"]
	if !ok || !strings.Contains(g.Remedy, "s3://") {
		t.Errorf("ui.uploadDir as a path is not reported with the s3:// remedy: %+v", g)
	}

	if _, err := newUploadStore(loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin, "AWESOME_AUTH_UI_UPLOAD_DIR", "s3://")), nil); err == nil {
		t.Error("s3:// with no bucket built a store; it is neither a path nor a location")
	}
}

// ── the knobs the core cannot honour ─────────────────────────────────────────

func TestAdminKnobGapsReportOnlyWhatDiffersFromTheCore(t *testing.T) {
	t.Parallel()

	paths := func(cfg *config.Config) map[string]bool {
		out := map[string]bool{}
		for _, g := range adminKnobGaps(cfg) {
			out[g.Path] = true
			if g.Problem == "" || g.Remedy == "" {
				t.Errorf("gap %s has an empty problem or remedy", g.Path)
			}
		}
		return out
	}

	quiet := paths(loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin, "AWESOME_AUTH_UI_UPLOAD_DIR", "s3://b/p")))
	if len(quiet) != 0 {
		t.Errorf("defaults plus an S3 location reported %v; the defaults are the values the core applies", quiet)
	}

	loud := paths(loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_SESSION_TTL", "12h",
		"AWESOME_AUTH_ADMIN_UPLOAD_MAX_FILE_SIZE_MB", "10",
		"AWESOME_AUTH_UI_UPLOAD_DIR", "/tmp/uploads",
	)))
	for _, want := range []string{"admin.sessionTtl", "admin.upload.maxFileSizeMb", "ui.uploadDir"} {
		if !loud[want] {
			t.Errorf("adminKnobGaps did not report %s", want)
		}
	}
}

// TestAdminSessionTTLMatchesTheCore holds the transcribed constant to the
// token the core actually mints: the reference's 24h, which is what the
// sessionTtl gap tells an operator the deployed value is.
func TestAdminSessionTTLMatchesTheCore(t *testing.T) {
	t.Parallel()
	s := newAdminSurface(t, loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)), Options{}, nil)
	cookie := s.rootLogin(t)

	parts := strings.Split(cookie.Value, ".")
	if len(parts) != 3 {
		t.Fatalf("the admin cookie is not a compact JWS: %q", cookie.Value)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims struct {
		Typ string `json:"typ"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if claims.Typ != "admin" {
		t.Errorf("typ = %q, want admin", claims.Typ)
	}
	if got := time.Duration(claims.Exp-claims.Iat) * time.Second; got != adminSessionTTL {
		t.Errorf("the minted admin session lives %s; adminSessionTTL says %s and the gap report would lie", got, adminSessionTTL)
	}
	if cookie.MaxAge != int(adminSessionTTL/time.Second) {
		t.Errorf("cookie Max-Age = %d, want %d: the reference pins both to the same day", cookie.MaxAge, int(adminSessionTTL/time.Second))
	}
}

// ── refusals ─────────────────────────────────────────────────────────────────

func TestAdminRootUserWithoutAHashIsRefused(t *testing.T) {
	t.Parallel()
	env := adminEnv(config.AdminAccessPolicyIsAdmin)
	delete(env, "AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH")
	cfg := loadAdmin(t, env)

	_, err := adminOptions(cfg, Options{}, newMemoryStoreBundle(), discardLogger())
	if err == nil || !strings.Contains(err.Error(), "admin.rootUser.passwordHash") {
		t.Fatalf("adminOptions = %v, want a refusal naming admin.rootUser.passwordHash", err)
	}

	bad := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin, "AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH", "hunter2"))
	if _, err := adminOptions(bad, Options{}, newMemoryStoreBundle(), discardLogger()); err == nil || !strings.Contains(err.Error(), "bcrypt") {
		t.Fatalf("a plaintext password where a hash belongs was accepted: %v", err)
	}
}

// ── the promote limiter ──────────────────────────────────────────────────────

// TestAdminPromoteRouteIsRateLimited: the console's own limiter slot covers the
// promote route ahead of the guard — an anonymous flood is refused with the
// registered 429 before a token is read — and nothing else on the surface, the
// admin login included.
func TestAdminPromoteRouteIsRateLimited(t *testing.T) {
	t.Parallel()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "true",
		"AWESOME_AUTH_RATE_LIMIT_MAX", "2",
		"AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "60",
	))
	s := newAdminSurface(t, cfg, Options{}, nil)

	for i := 1; i <= 2; i++ {
		if rec := s.call(t, http.MethodPost, "/admin/users/someone/promote", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("promote attempt %d answered %d, want 401 (under budget, refused by the guard)", i, rec.Code)
		}
	}
	rec := s.call(t, http.MethodPost, "/admin/users/someone/promote", nil)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("promote attempt 3 answered %d, want 429 ahead of the guard: %s", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != rateLimitBody {
		t.Errorf("429 body = %q, want the registered %q", rec.Body.String(), rateLimitBody)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 carries no Retry-After")
	}

	// The admin login is deliberately unlimited, on either line.
	for i := 1; i <= 5; i++ {
		if rec := s.call(t, http.MethodPost, "/admin/login", map[string]string{"email": "nobody@example.test", "password": "wrong"}); rec.Code == http.StatusTooManyRequests {
			t.Fatalf("POST /admin/login was rate limited on attempt %d; the slot covers the promote route alone", i)
		}
	}
	// And a different address is a different budget.
	other := httptest.NewRequest(http.MethodPost, "/admin/users/someone/promote", nil)
	other.RemoteAddr = "198.51.100.9:1"
	otherRec := httptest.NewRecorder()
	s.handler.ServeHTTP(otherRec, other)
	if otherRec.Code != http.StatusUnauthorized {
		t.Errorf("another address answered %d on its first promote, want 401", otherRec.Code)
	}

	if newAdminPromoteLimiter(mustLoad(t, baseEnv()), nil, discardLogger()) == nil {
		t.Error("the promote limiter is nil with rateLimit.enabled at its default of true")
	}
	if newAdminPromoteLimiter(mustLoad(t, with(baseEnv(), "AWESOME_AUTH_RATE_LIMIT_ENABLED", "false")), nil, discardLogger()) != nil {
		t.Error("the promote limiter is built with rateLimit.enabled off; nil is the reference's own default")
	}
}

// ── the documentation pair ───────────────────────────────────────────────────

func TestAdminDocsPairFollowsDocsSwaggerAndCarriesThePolicy(t *testing.T) {
	t.Parallel()

	on := newAdminSurface(t, loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)), Options{}, nil)
	spec := on.call(t, http.MethodGet, "/admin/api/openapi.json", nil)
	if spec.Code != http.StatusOK || spec.Header().Get("Content-Security-Policy") != docsSpecCSP {
		t.Errorf("GET /admin/api/openapi.json answered %d with CSP %q, want 200 and the document policy", spec.Code, spec.Header().Get("Content-Security-Policy"))
	}
	page := on.call(t, http.MethodGet, "/admin/api/docs", nil)
	if page.Code != http.StatusOK || page.Header().Get("Content-Security-Policy") != docsPageCSP {
		t.Errorf("GET /admin/api/docs answered %d with CSP %q, want 200 and the page policy", page.Code, page.Header().Get("Content-Security-Policy"))
	}

	// Production, docs.swagger at auto: both pairs off, no header on the 404.
	prodEnv := adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT", "production",
		"AWESOME_AUTH_STORES_DRIVER", "dynamodb",
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", "t",
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "eu-west-1",
		"AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE", "false",
	)
	off := newAdminSurface(t, loadAdmin(t, prodEnv), Options{}, nil)
	if rec := off.call(t, http.MethodGet, "/admin/api/docs", nil); rec.Code != http.StatusNotFound || rec.Header().Get("Content-Security-Policy") != "" {
		t.Errorf("in production GET /admin/api/docs answered %d with CSP %q, want 404 and no policy", rec.Code, rec.Header().Get("Content-Security-Policy"))
	}
}

// TestLogAdminSurfaceNamesTheBackfill pins the one line only the cold-start
// log can carry: on the DynamoDB driver the user directory is only as complete
// as the one-time sweep, and the operator hears it before the first 200 that
// under-reports.
func TestLogAdminSurfaceNamesTheBackfill(t *testing.T) {
	t.Parallel()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_STORES_DRIVER", "dynamodb",
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", "auth-live",
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "eu-west-1",
	))
	var buf bytes.Buffer
	logAdminSurface(cfg, httpConfig(cfg), newLogger(&buf, slog.LevelInfo))
	out := buf.String()
	for _, want := range []string{
		"admin console mounted", "is-admin-flag", "migrate backfill-users --table auth-live",
		"admin-unauthenticated-get-serves-only-the-login-form", "admin-login-skips-the-second-factor",
		// The boolean is readable: under its old name, bootstrapSecret, the
		// redaction list turned it into [REDACTED] on every cold start.
		`"bootstrapSecretConfigured":false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cold-start log does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, `"bootstrapSecretConfigured":"[REDACTED]"`) {
		t.Errorf("the bootstrap-secret boolean is redacted, so the line cannot say whether one is active:\n%s", out)
	}

	// With a secret configured the boolean flips, and the value itself never
	// appears.
	buf.Reset()
	withSecret := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin, "AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET", testBootstrapSecret))
	logAdminSurface(withSecret, httpConfig(withSecret), newLogger(&buf, slog.LevelInfo))
	if !strings.Contains(buf.String(), `"bootstrapSecretConfigured":true`) || strings.Contains(buf.String(), testBootstrapSecret) {
		t.Errorf("with a bootstrap secret the line must say so and never carry it:\n%s", buf.String())
	}

	// The open console is a Warn, not an Info: it admits the world on a stack
	// whose every front door is internet-facing.
	buf.Reset()
	open := loadAdmin(t, adminEnv(config.AdminAccessPolicyOpen))
	logAdminSurface(open, httpConfig(open), newLogger(&buf, slog.LevelInfo))
	if !strings.Contains(buf.String(), `"level":"WARN","msg":"admin console mounted"`) {
		t.Errorf("an open console is not announced at Warn:\n%s", buf.String())
	}
	if !strings.Contains(out, `"level":"INFO","msg":"admin console mounted"`) {
		t.Errorf("a guarded console is not announced at Info:\n%s", out)
	}

	buf.Reset()
	off := mustLoad(t, baseEnv())
	logAdminSurface(off, httpConfig(off), newLogger(&buf, slog.LevelInfo))
	if !strings.Contains(buf.String(), "admin console not mounted") {
		t.Errorf("an unmounted console is not announced:\n%s", buf.String())
	}
}

// TestDriverStoresListTheConsoleStores pins the widening that makes the five
// flags real switches on both drivers, and the one that stays out.
func TestDriverStoresListTheConsoleStores(t *testing.T) {
	t.Parallel()
	for _, driver := range []string{config.StoreDriverDynamoDB, config.StoreDriverMemory} {
		supported, ok := driverStores(driver)
		if !ok {
			t.Fatalf("%s: unknown driver", driver)
		}
		for _, name := range []string{"metadata", "rbac", "tenants", "apiKeys", "webhooks"} {
			if !supported[name] {
				t.Errorf("%s: stores.enable.%s is still refused; the admin slot hands it over now", driver, name)
			}
		}
		if supported["telemetry"] {
			t.Errorf("%s: stores.enable.telemetry is listed, but nothing hands the telemetry store to the core until the tools block does", driver)
		}
	}
	if fmt.Sprint(enabledStores(config.Defaults().Stores.Enable)) != "[sessions tokens users]" {
		t.Error("the defaults changed; the console's flags must stay off by default")
	}
}
