package config

import (
	"strings"
	"testing"
)

// TestConfiguringAnUnwiredDomainIsRefused is the promise that an operator who
// configures something that does nothing gets told. Each case touches one domain
// that P1 validates but does not act on; none of them may load silently.
func TestConfiguringAnUnwiredDomainIsRefused(t *testing.T) {
	cases := []struct {
		domain string
		mutate func(Document)
	}{
		{"security.jwt.extraClaims", func(doc Document) {
			set(doc, "security.jwt.extraClaims.tenant", map[string]any{"fromUserField": "tenantId"})
		}},
		{"security.jwt.claimsWebhook", func(doc Document) {
			set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
		}},
		{"email.siteUrls", func(doc Document) {
			set(doc, "email.siteUrls", []any{"https://app.example.com"})
		}},
		{"email.templatesDir", func(doc Document) {
			set(doc, "email.templatesDir", "./templates")
		}},
		{"email.deliveryWebhook", func(doc Document) {
			set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
		}},
		{"oauth", func(doc Document) {
			set(doc, "oauth.provisioning.autoCreate", true)
		}},
		{"twoFactor", func(doc Document) {
			set(doc, "twoFactor.appName", "Example")
		}},
		{"idProvider", func(doc Document) {
			set(doc, "idProvider.issuer", "https://auth.example.com")
		}},
		{"resourceServer", func(doc Document) {
			set(doc, "resourceServer.jwksCacheTtlMs", 60000)
		}},
		{"ui", func(doc Document) {
			set(doc, "ui.branding.siteName", "Example")
		}},
		{"admin", func(doc Document) {
			set(doc, "admin.basePath", "/console")
		}},
		{"tools", func(doc Document) {
			set(doc, "tools.basePath", "/ops")
		}},
		{"rateLimit", func(doc Document) {
			set(doc, "rateLimit.enabled", true)
			set(doc, "rateLimit.scope", []any{"login"})
		}},
		{"docs", func(doc Document) {
			set(doc, "docs.swagger", "false")
		}},
		{"runtimeSettings", func(doc Document) {
			set(doc, "runtimeSettings.lazyEmailVerificationGracePeriodDays", 14)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			d := requireRule(t, err, RuleUnimplemented, tc.domain)
			if !strings.Contains(d.Error(), "not yet wired") {
				t.Errorf("diagnostic does not say the block is inert:\n%s", d.Error())
			}
			if !strings.Contains(d.Error(), "P") {
				t.Errorf("diagnostic does not name the phase that wires it:\n%s", d.Error())
			}
		})
	}
}

// TestUnwiredDomainViaEnvIsAlsoRefused: the phase gap is detected on the layered
// result, so an override supplied through the environment counts exactly as much
// as one written in the document.
func TestUnwiredDomainViaEnvIsAlsoRefused(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_UI_ENABLED"] = "true"

	_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	requireRule(t, err, RuleUnimplemented, "ui")
}

// TestUnwiredDomainViaSecretIsAlsoRefused: a secret supplied through its
// documented variable leaves no trace in the Config tree, so the check also looks
// at what actually resolved.
func TestUnwiredDomainViaSecretIsAlsoRefused(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_IDP_PRIVATE_KEY"] = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"

	_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	requireRule(t, err, RuleUnimplemented, "idProvider")
}

// TestAllowUnimplementedDowngradesToWarning: the gap stays visible in the
// deployment log, it just no longer refuses. It must never become silence.
func TestAllowUnimplementedDowngradesToWarning(t *testing.T) {
	doc := baseDoc()
	set(doc, "ui.enabled", true)

	cfg, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(baseEnv()),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, w := range cfg.Warnings() {
		if w.Path == "ui" && strings.Contains(w.Problem, "not yet wired") {
			return
		}
	}
	t.Errorf("the phase gap disappeared instead of becoming a warning; warnings: %v", cfg.Warnings())
}

// TestWiredDomainsAreNotFlagged: the whole point of the P1 scope is that these
// domains work, so configuring them must not trip the phase-gap check.
func TestWiredDomainsAreNotFlagged(t *testing.T) {
	doc := baseDoc()
	set(doc, "cookies.secure", true)
	set(doc, "cookies.sameSite", "none")
	set(doc, "security.csrf.enabled", true)
	set(doc, "security.jwt.accessTokenTtl", "10m")
	set(doc, "security.password.bcryptSaltRounds", 13)
	set(doc, "sessions.checkOn", "allcalls")
	set(doc, "tokens.magicLinkTtlMinutes", 30)
	set(doc, "email.verification.mode", "strict")
	set(doc, "http.apiPrefix", "/identity")
	set(doc, "stores.enable.metadata", true)
	set(doc, "deployment.stage", "prod")

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("every knob here is in the P1 scope, so this must load:\n%v", err)
	}
	if cfg.Email.Verification.Mode != EmailVerificationStrict {
		t.Errorf("email.verification.mode = %q, want strict", cfg.Email.Verification.Mode)
	}
}

// TestDeliveryDomainsAreWired is the other side of the refusal table: the two
// blocks that select a credential transport must now load, because a deployment
// that configures them gets mail and text messages rather than a phase error.
//
// Both are written the way the schema requires them — email.mailer needs an
// endpoint and a from address together, sms needs an endpoint — so this also
// pins that un-gating did not quietly relax the block's own validation. What
// the AWS transports then do with the endpoint is cmd/auth's unwiredKnobs
// problem, not this package's.
func TestDeliveryDomainsAreWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
	}{
		{"email.mailer", func(doc Document) {
			set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
			set(doc, "email.mailer.from", "no-reply@example.com")
			set(doc, "email.mailer.fromName", "Example")
			set(doc, "email.mailer.defaultLang", "it")
		}},
		{"sms", func(doc Document) {
			set(doc, "sms.endpoint", "https://sms.example.com/send")
			set(doc, "sms.codeTtlMinutes", 5)
		}},
		{"both together", func(doc Document) {
			set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
			set(doc, "email.mailer.from", "no-reply@example.com")
			set(doc, "sms.endpoint", "https://sms.example.com/send")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			if err != nil {
				t.Fatalf("the delivery blocks are wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if (w.Path == "email.mailer" || w.Path == "sms") && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("%s is still reported as an unwired domain: %s", w.Path, w.Problem)
				}
			}
		})
	}
}

// TestDeliverySecretsNoLongerTripThePhaseGap: a secret supplied through its
// documented environment variable leaves no trace in the Config tree, so the
// phase check looks at resolved secrets too. Both delivery blocks had a
// secretPrefix, and removing the domains has to remove that half as well —
// otherwise an operator who puts the SMS credentials in Secrets Manager gets a
// refusal for a block that works.
func TestDeliverySecretsNoLongerTripThePhaseGap(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_MAILER_API_KEY"] = "mailer-api-key-value"
	env["AWESOME_AUTH_SMS_API_KEY"] = "sms-api-key-value"
	env["AWESOME_AUTH_SMS_USERNAME"] = "sms-user"
	env["AWESOME_AUTH_SMS_PASSWORD"] = "sms-pass"

	doc := baseDoc()
	set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
	set(doc, "email.mailer.from", "no-reply@example.com")
	set(doc, "sms.endpoint", "https://sms.example.com/send")

	if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)}); err != nil {
		t.Fatalf("delivery secrets must not reopen the phase gap:\n%v", err)
	}
}

// TestUnwiredDomainsAreDocumented keeps the exported list and the internal table
// in step, since the deployment tooling reads the exported one.
func TestUnwiredDomainsAreDocumented(t *testing.T) {
	exported := UnwiredDomains()
	if len(exported) != len(unwiredDomains()) {
		t.Fatalf("UnwiredDomains has %d entries, the table has %d", len(exported), len(unwiredDomains()))
	}
	for _, path := range sortedDomainPaths() {
		phase, ok := exported[path]
		if !ok {
			t.Errorf("%s is missing from UnwiredDomains", path)
			continue
		}
		if phase == "" {
			t.Errorf("%s has no phase recorded", path)
		}
	}
}
