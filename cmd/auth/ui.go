package main

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The hosted UI: everything under GET <prefix>/ui — the config document, the
// server-rendered pages, the static assets — built out of the product's `ui`
// block.
//
// Nothing in this file mounts a route, and that is the same absolute rule the
// documentation surface follows (docs.go): every path under the api prefix
// belongs to the imported adapter. Until v0.7.0 this binary mounted four OIDC
// endpoints of its own, the adapter took them over, and the duplicate
// registration killed the cold start inside http.ServeMux. What this file does
// is build auth.UIOptions out of `ui.*`, decide what a Lambda can put behind the
// two filesystem seams, refuse the one configuration that would come up serving
// nothing, and say at cold start which of those happened.
//
// ── what the core gives us, and where it puts it ─────────────────────────────
//
// awesome-go-auth v0.9.0 vendors the reference's own fourteen browser assets
// byte for byte (ui_upstream.go, pinned by sha256 against
// UpstreamUIAssetCommit) and serves the whole of the reference's ui.router.ts
// from one handler, (*Auth).UIHandler, which every adapter mounts at
// <prefix>/ui under HTTPConfig.UI.Enabled (adapter/nethttp/nethttp.go:126-131;
// the reference's own gate is auth.router.ts:1639-1648). Inside that handler,
// in the reference's order, are the config document, the headless
// short-circuit, the uploaded assets, the SSR catch-all with its page mapping
// and three fallbacks, and the static serve underneath.
//
// **`<prefix>/ui/config` is no longer a route of its own on any adapter.**
// v0.7.0 mounted it; v0.9.0 moved it inside UIHandler, which is where the
// reference has it — ui.router.ts:165 is a route inside the router
// auth.router.ts:1640 mounts at /ui. Same document, same `Cache-Control:
// no-store`, same CSRF wrapper. That matters here only because it is the reason
// there is nothing to register: the whole surface is one mount the adapter makes
// from one bool.
//
// ── this block fills no core option slot, and that is a decision ─────────────
//
// The `ui` slot in coreOptionSets stays empty, for exactly the reason `docs`
// does. There is no auth.Option for any knob in this block: the branding, the
// headless flag, the language default and both filesystem seams reach the core
// through HTTPConfig.UI, which the adapter reads at mount time, and the two
// stores the document is actually built from — the settings store and the
// template store — were handed over by other blocks long before this one
// existed. Filling the slot would mean inventing an option for the sake of the
// slot. TestCoreOptionSetsAreOrderedAndReserved still lists it, so that the
// emptiness is recorded rather than mistaken for unfinished work.
//
// ── the settings store is now on the page-render path ────────────────────────
//
// This is the first block whose surface reads the settings store per request,
// and it is worth stating plainly because it changes what
// `stores.enable.settings` costs.
//
// (*Auth).UIConfig reads the store first, before anything else in the document
// (ui_config.go, reproducing ui.router.ts:99), and the stored branding wins over
// the static `ui.branding.*` member by member. It then reads the template store
// for the `config` page's translations. So with the UI on and both stores
// enabled, **every SSR page render and every GET <prefix>/ui/config is two
// DynamoDB reads** — the SETTINGS singleton and the TEMPLATES partition — on top
// of whatever the page's own requests cost. Before this block the settings store
// was read once at cold start, by the seed, and once per POST /2fa/disable.
//
// The failure mode is the one to know about. A settings store that errors does
// not fail the request: the core catches it and serves the reference's own
// fallback document (ui.router.ts:143-161) — default branding, English, no
// translations, and a *shorter* features object carrying three of the eight
// flags, which is upstream's reproduced-not-fixed bug (reference-issues N32).
// A client cannot tell that from success. So the store being unreachable
// degrades every page in the hosted UI to the reference's default look, silently,
// and the only notice is the core's own log line. logUISurface says so at cold
// start rather than leaving it to be discovered.
//
// The other half of that interaction is what the settings store does *not*
// carry here. auth.AuthSettings.UI is the branding the document overrides with,
// and this product seeds none of it: `runtimeSettings` has no `ui` member, and
// declaredRuntimeSettings (settings.go) covers require2fa,
// enabledWebhookActions and lazyEmailVerificationGracePeriodDays. So until the
// admin surface can write it (D8, upstream U15), `settings.UI` is nil on every
// read and uiBranding falls straight through to `ui.branding.*`. The seed and
// the reader do not overlap at all, which is why turning the UI on changes
// nothing about what D3's seeding rule does — only about how often the store it
// seeds is read.
//
// ── the two filesystem seams, in a runtime that has no filesystem ────────────
//
// UIOptions has two fs.FS fields and a Lambda has to answer both.
//
// **Assets** is the reference's uiAssetsDir (ui.router.ts:11-14): the pages and
// scripts the handler serves and renders. nil means the vendored copies, which
// is the reference's own "if not provided, the internal Vanilla JS UI will be
// served" and is what almost every deployment wants — the assets are compiled
// into the binary, so they cost no I/O, no S3 bucket and no cold-start read.
// `ui.assetsDir` is wired anyway, because a deployment that ships its own SPA
// has exactly one place to put it — baked into the artifact, beside the
// configuration document and the mail templates — and os.DirFS over that path is
// the one-line spelling of the reference's directory. The artifact is read-only
// and that is fine: nothing here writes.
//
// A wrong `ui.assetsDir` is refused at cold start (checkUIAssets), and that is
// deliberate rather than defensive. The core takes a host that supplies its own
// asset set at its word and falls back to nothing — "a half-replaced UI is worse
// than a missing one" (UIOptions.Assets) — so a path with a typo in it does not
// degrade, it 404s every page while the deployment reports itself healthy. That
// is the exact shape of silent misconfiguration this product refuses elsewhere.
//
// **Uploads** is the reference's uploadDir (ui.router.ts:16-20), served under
// <prefix>/ui/assets/logo/ and <prefix>/ui/assets/uploads/ (:185-191). **It
// stays nil in this build, on purpose**, and `ui.uploadDir` is accepted and not
// honoured. See uiUploadsAreNotServed for the argument and the registered
// deviation; the short version is that there is nothing writing to it until D8,
// and building a read path over S3 now would mean a GetObject on the request
// path of every page that shows a logo, for a bucket that is always empty.
// Leaving the seam nil is also the core's documented unconfigured behaviour:
// neither path is mounted and both answer 404, rather than 500 on a store that
// is not there.
//
// ── the language default the core left to the host ───────────────────────────
//
// UIOptions.DefaultLang is the one field where the port deliberately declined to
// guess and this product has the answer. The reference reads the fallback
// language from `config.email.mailer.defaultLang` (ui.router.ts:103); the core
// has no mailer block on its Config — a mailer there is a transport the host
// builds — so it exposed the knob on UIOptions instead and defaulted it to
// English. This product *does* have `email.mailer.defaultLang`, validated to
// `en` or `it`, so wiring the two together reproduces the reference exactly
// rather than approximately, and an operator who set the mail language does not
// have to discover a second knob that means the same thing.

// uiOptions builds HTTPConfig.UI out of the `ui` block. It is total and does no
// I/O: httpConfig has half a dozen callers that want nothing but Prefix(), and
// every refusal this block can make is made by checkUISupport at cold start.
func uiOptions(cfg *config.Config) auth.UIOptions {
	return auth.UIOptions{
		Enabled:  cfg.UI.Enabled,
		Headless: cfg.UI.Headless,
		Branding: auth.UIBranding{
			PrimaryColor:   cfg.UI.Branding.PrimaryColor,
			SecondaryColor: cfg.UI.Branding.SecondaryColor,
			SiteName:       cfg.UI.Branding.SiteName,
			BgColor:        cfg.UI.Branding.BgColor,
			BgImage:        cfg.UI.Branding.BgImage,
			CardBg:         cfg.UI.Branding.CardBg,
			// One knob, and the core's *second* candidate is the one it fills.
			//
			// UIBranding carries both CustomLogo and LogoURL because the
			// reference carries both and prefers the first: the served logoUrl
			// is settings.ui.logoUrl, then config.ui.customLogo, then
			// config.ui.logoUrl (ui.router.ts:128). The schema collapsed the
			// pair into one knob — §1.12 records customLogo and logoUrl as one
			// field, since the reference documents the first and keeps the
			// second only as a legacy spelling — so there is one value to place
			// and the chain resolves to it either way. It goes in LogoURL and
			// not CustomLogo so that a `settings.ui.logoUrl` an administrator
			// saves still wins, and so that CustomLogo stays free for a
			// deployment that one day needs both rungs.
			LogoURL: cfg.UI.Branding.LogoURL,
		},
		// Static-only by construction on both sides: the reference reads
		// customCss from the config and never from the settings store
		// (ui.router.ts:130), and the core says so. It is injected into the page
		// unescaped, in a <style> of its own, there as here — it is stylesheet
		// source and there is nothing to escape it into. That is the host's own
		// code, which is exactly why no runtime-mutable layer may reach it.
		CustomCSS: cfg.UI.CustomCSS,
		// See the file header: the reference's fallback language is the
		// mailer's, and this product has a mailer block where the core does not.
		DefaultLang: cfg.Email.Mailer.DefaultLang,
		Assets:      uiAssets(cfg),
		// Deliberately absent. See uiUploadsAreNotServed.
		Uploads: nil,
	}
}

// uiAssets resolves the asset filesystem: the operator's directory, or nil for
// the vendored copies of the reference's own fourteen files.
//
// nil is not "no assets". auth.UIHandler reads a nil Assets as
// UpstreamUIAssetFS(), the embedded set, which is the whole UI for every
// deployment that does not ship its own. Returning nil rather than an empty
// fs.FS is therefore load-bearing and not a shortcut.
//
// os.DirFS performs no I/O and stats nothing, so calling this from httpConfig
// costs nothing on the paths that only want Prefix(). checkUIAssets is where the
// directory is actually looked at.
func uiAssets(cfg *config.Config) fs.FS {
	if dir := strings.TrimSpace(cfg.UI.AssetsDir); dir != "" {
		return os.DirFS(dir)
	}
	return nil
}

// uiFallbackPages is auth.UIHandler's page resolution order for a request that
// names no page of its own, transcribed so that checkUIAssets can ask the same
// question the handler will ask (ui_pages.go uiResolvePage, reproducing
// ui.router.ts:306-325): <page>.html, then login.html, index.html,
// index.csr.html.
//
// Only the fallbacks are listed, because only they are answerable in advance. A
// directory holding none of the three renders no page for any request at all —
// every path falls past the SSR catch-all into the static serve and ends at 404
// — which is the one thing about an asset set that can be checked without
// knowing which URL a visitor will ask for.
//
// The list is a copy, and copies drift. TestUIAssetFallbacksMatchTheCore fails
// if the core's own resolution order stops agreeing with it, which is when this
// check would otherwise start refusing a directory the handler would have
// served, or accepting one it would not.
var uiFallbackPages = []string{"login.html", "index.html", "index.csr.html"}

// checkUISupport refuses the one `ui` configuration that would come up serving
// nothing.
//
// It is called from New beside checkStoreSupport and checkResourceServerSupport,
// before the core is built, for the reason they are: an init failure is
// something the deployment reports and a rollback can act on, where a UI that
// 404s every page is a stack that looks healthy to every health check and to
// the operator who deployed it.
//
// Nothing here refuses a deployment for wanting the vendored assets, which is
// the default and needs no filesystem at all.
func checkUISupport(cfg *config.Config) error {
	if !cfg.UI.Enabled {
		return nil
	}
	return checkUIAssets(cfg)
}

// checkUIAssets refuses an `ui.assetsDir` that cannot render a page.
//
// The two failures are separate on purpose, because the remedies are. A path
// that is not a readable directory is a typo or a build that did not copy the
// files; a directory that is readable and holds none of the fallback pages is a
// build that copied the wrong thing, and the message has to say which pages the
// handler was going to look for or the operator has nothing to compare against.
//
// The check is one Stat plus at most three more, on the local filesystem, once
// per execution environment. On the default path — no assetsDir — it does not
// run at all.
func checkUIAssets(cfg *config.Config) error {
	dir := strings.TrimSpace(cfg.UI.AssetsDir)
	if dir == "" {
		return nil
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf(
			"config: refusing to start: ui.enabled is on and ui.assetsDir points at %q, which is not a readable directory in this artifact, "+
				"so the hosted UI would answer 404 on every page while the deployment reported itself healthy "+
				"-- bake the directory into the deployment package and name its path inside the function (/var/task/...), "+
				"or remove ui.assetsDir to serve the vendored copies of the reference's own assets",
			dir)
	}

	fsys := os.DirFS(dir)
	for _, name := range uiFallbackPages {
		if st, err := fs.Stat(fsys, name); err == nil && st.Mode().IsRegular() {
			return nil
		}
	}
	return fmt.Errorf(
		"config: refusing to start: ui.enabled is on and ui.assetsDir %q holds none of %s, "+
			"which are the three files the UI handler falls back to when a request names no page of its own -- "+
			"a request for <prefix>/ui therefore renders nothing and answers 404, and so does every page name the directory has no file for. "+
			"The core takes a supplied asset set at its word and never falls back to the vendored one, because a half-replaced UI is worse than a missing one "+
			"-- so either ship a complete asset set, or remove ui.assetsDir to serve the vendored copies",
		dir, strings.Join(uiFallbackPages, ", "))
}

// uiUploadsAreNotServed is the argument behind UIOptions.Uploads being nil, and
// the text the deviation register points at.
//
// **What the reference does.** `ui.uploadDir` is a directory an administrator's
// uploads are written into by the admin router (admin.router.ts:656) and read
// out of by two express.static mounts, <prefix>/ui/assets/logo/ and
// <prefix>/ui/assets/uploads/ (ui.router.ts:185-191). With the option unset the
// reference mounts neither and both paths 404, which is what makes an
// unconfigured deployment and a configured one that is asked for a file it does
// not hold behave alike.
//
// **What this product does.** It serves neither path, in every configuration,
// and `ui.uploadDir` is accepted by the schema and honoured by nothing.
//
// **Why, and why now rather than later.** Three things, in order of weight.
//
// *There is no writer.* The upload half is an admin route, and this build mounts
// no admin router — the `admin` domain is still refused by phases.go. So a read
// path built today would be a read path over an empty location, on every
// deployment, for as long as it takes D8 to land. The core made the same call
// for the same reason and says so in as many words: Uploads is read-only "on
// purpose", because "this port has no UploadStore to write through until U15".
//
// *A directory is the wrong noun here.* The knob names a filesystem path and a
// Lambda has no filesystem to name — /var/task is read-only and /tmp is per
// execution environment, so a logo uploaded through one cold start would be
// invisible to the next request and gone by the one after. The serverless shape
// is S3, which §1.12 already records ("serverless target is an S3 location").
// That is a different thing behind the same knob, and which thing it is decides
// what the value means, so it is D8's to define together with the writer rather
// than this block's to guess at.
//
// *An fs.FS over S3 costs per request, on the page path.* fs.FS has one
// operation and it is Open, so every miss and every hit is a GetObject — and the
// misses are the common case, because the logo is requested by every page of the
// hosted UI whether or not a deployment has ever uploaded one. Caching it in the
// execution environment trades that for an upload that does not appear until the
// next cold start, which is worse than not having the feature. The honest answer
// is that the read path belongs beside the write path, where one design can pay
// for both, and that is D8.
//
// **What a deployment sees in the meantime.** Exactly the reference's
// unconfigured behaviour: GET <prefix>/ui/assets/logo/<anything> and
// <prefix>/ui/assets/uploads/<anything> answer 404 — not 500, and not a
// half-served 200 — because the core leaves an unset Uploads unmounted rather
// than erroring. A deployment that wants a logo today sets
// `ui.branding.logoUrl` to a URL it hosts somewhere else, which is a knob this
// build does honour and which the SSR injection writes straight into the page.
// logUISurface names the knob at cold start when it is set, so nobody has to
// learn this from a 404.
const uiUploadsAreNotServed = "ui.uploadDir is accepted and not honoured; the two uploaded-asset paths answer 404 until the upload store lands"

// logUISurface announces what the `ui` block resolved to.
//
// It is the counterpart of logDocsSurface and exists for the same reason: only
// the composition root knows the prefix the adapter was actually mounted at, and
// an operator reading a cold-start log should be able to tell whether this
// deployment serves a login page at all without fetching one.
//
// Three things are said here that are said nowhere else, and each is something
// a deployment can get wrong while looking healthy: that the UI is off, which is
// the default and is the state the deployed stack is meant to be in until the
// admin and tools surfaces exist; that headless mode serves no HTML at all,
// which is a different product rather than a degraded one; and that the settings
// store is on the render path, with what its failure looks like from outside.
func logUISurface(cfg *config.Config, log *slog.Logger) {
	prefix := httpConfig(cfg).Prefix()
	mount := prefix + auth.UIRoute

	if !cfg.UI.Enabled {
		log.Info("hosted UI not mounted",
			slog.String("path", "ui.enabled"),
			slog.String("effect", "every path under "+mount+" answers 404, GET "+mount+"/config included"),
			slog.String("note", "emailed links therefore point at the API route itself and not at a UI page (HTTPConfig.UILink)"))
		return
	}

	assets := "vendored: the reference's own fourteen assets, embedded in the binary"
	if dir := strings.TrimSpace(cfg.UI.AssetsDir); dir != "" {
		assets = "ui.assetsDir " + dir + " (the vendored assets are not a fallback: a page this directory lacks is a 404)"
	}

	log.Info("hosted UI mounted",
		slog.String("mount", mount),
		slog.Bool("headless", cfg.UI.Headless),
		slog.String("assets", assets),
		slog.String("lang", cfg.Email.Mailer.DefaultLang),
		slog.String("siteName", cfg.UI.Branding.SiteName),
		slog.Bool("brandingFromSettingsStore", cfg.Stores.Enable.Settings),
		slog.String("note", "emailed links now point at "+mount+"/<page> rather than at the API route (HTTPConfig.UILink)"))

	if cfg.UI.Headless {
		log.Info("hosted UI is headless",
			slog.String("path", "ui.headless"),
			slog.String("effect", "no HTML page is served at all: "+mount+"/config and the static assets answer, and every page path 404s"),
			slog.String("remedy", "this is the SPA posture -- the hosting application provides its own login UI and loads "+mount+
				"/auth.js; turn it off if you meant to serve the built-in pages"))
	}

	if cfg.Stores.Enable.Settings {
		log.Info("the settings store is on the UI render path",
			slog.String("path", "stores.enable.settings"),
			slog.String("effect", "every SSR page and every GET "+mount+
				"/config reads the settings store and the template store, so the UI costs two more reads per page view"),
			slog.String("onFailure", "a store that errors is caught, not surfaced: the reference's fallback document is served instead "+
				"-- default branding, English, no translations and three of the eight feature flags -- and a client cannot tell that from success"))
	}

	if dir := strings.TrimSpace(cfg.UI.UploadDir); dir != "" {
		log.Warn("configured knob is not wired to the auth core",
			slog.String("path", "ui.uploadDir"),
			slog.String("problem", uiUploadsAreNotServed+" (deviation ui-uploaded-assets-are-not-served): "+
				"the writer is an admin route this build does not mount, and a Lambda has no durable directory for one to write to"),
			slog.String("remedy", "set ui.branding.logoUrl to a URL you host elsewhere, which this build does honour and injects into every page; "+
				"leave ui.uploadDir set only if the same document is deployed to another port in the family"))
	}
}
