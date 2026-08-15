package main

import (
	"context"
	"log/slog"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// Credential delivery: how a minted magic link, reset token, verification
// token, email-change token or SMS code leaves this deployment.
//
// awesome-go-auth v0.3.0 exposes five senders as func types on its Config, each
// wired by a With*Sender option that rejects nil. This file turns two blocks of
// configuration into those five functions, and nothing else in the binary knows
// that mail is SES or that a text message is SNS.
//
// ── transports or closures ───────────────────────────────────────────────────
//
// Upstream offers both: write five closures, or implement the two one-method
// transport interfaces (auth.MailerTransport, auth.SMSTransport) and let the
// ready-made bridges — MagicLinkMailer, PasswordResetMailer,
// EmailVerificationMailer, EmailChangeMailer, SMSTransportSender — do the rest.
// This port implements the transports, for three reasons:
//
//  1. Four of the five mail senders differ only in a template name and a URL
//     builder. Five closures would restate that mapping five times here, and
//     upstream itself factored TokenMailer out of exactly that duplication —
//     copying it back into a downstream port is how a template name or a
//     Content-Type quietly drifts from the rest of the family.
//  2. The URL shapes are upstream's to own. MagicLinkURL, PasswordResetURL,
//     EmailVerificationURL and EmailChangeConfirmURL are the links the verify
//     routes and the shipped clients expect; a closure that built them here
//     would be a second definition of a wire detail, free to diverge.
//  3. auth.MailerTransport is precisely SES's job description — put this
//     rendered message on the wire — and auth.SMSTransport is precisely SNS's.
//     Neither transport has to know what a magic link is, so neither does.
//
// The one thing a bridge cannot do is the OAuth link token, whose URL upstream
// builds itself and hands over ready-made; that one is a closure, below, and it
// still renders through the same templater.
//
// ── what an unconfigured deployment does ─────────────────────────────────────
//
// Nothing changes, and that is deliberate rather than incidental. With no
// email.mailer block the four mail senders stay nil, so POST /magic-link/send
// answers 500 EMAIL_NOT_CONFIGURED while /forgot-password,
// /send-verification-email and /change-email/request answer 200 and mail
// nothing. With no sms block POST /sms/send answers 500 SMS_NOT_CONFIGURED.
// That split is the reference's own — its magic-link strategy checks the email
// configuration up front and throws, its three token routes check nothing and
// succeed silently (wire-contract §2, "if neither exists, no email is sent and
// the route still succeeds") — and reproducing it is the whole point of being a
// port. It is also the safer half of the two: the routes that stay silent mint
// a token that is unguessable, single-use and expiring, so an undelivered one
// costs the caller a mail that never arrives and nothing else.
//
// What this port must NOT do is invent a third behaviour, such as refusing to
// start without a mailer. A deployment serving bearer clients that never touch
// a passwordless route is legitimate, and upstream's Config.validate agrees: it
// does not ask for a sender either.

// delivery holds the transports a cold start could build, plus everything the
// upstream mailers need to render with. A nil transport means "this deployment
// did not configure that half", and every use of it is gated on that.
type delivery struct {
	// mail is nil unless email.mailer is configured.
	mail auth.MailerTransport

	// sms is nil unless the sms block is configured.
	sms auth.SMSTransport

	// templates renders subject and body for the link-token closure. The four
	// bridge mailers hold their own equivalent; this one exists because
	// DeliverLinkToken has no bridge.
	templates *auth.MailTemplater

	appName string
	baseURL string
	locale  string
}

// mailConfigured and smsConfigured are the enable signals, and they are the
// schema's own rather than a new knob.
//
// internal/config/validate.go refuses a mailer block that has no `from`, and
// refuses an sms block that has no `endpoint`; both are required the moment any
// key of their block is set. So a non-empty from is exactly "the operator
// configured a mailer and it passed validation", and a non-empty sms endpoint is
// exactly the same statement about SMS. Deriving the signal from validation
// instead of re-implementing "is this block non-default" means the two can never
// disagree about whether a deployment sends mail.
func mailConfigured(cfg *config.Config) bool { return strings.TrimSpace(cfg.Email.Mailer.From) != "" }
func smsConfigured(cfg *config.Config) bool  { return strings.TrimSpace(cfg.SMS.Endpoint) != "" }

// newDelivery builds the transports this configuration asks for.
//
// It performs no I/O: both transports defer their SDK client to the first
// message they carry (internal/integration/aws lazy.go), so a deployment that
// configures mail and never sends any pays nothing for it at init — which
// matters because startTimeout gives the whole cold start 8 seconds.
//
// A bad from address is the one failure, and it aborts the cold start. That is
// the right place for it: an unverified or malformed sender is a deployment
// fault that would otherwise surface as a 500 on somebody's first password
// reset.
// mail and sms override the transports without changing the gating; both nil is
// the binary's own path.
func newDelivery(cfg *config.Config, mail auth.MailerTransport, sms auth.SMSTransport, log *slog.Logger) (*delivery, error) {
	d := &delivery{
		// Exactly the base auth.MagicLinkURL and its three siblings want: the
		// origin a mailbox can reach, plus the prefix the auth routes mount
		// under. Both are P1 knobs, so credential delivery needs no new one.
		baseURL: strings.TrimSuffix(cfg.Deployment.PublicURL, "/") + cfg.HTTP.APIPrefix,
		locale:  cfg.Email.Mailer.DefaultLang,
	}

	if mailConfigured(cfg) {
		d.appName = mailerAppName(cfg)
		d.mail = mail
		if d.mail == nil {
			transport, err := awsintegration.NewSESTransport(awsintegration.SESOptions{
				From:     cfg.Email.Mailer.From,
				FromName: cfg.Email.Mailer.FromName,
			})
			if err != nil {
				return nil, err
			}
			d.mail = transport
		}
		d.templates = auth.NewMailTemplater(d.appName)

		if cfg.Deployment.PublicURL == "" {
			// Not fatal — RS-2 already decides when a missing public URL is a
			// refusal, and a stack can legitimately run without one — but a
			// relative link in a mailbox is a dead link, and upstream calls the
			// empty base a misconfiguration in both ports. Better said once here
			// than discovered from a user who could not click through.
			log.Warn("mail is configured but deployment.publicUrl is unset, so every emailed link is relative and unusable from a mailbox",
				slog.String("path", "deployment.publicUrl"),
				slog.String("remedy", "set it to the origin clients reach, e.g. https://auth.example.com"))
		}
	}

	if smsConfigured(cfg) {
		d.sms = sms
		if d.sms == nil {
			d.sms = awsintegration.NewSNSTransport(awsintegration.SNSOptions{})
		}
	}

	return d, nil
}

// mailerAppName is what the built-in templates greet the recipient with and
// prefix every subject with.
//
// email.mailer.fromName is the knob for it: it is already the human-readable
// name of the sender, and using it means the name in the From header and the
// name in the body cannot disagree. When it is unset the sender's domain stands
// in, because MailTemplater renders an empty app name as a subject beginning
// with " - " and a deployment should not have to configure a display name to
// avoid that.
func mailerAppName(cfg *config.Config) string {
	if name := strings.TrimSpace(cfg.Email.Mailer.FromName); name != "" {
		return name
	}
	if i := strings.LastIndex(cfg.Email.Mailer.From, "@"); i >= 0 && i+1 < len(cfg.Email.Mailer.From) {
		return cfg.Email.Mailer.From[i+1:]
	}
	return ""
}

// deliveryOptions returns the sender options the core accepts, appending each
// one only when its transport exists.
//
// The gating cannot be "append a possibly-nil sender": every With*Sender option
// rejects nil with an error, so a nil transport handed to one of them would
// abort the cold start of a deployment that simply does not send mail.
func deliveryOptions(d *delivery, log *slog.Logger) []auth.Option {
	var opts []auth.Option

	if d.mail != nil {
		magic := auth.NewMagicLinkMailer(d.mail, d.appName, d.baseURL)
		magic.Locale = d.locale
		reset := auth.NewPasswordResetMailer(d.mail, d.appName, d.baseURL)
		reset.Locale = d.locale
		verify := auth.NewEmailVerificationMailer(d.mail, d.appName, d.baseURL)
		verify.Locale = d.locale
		change := auth.NewEmailChangeMailer(d.mail, d.appName, d.baseURL)
		change.Locale = d.locale

		opts = append(opts,
			auth.WithMagicLinkSender(magic.Send),
			auth.WithPasswordResetSender(reset.Send),
			auth.WithEmailVerificationSender(verify.Send),
			auth.WithEmailChangeSender(change.Send),
		)
	}

	if d.sms != nil {
		opts = append(opts, auth.WithSMSCodeSender(auth.SMSTransportSender(d.sms)))
	}

	// One line an operator can read the whole delivery posture off, including
	// the two routes that answer a coded 500 when their half is absent. The
	// transport name appears only when that half is actually on, so the line
	// cannot be misread as "mail is wired" by someone skimming for "ses".
	mailTransport, smsTransport := "none — POST /magic-link/send answers 500 EMAIL_NOT_CONFIGURED", "none — POST /sms/send answers 500 SMS_NOT_CONFIGURED"
	if d.mail != nil {
		mailTransport = "ses"
	}
	if d.sms != nil {
		smsTransport = "sns"
	}
	log.Info("credential delivery wired",
		slog.String("mailTransport", mailTransport),
		slog.String("smsTransport", smsTransport),
		slog.String("linkBase", d.baseURL),
		slog.String("locale", d.locale))

	return opts
}

// deliverLinkToken is the OAuth account-linking mail, POST /link-request.
//
// It is a closure rather than a bridge because upstream has no bridge for it:
// LinkTokenDelivery arrives with the URL already built — the route resolves it
// per request from the caller's Origin against the redirect allowlist, which no
// static BaseURL could reproduce — so there is nothing for a TokenMailer to
// construct.
//
// The verify_email template is the deliberate choice. The reference sends this
// mail through the same sendVerificationEmail callback its verification route
// uses (auth.router.ts:1530-1535) and has no template of its own for it, so
// reusing the verification template is what keeps the family consistent;
// inventing a link-specific one here would be a port-only divergence in
// something a user reads.
//
// EmailLang is honoured because upstream forwards the request's emailLang field
// verbatim for exactly this, and MailTemplater falls back to English on an
// unknown locale. It is the only route in this file with a per-request
// language, which is why the four bridge mailers are pinned to defaultLang.
func (d *delivery) deliverLinkToken(ctx context.Context, in auth.LinkTokenDelivery) error {
	locale := in.EmailLang
	if locale == "" {
		locale = d.locale
	}
	subject, body, err := d.templates.Render(locale, "verify_email", auth.MailTemplateData{
		UserName: in.Email,
		Token:    in.Token,
		URL:      in.URL,
	})
	if err != nil {
		return err
	}
	return d.mail.Send(ctx, auth.MailMessage{To: in.Email, Subject: subject, Body: body, IsHTML: true})
}
