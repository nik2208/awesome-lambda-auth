# Progress ledger

The single ledger for the 2026-09 build-out of `awesome-go-auth` (upstream, U) and `awesome-lambda-auth` (product, D). Decisions are in `spec/decisions.md`; deviations in `deviations.md`. Legend: `[ ]` open, `[~]` in flight, `[x]` green, `[!]` blocked-owner.

## Task board

### Housekeeping
- [x] H0 wrappers and pre-flight (`.tools/`, outside the repos)
- [x] H1 product `main` fast-forwarded and pushed; PR #1 merged (`2df5e32`)
- [x] H2 upstream `main` synced to `origin/main`; stale local branch dropped
- [x] H3 upstream `v0.3.1` tagged at `0079771`; changelog cut `4196ed1`; product pinned (`1c1cb23`)
- [x] H4 `scripts/toolchain.sh` forwards `DYNAMODB_ENDPOINT`, `GONOSUMDB`, `GOPRIVATE`, `TOOLCHAIN_NETWORK`
- [x] H5 upstream PR #47 merged (`f332082`): `.gitattributes`, LF for container-read files
- [x] H6 `.github/workflows/go.yml` + `scripts/check-artifact-size.sh`
- [x] H7 README rewrite, this ledger, `spec/decisions.md`, product deviation register (`5e77c84`)
- [x] H8 F1 re-check done 2026-09-11: dev line `node-auth@e8af923` pinned, 7 wire-visible deltas noted in place, event emission map recorded (wire-contract §6 8), F1 closed, N41–N43 added
- [x] H9 baseline: 41 contract cases green against the live stack, `REQUIRE=register,csrf,secure-cookies,sessions,totp`, 0 skips
- [x] H10 upstream PR #48 merged (`a8b8e26`): truthful README parity table and roadmap

### Phases (U half before D half)
- [ ] P2 email flows — U: v0.4.0 · D: `email.siteUrls`, `email.templatesDir`, `email.deliveryWebhook`
- [ ] P3 2FA issuer and claims — U: v0.5.0 · D: `twoFactor`, `security.jwt.extraClaims`, `security.jwt.claimsWebhook`
- [ ] P4 OAuth — U: v0.6.0 · D: `oauth`
- [ ] P5 IdP, JWKS, KMS, resource server — U: v0.7.0 · D: `idProvider`, `resourceServer`
- [ ] P6 settings, UI, docs, admin — U: v0.8.0, v0.9.0 · D: `ui`, `admin`, `docs`, `runtimeSettings`
- [ ] P7 tools, event plane, SSE, rate limiting — U: v0.10.0 · D: `tools`, `rateLimit`

### Product items
- [ ] X1 Cognito migration
- [ ] X2 Terraform and osls with IaC parity check
- [ ] X3 final docs, generated parity table, upstream v1.0.0
- [ ] X4 observability, budgets, per-router topology, e2e CI

## In flight

Upstream main `3d889c8`: eleven PRs merged today (#47–#57): line endings, parity table, gateway mailer (1.4), site URLs (1.1), reserved claims + loginProvider (2.2), delivery webhook (1.3), AuthCodeStore (4.3), wiretest conditional sets (4.0), OAuth provider parity (3.1), TwoFactorAppName + TOTP constants with two registered deviations (2.1), profileMap grammar + MapProfile (3.2). Workflow `upstream-batch-2` running: template store (1.2), claims helpers + webhook + Authenticate (2.3), adversarial review of the IdP signer (4.1). Then: tags v0.4.0 (after 1.2) and v0.5.0 (after 2.3), product P2-D block.

## Blocks

### B0 — Housekeeping (product · main · 2026-09-11)
Status: green (H8 spec update still open as its own block)
Landed: `1c1cb23` … `5e77c84` (toolchain, CI, deviation register, README, ledger) + this fix
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ build ✓ (auth-arm64.zip 6.77 MB, sha256 fb84dc9a…) deploy – (no runtime change) contract ✓ 41 cases
Deviations: product register introduced (`cmd/auth/deviations.go`), index in `deviations.md`
Decisions: D-0 … D-16 recorded
Upstream dance: `v0.3.1` at `0079771`; PR #47 and #48 squash-merged
Stack: unchanged
Notes: the `lambda-auth` profile resolves to the standalone project account, distinct from the `default` profile; the profile name is the invariant and the pre-flight enforces it.
Next: H8, H9, H10, then P2
