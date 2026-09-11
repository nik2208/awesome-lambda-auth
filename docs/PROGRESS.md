# Progress ledger

The single ledger for the 2026-09 build-out of `awesome-go-auth` (upstream, U) and `awesome-lambda-auth` (product, D). Decisions are in `spec/decisions.md`; deviations in `deviations.md`. Legend: `[ ]` open, `[~]` in flight, `[x]` green, `[!]` blocked-owner.

## Task board

### Housekeeping
- [x] H0 wrappers and pre-flight (`.tools/`, outside the repos)
- [x] H1 product `main` fast-forwarded and pushed; PR #1 merged (`2df5e32`)
- [x] H2 upstream `main` synced to `origin/main`; stale local branch dropped
- [x] H3 upstream `v0.3.1` tagged at `0079771`; changelog cut `4196ed1`; product pinned (`1c1cb23`)
- [x] H4 `scripts/toolchain.sh` forwards `DYNAMODB_ENDPOINT`, `GONOSUMDB`, `GOPRIVATE`, `TOOLCHAIN_NETWORK`
- [~] H5 upstream PR #47 `.gitattributes` (LF for container-read files)
- [x] H6 `.github/workflows/go.yml` + `scripts/check-artifact-size.sh`
- [~] H7 README rewrite, this ledger, `spec/decisions.md`, product deviation register
- [~] H8 F1 re-check of the wire contract against the private `node-auth` line
- [ ] H9 baseline: contract suite against the live stack
- [ ] H10 upstream PR: truthful README parity table

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

H7 — product docs and register. Gate so far: gofmt ✓ vet ✓ race ✓ (DynamoDB Local reached, `internal/store/dynamodb` 73 s) on the tree before the register was added; re-run pending.

## Blocks

### B0 — Housekeeping (product · main · 2026-09-11)
Status: in progress
Landed: `1c1cb23` build: depend on awesome-go-auth v0.3.1
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ build – deploy – contract –
Deviations: product register introduced (`cmd/auth/deviations.go`), index in `deviations.md`
Decisions: D-0 … D-16 recorded
Upstream dance: `v0.3.1` at `0079771`; PR #47 open
Stack: unchanged
Notes: the `lambda-auth` profile resolves to a different account than the one the project memory attributed to it; the profile name is the invariant and the pre-flight enforces it.
Next: H8, H9, H10, then P2
