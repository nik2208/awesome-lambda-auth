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
- [x] P2 email flows — U: v0.4.0 · D: wired, deployed, 44 contract cases green
- [x] P3 2FA issuer and claims — U: v0.5.0 · D: wired
- [x] P4 OAuth — U: v0.6.0 · D: wired
- [x] P5 IdP, JWKS, KMS, resource server — U: v0.6.0 · D: wired, con firma KMS e store dei codici OIDC
- [ ] P6 settings, UI, docs, admin — U: v0.7.0 (docs, ui/config), v0.8.0 (store seams), v0.9.0 (vendored UI), v0.10.0 (admin router) · D: `runtimeSettings` (D3), `docs` (D4), `ui` (D7), `admin` (D8)
- [ ] P7 tools, event plane, SSE, rate limiting — U: v0.7.0 (rate-limiter slot), v0.11.0 (event plane, webhooks, SSE, tools) · D: `rateLimit` (D5), `tools` (D9a-d)

### Product items
- [ ] X1 Cognito migration
- [ ] X2 Terraform and osls with IaC parity check
- [ ] X3 final docs, generated parity table, upstream v1.0.0
- [ ] X4 observability, budgets, per-router topology, e2e CI

## In flight

Upstream: `v0.8.0` tagliato — tre PR di seam di store, nessuna rotta (#72 WebhookStore, #73 admin/session/role lister piu `User.IsAdmin`, #74 APIKeyStore completo). In corso: U17 (vocabolario `identity.*` e contesto di richiesta, testa del percorso critico M9) e U10 (i 14 asset UI vendorizzati con il controllo di drift, M7). Prodotto: pinnato a `v0.7.0`, sei domini ancora gated; in corso D3 (runtime settings piu i due refactor abilitanti) e X1 (migrazione Cognito, che il seam `WithPasswordVerifier` di v0.7.0 ha sbloccato). Il pin a `v0.8.0` aspetta D3, e apre D6.

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

### B1 — P2 email flows (product · main · 2026-09-12)
Status: green
Landed: `4fda373` wiring + gates, `ceca016` DynamoDB template store, `08586fb` contract cases, `78addb9` driver claim
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ build ✓ (auth-arm64.zip, sha256 6a68aa26…) deploy ✓ UPDATE_COMPLETE contract ✓ 44 cases, 0 skips
Deviations: `templates-dir-only-seeds-absent-ids` added to the product register and the index
Decisions: D-17 (templates from the artifact), D-18 (the delivery webhook requires a secret), D-11 amended
Upstream dance: core pinned to v0.4.0 (`2e4bca8`)
Stack: no new resources; new parameters EmailSiteUrls, EmailDeliveryWebhookUrl, EmailDeliveryWebhookSecretArn, ConfigFile, all empty by default. $0/month added.
Next: P3-D (twoFactor, extraClaims, claimsWebhook) once v0.5.0 is pinned; upstream #61–#64 merge and tag

### B2 — core v0.7.0 pin, and the OIDC mount moves to the adapter (product · main · 2026-09-12)
Status: green
Landed: this commit
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ build – deploy – contract – (no stack change yet; D3 carries the next deploy)
Deviations: four core ids indexed (`register-issues-a-session`, `ui-config-verify-email-follows-the-effective-mode`, `register-route-is-always-mounted`, `docs-routes-are-opt-in`); no product or store entry added
Decisions: D-3's mounting bullet amended — the five OIDC routes are the adapter's, and the core's deprecated `<prefix>/jwks` alias is no longer served here
Upstream dance: core pinned to `v0.7.0`
Stack: unchanged. $0/month added.
Notes: the tripwire fired exactly as designed. Upstream #71 moved discovery, authorize, token and userinfo onto every adapter, so `cmd/auth`'s own `mountIDPEndpoints` became a second registration of four patterns and six `cmd/auth` tests refused the cold start with the pattern-collision message. The fix is subtraction: this binary now mounts nothing of its own, `mountAuthSurface` is `nethttp.MountWithConfig` plus the collision guard that `idProvider.jwksPath` still needs. `TestTheDeprecatedJWKSAliasIsNotServed` pins the one path that cost.
Next: D3 runtime settings

### B3 — upstream v0.8.0, i seam di store per l'admin (upstream · main · 2026-09-12)
Status: green (nessuna modifica al prodotto)
Landed: `71d4b39` (#72), `8663986` (#73), `1ff3fa3` (#74), tag `v0.8.0` su `6378054`
Gate: fmt ✓ vet ✓ build ✓ race ✓ su root e cinque adapter, per ogni PR, prima e dopo il rebase · CI GitHub verde su tutte e tre
Deviations: nessuna nuova, e per una ragione dichiarata in ognuna delle tre PR — nessuna rotta è montata, quindi niente è ancora visibile a un client. Due voci sono *dovute* da PR successive: U13 deve registrare l'ordinamento per id delle liste admin (la reference non impone alcun `ORDER BY`), e U14 quello delle chiavi API.
Decisions: `User.IsAdmin` è un campo persistito, non derivato da `Role` — la reference lo memorizza (`user.model.ts:90`) e `buildPolicyGuard` lo legge direttamente (`admin.router.ts:370`); derivarlo avrebbe inventato una regola che la reference non ha, nel punto in cui sbagliare consegna la console admin alla persona sbagliata. `AdminUserStore.ListUsers` porta un `tenantID` che filtra la *colonna* `User.TenantID` e mai l'appartenenza al tenant, con stringa vuota come jolly: è la firma che una Query DynamoDB può servire senza Scan, che era il vero collo di bottiglia dell'admin.
Upstream dance: `v0.8.0` = M6 completo
Stack: nessuna modifica. $0/mese.
Notes: una rottura deliberata, e solo di interfaccia: `APIKeyStore` ora richiede `FindByID`, che la reference dichiara obbligatorio. Nessun implementatore esiste fuori dai test. Segnalato e **non** corretto: la reference paga sempre il costo bcrypt confrontando con un hash fittizio quando il prefisso non risolve, per non lasciare un oracolo temporale su "questo prefisso esiste" (`api-key.strategy.ts:36-42`); il port va in corto circuito e l'oracolo c'è. È preesistente, chiuderlo cambia il percorso di verifica, e vive ora come attività a sé.
Next: pin del prodotto a `v0.8.0` insieme a D3, poi D6
