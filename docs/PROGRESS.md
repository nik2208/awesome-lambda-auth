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

Upstream: dopo `v0.9.0` sono atterrate U18, U12, U19, U20, U21 (facciata `AuthTools`), U13 (admin in lettura) e U22 (scheletro del router tools). In corso U14 (admin mutante), U23 (`track` e `notify`) e U24 (`stream`, ultimo anello del percorso critico prima di `v0.11.0`). Prodotto: pinnato a `v0.9.0`; D3, D4, D5, D6, D7 e X1 mergiati; **due** domini ancora gated, `admin` e `tools`.

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

### B4 — D3 runtime settings, e i due refactor che aprono la strada (product · main · 2026-09-12)
Status: green
Landed: `337df5f` (PR #2, sei commit), pin `1442ee9`
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ — in locale prima e dopo il rebase, e su CI GitHub. build ✓ (zip entro budget) deploy – contract – (nessuna capability nuova: l'admin è ciò che espone i settings, quindi i casi di contratto sono di D8)
Deviations: `runtime-settings-seed-only-fills-absent-keys` nel registro di prodotto e nell'indice
Decisions: il seed non sovrascrive mai, **per chiave e solo per le chiavi dichiarate**. Per chiave perché i settings sono un unico item e congelare l'intero documento al primo cold start fisserebbe chiavi per cui nessun blocco ha ancora knob. Solo-dichiarate perché un bool o un int con un default di schema risulterebbe altrimenti sempre "presente": seminare `require2fa:false` renderebbe inerte un `require2fa:true` aggiunto al documento mesi dopo. "Dichiarato" è lo stesso predicato che usano già `domainConfigured` e `checkStoreRequirements`.
Upstream dance: core pinnato a `v0.8.0` (nessuna rotta nuova, quindi `mountedRoutes()` non cresce — che è la risposta giusta del tripwire per un tag che non allarga la superficie)
Stack: nessuna risorsa nuova, nessun parametro nuovo. $0/mese. **Non ancora deployato**: il deploy è in attesa di approvazione.
Notes: due refactor abilitanti, che vanno fatti una volta sola. (1) Le capability della contract suite si auto-registrano: una regione contigua per capability in `test/contract/capabilities_test.go`, e ordine di probe, insieme accettato da `AWESOME_AUTH_CONTRACT_REQUIRE`, blocco di report e loop dei fault derivano tutti dal registro. Sotto c'era un bordo tagliente trovato e chiuso: `capOn` è `iota`, quindi lo zero di `capState` è "acceso" e una capability mai registrata avrebbe spento nessun caso — `assertSettled` lo impedisce. (2) `coreOptionSets` pre-riserva gli slot `settings, docs, ui, admin, tools` in ordine fisso, con builder e non slice già costruite, così un set che fa I/O non viene pagato prima del rifiuto di un set precedente. Una regola preesistente era troppo stretta e l'ho allargata: `rules.go` chiedeva lo store dei settings solo per `require2FA` o una allowlist non vuota, mancando un grace period non di default e una allowlist esplicitamente vuota — entrambe sarebbero partite con lo store spento e sarebbero state seminate nel nulla.
Next: D4 docs, D5 rate limiting, D6 store admin

### B5 — D4 superficie docs (product · main · 2026-09-12)
Status: green
Landed: `dfffa64` (PR #4, quattro commit, rimozione del gate ultima e da sola)
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ — in locale prima e dopo il rebase, e su CI GitHub. build ✓ deploy – contract – (i tre casi nuovi girano contro lo stack vivo, non in CI)
Deviations: `docs-page-carries-a-content-security-policy` nel registro di prodotto e nell'indice
Decisions: `docs.swagger: auto` si risolve contro `deployment.environment` e non contro `NODE_ENV`, perche il core rifiuta per principio di leggere l'ambiente del processo — e siccome `auto` è il default dello schema e `production` il default dell'ambiente, un deployment non configurato non serve nessuna delle due rotte dove la reference le serve entrambe. Nessuna deviazione nuova per questo: `production-by-default` nomina già swagger fra le tre cose che il suo default stringe. **Nessuna regola RS nuova per il CDN**, e la ragione è precisa: `DocsOptions.Enabled` è un solo interruttore per la pagina Swagger *e* per il documento leggibile a macchina, quindi un rifiuto mirato alla pagina si porterebbe via il documento — rifiutare un deployment di produzione perché vuole la metà della coppia che non carica script. Al suo posto: un avviso a deploy-time, e una Content-Security-Policy piu `nosniff` e `no-referrer` sulle due risposte, documentata ovunque come *restringimento e non chiusura* (un bundle compromesso gira comunque same-origin). `TestDocsPolicyCoversEveryOriginTheCorePageLoads` rende la pagina del core e fallisce il giorno in cui carica da un'origine che la policy non permette.
Upstream dance: nessun bump; D4 gira su `v0.8.0`
Stack: nessuna risorsa nuova. $0/mese. **Non ancora deployato.**
Notes: lo slot `docs` di `coreOptionSets` resta **deliberatamente vuoto** — non esiste nessuna `auth.Option` per queste due rotte, l'intero blocco raggiunge il core attraverso `HTTPConfig` — e sia lo slot sia il test che lo fissa ora registrano che è una decisione e non lavoro non finito. Richiesta aperta verso l'upstream: separare `DocsOptions.Enabled` fra documento e pagina, oppure servire la pagina dagli asset vendorizzati invece che da un CDN non pinnato e senza SRI; dopo #75 la seconda strada sembra raggiungibile, ed è l'unica ragione per cui qui si avvisa invece di rifiutare.
Next: D5 rate limiting (ultimo gate di P7 dopo `tools`), D6 store admin

### B6 — X1 migrazione da Cognito (product · main · 2026-09-12)
Status: green
Landed: `36d3f2f` (PR #3)
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ — in locale sull'albero finale ribasato, e su CI GitHub. build ✓ (zip entro budget) deploy – contract – (nessun caso: la migrazione non ha superficie di filo propria, ed è il punto)
Deviations: **nessuna** — e questa è la storia del blocco. La prima versione ne registrava una, `migrated-accounts-carry-a-marker-in-metadata`, perché il marker di migrazione finiva in `auth.User.Metadata`, che `NewPublicUser` serializza: un account importato rivelava a chi avesse una sessione su di esso la propria provenienza e l'id del pool. Le tre alternative scartate erano scartate bene; ne esisteva una quarta, e il prodotto aveva già la macchina per farla.
Decisions: il marker resta sull'item PROFILE e la lettura resta una sola, ma non passa più da `Metadata`: il wrapper migrante lo deposita in un **portatore sul contesto di richiesta** e il verifier lo rilegge da lì. Regge perché nel core il percorso di login passa lo stesso `ctx` non decorato a `GetUserByEmail` e poi a `verify` — verificato contro i tag, e `login_2fa.go`, `password_verifier.go`, `auth.go` e `config.go` risultano byte-identici fra `v0.7.0`, `v0.8.0` e `v0.9.0`, quindi la proprietà non è arrivata col pin e non se ne andrà in silenzio col prossimo. Il precedente in casa è `rotation.go`. Fail-closed: nessun record per l'utente significa nessun marker, mai un ripiego su `Metadata`, o la rivelazione rientrerebbe dalla porta del ripiego. Adozione **idempotente** e non esclusiva: l'interleaving escluso è marker-sparito-con-hash-ancora-vuoto, che bloccherebbe l'account per sempre. Dual-read **spento di default** e limitato, perché `GetUserByEmail` è raggiungibile da cinque rotte non autenticate che prendono un indirizzo dal corpo della richiesta — la stessa amplificazione che il marker gate del verifier esiste per impedire, in arrivo dall'altra porta. Nessuna cache negativa: una cache con una scadenza è un oracolo di enumerazione con una scadenza.
Upstream dance: nessun bump; il seam `WithPasswordVerifier` di `v0.7.0` era già tutto il necessario. Nessuna modifica upstream richiesta.
Stack: quattro parametri nuovi (`CognitoUserPoolId`, `CognitoRegion`, `CognitoAppClientId`, `CognitoMigrationMode`), due condizioni, due `Rules`, cinque variabili d'ambiente, e **una** statement IAM `ReadTheMigrationSourceUserPool` condizionata a un pool id non vuoto: `ListUsers`, `AdminGetUser`, `AdminInitiateAuth` e nient'altro. Nessuna azione di scrittura su Cognito, e deliberatamente nessun `AdminRespondToAuthChallenge`, così la decisione di trattare una sfida MFA come "non è la password" non si può ribaltare in silenzio nel solo codice. Un parametro vuoto non aggiunge nessuna statement e nessun costo. $0/mese finché non lo si configura. **Non ancora deployato.**
Notes: `imported` (gli attributi `custom:*` mappati) resta invece visibile su `/me`, e la distinzione è fissata da un test in entrambe le direzioni: il marker era plumbing di questo prodotto, scritto involontariamente su ogni riga importata e contenente il nome di una risorsa AWS; `imported` è dato sulla persona, fornito dall'operatore, nel campo che la reference definisce per quello, con opt-out per attributo prima che si scriva alcunché.
Next: D5, D6, poi D7 UI ospitata quando `v0.9.0` sarà pinnato

### B7 — D6 store admin, D5 rate limiting, pin a v0.9.0 (product · main · 2026-09-12)
Status: green
Landed: `eba471e` (PR #5, sei commit), `2b1eccb` (PR #6, sei commit), pin `5596eee`
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ per entrambe, in locale prima e dopo il rebase, e su CI GitHub. build ✓ deploy – contract – 
Deviations: quattro nuove. Dallo store: l'ordine di `ListUsers` non scopato è `(TenantID, ID)` e non `ID` (quella che l'autore upstream aveva predetto), i webhook sono elencati e risolti in ordine di id e non di prima inserzione, e la telemetria tratta un tenant assente come **letterale** e non come jolly. Dal prodotto: `rate-limited-routes-answer-429`. Piu due voci core indicizzate col pin (`event-handler-panic-does-not-fail-the-publisher`, `ui-ssr-config-json-is-html-escaped`).
Decisions: **nessun indice nuovo e nessuna modifica di tabella** — era il vincolo principale di D6 ed è rispettato: lo schema di chiavi esistente e la proiezione `INCLUDE` servono entrambe le enumerazioni nuove. Ma **c'è una migrazione**, dichiarata invece che nascosta: GSI1 è sparso, quindi i profili scritti prima di questa release sono invisibili a `ListUsers` finché un backfill una tantum non scrive `GSI1PK`/`GSI1SK`. Quel backfill è uno `Scan` — un job, non un metodo di store — e niente qui lo esegue. Sul rate limiter: `keyBy` di default è **`email`** e non `ip`, perché la minaccia ha la forma di un account e una chiave per indirizzo mette l'intero ufficio dietro un NAT nello stesso bucket *e* nella stessa partizione DynamoDB, rendendo il limitatore il disservizio per le persone a cui non era rivolto. **Fail open**: il contatore condivide la tabella con lo user store, quindi "non riesco a contare" e "non riesco a servire" sono lo stesso evento, e fallire chiuso trasformerebbe una degradazione parziale in un'interruzione totale. Niente header `RateLimit-*`: l'argomento decisivo non è che rivelino il limite, è che `RateLimit-Remaining` su un **200** con un contatore per account è un oracolo sul traffico di qualcun altro.
Upstream dance: core pinnato a `v0.9.0`
Stack: nessuna risorsa nuova. Il limitatore aggiunge **1 WCU per richiesta limitata**, concessa o rifiutata — DynamoDB fattura anche le scritture condizionali fallite. Sulle cinque rotte in scope e al traffico attuale è sotto la soglia di rilevanza. **Non ancora deployato.**
Notes: due correzioni collaterali trovate guidando le rotte invece che leggendo. (1) Il codec del profilo **perdeva `isAdmin` e `loginProvider`**: `isAdmin` è nuovo in `v0.8.0` ed è l'intera policy di accesso `is-admin-flag`, quindi senza di esso nessuno avrebbe mai potuto amministrare nulla; `loginProvider` si perdeva dal bump a `v0.7.0`, quindi ogni account creato via OAuth riportava `local`. Nessuno dei due richiede migrazione — assente decodifica al default corretto. (2) Il limitatore acceso di default ha rotto il test di identità-byte di X1, che spende di proposito il budget del limitatore *di migrazione* per dimostrare che il suo rifiuto è indistinguibile da una password sbagliata: con entrambi i limitatori attivi i due deployment rispondono diversamente per una ragione che non c'entra col verifier. Il limitatore di prodotto è spento in quella fixture e solo lì, con la ragione scritta dove viene spento.
Next: D7 UI ospitata (toglie `ui`), poi D8 admin e D9a-d tools

### B8 — D7 UI ospitata (product · main · 2026-09-12)
Status: green
Landed: `8013fdc` (PR #7, cinque commit, rimozione del gate ultima e da sola)
Gate: fmt ✓ vet ✓ race ✓ ddb-local ✓ in locale e su CI. build ✓ deploy – contract – (i tre casi nuovi girano solo contro uno stack vivo con la UI accesa)
Deviations: `ui-uploaded-assets-are-not-served`
Decisions: lo slot `ui` di `coreOptionSets` resta **deliberatamente vuoto**, come `docs`: l'intero blocco raggiunge il core attraverso `HTTPConfig.UI`, non esiste nessuna `auth.Option` per un colore o per un filesystem di asset, e i due store da cui il documento di configurazione è costruito erano già stati consegnati. Il test che fissa gli slot ora distingue le due decisioni dai due slot ancora pendenti, così la lista non si può leggere come lavoro non finito. `UIOptions.Uploads` resta **nil** e `ui.uploadDir` è accettato e non onorato: non c'è nessuno scrittore fino a D8, una directory è il sostantivo sbagliato in un runtime il cui unico percorso scrivibile è `/tmp` per ambiente di esecuzione, e un `fs.FS` su S3 sarebbe una `GetObject` per ogni `Open` su un percorso che ogni pagina richiede, mancati inclusi.
Upstream dance: nessun bump; D7 gira su `v0.9.0`
Stack: tre risorse nuove, tutte condizionate a `EnableCloudFront` con default `'false'`, quindi **niente viene creato e niente si paga**. Anche accese: distribuzione $0,00 (nessun canone fisso, 10M richieste e 1 TB/mese in free tier), cache policy $0,00, origin request policy $0,00 — **$0,00/mese aggiunti**, ben sotto la soglia dei $5. Niente è messo in cache, e le tre TTL a zero della policy lo dicono esplicitamente invece di rimandare a un id gestito: nessuna delle quattro classi di risposta è cacheabile in modo condiviso, e gli asset statici non si possono nemmeno rivalidare (niente ETag, niente Last-Modified su file embeddati). **Non ancora deployato.**
Notes: primo blocco che legge il settings store **per richiesta** — ogni pagina SSR e ogni `/ui/config` sono due letture DynamoDB. E un guasto dello store è **catturato, non propagato**: il core serve il documento di ripiego della reference, che un client non distingue dal successo, quindi uno store irraggiungibile degrada silenziosamente ogni pagina all'aspetto di default. Scritto in `config-reference.md` e annunciato a cold start. Sulla regola di seeding di D3 con un lettore vero: seme e lettore **non si sovrappongono affatto** — `UIConfig` legge `AuthSettings.UI`, e `runtimeSettings` non ha un membro `ui`, quindi la regola si comporta esattamente come progettata perché il lettore legge una chiave che il seme non scrive mai. **Rischio dichiarato invece che nascosto**: `ui.enabled` resta spento sullo stack finché non atterra D8, perché il set di asset vendorizzati è completo e porta con sé una dashboard admin che chiama rotte `/admin/*` e `/tools/*` che questa build non monta.
Next: D8 superficie admin (richiede `v0.10.0` upstream), poi D9a-d tools
