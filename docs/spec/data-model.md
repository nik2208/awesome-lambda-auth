# DynamoDB single-table data model — awesome-lambda-auth

Normative design for the persistence layer under `internal/store/dynamodb`. It is written **before** any store code so that the key schema is derived from the access patterns rather than the other way round.

**What it is derived from, in priority order:**

1. The store interfaces the port must satisfy, read from source in the pinned `awesome-go-auth` checkout beside this repo: `store.go` (`UserStore`, `SessionStore`, `SessionLookupStore`, `UserPasswordStore`, `MagicLinkStore`, `SMSStore`, `TOTPStore`, `EmailVerificationStore`, `EmailChangeStore`, `SessionAdminStore`, `UserAccountStore`, `UserMetadataStore`, `RolesPermissionsStore`, `TenantStore`), `account.go` (`UserPhoneStore`), `api_keys.go` (`APIKeyStore`), `oauth.go` (`LinkedAccountStore`, `PendingLinkStore`), `telemetry.go` (`TelemetryStore`), plus `memory_store.go` / `feature_stores.go` for the exact semantics each method must preserve.

   *Corrected during implementation.* `account.go` was not in this list, which is how `UserPhoneStore` came to be missing from §1.1 — it is the one optional interface declared beside its route rather than with the others. The lesson is in §9: the store surface is verified by driving the routes, because enumerating the files that declare interfaces is a step that can be done carefully and still be wrong.
2. The routes that call them, from [wire-contract.md](wire-contract.md).
3. The out-of-process state inventory in [serverless-gap-analysis.md](serverless-gap-analysis.md).

**Ground rule.** Where a store interface maps awkwardly onto DynamoDB, the awkwardness is named and priced here rather than hidden in the implementation. Everything not verifiable against source is in §8.

---

## 1. Access patterns

68 rows, covering 77 distinct method/code-path combinations (the four single-use token families are one parameterised block, §1.3). "Items" is the expected item count per invocation, not the RCU/WCU cost.

Conventions: `<t>` = tenant id, `<u>` = user id, `<sid>` = session id, `<h>` = `hex(sha256(rawToken))` (matching `hashToken`, `security.go:40`). All `GetItem` reads on the main table are **strongly consistent** unless the row says otherwise. `Tx` = `TransactWriteItems`.

### 1.1 Users and profile

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 1 | Create user | `CreateUser` ← `POST /register`, OAuth callback | Tx: Put `USER#<t>#<u>` / `PROFILE` if `attribute_not_exists(PK)`; Put `EMAIL#<t>#<email>` / `EMAIL` if `attribute_not_exists(PK)`; Put `TENANT#<t>` / `MEMBER#<u>` | main | 3 w |
| 2 | Resolve by email | `GetUserByEmail` ← `POST /login`, `/forgot-password`, `/magic-link/send`, `/change-email/request`, OAuth by-email | GetItem `PK=EMAIL#<t>#<email>`, then GetItem `PK=USER#<t>#<u>`, `SK=PROFILE` | main | 2 r |
| 3 | Resolve by id | `GetUserByID` ← `/me`, `/refresh`, every authenticated route | GetItem `PK=USER#<t>#<u>`, `SK=PROFILE` | main | 1 r |
| 4 | `/me` enrichment bundle | `GetUserByID` + `GetMetadata` + `GetRolesForUser` in one hop | Query `PK=USER#<t>#<u>` (no SK condition) | main | 1+K+R |
| 5 | Update profile | `UpdateProfile` ← `PATCH /profile` | UpdateItem `SET firstName, lastName, updatedAt` if `attribute_exists(PK)` | main | 1 w |
| 6 | Delete account | `DeleteUser` ← `DELETE /account` | Query collection (#4) + Query GSI1 by `USERID#<u>`; BatchWrite deletes incl. `EMAIL#<t>#<email>`, memberships, sessions, links | main+GSI1 | N |
| 7 | Set password | `UpdatePassword` ← `/reset-password`, `/change-password` | UpdateItem `SET passwordHash, updatedAt` if `attribute_exists(PK)` | main | 1 w |
| 8 | Mark verified | `MarkEmailVerified` ← `GET /verify-email`, magic-link first login | UpdateItem `SET isEmailVerified` | main | 1 w |
| 9 | TOTP secret | `UpdateTOTPSecret` ← `/2fa/verify-setup`, `/2fa/disable` | UpdateItem `SET isTotpEnabled, updatedAt` + `SET totpSecret` or `REMOVE totpSecret`, if `attribute_exists(PK)` | main | 1 w |
| 9b | Phone number | `UserPhoneStore.UpdatePhoneNumber` ← `POST /add-phone` | UpdateItem `SET phoneNumber, updatedAt` (or `REMOVE phoneNumber` to clear) if `attribute_exists(PK)`, `ReturnValues=ALL_NEW` | main | 1 w |

*Corrected during implementation, two rows.*

- **#9 had no condition and the wrong clear semantics.** `UpdateItem` creates a missing item, so a bare `SET totpSecret, isTotpEnabled` for a user who does not exist would have manufactured a profile-shaped item holding nothing but a shared secret, and answered success where `MemoryUserStore` answers "user not found" (`memory_store.go:262-264`). And `DisableTOTP` calls this with `("", false)` (`service.go:576-581`): writing the empty string would leave a zero-length copy of a credential on the item, so an empty secret `REMOVE`s the attribute, which is §5's omission rule applied to the one attribute where it also matters for secrecy. `enabled` follows the argument rather than the secret — a caller passing `("", true)` leaves TOTP enabled with nothing to verify against, exactly as the reference does, and `VerifyTOTP` refuses that user (`service.go:502-505`).
- **#9b was missing entirely, and the reason is worth recording.** `UserPhoneStore` (`account.go:18-25`) is the eighth optional interface and the only one declared *outside* `store.go`, `oauth.go`, `api_keys.go` and `telemetry.go` — it sits beside the `POST /add-phone` route that needs it. The derivation in this document's preamble enumerated the other four files and therefore never saw it, and nothing failed to compile, because the core discovers it by type assertion like the rest. It was found by driving every mounted route and looking for a 501 (`cmd/auth`'s store sweep), which is the only method that could have found it. There is no new item type: the number is already part of the profile (§5).

### 1.2 Sessions and refresh rotation

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 10 | Create session | `CreateSession` ← login, refresh, OAuth callback, `/2fa/verify`, `/magic-link/verify`, `/sms/verify`, `/link-verify` | Tx: Put `SESSION#<sid>` / `SESSION`; Put `REFRESH#<h>` / `REFRESH` if `attribute_not_exists(PK)` | main | 2 w |
| 11 | Resolve by refresh hash | `GetSessionByRefreshTokenHash` ← `POST /refresh`, `POST /logout` | GetItem `PK=REFRESH#<h>` → GetItem `PK=SESSION#<sid>` | main | 2 r |
| 12 | Rotate | `UpdateSession` ← `POST /refresh` | Tx: Put `REFRESH#<newH>` if `attribute_not_exists(PK)`; Update `SESSION#<sid>` `SET refreshHash, expiresAt, gen = gen+1` if `attribute_not_exists(revokedAt)` (+ `refreshHash = :oldH`, §4.3) | main | 2 w |
| 13 | Revoke on logout | `UpdateSession` (RevokedAt set) ← `POST /logout` | UpdateItem `SET revokedAt` if `attribute_not_exists(revokedAt)` | main | 1 w |
| 14 | Session check | `GetSessionByID` ← `authMiddleware` with `checkOn: allcalls` | GetItem `PK=SESSION#<sid>` | main | 1 r |
| 15 | List for user | `ListSessionsForUser` ← `GET /sessions`, `GET /admin/api/sessions` | Query GSI1 `GSI1PK=USER#<t>#<u>` AND `begins_with(GSI1SK,'SESSION#')` → BatchGetItem | GSI1 | N r |
| 16 | Revoke by id | `RevokeSessionByID` ← `DELETE /sessions/:handle`, `DELETE /admin/api/sessions/:handle` | UpdateItem `SET revokedAt` if `attribute_exists(PK)` | main | 1 w |
| 17 | Expire | `DeleteExpiredSessions` ← `POST /sessions/cleanup` (public cron route) | **none** — DynamoDB TTL (§4.5) | — | 0 |
| 18 | Replay response | rotated-out refresh presented at `POST /refresh` | detected in #11; UpdateItem `SESSION#<sid>` `SET revokedAt, revokedReason='refresh_replay'` | main | 1 w |

### 1.3 Single-use email/SMS token families

Four pointer-backed families share one shape, and SMS (#23-#25) is the same shape without a pointer — five families, one implementation. Substitute `F` and the profile attributes:

| Family | Pointer PK | Profile attrs | Routes | TTL source |
|---|---|---|---|---|
| password reset | `RESET#<h>` | `resetHash`, `resetExp` | `/forgot-password` → `/reset-password` | `tokens.passwordResetTtlMinutes` (ref. 1 h) |
| magic link | `MAGIC#<h>` | `magicHash`, `magicExp` | `/magic-link/send` → `/magic-link/verify` | `tokens.magicLinkTtlMinutes` (ref. 15 min) |
| email verification | `VERIFY#<h>` | `verifyHash`, `verifyExp` | `/send-verification-email` → `GET /verify-email` | `tokens.emailVerificationTtlMinutes` (ref. 24 h) |
| email change | `ECHG#<h>` | `echgHash`, `echgExp`, `pendingEmail` | `/change-email/request` → `/change-email/confirm` | `tokens.emailChangeTtlMinutes` (ref. 1 h) |

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 19 | Issue token (×4) | `Update{Reset,MagicLink,EmailVerification,EmailChange}Token` | Tx: Update `USER#<t>#<u>`/`PROFILE` `SET <F>Hash, <F>Exp, updatedAt` **(+ `pendingEmail` for `ECHG`)** if `attribute_exists(PK)`; Put `F#<h>` / `TOKEN` with `ttl`, if `attribute_not_exists(PK) OR (userId = :u AND tenantId = :t)` | main | 2 w |
| 20 | Consume token (×4) | `GetUserBy*TokenHash` | GetItem `PK=F#<h>` → UpdateItem `USER#<t>#<u>` `REMOVE <F>Hash, <F>Exp` **and nothing else** if `<F>Hash = :h AND <F>Exp > :now`, `ReturnValues=ALL_OLD` (§4.1) | main | 1 r + 1 w |
| 21 | Clear token (×4) | `Clear*Token` | UpdateItem `REMOVE <F>Hash, <F>Exp` **(+ `pendingEmail` for `ECHG`)** if `attribute_exists(PK)` — idempotent no-op after #20 | main | 1 w |
| 22 | Apply email change | `ApplyEmailChange` ← `POST /change-email/confirm` | GetItem `PROFILE` for `email`/`pendingEmail` → Tx: Put `EMAIL#<t>#<new>` if `attribute_not_exists(PK)`; Delete `EMAIL#<t>#<old>`; Update `PROFILE` `SET email = :new, updatedAt REMOVE pendingEmail` if `attribute_exists(PK) AND email = :old AND pendingEmail = :new` | main | 1 r + 3 w |
| 23 | Store SMS code | `UpdateSMSCode` ← `POST /sms/send` | UpdateItem `SET smsHash, smsExp, updatedAt` if `attribute_exists(PK)` | main | 1 w |
| 24 | Verify SMS code | `GetUserBySMSCodeHash` ← `POST /sms/verify` | UpdateItem `USER#<t>#<u>` `REMOVE smsHash, smsExp` if `smsHash = :h AND smsExp > :now`, `ALL_OLD` — **no pointer item; the method already carries `userID` and `tenantID`** | main | 1 w |
| 25 | Clear SMS code | `ClearSMSCode` | UpdateItem `REMOVE smsHash, smsExp` if `attribute_exists(PK)` — same shape as #21, idempotent no-op after #24 | main | 1 w |

*Corrected during implementation, five rows.*

- **#19 and #21 were incomplete for `ECHG`.** The family table above already lists `pendingEmail` among the email-change profile attributes, but the two write rows named only `<F>Hash`/`<F>Exp`. The address must be written *with* the token, in the same conditional update, or a token can outlive the address it was issued for and vice versa; and it must be cleared *with* the token, which is what `MemoryUserStore.ClearEmailChangeToken` does (`memory_store.go:390-395`). An abandoned request that left `pendingEmail` behind would leave something for a later `ApplyEmailChange` to promote.
- **#20 had to be pinned to "and nothing else".** The consuming read must *not* remove `pendingEmail`, because `ApplyEmailChange(ctx, userID, tenantID)` carries no address and reads it off the profile *after* the token has been consumed (`service.go:472-479`). Consume clears the token; only clear clears the address. Stated explicitly because the symmetry with #21 invites getting it wrong.
- **#22 needed a precondition and a read it did not admit to.** `ApplyEmailChange` carries neither address, so the two uniqueness keys can only come from a read — which the row omitted, along with the item count. The read is safe only because it decides nothing: the profile update is conditional on `email = :old AND pendingEmail = :new`, so a pending address that moved between the read and the transaction refuses the write instead of promoting a superseded address. Without that clause this would be the one read-then-write in the store, and §4.1's rule would have a hole in it. Two further consequences: the failure needs `ReturnValuesOnConditionCheckFailure = ALL_OLD` to tell "user gone" from "pending moved", and `pendingEmail == email` must be refused **before** the transaction is built, because old and new resolve to the same `EMAIL#` item and `TransactWriteItems` rejects two operations on one item outright. `MemoryUserStore` reaches `ErrUserExists` there by a different route (`memory_store.go:370-374`); the answer matches.
- **#23 had no condition, so it wrote a phantom profile.** `UpdateItem` creates a missing item, so `SET smsHash, smsExp` for a user who does not exist would have manufactured a profile-shaped item holding nothing but a code — and returned success where `MemoryUserStore` returns "user not found" (`memory_store.go:220-226`). `attribute_exists(PK)` is not optional on any of these updates.
- **#25 was not a no-op and not zero writes.** `Service.VerifySMSCode` calls `ClearSMSCode` unconditionally (`service.go:397`) and `MemoryUserStore` answers "user not found" for an unknown user (`memory_store.go:246-252`), so it is the same conditional `UpdateItem` as #21 — idempotent on the attributes, conditional on the user. Writing it down as "0 items" would have made a missing user look like success.

### 1.4 Metadata, RBAC, tenants

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 26 | Read metadata | `GetMetadata` ← `/me`, `GET /admin/api/users/:id/metadata` | Query `PK=USER#<t>#<u>` AND `begins_with(SK,'META#')`, or reuse #4 | main | K |
| 27 | Merge metadata | `UpdateMetadata` ← `PUT /admin/api/users/:id/metadata` | BatchWrite Put `META#<key>` per key (25/batch) | main | K w |
| 28 | Clear metadata | `ClearMetadata` ← `DELETE /account`, admin | Query then BatchWrite Delete | main | K |
| 29 | Assign role | `AddRoleToUser` ← `POST /admin/api/users/:id/roles` | Tx: ConditionCheck `ROLE#<role>` `attribute_exists(PK)` (preserves `ErrRoleNotFound`); Put `USER#<t>#<u>` / `ROLE#<role>` | main | 2 w |
| 30 | Unassign role | `RemoveRoleFromUser` ← `DELETE /admin/api/users/:id/roles/:role` | DeleteItem (unconditional — memory impl is silent on absence) | main | 1 w |
| 31 | Roles of user | `GetRolesForUser` ← `/me`, `rbac:` guards | Query `PK=USER#<t>#<u>` AND `begins_with(SK,'ROLE#')` | main | R |
| 32 | Create role | `CreateRole` ← `POST /admin/api/roles` | PutItem `ROLE#<role>` / `ROLE` with `permissions` (SS), unconditional (memory impl overwrites) | main | 1 w |
| 33 | Delete role | `DeleteRole` ← `DELETE /admin/api/roles/:name` | Delete `ROLE#<role>`; Query GSI1 `GSI1PK=ROLE#<role>` → BatchWrite delete assignments | GSI1 | 1+A |
| 34 | Grant permission | `AddPermissionToRole` | UpdateItem `ADD permissions :ss` — atomic set-add, no read | main | 1 w |
| 35 | Revoke permission | `RemovePermissionFromRole` | UpdateItem `DELETE permissions :ss` | main | 1 w |
| 36 | Permissions of role | `GetPermissionsForRole` ← `GET /admin/api/roles` | GetItem `PK=ROLE#<role>` | main | 1 r |
| 37 | Permissions of user | `GetPermissionsForUser` / `UserHasPermission` ← `/me`, `permission:` guards | #31 then BatchGetItem `ROLE#<r>` × R | main | 1+R |
| 38 | Create tenant | `CreateTenant` ← `POST /admin/api/tenants` | PutItem `PK=TENANTS`, `SK=TENANT#<t>` if `attribute_not_exists(SK)` (preserves `ErrAlreadyExists`) | main | 1 w |
| 39 | Get tenant | `GetTenantByID` | GetItem `PK=TENANTS`, `SK=TENANT#<t>` | main | 1 r |
| 40 | List tenants | `GetAllTenants` ← `GET /admin/api/tenants` | Query `PK=TENANTS` | main | T |
| 41 | Update tenant | `UpdateTenant` | UpdateItem `SET name, isActive, config` if `attribute_exists(SK)` | main | 1 w |
| 42 | Delete tenant | `DeleteTenant` | Delete directory entry; Query `PK=TENANT#<t>` `begins_with(SK,'MEMBER#')` → BatchWrite | main | 1+M |
| 43 | Add membership | `AssociateUserWithTenant` ← `POST /admin/api/tenants/:id/users` | Tx: ConditionCheck tenant exists; Put `TENANT#<t>` / `MEMBER#<u>` | main | 2 w |
| 44 | Drop membership | `DisassociateUserFromTenant` | DeleteItem | main | 1 w |
| 45 | Tenants of user | `GetTenantsForUser` ← `/me`, `DELETE /account` | Query GSI1 `GSI1PK=USERID#<u>` AND `begins_with(GSI1SK,'TENANT#')` → BatchGet directory | GSI1 | T' |
| 46 | Users of tenant | `GetUsersForTenant` ← `GET /admin/api/tenants/:id/users` | Query `PK=TENANT#<t>` AND `begins_with(SK,'MEMBER#')`, paged | main | M |
| 47 | Admin user list | `GET /admin/api/users?limit&offset&filter` | #46 page (≤500 when `filter` set, matching `admin.router.ts:760-780`) + BatchGet profiles + in-process filter | main | ≤500 |

### 1.5 API keys, OAuth, telemetry, rate limiting

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 48 | Save API key | `APIKeyStore.Save` ← `POST /admin/api/api-keys` | Tx: Put `APIKEY#<prefix>` / `APIKEY` if `attribute_not_exists(PK)`; Put `KEYID#<id>` / `KEYID` if `attribute_not_exists(PK)` | main | 2 w |
| 49 | Verify API key | `FindByPrefix` ← `APIKeyMiddleware`, every API-key request | GetItem `PK=APIKEY#<prefix>` | main | 1 r |
| 50 | Revoke API key | `Revoke(id)` ← `DELETE /admin/api/api-keys/:id/revoke` | GetItem `KEYID#<id>` → UpdateItem `SET isActive = false` | main | 1r+1w |
| 51 | Touch last-used | `UpdateLastUsed(id, when)` ← after successful verify | GetItem `KEYID#<id>` → UpdateItem `SET lastUsedAt` if `attribute_not_exists(lastUsedAt) OR lastUsedAt < :staleBefore` (throttled, §6.3) | main | 0–2 |
| 52 | Save link | `LinkedAccountStore.Save` ← OAuth callback, `/link-verify` | GetItem `OAUTH#<p>#<pid>` for the incumbent `linkId` → Tx: Put `OAUTH#<p>#<pid>` / `OAUTH` if `attribute_not_exists(PK) OR linkId = :observed`; Put `LINKID#<id>` / `LINKID` if `attribute_not_exists(PK) OR (userId = :u AND provider = :p AND providerId = :pid)`; Delete `LINKID#<observed>` when a different id held it | main | 1r + 2–3 w |
| 53 | Find link | `FindByProvider` ← OAuth callback | GetItem `PK=OAUTH#<provider>#<providerId>` | main | 1 r |
| 54 | List links | `ListForUser` ← `GET /linked-accounts` | Query GSI1 `GSI1PK=USERID#<u>` AND `begins_with(GSI1SK,'OAUTH#')` → BatchGetItem | GSI1+main | L r |
| 55 | Delete link | `Delete(id)` ← `DELETE /linked-accounts/:provider/:providerAccountId` | GetItem `KEYID`-style pointer `LINKID#<id>` → Tx: Delete `OAUTH#<p>#<pid>` if `linkId = :id`; Delete `LINKID#<id>` | main | 1r+2w |
| 56 | Stash pending link | `PendingLinkStore.Save(state, meta, ttl)` ← OAuth begin, `/link-request`, OAuth account conflict | PutItem `PLINK#<state>` / `PLINK` with `expiresAt`, `metaExpiresAt` and `ttl`, unconditional | main | 1 w |
| 57 | Read pending link | `Get(state)` ← OAuth callback, `/link-request`, `/link-verify` | **single-use namespaces:** DeleteItem `PK=PLINK#<state>` if `attribute_exists(PK) AND (attribute_not_exists(expiresAt) OR expiresAt > :now)`, `ALL_OLD` — the read *is* the consume (§4.1). **Conflict stash:** GetItem, expiry re-checked in code | main | 1 w / 1 r |
| 58 | Drop pending link | `Delete(state)` ← OAuth callback, `/link-verify` | DeleteItem, unconditional — idempotent no-op after #57 | main | 1 w |
| 59 | Record telemetry | `TelemetryStore.Record` ← `POST /tools/track/:eventName` | PutItem `PK=TEL#<t>#<yyyy-mm-dd>`, `SK=<rfc3339Nano>#<eventId>`, `ttl` | main | 1 w |
| 60 | Query telemetry | `TelemetryStore.Query` ← `GET /tools/telemetry` | Query per day in `[Since,Until]`, `SK BETWEEN`, `Limit` | main | pages |
| 61 | Rate-limit consume | NET-NEW (gap analysis §1.4) — login, forgot-password, magic-link, sms, 2fa | UpdateItem `PK=RL#<scope>#<subject>#<window>` `ADD n :1` if `attribute_not_exists(n) OR n < :max`, `ttl` | main | 1 w |

*Corrected during implementation, four rows.*

- **#52 was "unconditional — memory impl overwrites", and that is the upstream bug.** `MemoryLinkedAccounts.Save` re-points its provider index at the new link but never touches the old link's `byID` entry or the old owner's slice (`oauth.go:380-399`), so after a rebind the previous owner's `ListForUser` still advertises a provider account that no longer signs them in, the superseded id still resolves, and deleting it takes the live binding down with it. That is upstream `nik2208/awesome-go-auth#37` and it is a bug, not a semantic to reproduce. Here there is one canonical item, so an overwrite moves `GSI1PK` from `USERID#<old>` to `USERID#<new>` atomically and the only thing that could go stale — the previous `LINKID#` pointer — is deleted inside the same transaction. Which makes the write conditional after all: the incumbent `linkId` has to be read so its pointer can be named, and the transaction re-asserts it (`linkId = :observed`) so a concurrent rebind is refused and retried rather than deleting a pointer that now belongs to somebody else. Same shape as #22: the read supplies a key the interface does not carry and decides nothing. The pointer side is conditioned on **ownership** rather than absence, for the reason §4.1 gives for the token pointers — a retry of the same call must succeed, while a link id that already names a *different* provider account must fail loudly instead of orphaning the item it used to name.
- **#54 needed the `BatchGetItem` the row omitted.** `auth.OAuthLinkedAccount` gained `Email`, `Name` and `Picture` in v0.2.0 (`oauth.go:68-77`) and `GET /linked-accounts` projects all three (`oauth_wire.go:566-577`). None of them is in GSI1's keys or in its three-attribute `INCLUDE`, so the index alone cannot answer this. The alternative — widening the projection — was rejected: it would put a second physical copy of every linked address into an index with its own export and its own PITR restore, to save one round trip on a read that renders an account screen. The ordering that falls out is provider-then-account rather than the reference's insertion order, which is wire-visible and is in `CompatibilityNotes()`. The cap is 100 per user by default, refusing rather than truncating, which answers one of §8.6's four open list interfaces.
- **#55's canonical delete had to become conditional.** Unconditional, a `Delete(id)` that arrived after somebody else rebound the provider account would remove the *live* binding — precisely the failure the reference has. `linkId = :id` makes it remove only its own; when that condition loses, the pointer alone is dropped and the call still reports success, because `MemoryLinkedAccounts.Delete` answers success for an id it does not know (`oauth.go:423-426`) and `UnlinkAccount` answers success unconditionally.
- **#57 was "GetItem", which cannot make a link single-use.** The core's linking flow is `Get` → write the binding → `Delete` across three store calls, and it *discards `Delete`'s error* (`oauth_wire.go:765-805`), so a store whose `Get` merely reads lets two Lambdas holding one account-link token both pass and both write. The read is therefore the consume, exactly as in §4.1, but the write is a conditional `DeleteItem` of the whole item rather than an `UpdateItem` removing two attributes — here the credential *is* the partition key. This applies to the two namespaces the core writes and spends once, `oauth-state:` and `link-token:` (`oauth_wire.go:417-421`), and deliberately **not** to the third, `pending-link:<email>|<provider>`: that is the host-written conflict stash, which `LinkRequest` reads to resolve an identity (`:689`) and `LinkVerify` deletes only after the binding exists (`:804`). Consuming it would make an ordinary retry of `POST /link-request` — a user whose mail never arrived — answer 401 instead of issuing a second token. An unrecognised namespace defaults to re-readable, which is `MemoryPendingLinks`' own behaviour and therefore cannot regress a flow that works today.

Two further consequences of #56/#57, stated rather than hidden:

- **The item carries two expiry attributes.** `expiresAt` is the store's own deadline, derived from the `ttl` argument as `MemoryPendingLinks` derives its own (`oauth_wire.go:860-869`), and is what the consume condition and the DynamoDB `ttl` are built from; a non-positive `ttl` means no deadline and both are omitted. `metaExpiresAt` round-trips `OAuthPendingMeta.ExpiresAt`, which is the *caller's* value and exists so "a consumer can enforce the deadline itself rather than trusting the store to have honoured the ttl argument" (`oauth.go:55-57`). Folding one into the other would return a value the caller never wrote.
- **An expired account-link token answers `INVALID_LINK_TOKEN`, not `LINK_TOKEN_EXPIRED`.** Because the store refuses to return an entry past its deadline (§4.5), `LinkVerify`'s own expiry branch (`oauth_wire.go:770-775`) is never reached and its nicer code is unreachable. Handing an expired credential back so the route can label it better is not a trade this store makes. Wire-visible; in `CompatibilityNotes()`.
- **`pending-link:<email>|<provider>` is the one key in the whole model that is neither tenant-scoped nor high-entropy**, and the store cannot fix it: the key is composed by the core (`oauth_wire.go:424-426`) and `PendingLinkStore` has no tenant argument, so a read must compute the same key a write did. Two tenants with one address therefore share a stash entry, and the tenant used downstream comes from the entry (`oauth_wire.go:691-693`), so a `POST /link-request` in tenant B could drive a link in tenant A. Every implementation of this interface has that property, including `MemoryPendingLinks`; nothing in this port writes that namespace today, since the conflict stash is written by the host. Filed as §8.13 rather than papered over.

### 1.6 Mail templates and UI translations

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 62 | Read mail template | `TemplateStore.GetMailTemplate` ← `MailTemplater.RenderMail` (`mailer.go:495`), once per mail the service sends | GetItem `PK=TEMPLATES`, `SK=MAIL#<id>` | main | 1 r |
| 63 | List mail templates | `ListMailTemplates` ← `GET /admin/api/templates/mail` | Query `PK=TEMPLATES` AND `begins_with(SK,'MAIL#')` | main | T r |
| 64 | Upsert mail template | `UpdateMailTemplate(id, patch)` ← `PUT /admin/api/templates/mail/:id` | GetItem `MAIL#<id>` → PutItem the merged item if `updatedAt = :observed`, or if `attribute_not_exists(updatedAt)` when nothing was read; `ALL_OLD` on failure, retried from the pre-image | main | 1r + 1–n w |
| 65 | Read UI translations | `GetUITranslations` ← the reference's UI router (`ui.router.ts`); nothing in the core serves it yet | GetItem `PK=TEMPLATES`, `SK=UI#<page>` | main | 1 r |
| 66 | List UI translations | `ListUITranslations` ← `GET /admin/api/templates/ui` | Query `PK=TEMPLATES` AND `begins_with(SK,'UI#')` | main | P r |
| 67 | Replace UI translations | `UpdateUITranslations(page, translations)` ← `PUT /admin/api/templates/ui/:page` | PutItem `UI#<page>`, unconditional | main | 1 w |

The four admin rows name the routes the reference serves (`admin.router.ts`); the admin surface is P6 here, so today #62 is the only one an unmodified deployment reaches. It is also the only hot one.

*Notes, six.*

- **One directory partition, and no GSI.** `auth.TemplateStore` carries no tenant id and no owner — a template is deployment-global in the reference too — and its six methods address an entry only by id or by page. So `PK=TEMPLATES` with `SK=MAIL#<id>` / `SK=UI#<page>` answers every one of them: the two point reads are a `GetItem` on the full key, and each list is a **single Query on one partition** with a `begins_with` on the sort key. An index would need a second access path to justify its second physical copy, and there is none; nor a TTL, because a template is configuration and expires when an operator deletes it. §6.2 covers why sharing one partition is safe here.
- **The two namespaces cannot be forged into each other.** Ids and pages go through `checkID`, so they match `idPattern` and in particular exclude `#` (§2.1). Without that, a template id of `welcome` and a page of `welcome` are distinct keys but an id of `UI#welcome` would key the *page's* item, and a list of mail templates would hand a `UITranslation` to a caller expecting a `MailTemplate`. An id the store cannot key is not an error on read — `GetMailTemplate` answers the reference's `(zero, false, nil)`, as #57's sibling does — because a lookup for a malformed id has to read like a lookup for an unknown one; on write it is `ErrInvalidIdentifier`, because a write that cannot name its key has nowhere to go.
- **#64 is the third read-then-write in this store, and the only one whose lock is a timestamp.** The patch names only the fields it changes, the interface carries nothing else, and the rest has to come from somewhere — the same position `ApplyEmailChange` (#22) and `LinkedAccounts.Save` (#52) are in. What makes the read safe is the same thing: the write re-asserts it. `updatedAt` is the lock token, the `PutItem` is conditional on it still being the value observed, and a lost condition is retried from the `ALL_OLD` pre-image rather than applied over the top of a state it never saw. Two admins patching different fields of one template therefore both land, in whichever order they arrive. The token is written from the clock, or one nanosecond past the observed value when the clock has not moved — a token that failed to change would let the next stale patch through, which is the one thing it exists to prevent. The retry bound is 16, which is the point at which losing stops being contention (a writer loses at most once per concurrent writer) and becomes a fault; reaching it is `ErrTemplateConflict`, not a silent overwrite.
- **Translations are replaced, never merged, and that is the core's contract rather than a simplification.** `MailTemplatePatch.Translations` is one field of the reference's `Partial<MailTemplate>`, spread with `{...existing, ...template}` (`template_store.go`, `MemoryTemplateStore.UpdateMailTemplate`): a non-nil map replaces the whole `lang → key → value` map and languages it does not name are dropped. A caller changing one language reads the template and sends the map back whole. #64's lock is therefore about *fields*, not about locales: concurrent patches of two locales cannot both survive in any implementation of this interface, and a store that merged them would be answering a different contract from the one the shipped clients are pinned to. #67 is the same rule one level up — a page is set, not patched — which is why it needs no condition at all.
- **Both lists come back in sort-key order**, which is by id and by page, where `MemoryTemplateStore` returns first-insertion order (`mailOrder`/`uiOrder`). Wire-visible through the two admin list routes once they are mounted, so it is in `CompatibilityNotes()` and in [deviations.md](../deviations.md). Restoring insertion order would mean storing a sequence number and sorting on it — a second attribute, written on every upsert, to reproduce an order the reference itself gets by accident from a `Map`. An empty directory is `[]`, never `null`. The lists are drained behind an interface with no cursor, capped at 1 000 and refusing rather than truncating (§8.6).
- **A template body is caller-supplied and unbounded, so the item is capped at 300 KB** (`MaxTemplateBytes`), measured on the *merged* item — what the patch keeps plus what it sets — before anything is written. Two halves that each fit alone are refused together, with `ErrTemplateTooLarge` and the stored template untouched. The cap sits 100 KB under DynamoDB's 400 KB item limit, which is the margin that lets the size estimate be an estimate; its purpose is that an operator pasting a large HTML mail gets a typed refusal naming the limit instead of the SDK's `ValidationException`. The six reference templates are a few KB each (§6.3).

### 1.7 OIDC authorization codes

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 68 | Store an authorization code | `AuthCodeStore.SaveCode` ← `GET/POST <prefix>/authorize`, once per authorization | PutItem `PK=OIDC#<sha256(code)>`, `SK=CODE`, unconditional | main | 1 w |
| 69 | Redeem an authorization code | `AuthCodeStore.ConsumeCode` ← `POST <prefix>/token`, once per authorization | DeleteItem `OIDC#<sha256(code)>` if `attribute_exists(PK) AND (attribute_not_exists(expiresAt) OR expiresAt > :now)`, `ALL_OLD` | main | 1 w |

Both are net-new: the reference ships no authorization server, so there is no reference behaviour to reproduce and the shape is chosen for the runtime (`store.go`, `AuthCodeStore`, is explicit that it is).

*Notes, four.*

- **The record is the item, not two attributes of a profile.** The four single-use token families (§1.3) hang a hash and an expiry off `USER#<t>#<u>/PROFILE` because that is where the constraint lives and because their lookup methods carry no tenant. An authorization code has no such home: it is a record in its own right — client, redirect URI, nonce, scope, PKCE challenge — and the only thing addressing it is the hash. So the hash is the partition key and the record is the item, which is also what makes #69 one conditional `DeleteItem` instead of a conditional `UpdateItem` that has to leave the rest of a profile alone.
- **Keyed by the hash the core computes, never by the code.** `AuthCode.CodeHash` arrives as `hashToken(code)` and the clear-text code is never persisted, exactly as the refresh, reset, magic-link and verification partitions do it: a dump of this table cannot be redeemed at `/token`.
- **#69 is `consumeItemOnce`, and it is the same primitive #57 uses.** The expiry is inside the condition rather than checked after the read (§4.5: TTL deletion is best-effort and lags by up to ~48 h, so a late item must read as absent), the comparison is lexicographic and therefore chronological only because `tsLayout` pads to nine digits, and exactly one of any number of concurrent redemptions can satisfy the condition. That last property is the one RFC 6749 §4.1.2 asks for by name — "the authorization code MUST NOT be used more than once" — and it is the one a read-then-delete cannot give: two Lambdas racing on a code read out of a browser history, a `Referer` header or an access log would both pass the read and both mint a session. `Options.NonAtomicSingleUseTokens` deliberately does not reach this store: that switch exists to imitate the reference, and the reference has no codes.
- **A replay and an expiry are the same answer.** Both branches of `consumeItemOnce` map to `auth.ErrInvalidCode`, with the same rendered text, where §1.3's families distinguish them. The difference is that here the distinction would be an oracle: a caller who could tell "expired" from "never issued" could probe which codes were minted, and one who could tell "already redeemed" from "expired" would learn that the code they stole had been used — the single most useful fact to an attacker holding one. The core's handler maps every error to the same `400 invalid_grant`, so nothing on the wire is lost.

### 1.8 Runtime settings

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 70 | Read the settings | `SettingsStore.GetSettings` ← `POST <prefix>/2fa/disable` (`auth.router.ts:890`), and `GET <prefix>/ui/config` and the inbound-webhook sandbox once those land | GetItem `PK=SETTINGS`, `SK=SETTINGS`, strongly consistent | main | 1 r |
| 71 | Patch the settings | `UpdateSettings(patch)` ← `PATCH /admin/api/settings`, and the cold-start seed from `runtimeSettings` | GetItem → PutItem the merged document if `updatedAt = :observed`, or if `attribute_not_exists(updatedAt)` when nothing was read; `ALL_OLD` on failure, retried from the pre-image | main | 1r + 1–n w |

#70 is the only one an unmodified deployment reaches today, and only on `/2fa/disable`; #71 is reached by the cold-start seed and, from P6, by the admin surface.

*Notes, five.*

- **One item, its own partition, no identifier anywhere in the key.** `auth.SettingsStore` carries no tenant, no owner and no id — `GetSettings(ctx)` takes a context and nothing else — because the settings are deployment-global in the reference too: one object the admin Control panel patches (`settings-store.interface.ts:28-40`). So `PK=SETTINGS`, `SK=SETTINGS`, both constants, and there is no identifier to validate because there is none to forge. It is **not** a third sort-key namespace under `TEMPLATES`, even though both are deployment-global configuration: `TEMPLATES` is a *directory*, its two list methods are single Queries over the whole partition with a `begins_with`, and an item that is not a template sitting in it would have to be excluded by every one of them or be handed to a caller expecting a `MailTemplate`. A partition holding one item costs nothing — DynamoDB charges per item, not per partition — and keeps both key spaces describable in a line.
- **Absent is a value, and the omission rule is load-bearing for semantics here rather than for conditions.** Everywhere else in this table an omitted optional attribute means the zero value; in this document it means *the administrator has not set this key*, which `MergeSettings` reads as **keep what is stored**. A codec that wrote `false`, `""` or `0` for an unset key would change what the next patch means. So every field is written only when present, decoded through pointer accessors of its own, and a `S` is written even when empty — a pointer to `""` is a value the administrator set, and dropping it would make it read back as absent.
- **`enabledWebhookActions` is an `L`, and the empty one is the interesting case.** Nil (keep) and an empty non-nil slice (the administrator switching *every* inbound-webhook action off) are different values, and the core carries `AuthSettings.MarshalJSON` purely to keep that difference alive through an encoder — `omitempty` on a `[]string` drops an empty slice as well as a nil one, so a cleared allowlist would come back as absent, `MergeSettings` would read the next nil as keep, and the allowlist would quietly come back on. The same hole is open in an item encoding and is closed the same way: nil omits the attribute, and a non-nil slice is written as an `L`, an empty one included. An `L` and not an `SS` for two reasons — DynamoDB forbids an empty `SS`, which is precisely the value that has to be expressible; and an `SS` is a set, so it would silently deduplicate and reorder a list the reference stores as a JSON array. `ui` follows the same rule one level up: a non-nil block with nothing in it is an empty `M`, not an absent attribute.
- **#71 is the fourth read-then-write in this store, and shares #64's lock.** Same position as `UpdateMailTemplate` (#64): the patch names only the keys it changes, the interface carries nothing else, and the rest has to come from somewhere. What makes the read safe is that the write re-asserts it — `updatedAt` is the lock token, the `PutItem` is conditional on it still being the value observed, a lost condition is retried from the `ALL_OLD` pre-image, and the token advances by a nanosecond when the clock has not moved. The condition is literally the same code: `putIfUnchanged` and `nextStamp` moved to `store.go` when this store landed, because a second hand-rolled copy of a compare-and-set is the one that quietly gets it wrong (the argument `tokenFamily` makes for the five single-use families). The retry bound is 16, and reaching it is `ErrSettingsConflict` rather than a spin — more clearly a fault here than for a template, since the writers are administrators at an admin screen and not requests. **Two administrators patching different keys therefore both land.** What the lock cannot buy, because the contract forbids it: two administrators patching `ui` at the same time, since `ui` is one field of the patch and is replaced whole.
- **Capped at 300 KB on the merged document** (`MaxSettingsBytes`), the same number and the same 100 KB margin under the item limit as `MaxTemplateBytes`, for the same reason — the estimate has to be allowed to be an estimate. A singleton of half a dozen switches needs a cap because two of its fields are caller-supplied and unbounded: `enabledWebhookActions` has no length limit anywhere in the interface, and the branding strings are URLs that nothing stops an admin from pasting a `data:` URI into. A document that cannot be written is a settings store that answers 500 to every read of `require2FA`, so the refusal happens before the write and the stored document is untouched.

---

## 2. Key schema

### 2.1 Table

One table. Partition key `PK` (S), sort key `SK` (S). TTL attribute `ttl` (N, epoch seconds). Every item also carries `_t` (S, entity type) and `_v` (N, schema version) — see §7.

**One GSI, not three.** `GSI1PK` (S) / `GSI1SK` (S), sparse (only items that set both attributes are indexed).

The sketch proposed GSI1 for email/phone, GSI2 for tenant scan, GSI3 for `provider#providerUserId`. All three are rejected; §2.3 gives the reasons. The general principle that collapses them: **a lookup by an opaque, high-entropy, single-valued key belongs in the main table's key space, not in an index.** Indexes are eventually consistent, cannot enforce uniqueness, and cost a full write amplification on every mutation of every projected item. A GSI is warranted only for a genuine one-to-many fan-out whose parent key the caller does not hold — which, after this design, is exactly four patterns (#15, #33, #45, #54), all served by GSI1.

### 2.2 Item catalogue

| Entity | PK | SK | GSI1PK | GSI1SK | TTL |
|---|---|---|---|---|---|
| User profile | `USER#<t>#<u>` | `PROFILE` | — | — | no |
| Email uniqueness | `EMAIL#<t>#<normalizedEmail>` | `EMAIL` | — | — | no |
| Metadata entry | `USER#<t>#<u>` | `META#<key>` | — | — | no |
| Role assignment | `USER#<t>#<u>` | `ROLE#<role>` | `ROLE#<role>` | `USER#<t>#<u>` | no |
| Role definition | `ROLE#<role>` | `ROLE` | — | — | no |
| Session | `SESSION#<sid>` | `SESSION` | `USER#<t>#<u>` | `SESSION#<createdAtRFC3339>#<sid>` | yes |
| Refresh pointer | `REFRESH#<h>` | `REFRESH` | — | — | yes |
| Single-use pointer | `{RESET\|MAGIC\|VERIFY\|ECHG}#<h>` | `TOKEN` | — | — | yes |
| Pending OAuth link | `PLINK#<state>` | `PLINK` | — | — | yes |
| OIDC authorization code | `OIDC#<sha256(code)>` | `CODE` | — | — | yes |
| Linked account | `OAUTH#<provider>#<providerId>` | `OAUTH` | `USERID#<u>` | `OAUTH#<provider>#<providerId>` | no |
| Link id pointer | `LINKID#<linkId>` | `LINKID` | — | — | no |
| API key | `APIKEY#<prefix>` | `APIKEY` | — | — | optional |
| API key id pointer | `KEYID#<keyId>` | `KEYID` | — | — | optional |
| Tenant | `TENANTS` | `TENANT#<t>` | — | — | no |
| Tenant membership | `TENANT#<t>` | `MEMBER#<u>` | `USERID#<u>` | `TENANT#<t>` | no |
| Mail template | `TEMPLATES` | `MAIL#<id>` | — | — | no |
| UI translations | `TEMPLATES` | `UI#<page>` | — | — | no |
| Runtime settings | `SETTINGS` | `SETTINGS` | — | — | no |
| Telemetry event | `TEL#<t>#<yyyy-mm-dd>` | `<rfc3339Nano>#<eventId>` | — | — | yes |
| Rate-limit counter | `RL#<scope>#<subject>#<window>` | `RL` | — | — | yes |

**Item-collection discipline.** Only three child types live under `USER#<t>#<u>`: `META#*`, `PROFILE`, `ROLE#*`. Their ASCII order is `META# < PROFILE < ROLE#`, and all three have bounded cardinality, so an unconditioned `Query` on the user partition is always safe and always returns exactly the `/me` bundle (#4) in one round trip. Sessions, API keys and linked accounts are deliberately **not** in this collection: they are unbounded, and putting them there would turn the hottest read in the system into a paginated scan of the user's history. Any future child type must be named so it sorts inside `[META#, ROLE~]` if it belongs to the bundle, and outside if it does not.

### 2.3 Where the sketch is changed or rejected

| Sketch element | Verdict | Reason |
|---|---|---|
| `PK=USER#<tenantId>#<userId>` | **Accept**, with validation | Correct. But `#` is a legal character in a caller-supplied tenant id, and `TENANT#a#b` + `USER#c` collides with `TENANT#a` + `USER#b#c`. The store validates tenant and user ids against `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$` (empty tenant id allowed, §3) and rejects anything containing `#` with a typed error at the store boundary, never silently. |
| `SK=PROFILE` and `SK=CRED` split | **Reject the split** | Every `UserStore` method returns or requires a whole `auth.User` (`models.go:6-37`): login needs `email`, `passwordHash`, `isEmailVerified`, `require2FA`, `totpSecret` together. Splitting doubles reads on the hottest path. Worse, it makes the single-use semantics in §4.1 impossible: a DynamoDB conditional write is per-item, so the fields that constrain each other must share an item. IAM attribute-level isolation (`dynamodb:Attributes`) is the only argument for splitting, and it buys nothing when one Lambda role owns every store. |
| `SK=META#<key>` | **Accept** | Per-key items give atomic per-key merge with no read (`UpdateMetadata` merges, it does not replace — `feature_stores.go:30-42`). The alternative, one `META` item with a nested map, cannot be merged in a single call: `SET #d.#k = :v` fails when `#d` does not exist, and initialising it in the same expression is a conflicting-path error, so it degrades to read-modify-write. Cost accepted: `GetMetadata` is a Query (`K` items) and `ClearMetadata` is a Query + BatchWrite, which is **not atomic** — a partial failure during `DELETE /account` orphans metadata under a deleted user. Mitigation: the delete is driven off the same query and is idempotent on retry. |
| `SK=ROLE#<role>` | **Accept**, plus a role-definition item | Assignments are tenant-scoped (`AddRoleToUser(userID, role, tenantID)`); role definitions and their permissions are **global** (`CreateRole(role, permissions)`, no tenant). Two item types, not one. `permissions` is a String Set so `AddPermissionToRole`/`RemovePermissionFromRole` are `ADD`/`DELETE` — atomic, read-free. |
| `SK=LINK#<provider>` | **Reject** | Wrong key and wrong partition. Wrong key: the wire contract addresses links as `DELETE /linked-accounts/:provider/:providerAccountId`, and `FindByProvider(provider, providerID)` is the primary lookup, so `providerId` is part of the identity. Wrong partition: `FindByProvider`, `ListForUser(userID)` and `Delete(id)` **all lack a tenant id**, so a `USER#<t>#<u>` partition cannot serve any of them. Links become globally keyed `OAUTH#<provider>#<providerId>` with a `LINKID#<id>` pointer for `Delete(id)`. |
| `SK=SESSION#<id>` | **Reject** | Three of five session methods — `GetSessionByRefreshTokenHash`, `GetSessionByID`, `RevokeSessionByID` — carry neither tenant nor user, and two of them are on the refresh hot path. A user-partitioned session would need a second index to serve them anyway. Global `SESSION#<sid>` makes refresh two `GetItem`s and revocation one `UpdateItem`; the only by-user pattern (`ListSessionsForUser`, an admin/UI read) moves to GSI1 where eventual consistency is acceptable. |
| `SK=APIKEY#<hash>` | **Reject** | `APIKeyRecord` (`api_keys.go:14-25`) has no user id and no tenant id — only `ServiceID`. It cannot live under a user partition. Lookup is by `Prefix` (`FindByPrefix`), and mutation is by `ID` (`Revoke`, `UpdateLastUsed`), so two keys are unavoidable: canonical item keyed by prefix (hot path, 1 GetItem) plus a `KEYID#<id>` pointer for the two cold mutations. Also: the prefix is `ak_` + 8 hex = **32 bits**, so a birthday collision is expected around ~77 000 live keys, and `FindByPrefix` returns exactly one record. Keying the canonical item by prefix with `attribute_not_exists(PK)` converts that from a silent authentication failure into a loud `Save` error the caller can retry. |
| GSI1 for email lookup | **Reject** | A GSI cannot enforce uniqueness and is eventually consistent. `CreateUser` must return `ErrUserExists` on a duplicate (`memory_store.go:42-45`) and `ApplyEmailChange` must return it when the new address is taken (`memory_store.go:372-374`) — both are uniqueness constraints, which in DynamoDB means a **separate item with `attribute_not_exists` inside a transaction**, never an index. `GetUserByEmail` then costs two strongly-consistent `GetItem`s instead of one eventually-consistent Query, which is the correct trade for a login path. |
| GSI1 for phone lookup | **Reject — no such pattern** | No interface method resolves a user by phone number. `POST /add-phone` writes it; `POST /sms/send` resolves by `email` or `userId` (`auth.router.ts:1204-1220`). Building an index for a pattern nobody has is pure write amplification. If a by-phone lookup ever lands, it is a `PHONE#<t>#<e164>` uniqueness item, not an index. |
| GSI2 for tenant scan | **Reject** | Served by the main table. Tenants live at `PK=TENANTS`, `SK=TENANT#<t>`, so `GetTenantByID` is a `GetItem` and `GetAllTenants` a `Query` on one partition. Memberships live at `PK=TENANT#<t>`, `SK=MEMBER#<u>`, so `GetUsersForTenant` is a `Query` on a partition already scoped to exactly one tenant — tenant isolation by key, for free. A GSI would only reintroduce eventual consistency and a second copy of every membership. |
| GSI3 for `provider#providerUserId` | **Reject** | Superseded: that is now the main-table partition key of the linked-account item. |
| `OTP#` ephemeral item | **Reject** | `GetUserBySMSCodeHash(ctx, userID, tenantID, codeHash)` already carries the full user key (`store.go:51`). The code hash and its expiry live on the profile item, where a single conditional `UpdateItem` verifies and consumes atomically (#24). A separate item would add a write per send and a read per verify and buy nothing. |
| `MAGIC#` / `REFRESH#` / `PENDING_LINK#` ephemerals | **Accept** | Each is the only way to resolve a tenant-less, hash-keyed lookup, and each is genuinely ephemeral. |
| `CSRF#` ephemeral item | **Reject** | CSRF is a **stateless double-submit** in both the reference (`auth.middleware.ts:33-42`: cookie value compared to the `X-CSRF-Token` header, no store lookup anywhere) and in `awesome-go-auth` (`csrf.go:44-80`, same). There is no server-side CSRF state to persist. Adding one would be a behaviour change *and* a DynamoDB write on every single request. |
| `IDEMPOTENCY#` ephemeral item | **Defer, namespace reserved** | Not derived from any store interface or any reference behaviour. It is a plausible answer to API Gateway/SQS at-least-once delivery, but that belongs to the `lambdahttp` and event layers, not the auth store. Reserved shape if adopted: `PK=IDEM#<scope>#<key>`, `SK=IDEM`, `attribute_not_exists(PK)`, TTL. See §8. |
| "TTL replaces the session-cleanup cron" | **Accept, with a visible consequence** | Correct, and it removes `DeleteExpiredSessions` entirely — see §4.5 for the wire-visible consequence that needs sign-off. |

---

## 3. Tenant isolation

**Rule.** Tenant isolation is a property of the key, never of a filter expression. No `FilterExpression`, no post-query `if item.tenantId == x` check, anywhere in the store. A query that returns the wrong tenant's data must be impossible to write, not merely wrong.

Concretely:

- Every tenant-scoped item embeds `<t>` in the **partition key**: `USER#<t>#<u>`, `EMAIL#<t>#<email>`, `TENANT#<t>`, `TEL#<t>#<day>`. A query for tenant A physically cannot read tenant B's partition.
- `<t>` is only ever taken from (a) the `tid` claim of a verified token (`token.go:14`), (b) an argument the core passes down from such a claim, or (c) the `tenantId` attribute stored on a pointer item the store itself wrote. **Never** from a request body, path parameter, query string or header. The store's public methods take `tenantID` as an explicit argument precisely so this is auditable at the call site.
- Items whose lookup key is a high-entropy secret hash (`REFRESH#`, `RESET#`, `MAGIC#`, `VERIFY#`, `ECHG#`, `PLINK#`, `SESSION#`, `OAUTH#`, `APIKEY#`) are **necessarily global**: the interface methods that read them (`GetSessionByRefreshTokenHash`, `GetSessionByID`, `RevokeSessionByID`, `GetUserBy*TokenHash`, `FindByProvider`, `ListForUser`, `FindByPrefix`, `PendingLinkStore.Get`) take no tenant id. These items are **capabilities**, not directories: possession of the 256-bit value is the authorisation, and each item carries `tenantId` so that the *next* access re-derives a tenant-scoped key. Isolation is preserved because the tenant id used downstream comes from the stored item, not from the caller.
- Cross-tenant confusion is therefore reduced to one question per global item: *could an attacker guess the key?* `sha256` of a 32-byte random token, a `ses_`/`usr_`/`key_` id (16 random bytes, `security.go:18-26`), and an OAuth `state` (16 random bytes) are all ≥128 bits. The one exception is the API-key prefix at 32 bits, handled in §2.3.

**A missing `tenantId` means the empty-string tenant, not "any tenant".** `awesome-go-auth` treats `""` as an ordinary tenant value: `userEmailKey` composes `"" + ":" + email` (`memory_store.go:32-34`) and `GetUserByID` compares `u.TenantID != tenantID` exactly (`:70`), so a user created with `""` is invisible to a lookup with `"acme"` and vice versa. The DynamoDB store preserves this precisely:

- `tenantID == ""` maps to the literal partition `USER##<u>` / `EMAIL##<email>`. It is a real, distinct tenant — the single-tenant deployment's tenant.
- The store **must not** substitute a configured default, and **must not** treat `""` as a wildcard. Both would silently merge or leak tenants.
- When `stores.multiTenant` is enabled in config, an empty tenant id is rejected at the store boundary with a typed error rather than written. When it is disabled the store accepts **any** tenant id, including `""`. The check lives in one place so it cannot be forgotten per method.

  *Corrected during implementation.* This section originally said that with multi-tenancy disabled, `""` was the *only* accepted value. That is unimplementable without breaking deployments: `tenantID` reaches the store from the `tid` claim, so any existing token carrying a non-empty tenant would start failing every request the moment the knob defaulted off, and `awesome-go-auth` itself treats a tenant id as an ordinary opaque value with no notion of a "configured" one. Rejecting a *missing* tenant where one is required catches a real bug; rejecting a *present* one catches nothing and turns a config default into an outage. The single-tenant deployment simply keys everything under `""`.

**Interfaces that make key-based isolation impossible.** Named here so nobody rediscovers them in review: `GetSessionByID`, `RevokeSessionByID`, `GetSessionByRefreshTokenHash`, `DeleteExpiredSessions`, all four `GetUserBy*TokenHash`, all three `UserMetadataStore` methods, `LinkedAccountStore.{FindByProvider,ListForUser,Delete}`, `PendingLinkStore.*`, and the whole of `APIKeyStore`. For the capability-keyed ones the design above is sound. `UserMetadataStore.GetMetadata(ctx, userID)` is the one that is *not* sound: it is genuinely under-specified, since metadata items live under `USER#<t>#<u>` and the method cannot name `<t>`. The port resolves it by requiring the caller to pass a tenant-bound context (the store reads `<t>` from the request-scoped principal), and files an upstream request to widen the signature to `GetMetadata(ctx, userID, tenantID)`. Until that lands, a deployment with multiple tenants and metadata enabled has an unindexable method — see §8.

---

## 4. Single-use and rotation semantics

No path in this store performs read-then-write across two round trips to enforce a constraint. Every constraint is a `ConditionExpression`.

### 4.1 Single-use tokens: consume-on-read

The core calls `GetUserBy*TokenHash` → mutate → `Clear*Token` as three separate store calls (`auth.router.ts:818-820` for the reference, `service.go:246-266` for Go). Nothing in that sequence is atomic, and the wire contract already documents the resulting hole ("a store failure in the clear step leaves a consumed-but-valid token", §2 *Single-use clearing summary*). Two Lambdas racing on the same magic link both pass the read.

The fix is to make the **read** the consume, in one conditional write:

```
UpdateItem
  Key                 PK = USER#<t>#<u>, SK = PROFILE
  UpdateExpression    REMOVE resetHash, resetExp
  ConditionExpression resetHash = :h AND resetExp > :now
  ReturnValues        ALL_OLD
```

`ALL_OLD` returns the full pre-image, which is exactly the `auth.User` the method must return — including the hash and the expiry, which the core re-checks on the returned user and treats a nil expiry as invalid (`service.go:343`, `:394`, `:435`, `:473`). Exactly one concurrent caller succeeds; the losers get `ConditionalCheckFailedException`, mapped to `ErrInvalidToken`. `Clear*Token` becomes an idempotent no-op. The pointer item (`RESET#<h>` etc.) supplies `<t>` and `<u>` and is a **hint only** — a stale pointer whose hash no longer matches the profile fails the condition and is harmless; TTL reaps it.

**The mapped error is per-family, not `ErrInvalidToken` everywhere** (corrected during implementation). `MemoryUserStore.GetUserBySMSCodeHash` returns `ErrInvalidCode` (`memory_store.go:238`) where the four token families return `ErrInvalidToken` (`:195`), and `SMSVerifyHTTPError` versus `MagicLinkVerifyHTTPError` are built on that difference. Flattening the two would change the status and code on the wire, so the error is a property of the family alongside its key prefix and attribute names. A lost condition is an *authentication outcome*; a genuine fault must never be flattened into it, which is why only `ConditionalCheckFailedException` takes that branch.

**`Clear*Token` must be conditional on the user, not on the attribute** (corrected in #21, which originally said `attribute_exists(<F>Hash)`). After #20 the attribute is already gone, so that condition would fail on the ordinary path — and `Service.ResetPassword` calls `ClearResetToken` *after* `UpdatePassword` has already committed (`service.go:262-265`), so the failure would surface as a 500 on a request whose password change had in fact succeeded. `attribute_exists(PK)` keeps the useful part of the check (a missing user is still `ErrUserNotFound`) and drops the harmful part. `REMOVE` of an absent attribute is a documented no-op, which is all the idempotency this needs.

**Pointer writes are conditioned on ownership, not merely on absence** (corrected in #19, #10, #12). A bare `attribute_not_exists(PK)` makes an ordinary retry of the *same* call fail permanently: the pointer the first attempt wrote is indistinguishable from a collision. `attribute_not_exists(PK) OR (userId = :u AND tenantId = :t)` — `OR sessionId = :sid` for the session pointers — lets a caller reclaim its own pointer while a genuinely different owner behind the same hash, which is a sha256 collision, still fails loudly.

Consequences, stated rather than hidden:

- **Fail-closed.** If the subsequent `UpdatePassword` fails, the token is already burned and the user must request a new link. This is the correct posture for auth and it matches the reference's magic-link behaviour, which burns the token even when the following `tempToken` comparison fails (wire contract §3, `/magic-link/verify`).
- SMS is the same shape without a pointer (#24), and the condition `smsHash = :h` means a **wrong** code does not burn the stored code — preserving `sms.strategy.ts:23-36` (retry until expiry, no attempt counter).
- Governed by `stores.dynamodb.consumeSingleUseOnRead`, default `true`, which the store takes as `Options.NonAtomicSingleUseTokens` — stated as an opt-*out* so that a zero-value `Options` gives the safe behaviour rather than the reference's hole. Setting it restores the non-atomic read-then-clear verbatim for strict-parity testing, with one unavoidable difference: the hash is still compared against the profile, because unlike the reference's in-memory map a pointer item outlives the token it names and a rotated-out pointer must not resolve.

### 4.2 Email uniqueness

`CreateUser` and `ApplyEmailChange` are the only two operations that must be globally serialised. Both are `TransactWriteItems` with `attribute_not_exists(PK)` on the `EMAIL#<t>#<email>` item (#1, #22). A `TransactionCanceledException` whose `CancellationReasons[i].Code == "ConditionalCheckFailed"` on the email item maps to `ErrUserExists`; on the profile item, to `ErrUserExists` as well (`memory_store.go:39-45` returns the same error for a duplicate id).

### 4.3 Refresh rotation and token families

**Family = session.** `Service.Refresh` keeps the same `session.ID` across rotations and only replaces `RefreshTokenHash` (`service.go:122-162`), so the session *is* the family and no separate `familyId` is needed. Revoking the family is one `UpdateItem` on `SESSION#<sid>`; every subsequent refresh reads that item and sees `revokedAt`.

State: the session item holds the **authoritative** `refreshHash` and a monotonic `gen`. Each generation additionally gets a `REFRESH#<h>` pointer with a TTL.

Rotation (#12) is one transaction:

```
TransactWriteItems
  Put    PK = REFRESH#<newHash>, SK = REFRESH, {sid, uid, tid, gen: g+1, ttl}
         ConditionExpression attribute_not_exists(PK)
  Update PK = SESSION#<sid>,     SK = SESSION
         SET refreshHash = :newHash, expiresAt = :exp, gen = :gPlus1, updatedAt = :now
         ConditionExpression attribute_not_exists(revokedAt)
                             AND refreshHash = :oldHash      -- when available, see below
                             AND gen = :g
```

**Replay detection** happens on the read path (#11), where both values are in hand:

```
GetItem REFRESH#<h>            -> {sid, gen}
GetItem SESSION#<sid>          -> {refreshHash, gen, revokedAt, expiresAt}
if revokedAt != nil            -> return the Session, with RevokedAt populated
if refreshHash != <h>          -> REPLAY of a rotated-out generation
```

**A revoked session is returned, not turned into an error.** `Service.Refresh` maps *any* error out of `GetSessionByRefreshTokenHash` to `ErrSessionNotFound` (`service.go:129-131`) and only produces `ErrSessionRevoked` from the struct field it checks next (`service.go:133-135`). Returning `ErrSessionRevoked` from the store would therefore be swallowed and change the status on the wire. `Logout` depends on the same thing: it re-revokes a session it just read (`service.go:171-180`), which an error would prevent. (Earlier drafts of this line said `-> ErrSessionRevoked`, which reads correctly as intent and is wrong as an instruction to the store.)

A hash that resolves to a live session whose current `refreshHash` differs can only be a previous generation, i.e. a token that was already exchanged. The response is immediate family revocation:

```
UpdateItem PK = SESSION#<sid>, SK = SESSION
  SET revokedAt = :now, revokedReason = 'refresh_replay', revokedGen = :gen
  ConditionExpression attribute_not_exists(revokedAt)
```

then return `ErrSessionNotFound` (the error `Service.Refresh` already maps at `service.go:129-131`). This is a write inside a nominally read-only method; it is a deliberate, documented deviation, justified because a replay is a security event and deferring the response to the next request leaves the attacker a valid window. No pointer enumeration is needed — killing the session kills every generation at once.

**The interface cannot fully express this, and that is the sharpest mismatch in the whole model.** `SessionStore.UpdateSession(ctx, Session)` (`store.go:25`) is a whole-struct write with no precondition token: the store receives the *new* hash and never learns the old one, and `auth.Session` (`models.go:49-57`) has no version/generation field. So the `refreshHash = :oldHash AND gen = :g` clause above has no source. Ranked resolutions:

1. **Upstream (preferred).** Add an optional interface discovered by type assertion, in the same style as `SessionLookupStore`/`SessionAdminStore`:
   `SessionRotationStore { RotateSession(ctx context.Context, sessionID, oldRefreshHash string, next Session) error }`.
   `Service.Refresh` uses it when the store implements it. File as an upstream issue; the port implements it from day one.
2. **Interim.** `GetSessionByRefreshTokenHash` records the hash and `gen` it observed into a **mutable carrier the HTTP layer installed on the `context.Context` beforehand**; `UpdateSession` takes it back out. `Service.Refresh` passes the same `ctx` to both calls (`service.go:129`, `service.go:159`), so this is correct and request-scoped. When the carrier is absent, the store degrades to `attribute_not_exists(revokedAt)` alone and logs a warning once per cold start.

   *Corrected during implementation:* a callee cannot add a value to a `context.Context` it was handed — `context.WithValue` returns a new context the caller never sees. So the interim only works if something upstream installs a pointer first, which makes it a two-part contract rather than a store-local trick: the store exports `WithRotationScope(ctx)` and the Lambda HTTP layer **must** call it once per request. A deployment that forgets is silently in the degraded mode of (3), which is why the warning exists and why `CompatibilityNotes()` does not hide it.
3. **Residual.** Under degradation, two concurrent refreshes of the same token both succeed and the second overwrites the first. The loser's token is then a rotated-out generation, so the *next* use of it is caught by replay detection and revokes the family. That is the correct end state for rotation; the only loss is that it is detected one request late. With the scope installed there is no such window: the loser's transaction is refused, and the loser itself revokes the family immediately.

   The rotation `UpdateExpression` uses `ADD gen :one` rather than `SET gen = :g + 1`, so the counter advances correctly even in the degraded path where `:g` is unknown; `gen = :g` remains as a *condition* whenever the scope supplies it.

Cost: the rotation transaction is 2× WCU versus a bare write. Refresh runs at most once per access-token lifetime (15 min default), so this is a rounding error against the per-request read traffic.

### 4.4 Other conditional writes

| Operation | Condition | Failure maps to |
|---|---|---|
| `CreateSession` refresh pointer | `attribute_not_exists(PK) OR sessionId = :sid` | internal error (hash collision — impossible in practice, loud if not) |
| `RevokeSessionByID` | `attribute_exists(PK)`, with `SET revokedAt = if_not_exists(revokedAt, :now)` | `ErrSessionNotFound` |
| `UpdateSession` (logout) | `attribute_exists(PK) AND attribute_not_exists(revokedAt)` | absent → `ErrSessionNotFound`; already revoked → success (idempotent) |
| Issue single-use token, profile side | `attribute_exists(PK)` | `ErrUserNotFound` |
| Issue single-use token, pointer side | `attribute_not_exists(PK) OR (userId = :u AND tenantId = :t)` | internal error (sha256 collision, or one tenant reaching for another's pointer) |
| Consume single-use token / SMS code | `<F>Hash = :h AND <F>Exp > :now` | `ErrInvalidToken`, or `ErrInvalidCode` for SMS (§4.1) |
| `Clear*Token`, `ClearSMSCode`, `MarkEmailVerified`, `UpdateTOTPSecret`, `UpdatePhoneNumber` | `attribute_exists(PK)` | `ErrUserNotFound` |
| Consume pending link (single-use namespaces) | `attribute_exists(PK) AND (attribute_not_exists(expiresAt) OR expiresAt > :now)` | empty pre-image → `ErrPendingLinkNotFound`; non-empty → `ErrPendingLinkExpired` |
| `LinkedAccountStore.Save`, canonical item | `attribute_not_exists(PK) OR linkId = :observed` | concurrent rebind → retry, then `ErrLinkedAccountConflict` |
| `LinkedAccountStore.Save`, id pointer | `attribute_not_exists(PK) OR (userId = :u AND provider = :p AND providerId = :pid)` | internal error (the link id already names a different provider account) |
| `LinkedAccountStore.Delete`, canonical item | `linkId = :id` | the binding moved on → drop the pointer alone and report success |
| `ApplyEmailChange` new address | `attribute_not_exists(PK)` | `ErrUserExists` |
| `ApplyEmailChange` profile | `attribute_exists(PK) AND email = :old AND pendingEmail = :new` | absent → `ErrUserNotFound`; moved → `ErrInvalidToken` |
| `AddRoleToUser` | ConditionCheck `attribute_exists(ROLE#<role>)` | `ErrRoleNotFound` (`feature_stores.go:68-70`) |
| `CreateTenant` | `attribute_not_exists(SK)` | `ErrAlreadyExists` |
| `UpdateTenant` | `attribute_exists(SK)` | `ErrTenantNotFound` |
| `APIKeyStore.Save` | `attribute_not_exists(PK)` on both items | prefix collision → caller regenerates |
| Rate-limit consume | `attribute_not_exists(n) OR n < :max` | 429 |

`ReturnValuesOnConditionCheckFailure = ALL_OLD` is set on every conditional write whose failure needs to be distinguished (replay vs. race, taken-email vs. taken-id). Inside `TransactWriteItems` the pre-image comes back in `CancellationReasons[i].Item`.

Three notes the implementation forced:

- `attribute_not_exists(revokedAt)` alone is not enough on an `UpdateItem`, because `UpdateItem` **creates** a missing item and the condition is trivially true for one. Every such condition is paired with `attribute_exists(PK)`.
- With the two combined, a `ConditionalCheckFailedException` no longer says which half failed. The pre-image disambiguates: empty means the item did not exist, non-empty means it was already revoked. Where a pre-image does not come back (an older DynamoDB Local, an endpoint that ignores the flag) the store falls back to a `GetItem` **after** the write was refused — a read that classifies a rejection, not the read-then-write this section forbids.
- `RevokeSessionByID` writes through `if_not_exists`, so an administrative revocation cannot relabel an earlier `refresh_replay` one. That is a small, deliberate divergence from `MemorySessionStore.RevokeSessionByID` (`memory_store.go:473-484`), which overwrites `RevokedAt`; keeping the first revocation is what makes `revokedReason` worth storing. Listed in `CompatibilityNotes()`.

### 4.5 TTL replaces the cleanup cron — and one wire-visible consequence

`ttl` (epoch seconds) is set on sessions (`expiresAt` + 24 h grace, so replay detection still works briefly after expiry), refresh pointers, all four single-use pointers, pending links, telemetry events and rate-limit counters. `SessionAdminStore.DeleteExpiredSessions` becomes a no-op.

**TTL is not a security boundary.** DynamoDB deletes expired items on a best-effort basis, typically within 48 hours. Every read of a TTL-bearing item must re-check its expiry attribute in code and treat a late item as absent. The `ExpiresAt` / `<F>Exp` conditions in §4.1–4.3 already do this; nothing may rely on the item being gone.

**Consequence needing sign-off.** `POST /sessions/cleanup` returns `200 {"success":true,"deleted":<number>}` (wire contract §1, 3.8). With TTL there is no count, so the port returns `deleted: 0`. Producing a real number would require a `EXPIRES#<bucket>` index — an extra GSI plus a write on every session — to reproduce a number that the route's only documented consumer is a cron job. Recommendation: return `0`, add a `CompatibilityNotes()` entry. Flagged in §8.

---

## 5. Item shapes and GSI projections

Types are DynamoDB attribute types. Timestamps are `S`, RFC 3339 in UTC with a **fixed nine-digit fraction** (`2006-01-02T15:04:05.000000000Z`); `ttl` is `N` epoch seconds. Absent optional fields are **omitted**, never written as `NULL`, so `attribute_not_exists` conditions stay meaningful.

**The fixed width is load-bearing, not cosmetic.** DynamoDB compares strings bytewise, and Go's `time.RFC3339Nano` *trims* trailing zeros from the fraction, so `2026-01-01T00:00:00Z` sorts **after** `2026-01-01T00:00:00.5Z` (`Z` = 0x5A > `.` = 0x2E). Lexicographic order would then stop matching chronological order, silently breaking two things that depend on the equivalence: the `<F>Exp > :now` conditions in §4.1 and the `SESSION#<createdAt>#<sid>` sort key on GSI1. Padding to nine digits restores it. Readers accept a variable-width fraction as well, so items written before this was pinned still decode (§7 rule 1).

**User profile** — `_t: "user"`, `userId` S, `tenantId` S, `email` S (normalized, `service.go:58`), `passwordHash` S, `phoneNumber` S?, `firstName` S?, `lastName` S?, `role` S?, `isEmailVerified` BOOL, `require2FA` BOOL, `isTotpEnabled` BOOL, `totpSecret` S?, `resetHash`/`resetExp`, `magicHash`/`magicExp`, `verifyHash`/`verifyExp`, `echgHash`/`echgExp`, `pendingEmail` S?, `smsHash`/`smsExp`, `createdAt` S, `updatedAt` S. `~500 B` typical, `~1.5 KB` worst case.

**Email uniqueness** — `_t: "email"`, `userId` S, `tenantId` S. `~120 B`. Deliberately minimal: it is written inside a transaction on the registration path and read on every login.

**Session** — `_t: "session"`, `sessionId` S, `userId` S, `tenantId` S, `refreshHash` S, `gen` N, `createdAt` S, `expiresAt` S, `revokedAt` S?, `revokedReason` S?, `ttl` N. Optional device metadata (`userAgent`, `ipAddress`, `lastActiveAt`) is written when the HTTP layer supplies it — `auth.Session` has no such fields (`models.go:49-57`), so they are store-side extras for the admin surface, and the store must not lose them when `UpdateSession` writes back a struct that never carried them: rotation uses `UpdateItem` with an explicit attribute list, never `PutItem`.

**Refresh pointer** — `_t: "refresh"`, `sessionId`, `userId`, `tenantId`, `gen` N, `ttl` N. `~150 B`.

**Single-use pointer** — `_t: "token"`, `family` S (`reset`|`magic`|`verify`|`echg`), `userId`, `tenantId`, `ttl` N.

**Role definition** — `_t: "role"`, `role` S, `permissions` SS. A String Set, not a List: it gives set semantics and read-free `ADD`/`DELETE`. Empty sets are illegal in DynamoDB, so a role with no permissions omits the attribute and `GetPermissionsForRole` returns an empty slice.

**Metadata entry** — `_t: "meta"`, `key` S, `value` (any DynamoDB type, via `attributevalue` marshalling of `any`). Values that fail to marshal (`chan`, `func`) are rejected at the store boundary, not silently dropped.

**Linked account** — `_t: "link"`, `linkId` S, `userId` S, `provider` S, `providerId` S, `email` S?, `name` S?, `picture` S?, `createdAt` S. **`tenantId` is deliberately absent**: `OAuthLinkedAccount` (`oauth.go:68-77`) has no tenant field and `HandleCallback` resolves the user with a tenant supplied by the caller. Adding one would invent semantics. The three optional profile columns arrived with v0.2.0 and are what `GET /linked-accounts` renders; `email` is written by every link the library itself creates, `name` and `picture` only by a host that fills them in.

**Link id pointer** — `_t: "linkid"`, `linkId` S, `userId` S, `provider` S, `providerId` S. Deliberately minimal: it exists only so `Delete(id)` can name the canonical key, and both of its values are read back out of it rather than off the request.

**Mail template** — `_t: "template"`, `baseHtml` S?, `baseText` S?, `translations` M (`lang → M (key → S)`; always present, `{}` when empty, because the reference encodes it as `{}` and never as `null`; an empty value is an empty `S`), `updatedAt` S (the optimistic-lock token of #64, not merely a timestamp). The id is not duplicated into an attribute: it is the tail of `SK`, and `mailTemplateIDFromSK` is the only decoder. Up to 300 KB by construction (`MaxTemplateBytes`); the six reference templates are a few KB each. That attribute set is exact — a test reads the item back raw and pins it, so a cleared body is an absent attribute rather than a `NULL` or an empty string.

**UI translations** — `_t: "uitranslation"`, `translations` M as above, `updatedAt` S. The page is the tail of `SK`. A distinct `_t` from the mail template rather than a shared one: the two have different attribute sets, and `_t` exists so a migration sweep can tell item types apart without inferring them from the sort-key prefix (§7).

**Runtime settings** — `_t: "settings"`, `requireEmailVerification` BOOL?, `emailVerificationMode` S?, `lazyEmailVerificationGracePeriodDays` N?, `require2FA` BOOL?, `enabledWebhookActions` L of S?, `ui` M of S?, `updatedAt` S (the optimistic-lock token of #71, not merely a timestamp). The attribute names are the reference's JSON names verbatim (`settings-store.interface.ts:45-92`), capitalisation of `require2FA` included, so a raw dump of this item is the document a node-auth deployment stores and a migration between the two is a copy. `require2FA` is the same attribute *name* the user profile carries for its own per-user flag (`models.go:23`); they live on different item types and never in one item, and the name is shared rather than duplicated so a codec and a condition cannot drift apart. Every field is optional and **absent means absent, not zero** — see §1.8 — and the two composite fields are present-but-empty when cleared: `L` `[]` for "every webhook action off", `M` `{}` for "every branding field cleared". That attribute set is exact; a test reads the item back raw and pins it, so a key nobody set is an absent attribute rather than a `NULL` or a `false`. Up to 300 KB by construction (`MaxSettingsBytes`); a realistic document is a few hundred bytes.

**Pending OAuth link** — `_t: "plink"`, `provider` S?, `redirectUrl` S?, `tenantId` S?, `userId` S?, `email` S?, `providerId` S?, `expiresAt` S? (the store's deadline, driving the consume condition), `metaExpiresAt` S? (the caller's own, round-tripped verbatim), `createdAt` S, `ttl` N. Every field is optional because `OAuthPendingMeta` has three different shapes across the three namespaces that use it, and the omission rule means an absent one round-trips as the zero value rather than as `NULL`.

**API key** — `_t: "apikey"`, `keyId` S, `prefix` S, `name` S, `serviceId` S, `keyHash` S (bcrypt), `scopes` SS?, `allowedIPs` SS?, `isActive` BOOL, `expiresAt` S?, `lastUsedAt` S?, `createdAt` S.

**OIDC authorization code** — `_t: "authcode"`, `userId` S?, `tenantId` S?, `clientId` S?, `redirectUri` S?, `nonce` S?, `scope` S?, `codeChallenge` S?, `codeChallengeMethod` S?, `expiresAt` S (driving the consume condition), `createdAt` S, `ttl` N. No `codeHash` attribute: the hash is the partition key, and a second copy of it would be a value with nothing keeping the two in step. The PKCE pair and the scope are recorded as plain data the core does not verify yet, so that it can start verifying them without a schema change. Everything but the two timestamps is optional, because the omission rule means an absent field round-trips as the zero value rather than as `NULL`.

### GSI1 projection

**`INCLUDE` of exactly `_t`, `linkId`, `createdAt`.** Everything else is fetched by `BatchGetItem` against the main table.

Why not `ALL`: GSI1 indexes sessions, memberships, links and role assignments. `ALL` would duplicate every session item — the highest-churn entity in the table — doubling both storage and the WCU cost of every login and every rotation, to save one round trip on `GET /sessions`, an interactive admin/UI read.

*Corrected during implementation, twice.* This paragraph first claimed the three included attributes let `ListForUser` answer from the index alone. That stopped being true when `auth.OAuthLinkedAccount` gained `Email`, `Name` and `Picture` (v0.2.0), all three of which `GET /linked-accounts` projects and none of which is in the index — so #54 is a Query followed by a `BatchGetItem`, like #15. The projection was deliberately *not* widened to match: a GSI is a second physical copy with its own export and its own PITR restore, and putting every linked email address into one to save a round trip on an account screen is the wrong trade.

It then claimed `linkId` had to stay projected because "`DeleteUser`'s link sweep and `Delete(id)`'s pointer both need `linkId` … and getting it from the index is what keeps the sweep to one query." **Both halves were wrong, and the second half described a bug.** `Delete(id)` never touches the index at all — it reads `LINKID#<id>` straight by key. And the sweep must *not* take `linkId` from the index, for the reason in the rule below. `linkId` is now surplus in the projection; it is left there rather than narrowed because changing a GSI's projection means dropping and recreating the index, which is a migration and belongs to infrastructure code, and because a projection wider than necessary is a cost question rather than a correctness one — no secret is in it.

**Rule: GSI1 is authoritative for *reachability*, never for *ownership*.** An index entry says "this item was, at some point, attributed to this owner". Ownership lives on the canonical item, and a `Save` that rebinds a provider account moves `GSI1PK` from one owner to the next atomically *in that item* while the old owner's index partition goes on advertising the entry until the index catches up. Every by-owner fan-out therefore re-reads the canonical item and drops what no longer belongs to the caller (`LinkedAccounts.ownedLinksForUser`). This is not the post-read tenant filter §3 forbids: the Query is still confined to one `USERID#<u>` index partition and no other partition is reachable from it. It is a staleness guard, and it fails closed.

Trusting the index for ownership was reproduced as two live defects before the guard was added: `ListForUser` returned one user another user's binding, complete with the provider email `GET /linked-accounts` renders; and `DeleteUser` — which sweeps these keys with a `BatchWriteItem`, which cannot carry a `ConditionExpression`, against a canonical key (`OAUTH#<provider>#<providerId>`) that is identical whoever owns it — deleted a live binding out from under its current owner, stranding that provider identity. `DeleteUser` therefore also rebuilds the `LINKID#` key from the canonical item, since the index's `linkId` is exactly as stale as its `GSI1PK`.

**Nothing secret is ever projected.** `passwordHash`, `totpSecret`, `refreshHash`, `keyHash` and every `*Hash`/`*Exp` attribute are excluded from GSI1 by construction. A GSI is a second physical copy with its own export, its own PITR restore and its own blast radius; secrets exist in exactly one place.

Everything the four GSI1 patterns need to *address* the main table is already in the index keys: `ListSessionsForUser` gets `sid` from `GSI1SK`; `GetTenantsForUser` gets `<t>` from the base `PK` returned with every index item; `DeleteRole` gets the assignment's full key; `ListForUser` gets `provider` and `providerId` from `GSI1SK`. What none of them may take from the index is who the item belongs to — see the ownership rule above.

---

## 6. Capacity, durability, and the risks actually present

### 6.1 Defaults

| Setting | Value | Note |
|---|---|---|
| Billing | `PAY_PER_REQUEST` | Auth traffic is spiky and per-tenant unpredictable; provisioned capacity would need autoscaling to do worse. |
| On-demand ceiling | `MaxReadRequestUnits` / `MaxWriteRequestUnits` set per environment | A credential-stuffing run against `POST /login` is a DynamoDB bill before it is an outage. Cap it and alarm on the cap, do not leave it unbounded. |
| PITR | **on** | 35-day continuous backup. Cheap insurance against a bad migration (§7). |
| Encryption | SSE with a **customer-managed KMS key** | Key policy grants the Lambda execution role and `dynamodb.amazonaws.com` via `kms:ViaService`. Consequences to plan for: the CMK must exist in every region the table is replicated to; a PITR restore and an S3 export both require `kms:Decrypt` on the same key; deleting the key destroys the table's data irrecoverably, so schedule-for-deletion must be alarmed. |
| Deletion protection | **on** | |
| Streams | `NEW_AND_OLD_IMAGES` from day one | Enabling later gives no history. The consumer is optional — the event/SSE-distributor plane (gap analysis §1.5) and audit export. |
| TTL | attribute `ttl` | §4.5. |
| Backups | PITR + a scheduled on-demand backup for long retention | |
| Contributor Insights | off by default, on during load testing | It is billed per event. |

### 6.2 Hot partitions

DynamoDB's hard per-partition limits are 1 000 WCU and 3 000 RCU; adaptive capacity and split-for-heat mitigate skew across key ranges but cannot split a single item.

- **`PK=TENANTS`.** Every tenant record shares one partition. Tenant CRUD is an operator-scale event, not a user-scale one, so 1 000 writes/s is a ceiling nobody reaches. `GetAllTenants` reads the whole partition: hard-cap it (default 10 000) and paginate, and note that the interface returns `[]Tenant` with no cursor (§8).
- **`PK=TEMPLATES`.** Every mail template and UI translation set shares one partition, and a template is read once per mail the core sends. Reads are the traffic (3 000 RCU per partition, one strongly-consistent `GetItem` of a few KB per send); writes are admin edits. Nothing to design for.
- **`PK=SETTINGS`.** One item, and adaptive capacity cannot split one item, so this is the only partition in the table whose ceiling is a hard 3 000 RCU with no mitigation. It is nowhere near binding today: the settings are read on `POST /2fa/disable` and once per cold start, not on the login path. Two future readers are the ones to watch — `GET /ui/config`, which every hosted-UI page load hits, and the inbound-webhook sandbox, which reads the allowlist per delivery. Neither is mounted yet; when one is, the answer is a per-execution-environment cache with a short TTL in the composition root and not a change of key, because a settings document that is seconds stale is exactly what the reference serves from its own process memory.
- **`PK=TENANT#<t>` in a single-tenant deployment.** All memberships in one partition. Membership writes happen once per user (at `CreateUser` and `AssociateUserWithTenant`), so the write rate equals the registration rate; 1 000 registrations/s is not a realistic auth workload. Reads are the admin user list, paginated. If a deployment ever approaches it, the fix is sharding `MEMBER#<shard>#<u>` with an 8-way fan-out on read — designed for, not built now.
- **`PK=RL#<scope>#<subject>#<window>` for a per-IP counter.** A single abusive source is a single partition, capped at 1 000 WCU. That is mostly a feature — the attacker throttles themselves — but a large NAT or corporate egress shares one key with all its legitimate users. Per-IP windows must therefore be short and the account-scoped limiter must be the primary control.
- **Everything else** (`USER#`, `SESSION#`, `REFRESH#`, `EMAIL#`, `OAUTH#`) is keyed on random ids or hashes and distributes uniformly.

### 6.3 Item size and write amplification

- The 400 KB item limit binds only on metadata values and on the aggregate returned by `GetMetadata`, which is a `Query` and can therefore return megabytes across many items. Cap total metadata per user (default 64 KB, configurable) and reject oversize writes loudly.
- Template bodies are the other unbounded caller value, and the one already built: capped at 300 KB per item on the merged result (§1.6, `MaxTemplateBytes`), so the 400 KB limit is never the error the caller sees.
- `UpdateItem` is billed on the **whole item's** size, not the delta. The profile item is the most-written item in the table (`UpdateLastLogin`-equivalents, token issue/consume, verification flags), which is another reason it stays small and metadata stays out of it.
- `UpdateLastUsed` on API keys fires on **every** API-key-authenticated request (`api_keys.go:111`). Unthrottled that is one write per request. It is throttled to at most one write per key per 60 s via `attribute_not_exists(lastUsedAt) OR lastUsedAt < :staleBefore`; the resulting timestamp is up to 60 s stale, which no consumer of `LastUsedAt` cares about. Same treatment for any session `lastActiveAt` (gap analysis §1.2 asks for exactly this).
- `TransactWriteItems` costs 2× WCU. It is used on six paths only: create user, apply email change, issue single-use token, create session, rotate session, save API key, save link. All are per-login-or-rarer.

### 6.4 Limits worth writing down

`TransactWriteItems` ≤ 100 items / 4 MB and no two operations on the same item; `BatchGetItem` ≤ 100 items / 16 MB; `BatchWriteItem` ≤ 25 items; `Query` page 1 MB; item 400 KB; 20 GSIs per table. `DeleteRole` (#33), `DeleteTenant` (#42) and `DeleteUser` (#6) are the three fan-out operations that can exceed a batch and must page — and `DeleteRole` on a widely-assigned role is a Lambda-timeout risk behind a synchronous interface (§8).

---

## 7. Schema evolution without a table rebuild

The table is never rebuilt. Five rules make that hold:

1. **Every item carries `_v` (N) and `_t` (S).** Readers accept `_v <= currentVersion` and must tolerate unknown attributes; writers always stamp `currentVersion`. `_t` makes a filtered migration sweep possible without inferring type from key prefixes.
2. **Attributes are additive only.** A new optional attribute needs no migration: absent means default. An attribute is never repurposed, only added and later stopped being written. Removal is a three-step release: stop reading → stop writing → sweep (optional, since unread attributes only cost storage).
3. **A new access pattern is a new GSI or a new item type, never a re-key.** GSIs can be added online; the backfill is asynchronous and the index returns partial results while it runs, so a new index is gated behind a config flag that is flipped only after `IndexStatus == ACTIVE` and `Backfilling == false`. GSI1's attributes are named generically (`GSI1PK`/`GSI1SK`) precisely so their meaning can differ per item type and change without renaming the index.
4. **A key-shape change is a dual-write migration, not a rebuild.** Write both the old and the new key for one release; migrate lazily on read (read old → write new → delete old, each step conditional and idempotent); sweep the remainder with a paged, resumable job driven off `_t`; then stop writing the old key. Correctness during the overlap comes from the new key being written first inside the same transaction as the old one.
5. **Escape hatch, priced.** If a change cannot be made additively — a different partition-key composition for every item, say — the path is S3 export (`ExportTableToPointInTime`, does not consume RCU, billed per GB) → transform → `ImportTable` into a new table → alias cutover. This is the only operation with real downtime and real cost; it is a last resort, and the reason rules 1–4 exist.

Version history lives in this document, one row per `_v`, alongside the code that reads it.

---

## 8. Open questions

Everything below could not be resolved against source and needs a decision before the store is written.

1. **`UserMetadataStore` has no tenant id** (`store.go:85-87`). Metadata items live under `USER#<t>#<u>`; the method cannot name `<t>`. Interim: read the tenant from the request-scoped principal on the context. Proper fix: upstream signature widening to `GetMetadata(ctx, userID, tenantID)`. Until then a multi-tenant deployment with metadata enabled has one unkeyable method.
2. **`SessionStore.UpdateSession` cannot express rotation** (§4.3). Needs the upstream `SessionRotationStore` optional interface, or acceptance of the context-carried interim and its one-request-late replay detection. **Status:** both are built. `RotateSession(ctx, sessionID, oldRefreshHash, next)` exists with the proposed upstream signature, and the interim carrier is `WithRotationScope(ctx)`, which the HTTP layer must install per request (§4.3, resolution 2). Still needs the upstream issue filed; until then the correctness of `/refresh` depends on a call the store cannot make for itself.
3. **`DeleteExpiredSessions` returns a count that TTL cannot produce** (§4.5). `POST /sessions/cleanup` will return `deleted: 0`. Wire-visible; needs sign-off and a `CompatibilityNotes()` entry. **Status:** implemented as a no-op returning `0`; the entry is in `CompatibilityNotes()`. Sign-off outstanding.
4. **Per-session token families exceed reference semantics.** The gap analysis (§1.2, §3) records that the reference stores one refresh token per *user*, has no families, and that adopting them changes multi-device behaviour. This document assumes families are adopted (family = session). If they are not, §4.3 collapses to a single conditional write and replay detection disappears.
5. ~~**No account-link store interface exists in `awesome-go-auth`.**~~ **Answered by v0.2.0, differently than expected.** The account-link token is not a profile-borne token family at all: the core stores it in `PendingLinkStore` under the `link-token:<sha256>` namespace and resolves the whole flow — the in-flight OAuth nonce, the emailed link token and the account-conflict stash — through that one interface (`oauth_wire.go:417-426`). So no `ALINK#` family and no new profile attributes; #56-#58 cover all three, and the single-use half of them consumes on read (§1.5). The reserved shape above is withdrawn.
6. **Unbounded list interfaces.** `GetUsersForTenant` (`[]string`), `GetAllTenants` (`[]Tenant`), `ListSessionsForUser` (`[]Session`), `ListForUser` (`[]OAuthLinkedAccount`) and the two template lists, `ListMailTemplates` (`[]MailTemplate`) and `ListUITranslations` (`[]UITranslation`), have no cursor parameter. The store must fully drain a paginated Query behind each. Proposed: a hard cap plus a typed `ErrResultTooLarge`, and an upstream request for cursor variants.

   **Answered for `ListSessionsForUser` (P1): 1000, configurable, refusing rather than truncating.** A user with four digits of live sessions is an incident to investigate, not a page to render, and a silent truncation would make `GET /sessions` lie about which devices are signed in — the one thing that screen exists to tell the truth about. **Answered for `ListForUser` the same way: 100, configurable, refusing.** A user with three digits of provider bindings is likewise an incident, and truncating would make `GET /linked-accounts` lie about which providers can sign the account in. **Answered for the two template lists the same way: 1 000, refusing** — there the number is an integrity check rather than a page size, because the directory holds the six reference ids, whatever the deployment adds to them and one entry per UI page (§1.6), so four digits of entries means something is writing them that should not be. The remaining two keep the question open until their stores land; `GetAllTenants` in particular reads a single partition (§6.2) and wants a different number.
7. **`offset`-based pagination is not expressible in DynamoDB.** The admin surface takes `limit`/`offset` and returns a `total` that the reference itself computes as a heuristic (`admin.router.ts:782`). Options: map opaque cursors onto the `offset` parameter, or reproduce the heuristic by over-reading. Which?
8. **`DeleteRole` fan-out is synchronous.** Deleting a role assigned to 100 000 users is a paged delete behind a blocking interface call. Accept a Lambda timeout risk, or make it a two-phase operation (mark the definition deleted, sweep asynchronously) and accept that `GetRolesForUser` briefly lists a deleted role?
9. **API-key prefix entropy is 32 bits** (§2.3). `attribute_not_exists` turns a collision into a `Save` error the core does not currently retry (`api_keys.go:85-87`). Confirm the caller-visible behaviour, or file upstream for a wider prefix.
10. **`IDEMPOTENCY#` scope.** Namespace reserved, nothing built. Does at-least-once delivery protection belong to this store, to `lambdahttp`, or to the SQS consumers only?
11. **Telemetry partitioning** (`TEL#<t>#<day>`) is a guess: `TelemetryFilter` (`telemetry.go:29-37`) supports `UserID`, `TenantID`, `EventName`, `Since`, `Until`, `Limit`, and a day-bucketed tenant partition serves the time-range case at the cost of a fan-out per day and a full scan of each day's partition when filtering by `UserID`. If user-scoped telemetry queries are a real access pattern, this needs a second index and its own review.
12. **`stores.multiTenant` does not yet exist** in [config-schema.md](config-schema.md) §1.18. §3 depends on it to decide whether an empty tenant id is legal. Add the knob, or derive it from `stores.tenants` being enabled? **Status:** the store takes it as `Options.MultiTenant`, defaulting off, so the decision can be made in config without touching the store. The narrowed rule in §3 means the default is now safe either way: off accepts everything, on requires a tenant.
13. **`PendingLinkStore` cannot be tenant-keyed, and one of its three namespaces is guessable.** `Save`/`Get`/`Delete` take no tenant id, which is fine for the two high-entropy namespaces — they are capabilities, and the tenant is read back out of the stored entry (§3) — but the conflict stash key is `pending-link:<normalizedEmail>|<provider>`, composed by the core (`oauth_wire.go:424-426`). Two tenants holding one address therefore share one entry, and `LinkRequest` takes the tenant from whichever entry it finds (`:691-693`), so a request in tenant B can drive a link in tenant A. The store cannot correct it: a read has to compute the key a write computed, and no tenant is available at either point. Unreachable in this port today, because nothing here writes that namespace — the reference's OAuth callback does. Needs an upstream signature widening (`Save(ctx, tenantID, state, …)`) or a documented single-tenant-only restriction on the conflict flow.
14. **`OAuthWiring` is not discovered by type assertion, unlike every other optional store.** `LinkedAccountStore` and `PendingLinkStore` both declare `Save` *and* `Delete(ctx, string) error`, so no single type can implement both and the core takes them as explicit struct members instead (`oauth_wire.go:170-179`). The consequence is that the composition root, not the store package, decides whether the account-linking routes work, and a port that forgot to pass them would build and pass every store test. It is covered by driving the routes (`cmd/auth`'s store sweep). Worth an upstream note: had the two interfaces named their methods for what they persist, the pattern the other ten follow would have applied here too.

---

## 9. Implementation status

`internal/store/dynamodb` implements the **P1 subset** — `UserStore`, `UserAccountStore`, `UserPasswordStore`, `SessionStore`, `SessionLookupStore`, `SessionAdminStore` — the four **single-use token stores** (`MagicLinkStore`, `SMSStore`, `EmailVerificationStore`, `EmailChangeStore`), and **`TOTPStore`**, **`UserPhoneStore`**, **`LinkedAccountStore`**, **`PendingLinkStore`**, **`AuthCodeStore`**, — from `template_store.go`, core v0.4.0 — **`TemplateStore`**, and — from `settings_store.go` — **`SettingsStore`**. Compile-time assertions in `interfaces.go` pin them all; the five that are not implemented — `UserMetadataStore`, `RolesPermissionsStore`, `TenantStore`, `APIKeyStore`, `TelemetryStore` — are listed there too, deliberately absent rather than stubbed, because the core discovers them by type assertion and a stub returning "not implemented" would make `Service` advertise a feature that fails on the wire where an absent method makes it return `ErrFeatureNotSupported`.

Item types written so far: user profile, email uniqueness, tenant membership, session, refresh pointer, all four single-use pointers (`RESET#`, `MAGIC#`, `VERIFY#`, `ECHG#`), linked account (`OAUTH#`) with its id pointer (`LINKID#`), the pending-link stash (`PLINK#`), the OIDC authorization code (`OIDC#`, §1.7), the template directory (`TEMPLATES` with `MAIL#<id>` and `UI#<page>`, §1.6) and the runtime settings singleton (`SETTINGS`, §1.8). Not yet written: metadata entries, role assignments and definitions, the tenant directory, API keys and their id pointers, telemetry events, rate-limit counters — each lands with the store that owns it.

**Three of them the core does not discover by type assertion.** `TemplateStore`, `SettingsStore` and `AuthCodeStore` are handed over explicitly — `auth.WithTemplateStore`, `auth.WithSettingsStore`, `IDPConfig.Codes` — so a signature that drifted out of shape would not fail to build and would not fail a store test either: the feature would simply stop being offered. That is why `interfaces.go` pins all three, why each is reached through an accessor the composition root asserts for structurally (`Templates()`, `Settings()`, `AuthCodes()`), and why `cmd/auth` pins the accessors as well as the interfaces.

**Two of the fourteen are not on `*Store`, and cannot be.** `auth.LinkedAccountStore` and `auth.PendingLinkStore` both declare `Save`, with different signatures, and both declare `Delete(ctx context.Context, id string) error` — meaning "drop this link id" in one and "drop this state key" in the other. One Go type physically cannot satisfy both, so each is a view constructed from a `Store`: `Store.LinkedAccounts()` and `Store.PendingLinks()`. They are also the only two the core does not find by type assertion; they are handed to it through `auth.WithOAuth`, which is why `cmd/auth` has to pass them and why the sweep below exists (§8.14).

**Every capability is verified through the routes, not through the assertions.** `cmd/auth`'s store sweep drives all 33 mounted routes through `lambdahttp` — once against the memory driver, and once against the real DynamoDB store on DynamoDB Local — and fails on a 501 `NOT_IMPLEMENTED`, on a body containing "does not implement", or on a 403 that means the request never reached its store at all. That is what found `UserPhoneStore` (§1.1 #9b), which no amount of reading `store.go` would have.

Two mounted routes still cannot complete, and **neither is a store gap**:

- `GET /oauth/{provider}` and `GET /oauth/{provider}/callback` answer the reference's "`<Provider>` OAuth not configured" 404 on the sweep's own configuration, which names no `oauth.providers` entry: `OAuthWiring.Service` is built from that block (`cmd/auth/oauth.go`), so with no provider the registry is empty and the route answers the stub the reference answers with no strategy passed. Configure one and both routes work; `cmd/auth/oauth_test.go` drives the whole flow against an httptest provider. The four account-linking routes need no registry and work either way.
- Everything that mails or texts a secret — `POST /forgot-password`, `/send-verification-email`, `/change-email/request`, `/magic-link/send`, `/sms/send`, `/link-request` — persists the token correctly and answers success without delivering it, because the transport (SES/SNS) is a separate effort. The core's send methods return the secret to their caller and gate only on the store, so none of them reports a missing store; the gap is that nothing sends what they produce.

The five families are five `tokenFamily` values in `keys.go` and one implementation in `tokens.go` — `issueSingleUseToken`, `consumeSingleUseToken`, `clearSingleUseToken` — with the twelve interface methods in `feature_tokens.go` doing nothing but binding a family to a name. That is a deliberate constraint rather than brevity for its own sake: these are the only "issue a secret, spend it once" paths in the port, and a reviewer who has checked one conditional write has checked all five. The two methods that are *not* token-shaped, `MarkEmailVerified` (#8) and `ApplyEmailChange` (#22), are the only ones with bodies of their own. A family differs in exactly four things: key prefix (empty ⇒ no pointer item), the two profile attribute names, the attributes that travel with the token, and the error a lost condition maps to.

**The consume-once shape is one pattern in two places, not two patterns.** `consumeSingleUseToken` and `consumeItemOnce` (both in `tokens.go`, deliberately adjacent) differ in exactly one respect that cannot be parameterised: for a token family the secret is an attribute of a user profile that must survive the consume, so the write is a conditional `UpdateItem` that `REMOVE`s two attributes and returns the profile; for a pending link the secret *is* the partition key, so the write is a conditional `DeleteItem` of the whole item. Everything that makes either one correct is identical and kept identical — the expiry inside the condition rather than trusted to TTL, the lexicographic comparison that only works because `tsLayout` pads, the `ALL_OLD` pre-image, and `ConditionalCheckFailedException` as the *only* error that becomes an authentication outcome.

`consumeItemOnce` now has a second caller, and it landed without a line of new consume logic: `ConsumeCode` (§1.7 #69, `auth_codes.go`) is the same conditional `DeleteItem` against the same expiry clause. It differs from `PendingLinks.Get` in one deliberate way — both failure branches map to one error, because here the distinction is an oracle — and in one that is absent: `Options.NonAtomicSingleUseTokens` does not reach it, since the flag exists to imitate a reference that has no authorization codes at all.

Behaviours worth knowing before reading the code:

- **`UpdateTOTPSecret` and `UpdatePhoneNumber` clear by `REMOVE`, not by writing `""`.** §5's omission rule, and for the TOTP secret it also means disabling 2FA erases the shared secret instead of leaving a zero-length copy of a credential on the item.
- **`LinkedAccounts.Save` reads before it writes, for the same reason `ApplyEmailChange` does.** The incumbent `linkId` is not something the interface carries, and the superseded pointer cannot be deleted without naming it. The read decides nothing: `linkId = :observed` re-asserts it, and a concurrent rebind is retried rather than allowed to delete somebody else's pointer.
- **`UpdateMailTemplate` reads before it writes, for the same reason `LinkedAccounts.Save` does.** The patch names only the fields it changes and the interface carries nothing else, so the rest is read; the `PutItem` re-asserts the `updatedAt` it observed, and a lost condition is retried from the failure's pre-image (§1.6 #64). `TemplateStore` is the third capability the core does not discover by type assertion — it is passed through `auth.WithTemplateStore` — but unlike the two OAuth views its methods are on `*Store` itself, because none of its names collides with anything; `Store.Templates()` exists only so the composition root can find it structurally.
- **`PendingLinks.Get` behaves differently per key namespace, and the table that decides it is unit-tested on its own.** `TestPendingLinkSingleUseTableMatchesTheCoreNamespaces` pins the two consuming namespaces against the literals the core composes and pins the conflict stash as re-readable, because a namespace classified the wrong way round is silent — the entry still reads and writes, it just gets spent when it should not, or survives when it should not.
- **`ApplyEmailChange` reads before it writes, and that is not a violation of §4.1.** The interface gives it only `(userID, tenantID)`, so the two uniqueness keys have to come from somewhere; what makes it safe is that the read decides nothing — the transaction re-asserts both addresses as a condition. See the #22 correction in §1.3.
- **`ErrNoPendingEmailChange` has no counterpart in the reference.** `MemoryUserStore.ApplyEmailChange` with no pending address promotes the empty string and orphans the uniqueness item (`memory_store.go:376`). The port refuses instead. Listed in `CompatibilityNotes()`.

and, carried over from the P1 subset:

- **`DeleteUser`'s session sweep goes through GSI1 and is therefore eventually consistent.** A session created microseconds before the delete can be missed. This is acceptable rather than papered over: the profile is gone by then, so `Service.Refresh`'s `GetUserByID` fails and a surviving session cannot mint a token. Refresh pointers are likewise left to TTL, since a pointer to a deleted session resolves to nothing. The rest of the sweep — the user's whole item collection, the email item, the membership, the single-use pointers named on the profile — is driven off a strongly-consistent Query of the user partition and is idempotent on retry.
- **`ListSessionsForUser` returns results oldest-first**, because `GSI1SK` embeds the creation timestamp and `BatchGetItem` does not preserve request order, so the ordering is restored explicitly. The reference iterates a map and returns them in no order at all. Listed in `CompatibilityNotes()`. `ListForUser` restores its own order the same way, by provider then provider account id.
- **`DeleteUser` now also sweeps the OAuth bindings and their id pointers** (#6, "links"), through the same eventually-consistent GSI1 query and with the same reasoning. It runs whether or not the deployment wired the `LinkedAccountStore`: the items outlive the interface that wrote them, and a binding left behind would keep resolving `FindByProvider` to a user who no longer exists — which `HandleCallback` answers with `ErrInvalidCredentials` rather than by creating a fresh account, so the provider identity would be stranded.

Tests run against DynamoDB Local and skip cleanly when no endpoint is reachable, so a plain checkout still has a green suite. Every race this document claims is impossible is asserted as a race, repeated 30 rounds × 8 goroutines, under `-race`: two registrations of one address, two registrations of one id, two refreshes of one token, two consumptions of one token or SMS code on all five families, a token replaced while it is being consumed, two confirmations of one email change, **two consumptions of one pending link in both single-use namespaces, eight simultaneous rebinds of one provider account, and sixteen simultaneous patches of one mail template** — the last asserting not one winner but that every patch lands and no field is clobbered back to what a slower writer observed. Everything the families share is a table-driven test over all five, so a behaviour that held only for password reset fails for the other four.

The rebind race is the one whose invariant is not "exactly one winner": every racer rebinds the same provider account to a different user, and several legitimately succeed, because a rebind supersedes rather than conflicts. What is asserted is that the outcome is *one consistent binding* — one canonical item, one surviving `LINKID#` pointer and it belongs to that item, no losing owner still listing the account, and the survivor written by one racer rather than assembled from two. A store built the reference's way fails that on the first round. Losing the compare-and-set often enough to exhaust its four attempts is accepted as `ErrLinkedAccountConflict` rather than silently dropping a link.

One test-coverage caveat, logged by the test itself rather than left implicit: in the replacement race the two orders do not come up evenly, because a pointer-backed consume spends a `GetItem` resolving the pointer before it writes, so the reissuer usually gets there first (0-2 of 30 rounds went the other way), while SMS goes straight at the profile and the consumers usually win (24 of 30). Both orders are therefore also pinned deterministically; the race's job is to prove there is no third outcome.

TTL units are asserted by reading the item back raw and comparing `ttl` to `expiry.Unix()`, not by trusting the code that wrote it — a millisecond value is not an error DynamoDB reports, it just means the item never expires. Both TTL-bearing item types this section covers are checked that way: the single-use pointers, and the pending-link stash, whose test also pins the padded `expiresAt` string the consume condition compares and refuses any `ttl` large enough to be milliseconds.
