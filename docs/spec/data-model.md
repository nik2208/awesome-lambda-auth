# DynamoDB single-table data model — awesome-lambda-auth

Normative design for the persistence layer under `internal/store/dynamodb`. It is written **before** any store code so that the key schema is derived from the access patterns rather than the other way round.

**What it is derived from, in priority order:**

1. The store interfaces the port must satisfy, read from source in the pinned `awesome-go-auth` checkout beside this repo: `store.go` (`UserStore`, `SessionStore`, `SessionLookupStore`, `UserPasswordStore`, `MagicLinkStore`, `SMSStore`, `TOTPStore`, `EmailVerificationStore`, `EmailChangeStore`, `SessionAdminStore`, `UserAccountStore`, `UserMetadataStore`, `RolesPermissionsStore`, `TenantStore`), `api_keys.go` (`APIKeyStore`), `oauth.go` (`LinkedAccountStore`, `PendingLinkStore`), `telemetry.go` (`TelemetryStore`), plus `memory_store.go` / `feature_stores.go` for the exact semantics each method must preserve.
2. The routes that call them, from [wire-contract.md](wire-contract.md).
3. The out-of-process state inventory in [serverless-gap-analysis.md](serverless-gap-analysis.md).

**Ground rule.** Where a store interface maps awkwardly onto DynamoDB, the awkwardness is named and priced here rather than hidden in the implementation. Everything not verifiable against source is in §8.

---

## 1. Access patterns

61 rows, covering 70 distinct method/code-path combinations (the four single-use token families are one parameterised block, §1.3). "Items" is the expected item count per invocation, not the RCU/WCU cost.

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
| 9 | TOTP secret | `UpdateTOTPSecret` ← `/2fa/verify-setup`, `/2fa/disable` | UpdateItem `SET totpSecret, isTotpEnabled` | main | 1 w |

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

Four families share one shape. Substitute `F` and the profile attributes:

| Family | Pointer PK | Profile attrs | Routes | TTL source |
|---|---|---|---|---|
| password reset | `RESET#<h>` | `resetHash`, `resetExp` | `/forgot-password` → `/reset-password` | `tokens.passwordResetTtlMinutes` (ref. 1 h) |
| magic link | `MAGIC#<h>` | `magicHash`, `magicExp` | `/magic-link/send` → `/magic-link/verify` | `tokens.magicLinkTtlMinutes` (ref. 15 min) |
| email verification | `VERIFY#<h>` | `verifyHash`, `verifyExp` | `/send-verification-email` → `GET /verify-email` | `tokens.emailVerificationTtlMinutes` (ref. 24 h) |
| email change | `ECHG#<h>` | `echgHash`, `echgExp`, `pendingEmail` | `/change-email/request` → `/change-email/confirm` | `tokens.emailChangeTtlMinutes` (ref. 1 h) |

| # | Pattern | Trigger | Key condition | Index | Items |
|---|---|---|---|---|---|
| 19 | Issue token (×4) | `Update{Reset,MagicLink,EmailVerification,EmailChange}Token` | Tx: Update `USER#<t>#<u>`/`PROFILE` `SET <F>Hash, <F>Exp` if `attribute_exists(PK)`; Put `F#<h>` / `TOKEN` with `ttl`, if `attribute_not_exists(PK) OR (userId = :u AND tenantId = :t)` | main | 2 w |
| 20 | Consume token (×4) | `GetUserBy*TokenHash` | GetItem `PK=F#<h>` → UpdateItem `USER#<t>#<u>` `REMOVE <F>Hash, <F>Exp` if `<F>Hash = :h AND <F>Exp > :now`, `ReturnValues=ALL_OLD` (§4.1) | main | 1 r + 1 w |
| 21 | Clear token (×4) | `Clear*Token` | UpdateItem `REMOVE <F>Hash, <F>Exp` if `attribute_exists(PK)` — idempotent no-op after #20 | main | 1 w |
| 22 | Apply email change | `ApplyEmailChange` ← `POST /change-email/confirm` | Tx: Put `EMAIL#<t>#<new>` if `attribute_not_exists(PK)`; Delete `EMAIL#<t>#<old>`; Update `PROFILE` `SET email = :new REMOVE pendingEmail` | main | 3 w |
| 23 | Store SMS code | `UpdateSMSCode` ← `POST /sms/send` | UpdateItem `SET smsHash, smsExp` | main | 1 w |
| 24 | Verify SMS code | `GetUserBySMSCodeHash` ← `POST /sms/verify` | UpdateItem `USER#<t>#<u>` `REMOVE smsHash, smsExp` if `smsHash = :h AND smsExp > :now`, `ALL_OLD` — **no pointer item; the method already carries `userID` and `tenantID`** | main | 1 w |
| 25 | Clear SMS code | `ClearSMSCode` | no-op after #24 | main | 0 |

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
| 52 | Save link | `LinkedAccountStore.Save` ← OAuth callback, `/link-verify` | Tx: Put `OAUTH#<provider>#<providerId>` / `OAUTH` (unconditional — memory impl overwrites); Put `LINKID#<id>` / `LINKID` | main | 2 w |
| 53 | Find link | `FindByProvider` ← OAuth callback | GetItem `PK=OAUTH#<provider>#<providerId>` | main | 1 r |
| 54 | List links | `ListForUser` ← `GET /linked-accounts` | Query GSI1 `GSI1PK=USERID#<u>` AND `begins_with(GSI1SK,'OAUTH#')` | GSI1 | L |
| 55 | Delete link | `Delete(id)` ← `DELETE /linked-accounts/:provider/:providerAccountId` | GetItem `KEYID`-style pointer `LINKID#<id>` → Tx delete both | main | 1r+2w |
| 56 | Stash pending link | `PendingLinkStore.Save(state, meta, ttl)` ← OAuth account conflict | PutItem `PLINK#<state>` / `PLINK` with `ttl` | main | 1 w |
| 57 | Read pending link | `Get(state)` ← `POST /link-request` | GetItem `PK=PLINK#<state>` | main | 1 r |
| 58 | Drop pending link | `Delete(state)` ← `POST /link-verify` | DeleteItem | main | 1 w |
| 59 | Record telemetry | `TelemetryStore.Record` ← `POST /tools/track/:eventName` | PutItem `PK=TEL#<t>#<yyyy-mm-dd>`, `SK=<rfc3339Nano>#<eventId>`, `ttl` | main | 1 w |
| 60 | Query telemetry | `TelemetryStore.Query` ← `GET /tools/telemetry` | Query per day in `[Since,Until]`, `SK BETWEEN`, `Limit` | main | pages |
| 61 | Rate-limit consume | NET-NEW (gap analysis §1.4) — login, forgot-password, magic-link, sms, 2fa | UpdateItem `PK=RL#<scope>#<subject>#<window>` `ADD n :1` if `attribute_not_exists(n) OR n < :max`, `ttl` | main | 1 w |

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
| Linked account | `OAUTH#<provider>#<providerId>` | `OAUTH` | `USERID#<u>` | `OAUTH#<provider>#<providerId>` | no |
| Link id pointer | `LINKID#<linkId>` | `LINKID` | — | — | no |
| API key | `APIKEY#<prefix>` | `APIKEY` | — | — | optional |
| API key id pointer | `KEYID#<keyId>` | `KEYID` | — | — | optional |
| Tenant | `TENANTS` | `TENANT#<t>` | — | — | no |
| Tenant membership | `TENANT#<t>` | `MEMBER#<u>` | `USERID#<u>` | `TENANT#<t>` | no |
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

`ALL_OLD` returns the full pre-image, which is exactly the `auth.User` the method must return. Exactly one concurrent caller succeeds; the losers get `ConditionalCheckFailedException`, mapped to `ErrInvalidToken`. `Clear*Token` becomes an idempotent no-op. The pointer item (`RESET#<h>` etc.) supplies `<t>` and `<u>` and is a **hint only** — a stale pointer whose hash no longer matches the profile fails the condition and is harmless; TTL reaps it.

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

**Linked account** — `_t: "link"`, `linkId` S, `userId` S, `provider` S, `providerId` S, `createdAt` S. **`tenantId` is deliberately absent**: `OAuthLinkedAccount` (`oauth.go:53-59`) has no tenant field and `HandleCallback` resolves the user with a tenant supplied by the caller. Adding one would invent semantics.

**API key** — `_t: "apikey"`, `keyId` S, `prefix` S, `name` S, `serviceId` S, `keyHash` S (bcrypt), `scopes` SS?, `allowedIPs` SS?, `isActive` BOOL, `expiresAt` S?, `lastUsedAt` S?, `createdAt` S.

### GSI1 projection

**`INCLUDE` of exactly `_t`, `linkId`, `createdAt`.** Everything else is fetched by `BatchGetItem` against the main table.

Why not `ALL`: GSI1 indexes sessions, memberships, links and role assignments. `ALL` would duplicate every session item — the highest-churn entity in the table — doubling both storage and the WCU cost of every login and every rotation, to save one round trip on `GET /sessions`, an interactive admin/UI read. Why not `KEYS_ONLY`: `ListForUser` must return `OAuthLinkedAccount.ID` and `.CreatedAt`, and neither is in the key; three small attributes are cheaper than a second fetch on that path.

**Nothing secret is ever projected.** `passwordHash`, `totpSecret`, `refreshHash`, `keyHash` and every `*Hash`/`*Exp` attribute are excluded from GSI1 by construction. A GSI is a second physical copy with its own export, its own PITR restore and its own blast radius; secrets exist in exactly one place.

Everything the four GSI1 patterns need is already in the index keys: `ListSessionsForUser` gets `sid` from `GSI1SK`; `GetTenantsForUser` gets `<t>` from the base `PK` returned with every index item; `DeleteRole` gets the assignment's full key; `ListForUser` gets `provider` and `providerId` from `GSI1SK`.

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
- **`PK=TENANT#<t>` in a single-tenant deployment.** All memberships in one partition. Membership writes happen once per user (at `CreateUser` and `AssociateUserWithTenant`), so the write rate equals the registration rate; 1 000 registrations/s is not a realistic auth workload. Reads are the admin user list, paginated. If a deployment ever approaches it, the fix is sharding `MEMBER#<shard>#<u>` with an 8-way fan-out on read — designed for, not built now.
- **`PK=RL#<scope>#<subject>#<window>` for a per-IP counter.** A single abusive source is a single partition, capped at 1 000 WCU. That is mostly a feature — the attacker throttles themselves — but a large NAT or corporate egress shares one key with all its legitimate users. Per-IP windows must therefore be short and the account-scoped limiter must be the primary control.
- **Everything else** (`USER#`, `SESSION#`, `REFRESH#`, `EMAIL#`, `OAUTH#`) is keyed on random ids or hashes and distributes uniformly.

### 6.3 Item size and write amplification

- The 400 KB item limit binds only on metadata values and on the aggregate returned by `GetMetadata`, which is a `Query` and can therefore return megabytes across many items. Cap total metadata per user (default 64 KB, configurable) and reject oversize writes loudly.
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
5. **No account-link store interface exists in `awesome-go-auth`.** The wire contract's `POST /link-request` / `POST /link-verify` require `updateAccountLinkToken` / `findByAccountLinkToken` on the user store (wire contract §4). There is no Go counterpart. If those routes ship, a fifth single-use token family (`ALINK#<h>` + `alinkHash`/`alinkExp`/`alinkPendingEmail`/`alinkPendingProvider` on the profile) slots into §1.3 unchanged — but the interface must exist first.
6. **Unbounded list interfaces.** `GetUsersForTenant` (`[]string`), `GetAllTenants` (`[]Tenant`), `ListSessionsForUser` (`[]Session`) and `ListForUser` (`[]OAuthLinkedAccount`) have no cursor parameter. The store must fully drain a paginated Query behind each. Proposed: a hard cap plus a typed `ErrResultTooLarge`, and an upstream request for cursor variants.

   **Answered for `ListSessionsForUser` (P1): 1000, configurable, refusing rather than truncating.** A user with four digits of live sessions is an incident to investigate, not a page to render, and a silent truncation would make `GET /sessions` lie about which devices are signed in — the one thing that screen exists to tell the truth about. The remaining three keep the question open until their stores land; `GetAllTenants` in particular reads a single partition (§6.2) and wants a different number.
7. **`offset`-based pagination is not expressible in DynamoDB.** The admin surface takes `limit`/`offset` and returns a `total` that the reference itself computes as a heuristic (`admin.router.ts:782`). Options: map opaque cursors onto the `offset` parameter, or reproduce the heuristic by over-reading. Which?
8. **`DeleteRole` fan-out is synchronous.** Deleting a role assigned to 100 000 users is a paged delete behind a blocking interface call. Accept a Lambda timeout risk, or make it a two-phase operation (mark the definition deleted, sweep asynchronously) and accept that `GetRolesForUser` briefly lists a deleted role?
9. **API-key prefix entropy is 32 bits** (§2.3). `attribute_not_exists` turns a collision into a `Save` error the core does not currently retry (`api_keys.go:85-87`). Confirm the caller-visible behaviour, or file upstream for a wider prefix.
10. **`IDEMPOTENCY#` scope.** Namespace reserved, nothing built. Does at-least-once delivery protection belong to this store, to `lambdahttp`, or to the SQS consumers only?
11. **Telemetry partitioning** (`TEL#<t>#<day>`) is a guess: `TelemetryFilter` (`telemetry.go:29-37`) supports `UserID`, `TenantID`, `EventName`, `Since`, `Until`, `Limit`, and a day-bucketed tenant partition serves the time-range case at the cost of a fan-out per day and a full scan of each day's partition when filtering by `UserID`. If user-scoped telemetry queries are a real access pattern, this needs a second index and its own review.
12. **`stores.multiTenant` does not yet exist** in [config-schema.md](config-schema.md) §1.18. §3 depends on it to decide whether an empty tenant id is legal. Add the knob, or derive it from `stores.tenants` being enabled? **Status:** the store takes it as `Options.MultiTenant`, defaulting off, so the decision can be made in config without touching the store. The narrowed rule in §3 means the default is now safe either way: off accepts everything, on requires a tenant.

---

## 9. Implementation status

`internal/store/dynamodb` currently implements the **P1 subset**: `UserStore`, `UserAccountStore`, `UserPasswordStore`, `SessionStore`, `SessionLookupStore`, `SessionAdminStore`. Compile-time assertions in `interfaces.go` pin those; the optional interfaces that are not implemented are listed there too, deliberately absent rather than stubbed — the core discovers them by type assertion, so a stub returning "not implemented" would make `Service` advertise a feature that fails on the wire where an absent method makes it return `ErrFeatureNotSupported`.

Item types written so far: user profile, email uniqueness, tenant membership, session, refresh pointer, and the `RESET#` single-use pointer. The other three token families are one `tokenFamily` value each and reuse the same three functions.

Two behaviours worth knowing before reading the code:

- **`DeleteUser`'s session sweep goes through GSI1 and is therefore eventually consistent.** A session created microseconds before the delete can be missed. This is acceptable rather than papered over: the profile is gone by then, so `Service.Refresh`'s `GetUserByID` fails and a surviving session cannot mint a token. Refresh pointers are likewise left to TTL, since a pointer to a deleted session resolves to nothing. The rest of the sweep — the user's whole item collection, the email item, the membership, the single-use pointers named on the profile — is driven off a strongly-consistent Query of the user partition and is idempotent on retry.
- **`ListSessionsForUser` returns results oldest-first**, because `GSI1SK` embeds the creation timestamp and `BatchGetItem` does not preserve request order, so the ordering is restored explicitly. The reference iterates a map and returns them in no order at all. Listed in `CompatibilityNotes()`.

Tests run against DynamoDB Local and skip cleanly when no endpoint is reachable, so a plain checkout still has a green suite. The two races this document claims are impossible — two registrations of one address, two refreshes of one token — are asserted as races, repeated, under `-race`.
