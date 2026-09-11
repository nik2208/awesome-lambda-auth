# Deviations from the reference

The standing rule is to reproduce `awesome-node-auth` including its quirks, because the family's shipped clients (`ng-awesome-node-auth`, `awesome-node-auth-flutter`, the served `auth.js`) are pinned to it. Every place the rule is set aside is recorded in one of three executable registers, each living where its behaviour lives, and this page indexes all three. `cmd/auth/deviations_test.go` fails when an entry of any register is missing from this page, and every register is written to the cold-start log.

| Register | Where | Scope |
|---|---|---|
| Product | `cmd/auth/deviations.go` `WireDeviations()` | configuration defaults, refusals and policies no store or core route owns |
| Store | `internal/store/dynamodb/store.go` `(*Store).CompatibilityNotes()` | what the DynamoDB single-table design answers differently |
| Core | `awesome-go-auth` `auth.CompatibilityNotes()` | the imported core's own register, mirrored into its README |

## 1. Product register

| ID | Surface | This product | The reference | Why | Argued in |
|---|---|---|---|---|---|
| `csrf-enabled-by-default` | `security.csrf.enabled` | double-submit CSRF enforced unless turned off; off in production is refused (RS-3) | `csrf.enabled` defaults to false (`src/middleware/auth.middleware.ts:35`) | a product must be safe with an empty configuration | `docs/spec/config-schema.md` §1.3, §2 RS-3 |
| `production-by-default` | `deployment.environment` | defaults to production, the strict side of every environment-dependent rule | no environment knob; `NODE_ENV` unset means not production | forgetting to name the environment should tighten, not loosen | `docs/spec/config-schema.md` §1, §2 |
| `refresh-token-families` | `POST <prefix>/refresh` | a replayed refresh token revokes the whole session; later refreshes answer `401 SESSION_REVOKED` | rotation replaces the token; a replay fails alone and the session lives on | a replay is the signature of a stolen token | `docs/spec/data-model.md` §4.3; `docs/spec/decisions.md` D-7 |

## 2. Store register

Quoted verbatim from `CompatibilityNotes()`; the test compares these strings byte for byte.

Unconditional:

- POST /sessions/cleanup always reports deleted:0 — expiry is DynamoDB TTL, which produces no count (data-model.md §4.5).
- GET /sessions returns sessions oldest-first by creation time; the reference returns them in unspecified map order (data-model.md §5).
- Revoking an already-revoked session keeps the first revocation's timestamp and reason instead of overwriting them (data-model.md §4.4).
- POST /change-email/confirm fails rather than applying an empty address when no email change is pending; the reference would overwrite the address (data-model.md §4.1).
- POST /change-email/confirm fails if the pending address changed between reading the token and applying it, instead of applying the address it read (data-model.md §1.3 #22).
- GET /linked-accounts returns bindings ordered by provider then provider account id; the reference returns them in insertion order (data-model.md §1.5 #54).
- Re-linking a provider account that is already linked moves the binding and deletes the previous link id; the reference leaves the old id resolvable and still listed under its old owner (upstream nik2208/awesome-go-auth#37).
- POST /link-verify answers INVALID_LINK_TOKEN for an expired account-link token, where the reference answers LINK_TOKEN_EXPIRED: the store refuses to return an entry past its deadline, so the route's own expiry branch is never reached (data-model.md §4.5).

With single-use consumption on read (the default):

- Single-use tokens and SMS codes are consumed by the lookup itself, so a failure in the step that follows burns them and the user must request a new one (data-model.md §4.1). A code that does not match burns nothing.
- A replayed refresh token revokes the whole session, not just that token (data-model.md §4.3).
- An OAuth state nonce and an account-link token are consumed by PendingLinkStore.Get, so two callers racing on one link produce exactly one winner and the loser sees an invalid token (data-model.md §1.5 #57).

The `deleted:0` entry and the refresh-family design were signed off on 2026-09-11 (`docs/spec/decisions.md` D-7).

## 3. Core register (awesome-go-auth)

The ids below are `auth.CompatibilityNotes().KnownDeviations`; the full text of each entry is generated into the upstream README section "Deliberate deviations from the reference".

- `forgot-password-succeeds-on-delivery-failure` — `POST /forgot-password` answers 200 even when the configured sender fails or none is configured.
- `temp-token-is-typed-not-an-access-token` — the 2FA step-up `tempToken` carries `typ: "temp"` and is refused as a session credential.
- `link-request-exempts-bearer-from-csrf` — `POST /link-request` is CSRF-checked for cookie callers only.
- `password-policy-on-reset-and-change` — reset and change apply the password policy (`400 WEAK_PASSWORD`); the reference applies it on register only.
- `totp-setup-omits-qrcode` — `POST /2fa/setup` returns `secret` and `otpauthUrl` without a `qrCode` data URL. The contract suite fails when this stops being true so the entry can be retired.
- `one-time-tokens-are-base64url` — minted one-time tokens are base64url rather than hex.
- `advertised-2fa-methods-require-store-support` — `available2faMethods` lists only the factors the mounted stores can complete.
- `csrf-cookie-not-reissued-with-tokens` — the CSRF cookie is distributed by the middleware, not re-set by every token-issuing response.
- `cookie-max-age-follows-configured-ttl` — cookie `Max-Age` derives from the configured token TTLs instead of fixed values.

## Recording a new deviation

1. Add it to the register that owns the behaviour, with the reference citation and the reason.
2. Add it here, in the matching section.
3. Run `./scripts/toolchain.sh go test ./cmd/auth/...`; `TestDeviationsIndexIsComplete` is the tripwire.
