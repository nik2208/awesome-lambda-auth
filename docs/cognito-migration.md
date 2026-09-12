# Migrating a Cognito user pool

A runbook. It assumes a deployed stack and a user pool you still control, and it
is written to be followed once, under time pressure, by somebody who did not
write the code.

For what you gain and lose by doing this at all, read
[cognito-comparison.md](cognito-comparison.md) first — in particular §4, which
says plainly that this product has no rate limiting yet.

## 1. The shape of it

Two things cross, by two different routes, because one of them cannot be copied.

**The records cross in bulk.** `migrate cognito` pages the pool and writes each
user into your table. It takes minutes for a small pool and is safe to re-run.

**The passwords do not cross at all.** A user pool yields no password hash to
anybody — that is the point of a managed directory — so every imported row lands
with an **empty** password hash and a *migration marker*. The password is
collected later, one person at a time, on their next login: the login route asks
the pool whether the password is right, and if it is, hashes it into your table
and never asks again. That account's migration is then over.

So the migration is finished when the last person has logged in once. You can
watch it happen by counting the rows that still carry a marker (§6).

A person who never comes back is not stranded: their row exists, their address
is verified if it was verified in the pool, and forgot-password works, because
an empty stored hash is exactly what the passwordless initial-password path
keys on.

## 2. Before you start

In the pool being migrated away from:

1. **Create an app client** with no client secret and with
   `ALLOW_ADMIN_USER_PASSWORD_AUTH` among its explicit auth flows. A client
   *with* a secret cannot be used: this product does not compute the
   `SECRET_HASH` the flow would then require, and it reports the failure by name
   in the cold-start-adjacent log rather than as "wrong password" on every
   login.
2. **Note the pool id and its region.** The region is required separately
   everywhere below and is never inherited: a pool addressed in the wrong region
   answers "no such user" for every person, which looks exactly like an empty
   pool.
3. **Decide what to do with `custom:*` attributes** (§3).

In this stack: nothing yet. The migration is off until you set a parameter.

## 3. Map the attributes

Without a map, the import carries:

| Cognito attribute | becomes |
|---|---|
| `email` | `email` (trimmed, lower-cased) |
| `email_verified` | `isEmailVerified`, true only for the exact string `true` |
| `phone_number` | `phoneNumber` |
| `given_name` | `firstName` |
| `family_name` | `lastName` |
| `custom:<name>` | `metadata.imported.<name>` |
| anything else | dropped |

`sub` is deliberately not carried: your rows get identifiers in this product's
own shape, and recording the pool's would invite something downstream to treat
it as a foreign key into a directory you are deleting.

To change any of that, write a flat JSON file and pass `--attribute-map`:

```json
{
  "custom:tier": "role",
  "custom:department": "metadata:dept",
  "locale": "-"
}
```

Targets are `email`, `isEmailVerified`, `phoneNumber`, `firstName`, `lastName`,
`role`, `metadata:<key>`, or `-` to drop. The map is validated before the first
page is read, so a misspelling is a refusal rather than four thousand users
imported without a phone number.

## 4. Choose a mode

| | `import-only` (the default) | `dual-read` |
|---|---|---|
| A user lookup that misses | is a miss | falls through to the pool and creates the local row |
| Cost per miss | nothing | one `AdminGetUser`, on an unauthenticated route |
| Use it | once the bulk import has been verified | while the import is incomplete |

**Dual-read is a safety net with a bill attached.** The lookup it hooks is
reached from `POST /login`, `/register`, `/forgot-password`, `/magic-link/send`
and `/sms-code/send` — all unauthenticated, all taking an address straight from
a request body — so an attacker naming addresses costs you one Cognito call per
name. That is bounded, per execution environment, by a token bucket: a few
attempts per address, a few dozen per second overall, after which a miss is
simply a miss and nothing errors. It is *not* eliminated. Turn dual-read off
once §6 says the import is complete.

The password verifier is bounded the same way and separately, so a flood of
lookups cannot starve it.

Both bounds are per execution environment, and a Lambda under load runs many. A
shared counter would need a store round trip on the very path whose cost this is
containing; the point is to remove the unbounded multiplier between requests an
attacker sends and calls your pool receives, not to enforce a quota to the digit.

## 5. Run it

Bulk import, dry run first — always:

```sh
migrate cognito \
  --user-pool-id <region>_XXXXXXXXX \
  --region <pool region> \
  --table <your table> \
  --profile <your profile> \
  --dry-run
```

The dry run prints one line per user, with the marker and the mapped attributes,
and writes nothing. It is the same code path as the real run: everything above
the write is exercised exactly as it would be.

Then drop `--dry-run`. Useful flags:

- `--table-region` when the table is not in the pool's region (common).
- `--tenant` to write every row under one tenant id.
- `--page-size` (1–60, Cognito's own ceiling).
- `--start-token` to resume — see below.

**What it does on each kind of trouble**, decided once so you do not have to
decide under pressure:

| | what happens |
|---|---|
| the user already exists locally | **skipped, never overwritten**, and not an error |
| the pool stops answering mid-run | the run stops, prints its summary, and prints a `--start-token` for the last page that *completed* |
| a record has no email address | **skipped and listed by its pool username**; the run continues and then exits non-zero |
| anything else fails for one record | listed; the run continues and then exits non-zero |

Re-running the whole command from the beginning is always safe and is the
recommended recovery from anything. The resume token only saves time. The
already-exists rule is what makes that true, and it is also why the import never
overwrites: a row that has already adopted a password would otherwise be
rewritten with an empty hash and a marker, stranding somebody on a directory
they had already left.

The exit status is 0 when every record was written or skipped as already
present, and 1 when any record could not be imported — so a pipeline notices
without parsing the summary.

## 6. Turn the stack on

Deploy with:

```
CognitoUserPoolId=<region>_XXXXXXXXX
CognitoRegion=<pool region>
CognitoAppClientId=<the app client from §2>
CognitoMigrationMode=import-only    # or dual-read
```

The changeset refuses a pool id with no region, and an app client id with no
pool. Cold start refuses the same combinations (rule `RS-13`) plus any store
driver other than `dynamodb`, because the marker is a DynamoDB profile
attribute and there is nowhere else it survives.

An empty `CognitoUserPoolId` — the default — adds **no IAM statement and no
cost**, and the running function is byte-for-byte the one that shipped before
this block existed.

The IAM the stack grants while it is set: `cognito-idp:ListUsers`,
`AdminGetUser` and `AdminInitiateAuth`, on that one pool ARN and nothing else.
No write action anywhere in Cognito, and deliberately no
`AdminRespondToAuthChallenge` — a pool that answers a login with an MFA
challenge is treated as "not the password", and the permission to do otherwise
is not granted.

## 7. Watch it finish

An account is migrated when its row no longer carries a `migration` marker. Two
ways to see it:

- **In aggregate**: scan for profile items with a `migration` attribute. This is
  the one legitimate use of a table scan against this schema; run it from a
  workstation, not from the function.

  ```sh
  aws dynamodb scan --table-name <your table> \
    --filter-expression 'attribute_exists(migration)' \
    --select COUNT
  ```

There is deliberately **no per-account way to see it from the API**. The marker
is not on the user record and not in any response body — it travels from the
store's profile read to the password verifier on the request context and nowhere
else, so that a not-yet-migrated account does not disclose your pool id to
whoever holds a session on it ([cognito-comparison.md](cognito-comparison.md)
§5). The table is where you look.

The cold-start log announces the block on every deployment, with the pool and
the mode, so `user migration is active` in CloudWatch Logs Insights tells you
which stacks are still mid-migration.

## 8. Finish it

In order:

1. Re-run `migrate cognito` once more, to pick up anyone created in the pool
   since the first run. Everyone already imported is skipped.
2. Set `CognitoMigrationMode=import-only` and deploy. Dual-read stops costing.
3. When the marker count is low enough that the stragglers can be asked to use
   forgot-password, **clear `CognitoAppClientId`** and deploy. No login calls
   the pool after that; the remaining marked accounts simply behave as accounts
   that have never had a password, and forgot-password works for them.
4. Clear `CognitoUserPoolId` and deploy. The IAM statement disappears.
5. Delete the app client, then the pool.

Steps 3 and 4 are the ones worth not rushing: between them, an account that
still carries a marker can no longer prove its old password here, so make sure
those people can receive email before you take the pool away.

## 9. If it goes wrong

**Every migrating login answers 500.** The app client almost certainly has a
client secret. The log names it (`the migration app client is configured with a
client secret`). Create one without a secret and redeploy.

**Every migrating login answers 401 with a correct password.** Check the region
first — a pool addressed in the wrong region answers "no such user" for
everyone. Then check that the app client has `ALLOW_ADMIN_USER_PASSWORD_AUTH`
among its explicit auth flows. Then check whether the pool is answering with a
challenge: an account with MFA enabled in the pool, or one Cognito wants to
force a password change on, is deliberately refused here rather than accepted,
because accepting it would silently drop the factor the pool was enforcing.
Those people should use forgot-password.

**Logins are slow.** A marked account whose password does not verify locally
pays a network round trip to the pool. That is the migration working. It stops
per account the moment that account's password is adopted.

**The stack refuses to start after a parameter change.** The message names the
rule (`RS-13`), the knob and what to do. There is no combination of these
parameters that deploys and is silently wrong.
