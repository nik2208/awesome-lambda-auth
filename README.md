# awesome-lambda-auth

The serverless-native member of the [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) family: an open-source, self-hosted alternative to AWS Cognito, deployed as a stack in your own AWS account. MIT, no per-MAU pricing, no phone-home.

Unlike the other ports in the family, this is **not a language port**: it imports the auth core from [awesome-go-auth](https://github.com/nik2208/awesome-go-auth) unchanged, keeps the wire contract byte-compatible with the reference, and replaces every long-lived-process assumption with a serverless-native primitive. It is a **deployable product** (configured by file and environment, extended through webhooks and OIDC), not a library you compile against.

## Status

The stack deploys and the two official clients, unmodified, register, log in, refresh with CSRF, enrol TOTP, complete a 2FA login and revoke sessions against it. What is wired today, what is still gated, and where the work is going is tracked in [docs/PROGRESS.md](docs/PROGRESS.md).

| Area | State |
|---|---|
| Event normalisation (`internal/lambdahttp`) | API Gateway HTTP v2 and REST v1, Function URL, ALB; multi-cookie round trips tested per shape |
| Declarative configuration (`internal/config`) | JSON document + `AWESOME_AUTH_*` environment, refuse-to-start rules RS-1…RS-12, secrets from Secrets Manager → SSM → env |
| Stores (`internal/store/dynamodb`) | users, sessions with refresh-token families, single-use tokens, TOTP, linked accounts, pending links, on one table with TTL |
| Credential delivery (`internal/integration/aws`) | SES for mail, SNS for SMS, behind the core's sender seams |
| Auth surface | every route `awesome-go-auth` mounts: register, login, refresh, logout, me, sessions, password and email flows, magic link, SMS OTP, TOTP, account linking |
| Infrastructure (`infra/sam`) | HTTP API + Lambda (`provided.al2023`, arm64) + DynamoDB + Secrets Manager, deployed with the plain AWS CLI |
| Contract suite (`test/contract`) | black-box, parametrised on a base URL, runs against this stack or the reference Express app |
| Examples | `examples/angular-client` (ng-awesome-node-auth from npm) and `examples/flutter-client` (awesome_node_auth_flutter from pub.dev), unmodified |

Configuration domains the schema accepts but the binary does not act on yet are **refused at start** (rule `PHASE`), never silently ignored. The list is `unwiredDomains()` in [internal/config/phases.go](internal/config/phases.go); at the time of writing: `email.siteUrls`, `email.templatesDir`, `email.deliveryWebhook`, `twoFactor`, `security.jwt.extraClaims`, `security.jwt.claimsWebhook`, `oauth`, `idProvider`, `resourceServer`, `ui`, `admin`, `docs`, `runtimeSettings`, `tools`, `rateLimit`. Each lands with the phase that wires it.

## Configuration

Two sources, layered:

1. A JSON document, from `AWESOME_AUTH_CONFIG_FILE=<path>` or inline in `AWESOME_AUTH_CONFIG_JSON`. Neither set means defaults.
2. `AWESOME_AUTH_*` environment variables, one per knob, on top of the document. The SAM template sets only these.

Secrets are never values in the document. A secret-tagged knob is a reference (`{"secretsManager": "<arn>#<jsonKey>"}`, `{"ssmParameter": "<name>"}`, or its environment variable), resolved at cold start in that order; the template passes them as `AWESOME_AUTH_JWT_ACCESS_SECRET_SECRETSMANAGER` and friends. A plaintext secret in the document refuses to start.

The schema, every default with its reference citation, and the refuse-to-start rules are in [docs/spec/config-schema.md](docs/spec/config-schema.md).

## Toolchain

Nothing is installed on the host. Every tool runs in a pinned container against the bind-mounted repo:

```bash
./scripts/toolchain.sh go test -race ./...
```

Requires Docker (WSL2 on Windows). Module and build caches live in named volumes, so only source crosses the bind mount.

The DynamoDB store tests run against DynamoDB Local and skip when it is unreachable. To run them, start it on a Docker network and point the container at it by name:

```bash
docker network create awesome-auth-test
docker run -d --name ddblocal --network awesome-auth-test amazon/dynamodb-local -jar DynamoDBLocal.jar -inMemory -sharedDb
DYNAMODB_ENDPOINT=http://ddblocal:8000 TOOLCHAIN_NETWORK=awesome-auth-test ./scripts/toolchain.sh go test -race ./...
```

CI (`.github/workflows/go.yml`) runs the same gate with a DynamoDB Local service container, then builds the Lambda zip and enforces its size budget.

## Deploy

```bash
./scripts/build-lambda.sh                                   # dist/auth-lambda.zip, reproducible
./scripts/deploy.sh --profile <profile> --region <region>   # package + deploy with the AWS CLI, no SAM CLI
```

`--profile` and `--region` are required and have no defaults, on purpose. The template, its parameters, the IAM policy (written from the store's exact call list) and the measured cold-start numbers are documented in [infra/sam/README.md](infra/sam/README.md). `scripts/teardown.sh` removes the stack and names what outlives it.

## Verifying a deployment

```bash
AWESOME_AUTH_CONTRACT_BASE_URL=https://<api-id>.execute-api.<region>.amazonaws.com \
AWESOME_AUTH_CONTRACT_REQUIRE=register,csrf,secure-cookies,sessions,totp \
./scripts/toolchain.sh go test -count=1 -v ./test/contract/...
```

`REQUIRE` turns "capability absent" from a skip into a failure, so a deployment that lost a feature cannot pass by skipping it. See [test/contract/README.md](test/contract/README.md).

## Documents

| Document | Purpose |
|---|---|
| [docs/PROGRESS.md](docs/PROGRESS.md) | task board and per-block ledger of the build-out |
| [docs/deviations.md](docs/deviations.md) | index of the three deviation registers (product, store, core), pinned by a test |
| [docs/spec/decisions.md](docs/spec/decisions.md) | decisions the reference does not settle, with reversal cost |
| [docs/spec/wire-contract.md](docs/spec/wire-contract.md) | the HTTP contract extracted from the reference source, which this port is forbidden to break |
| [docs/spec/config-schema.md](docs/spec/config-schema.md) | declarative configuration schema and refuse-to-start rules |
| [docs/spec/data-model.md](docs/spec/data-model.md) | DynamoDB single-table design, access patterns, conditional writes |
| [docs/spec/serverless-gap-analysis.md](docs/spec/serverless-gap-analysis.md) | per-module: survives, adapt, or re-architect under Lambda |
| [docs/spec/parity-gap-node-vs-go.md](docs/spec/parity-gap-node-vs-go.md) | verified capability diff between the reference and awesome-go-auth |
| [docs/spec/reference-issues.md](docs/spec/reference-issues.md) | doc-vs-code disagreements and defects found in the family |
| [docs/spec/recon-manifest.md](docs/spec/recon-manifest.md) | pinned commits and method; every spec claim is reproducible |
| [docs/spec/_extract/](docs/spec/_extract/) | the raw extraction the specs were built from |

## Family

| Repo | Role |
|---|---|
| [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) | Reference implementation and source of truth |
| [awesome-go-auth](https://github.com/nik2208/awesome-go-auth) | Go port; the core this product imports |
| [awesome-rust-auth](https://github.com/nik2208/awesome-rust-auth) | Rust port |
| [awesome-python-auth](https://github.com/nik2208/awesome-python-auth) / [awesome-dart-auth](https://github.com/nik2208/awesome-dart-auth) | Python / Dart ports |
| [ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth) / [awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter) | Clients that must keep working unmodified |

License: MIT
