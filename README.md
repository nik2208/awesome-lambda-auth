# awesome-lambda-auth

The serverless-native member of the [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) family: an open-source, self-hosted alternative to AWS Cognito, deployed as a stack in your own AWS account. MIT, no per-MAU pricing, no phone-home.

Unlike the other ports in the family, this is **not a language port**: it keeps the wire contract byte-compatible while replacing every stateful long-lived-process assumption with a serverless-native primitive — and it is a **deployable product** (configured by file/env, extended via webhooks and OIDC), not a library you compile against.

## Status: Phase 0 — recon and specification

No implementation code yet, by design. Current deliverables live in [docs/spec/](docs/spec/):

| Document | Purpose |
|---|---|
| `wire-contract.md` | The exhaustive HTTP contract extracted from the reference source — the contract this port is forbidden to break |
| `parity-gap-node-vs-go.md` | Verified capability diff between the reference and awesome-go-auth |
| `serverless-gap-analysis.md` | Per-module: survives / adapt / re-architect under the Lambda runtime model |
| `config-schema.md` | Declarative config schema replacing in-code configuration |
| `recon-manifest.md` | Pinned commits and method — every spec claim is reproducible |
| `reference-issues.md` | Doc-vs-code disagreements and bugs found in the family during recon |

## Family

| Repo | Role |
|---|---|
| [awesome-node-auth](https://github.com/nik2208/awesome-node-auth) | Reference implementation and source of truth |
| [awesome-go-auth](https://github.com/nik2208/awesome-go-auth) | Go port |
| [awesome-rust-auth](https://github.com/nik2208/awesome-rust-auth) | Rust port |
| [awesome-python-auth](https://github.com/nik2208/awesome-python-auth) / [awesome-dart-auth](https://github.com/nik2208/awesome-dart-auth) | Python / Dart ports |
| [ng-awesome-node-auth](https://github.com/nik2208/ng-awesome-node-auth) / [awesome-node-auth-flutter](https://github.com/nik2208/awesome-node-auth-flutter) | Clients that must keep working unmodified |

License: MIT
