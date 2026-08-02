# Recon manifest

Every claim in the Phase 0 spec documents is grounded in the source of the repos below, at the exact commits below. File/line references throughout `docs/spec/` resolve against these SHAs. Where a repo's documentation and its code disagreed, the code was followed and the disagreement recorded in [reference-issues.md](reference-issues.md).

Extraction date: **2026-07-28**. Local checkouts live as siblings of this repo inside the `awesome-${lang}-auth` workspace folder.

| Repo | Branch | Commit | Version marker |
|---|---|---|---|
| nik2208/awesome-node-auth (reference) | main | `cc01e9975fe9e425dc6d938a9c5d0738b59c79d8` | npm 1.9.0 (2026-04-29) |
| nik2208/awesome-go-auth | main | `4b2fc5c11cb43b4cf28f0223832ecff6d3155425` | untagged (no releases) |
| nik2208/awesome-rust-auth | main | `0623d4152d8fe91cedd6c0fee58d22f5597887cb` | untagged |
| nik2208/ng-awesome-node-auth | develop | `acc55166c6f0653aa4adf627676704c30e987bac` | — |
| nik2208/awesome-node-auth-flutter | main | `1cd2f0a4ccedc2fc2610cc1a53223236be19e945` | — |

## Source-of-truth correction (2026-08-02)

The extraction above used the **public** `nik2208/awesome-node-auth`. The reference's actual development repository is **`nik2208/node-auth`** (private; it also carries the documentation wiki and the MCP server source). The public repo is a mirror produced by that repo's `npm run sync:public`, and it lags.

Both report `version: 1.9.0`, but the dev repo carries merged work the mirror does not (PR #56, `copilot/fix-auth-events-publishing`, merged as `04f317e`). Diffed dev `1ad9340` against public `cc01e997`, ignoring line endings — note a naive `diff -rq` reports every file as differing because the public checkout is CRLF on Windows and the dev checkout is LF:

| File | Delta | Substance |
|---|---|---|
| `src/router/auth.router.ts` | +161 −14 | Event publishing from the router (`publishRouterEvent`, request context from `x-correlation-id` / IP / User-Agent). 25 event references vs **0** in the mirror |
| `src/router/admin.router.ts` | +146 −11 | Admin DX surfaces |
| `src/auth-configurator.ts` | +104 −2 | NestJS DX surfaces |
| `src/tools/auth-tools.ts` | +22 −3 | Event context plumbing |
| `src/interfaces/user-store.interface.ts` | +6 | Additional optional methods |
| `src/events/auth-event-names.ts`, `src/index.ts`, `src/router/ui.router.ts` | small | Names and exports |

**The route surface is unchanged**: the set of route registrations in `auth.router.ts` is byte-identical between the two, so [wire-contract.md](wire-contract.md)'s route inventory and shapes stand.

Two consequences worth carrying forward:

1. **`POST /register` is mounted by default in the dev repo** when the user store implements `create`, whereas in the mirror it exists only if the embedder supplies `onRegister` (otherwise 404). Section 1 of the wire contract documents the mirror's behaviour; the dev behaviour is the newer one, and it is what `awesome-go-auth` already does.
2. The event-publishing work is what `nik2208/awesome-go-auth#4` tracks as "v1.10 parity". There is **no v1.10.0**: `package.json` on the dev main is still `1.9.0` and no such tag or release exists. The issue's reference to `node-auth/pull/56` is accurate, but the PR is titled "Wire auth/admin DX surfaces for NestJS integrations" — the events are part of it, not a release of their own.

## Method

1. Three parallel structural recon passes over the GitHub repos (reference, Go port, Rust port + docs site + both clients).
2. Shallow clones pinned to the SHAs above.
3. Multi-agent contract extraction over the local reference source, one agent per HTTP surface, grounded in `src/` and `tests/` — never README prose.
4. Adversarial verification pass: independent agents attempt to refute sampled claims from each extraction report; contradictions re-extracted.
5. Cross-validation of the wire contract against the three independent client implementations (`src/ui/assets/auth.js`, ng-awesome-node-auth, awesome-node-auth-flutter) and the reference's own test assertions (~673 tests, in-process supertest).

The docs site (https://www.awesomenodeauth.com/docs/, 62 pages, sitemap-mapped) was consulted only where source was ambiguous; source beats documentation throughout (rule of engagement §8).
