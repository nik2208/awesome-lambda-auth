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

## Method

1. Three parallel structural recon passes over the GitHub repos (reference, Go port, Rust port + docs site + both clients).
2. Shallow clones pinned to the SHAs above.
3. Multi-agent contract extraction over the local reference source, one agent per HTTP surface, grounded in `src/` and `tests/` — never README prose.
4. Adversarial verification pass: independent agents attempt to refute sampled claims from each extraction report; contradictions re-extracted.
5. Cross-validation of the wire contract against the three independent client implementations (`src/ui/assets/auth.js`, ng-awesome-node-auth, awesome-node-auth-flutter) and the reference's own test assertions (~673 tests, in-process supertest).

The docs site (https://www.awesomenodeauth.com/docs/, 62 pages, sitemap-mapped) was consulted only where source was ambiguous; source beats documentation throughout (rule of engagement §8).
