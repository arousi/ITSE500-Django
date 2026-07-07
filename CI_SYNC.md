# ITSE500 — Cross‑Repo Tests & CI Sync

> Goal: **one API contract, three repos in lockstep.** The Django backend publishes an OpenAPI schema; the Flutter and React clients are **generated from that schema**; every repo runs consistent CI; and a **contract/codegen‑drift check** fails the build whenever a client and the backend disagree.

## The three repos

| Repo | GitHub | Role | Stack | Tests today | CI today |
|---|---|---|---|---|---|
| **Django** | `arousi/ITSE500-Django` | **Contract producer** (API) | Django 5.1.7 / DRF / drf‑spectacular | stale suites quarantined + new security tests | being added (this effort) |
| **Flutter** | `arousi/ITSE500-Flutter` (`main`) | Consumer (mobile/desktop/web) | Flutter 3.5 / bloc / `http` | **none** | release‑only (`v*` tags) |
| **React** | `arousi/ITSE500-ok-REACT` | Consumer (web) | React 19 / TS / axios / CRA | 1 scaffold test | none | 

> ⚠️ **The real React app lives in the worktree `.claude/worktrees/cranky-gauss-62a788`, not `main`** (React 19 + TypeScript + axios). `main` is still the DigitalOcean CRA template. The codegen/CI work targets the worktree branch; it merges to `main` with the app.

## Why contract‑driven (a real drift already exists)

The Flutter client calls `sync-conversations/`, `associate-device/`, and `sync-or-register/` — endpoints the **current backend does not expose** (`chat_api` is disabled). That is exactly the front/back drift a contract check catches automatically. Backend endpoint coverage will grow when Phase 4 (chat MVP) lands; the contract check makes the gap **visible and enforced** in the meantime.

## Architecture

```
          ┌─────────────────────── arousi/ITSE500-Django ───────────────────────┐
          │  DRF views ──drf-spectacular──▶  api/schema.yaml  (committed, SOURCE) │
          │                                        │  CI: schema-drift check      │
          └────────────────────────────────────────┼─────────────────────────────┘
                                                    │  (schema is vendored into each client repo)
                    ┌───────────────────────────────┴───────────────────────────────┐
                    ▼                                                                 ▼
   ┌──────── arousi/ITSE500-ok-REACT ────────┐                 ┌──────── arousi/ITSE500-Flutter ────────┐
   │ openapi-typescript / orval → src/api/**  │                 │ swagger_dart_code_generator → lib/api/** │
   │ CI: lint · tsc · jest · **codegen-drift**│                 │ CI: analyze · test · **codegen-drift**   │
   └──────────────────────────────────────────┘                 └──────────────────────────────────────────┘
```

**Sync mechanism:** the backend's `api/schema.yaml` is the single source of truth. Each client repo vendors a copy and regenerates its typed client from it in CI; if the checked‑in generated client no longer matches the schema, CI fails. Updating the API = regenerate the schema in Django → bump the vendored copy in each client → regenerate → the drift check keeps everyone honest.

## Tooling decisions (this machine: node 22 ✅, dart 3.12 ✅, **java 1.8** ⚠️)

- **React → `openapi-typescript`** (types) + a thin typed axios wrapper, or **`orval`** for a full react‑query/axios client. Node‑based, no Java. TS 4.9 already in the repo.
- **Flutter → `swagger_dart_code_generator`** (pure Dart via `build_runner`). Chosen over `openapi-generator` because that tool needs **Java 11+** and only Java 8 is installed. No new system deps.
- **Contract check** = regenerate client from `schema.yaml` in CI and `git diff --exit-code` the generated output.

## CI shape (consistent across all three)

Every repo gets one `.github/workflows/ci.yml` on `push` + `pull_request` with the same spine, adapted per stack:

| Stage | Django | React | Flutter |
|---|---|---|---|
| Lint/format | `ruff check` + `ruff format --check` | `eslint` + `tsc --noEmit` | `dart format --set-exit-if-changed` + `flutter analyze` |
| Test (+coverage) | `pytest --cov` | `react-scripts test` (jest) `--coverage` | `flutter test --coverage` |
| Contract/schema | regenerate schema → diff vs `api/schema.yaml` | regenerate TS client → `git diff --exit-code` | regenerate Dart client → `git diff --exit-code` |
| Build | `manage.py check --deploy` | `react-scripts build` | `flutter build web --release` |
| Security | `pip-audit` | `npm audit` / dependabot | `flutter pub outdated` |

## Phased rollout

- **Phase A — Django foundation (in progress):** quarantine stale suites so the suite is green; publish `api/schema.yaml`; add `ci.yml` (lint · test+cov · schema‑drift · pip‑audit); `make schema` target.
- **Phase B — Schema quality:** add `@extend_schema` request/response annotations to the untyped APIViews (Login, Register, `UnifiedSyncView`, UMK, OAuth) and de‑dupe the trailing‑slash routes, so generated clients are strongly typed. *(Required before the generated clients are genuinely useful.)*
- **Phase C — React:** vendor the schema; generate the typed client into `src/api/`; wire `ci.yml` (eslint · tsc · jest+cov · codegen‑drift · build); replace ad‑hoc axios calls with the generated client incrementally.
- **Phase D — Flutter:** add `swagger_dart_code_generator` + `build_runner`; generate the client into `lib/api/`; add `ci.yml` (format · analyze · `flutter test` · codegen‑drift); add a **baseline** test suite (auth cubit, api_service failover, a widget smoke test) and grow it; migrate `api_service.dart`'s hand‑written endpoints onto the generated client over time.
- **Phase E — Keep in sync:** a short release note / script so a backend schema change fans out to both clients; optional `repository_dispatch` so a backend merge nudges the client repos to regenerate.

## Notes / constraints

- Full Flutter client migration is a large refactor of the ~3,000‑line `api_service.dart`; do it incrementally behind the generated client, not big‑bang, to avoid regressing the working app.
- The schema only contains **implemented** endpoints; chat endpoints appear when Phase 4 ships. Until then the Flutter contract check will (correctly) flag its chat calls as drift.
- Each repo is a separate GitHub repo → CI lives per‑repo; "sync" = identical workflow shape + the shared vendored schema, not a monorepo.

## Status (implementation)

- ✅ **Phase A (Django)** — `api/schema.yaml` published; `.github/workflows/ci.yml` (ruff · pytest+cov · schema‑drift · pip‑audit); stale suites quarantined; suite green.
- ✅ **Phase B (schema quality)** — client‑facing endpoints typed via `@extend_schema`; OAuth redirects excluded; **spectacular errors 47 → 0**.
- ✅ **Phase C (React)** — branch `feat/openapi-codegen` off `dev/cranky-gauss-62a788` (commit `9f6f742`, **not pushed**): vendored `openapi/schema.yaml`; `openapi-typescript@6.7.6` → `src/api/schema.d.ts` (1923 LOC) + a thin typed wrapper; `api-drift` CI job. Notes: the app is actually plain JS/JSX (added a `tsconfig.json` scoped to `src/api/**` to typecheck the generated surface); the repo's pre‑existing `npm test` reports "no tests found" on this Windows worktree path (reproduces on the base commit — a glob quirk, green on ubuntu CI).
- ✅ **Phase D (Flutter)** — branch `feat/openapi-codegen` off `feat/ci-and-smoke-test` (commit `6fdb83f`, **not pushed**): vendored schema; `swagger_dart_code_generator` + chopper → `lib/api/generated/` (~13.5k LOC); `api-contract-drift` CI job; `api_service.dart` untouched. Notes: SDK floor bumped `^3.5.3 → ^3.9.0` (codegen deps need Dart 3.9; CI Flutter pin → 3.44.5); the multipart **attachments** endpoint is excluded from codegen (generator couldn't model its `oneOf` body) — keep that one call hand‑written.
- ⏭️ **Phase E (keep in sync)** — adopt the generated clients into the hand‑written clients incrementally (start with read‑only paths: `me/`, `health/`; then `login`/`register`). When the backend contract changes: regenerate `api/schema.yaml` (Django), re‑vendor `openapi/schema.yaml` into each frontend, regenerate — the per‑repo drift jobs fail the build if anyone forgets. **Open PRs** for the two `feat/openapi-codegen` branches when ready.
