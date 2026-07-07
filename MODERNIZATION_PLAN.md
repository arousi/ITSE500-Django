# Prompeteer Server — Modernization & MVP Plan

> Status: **Proposed** · Owner: Sanad / Mohanned · Target: **Real production launch on self-managed VPS** (PostgreSQL + Redis + MinIO)
> Scope decision: **Full MVP** — harden the existing backend *and* build the missing core LLM‑chat feature to a working end‑to‑end product.

---

## 1. Context

"Prompeteer Server" (course project **ITSE500**) is a Django 5.1.7 / Django REST Framework backend for a privacy‑focused, multi‑provider **LLM chat** application. It already ships a genuinely strong **authentication + user‑management** core (multi‑provider OAuth with PKCE, JWT, a custom UUID `Custom_User`, visitor mode, data export/soft‑delete, a polished admin) and rich design documentation under `docs/`.

The problem: the **product's actual reason to exist — the chat/LLM feature — is not built**. `chat_api` is a 36‑line stub with its routes commented out, there is no LLM execution, no attachment upload, and no real‑time layer. On top of that the repo carries **live committed secrets**, a **non‑reproducible migration/deploy pipeline**, **SQLite in the production config**, and **no CI**.

This plan takes it from "solid auth skeleton" to a **secure, reproducible, production‑deployable MVP** that actually does the chat job, deployed to your VPS against **PostgreSQL, Redis, and MinIO**.

### Goals
1. **Secure** — rotate leaked credentials, fix the token model, harden settings/auth for the public internet.
2. **Modernize & stabilize** — reproducible dependencies + migrations, latest LTS, clean deploy pipeline.
3. **Infra** — PostgreSQL (data), Redis (cache / channels / task broker), MinIO (object storage for attachments & exports).
4. **Build the MVP** — working `chat_api` (conversations, messages, attachments) + LLM execution + sync, optionally real‑time.
5. **Performance** — kill N+1s, paginate, cache, move heavy work off the request path.
6. **Confidence** — tests + CI + observability so you can ship and iterate safely.

---

## 2. Current State (verified)

### Strengths — keep and build on
- `auth_api` (~90%): 4 OAuth providers + PKCE, JWT issuance, email‑PIN flow, encrypted provider‑token storage (`ProviderOAuthToken` uses Fernet). ~1,900 LOC, real error handling.
- `user_mang` (~95%): `UnifiedSyncView` (GET/POST/PATCH/DELETE) handles profile + chat upsert transactionally, CSV/PDF export, soft‑delete. Custom UUID `Custom_User`.
- Data model is **fully designed and migrated** for the whole system (Conversation / Message / Attachment / MessageRequest / MessageResponse / MessageOutput), plus a polished Jazzmin admin with health dashboards.
- Extensive design docs (ERD, sequence, use‑case, FR) under `docs/`.

### Gaps / risks — verified this session
| # | Finding | Evidence | Severity |
|---|---------|----------|----------|
| 1 | **Google OAuth client secret committed to git history** (pushed via PR #1) | `client_secret_…googleusercontent.com.json` tracked since `897388d` | 🔴 Critical |
| 2 | **API key hardcoded in source** | `ZERUH_API_KEY = "7f97…"` at `settings.py:33` | 🔴 Critical |
| 3 | **Migrations gitignored + regenerated on the prod server** | `.gitignore:118 **/migrations/`; 0 tracked; `.do/app.yaml:24,90` runs `makemigrations` | 🔴 Critical |
| 4 | **30‑day access tokens, no blacklist/rotation** | `settings.py:137-138` | 🔴 Critical |
| 5 | Insecure secret fallbacks (`fallback_dev_key`, `fallback_dev_salt`) | `settings.py:76,99` | 🟠 High |
| 6 | **SQLite in the DB config** (prod on SQLite) | `settings.py` DATABASES | 🟠 High |
| 7 | Custom password hashing (double SHA‑256 + static salt), bypasses Django auth | `user_mang/models/custom_user.py` | 🟠 High |
| 8 | Email verification effectively disabled (PIN auto‑verified) | `auth_api/views.py` RegisterView | 🟠 High |
| 9 | **Core feature unbuilt**: `chat_api` stub, routes commented out; no LLM exec; no attachment upload | `chat_api/views.py` (36 LOC), `prompeteer_server/urls.py` | 🟠 High (MVP blocker) |
| 10 | No rate limiting on auth endpoints | auth views / settings | 🟠 High |
| 11 | `requirements.txt` is **UTF‑16 encoded**, unpinned transitively, ~177 pkgs incl. unused heavies (Flask, Tornado, SQLAlchemy, Selenium/Playwright, Jupyter) | `requirements.txt` | 🟡 Medium |
| 12 | No CI/CD, no coverage gate; `chat_api` has no real tests | repo | 🟡 Medium |
| 13 | Python mismatch: Docker `3.11` vs local `3.13` | `Dockerfile` | 🟡 Medium |
| 14 | Junk committed (`Untitled-1.sqlite3-query`, screenshot) | git ls-files | 🟢 Low |

### Revisions after architecture review + implementation session 1

**✅ Already fixed (session 1, branch `claude/wizardly-stonebraker-716af6`):** #2 (ZERUH→env), #4 (JWT 15‑min access + rotation + blacklist), #5 (secret fail‑fast), #11 (requirements UTF‑8 + split + pruned), #13 (Docker→3.13), #14 (junk removed), migrations un‑ignored, `.do/app.yaml` secret literals scrubbed, logout blacklists refresh, production security headers + DRF throttling added. #1 client secret **untracked** (`git rm --cached`) but **still needs rotation + git‑history purge**.

**🔴 New blockers found by the architecture review (were NOT in the table above):**

| # | Finding | Evidence | Severity |
|---|---------|----------|----------|
| 15 | **IDOR — unauthenticated cross‑user read**: `allow_public_uuid=true` + any `user_id` returns a stranger's full profile + chat graph | `user_mang/views.py:263` (`resolve_user`, GET) | 🔴 Critical (live) |
| 16 | **IDOR — cross‑user overwrite**: POST upsert loads rows by client‑supplied id with no ownership check; can reparent another user's conversation to the caller | `user_mang/views.py:712-825` | 🔴 Critical (live) |
| 17 | **Model defect**: `MessageResponse.response_id` is a `blank=True` CharField primary key; `MessageOutput.output_id` is a bare non‑unique column — fix BEFORE generating initial migrations | `chat_api/models/message_response.py:5`, `message_output.py` | 🟠 High |
| 18 | Second leaked secret: **`MAILEROO_API_KEY`** was literal in `.do/app.yaml` (now scrubbed) — **rotate it** with the Google + Zeruh keys | `.do/app.yaml` | 🔴 Critical |
| 19 | `throttle_scope='auth'` configured but **not applied** to login/register/OTP views (10‑min follow‑up) | `settings.py` REST_FRAMEWORK | 🟠 High |

**Password‑hashing (refines §7.2 / Phase 3):** the root problem is `Custom_User` setting `password = None` (bypassing `AbstractBaseUser`), not just the SHA‑256 choice. Safe path: write a `CustomDoubleSha256Hasher` wrapping the current verification, list it first in `PASSWORD_HASHERS` with Argon2 second, stop nulling `password`, and let Django's built‑in `check_password(..., setter=user.set_password)` re‑hash to Argon2 on next login. Sequence AFTER the Postgres move.

**Also (review):** add a `Message.status` enum (`pending|streaming|complete|error`) before Phase 4 LLM execution (a total request failure is currently unrepresentable); N+1 in the POST write path (GET path already uses `select_related`/`prefetch`); design pagination into the `chat_api` list endpoints from day one (Phase 4), not Phase 6; confirm attachment upload order (`Attachment` FKs `Message` only).

---

## 3. Target Architecture (VPS)

```
                         ┌──────────── your VPS ────────────┐
  Clients (React /       │                                   │
  Flutter / mobile)      │   nginx / Caddy  (TLS, reverse    │
        │                │        proxy, static)             │
        ▼                │        │            │             │
   HTTPS  ───────────────┼────────┤            │             │
                         │   gunicorn (WSGI)   uvicorn/daphne │
                         │   Django REST       (ASGI/Channels │
                         │       │             WebSockets)    │
                         │       │                  │         │
                         │   Celery worker + beat (async)     │
                         │       │        │         │         │
                         │       ▼        ▼         ▼         │
                         │  PostgreSQL   Redis     MinIO      │  ← existing services
                         │  (data)     (cache/     (S3 object │
                         │             broker/     storage:   │
                         │             channels)   media,     │
                         │                         exports)   │
                         └───────────────────────────────────┘
```

- **PostgreSQL** — primary datastore (replaces SQLite). `psycopg[binary]`, `CONN_MAX_AGE` pooling.
- **Redis** — Django cache backend, Celery broker/result, and Channels layer (`channels-redis`).
- **MinIO** — S3‑compatible object storage via `django-storages[s3]` + `boto3` for attachments, message images/docs, and data exports.
- **Celery** — moves email/PIN sending, CSV/PDF export, and LLM calls off the request path.

---

## 4. Roadmap at a Glance

| Phase | Theme | Priority | Effort | Blocks launch? |
|------|-------|----------|--------|----------------|
| **0** | Secret rotation & leak triage | 🔴 Do first | S | Yes |
| **1** | Repo hygiene: migrations→git, deps, env, settings split | 🔴 High | M | Yes |
| **2** | Infra wiring: PostgreSQL + Redis + MinIO | 🔴 High | M | Yes |
| **3** | Security hardening: tokens, hashing, headers, throttling | 🔴 High | M | Yes |
| **4** | **Build the MVP feature**: chat_api + LLM exec + attachments + sync | 🟠 Core | L | Yes (it's the product) |
| **5** | Real‑time (Channels + Redis) | 🟡 Optional‑MVP | M | No |
| **6** | Performance: N+1, pagination, caching, async offload | 🟠 High | M | Recommended |
| **7** | Testing & CI/CD | 🟠 High | M | Recommended |
| **8** | Observability & VPS deploy | 🔴 High | M | Yes |
| **9** | Docs & handoff | 🟡 Medium | S | No |

Effort key: S ≈ hours, M ≈ 1–3 days, L ≈ 1–2 weeks of focused work.

---

## 5. Phases in Detail

### Phase 0 — Secret rotation & leak triage 🔴 *(do before anything else)*
The point of this phase is that findings #1 and #2 are **already public**. Rotating is non‑negotiable; scrubbing history is secondary.
- [ ] **Rotate the Google OAuth client secret** in Google Cloud Console (new client secret; update the VPS env, not the repo).
- [ ] **Rotate `ZERUH_API_KEY`** and any other provider keys currently in `settings.py` / `.do/app.yaml`.
- [ ] `git rm --cached` the secret file + junk (`client_secret_*.json`, `*.sqlite3-query`, screenshot); confirm `.gitignore` covers them.
- [ ] Move **all** secrets to environment only; delete literals from `settings.py:33` and `.do/app.yaml`.
- [ ] Purge secrets from git history (`git filter-repo`) and force‑push, **or** (pragmatic) accept the rotation and start a clean history — decision needed (see §7).
- [ ] Add a secret‑scanning pre‑commit hook (`gitleaks`/`detect-secrets`).

### Phase 1 — Repo hygiene & reproducibility 🔴
Goal: a checkout that builds identically everywhere.
- [ ] **Commit migrations to git.** Remove `**/migrations/` from `.gitignore:118`, add all existing migration files, verify `makemigrations` produces **no** diff. This is the single most important reliability fix.
- [ ] **Stop generating migrations at deploy.** Remove `makemigrations` from `.do/app.yaml` and `entrypoint.sh`; deploy runs `migrate` only.
- [ ] **Fix `requirements.txt`**: re‑encode UTF‑16 → UTF‑8; adopt **`uv`** (or `pip-tools`) with a `pyproject.toml` + lockfile. Split `requirements/base.txt`, `requirements/prod.txt`, `requirements/dev.txt`.
- [ ] **Prune dependencies**: drop unused heavies — `Flask`, `tornado`, `SQLAlchemy`, and (unless a feature needs them) `Crawl4AI`/`playwright`/`selenium`/`pytube`/`yt-dlp`; move `jupyter*`, `ipython`, `debugpy`, `notebook` to dev‑only. Keep `reportlab` (PDF export), review the other PDF libs against actual use.
- [ ] Align Python: bump `Dockerfile` base to **3.13** to match local + `.python-version`.
- [ ] Delete the redundant `reqs.txt`.

### Phase 2 — Infrastructure: PostgreSQL + Redis + MinIO 🔴
Goal: the app talks to your VPS services; nothing is stored on local disk/SQLite.
- [ ] **PostgreSQL**: add `psycopg[binary]`; switch `DATABASES` to Postgres via env (the commented block in `settings.py` is the starting point); set `CONN_MAX_AGE`. Migrate schema, then port existing SQLite data if any is worth keeping (`dumpdata`/`loaddata` or a one‑off script).
- [ ] **Redis cache**: configure Django's native `django.core.cache.backends.redis.RedisCache`; point sessions at cache or DB.
- [ ] **MinIO**: add `django-storages[s3]` + `boto3`; configure the Django 5 `STORAGES` setting with S3 backend → MinIO endpoint (`AWS_S3_ENDPOINT_URL`, `AWS_S3_ADDRESSING_STYLE="path"`, bucket, creds via env). Migrate `Message.img_Url`/`doc_url`, `Attachment.encrypted_blob`, and `MEDIA_ROOT/exports/` to MinIO.
- [ ] **Celery + Redis broker**: add `celery[redis]`; scaffold `prompeteer_server/celery.py`; convert email/PIN send and CSV/PDF export (currently inline in `UnifiedSyncView.delete`) into tasks.
- [ ] Introduce **`django-environ`** (or `python-decouple`) to replace the hand‑rolled `.env` parser in `settings.py`; add a committed **`.env.example`**.

### Phase 3 — Security hardening 🔴
Goal: safe to expose on the public internet.
- [ ] **JWT**: `ACCESS_TOKEN_LIFETIME` → ~15 min; `REFRESH_TOKEN_LIFETIME` → 7–30 days; enable `ROTATE_REFRESH_TOKENS` + `BLACKLIST_AFTER_ROTATION`; add `rest_framework_simplejwt.token_blacklist` to `INSTALLED_APPS` (+ migration). Make `LogoutView` blacklist the refresh token.
- [ ] **Password hashing**: migrate off custom double‑SHA‑256 to Django's **Argon2** hasher (`argon2-cffi` is already installed) with a transitional re‑hash‑on‑login path; keep client‑side hashing only as a transport measure, wrapped by Argon2 at rest. *(Highest‑risk refactor — see §7.)*
- [ ] **Secrets**: remove `fallback_dev_key`/`fallback_dev_salt`; fail fast if `SECRET_KEY`/salt unset while `DEBUG=False`.
- [ ] **Production headers** (behind nginx): `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SECURE_PROXY_SSL_HEADER`, `SECURE_CONTENT_TYPE_NOSNIFF`, `X_FRAME_OPTIONS`.
- [ ] **Throttling**: DRF throttles on `login`/`register`/`otp`/OAuth callbacks (brute‑force protection).
- [ ] **Re‑enable email verification** for production (PIN flow exists; the auto‑verify shortcut should be config‑gated).
- [ ] **Upload validation** for attachments: max size, MIME allow‑list, extension checks.
- [ ] Ensure `debug_toolbar`/`silk` are strictly `DEBUG`‑only; run `manage.py check --deploy` clean.

### Phase 4 — Build the MVP feature (chat_api + LLM) 🟠 *(the actual product)*
Goal: a user can start a conversation, send a message, get a real model response, attach a file, and sync across devices. Models already exist — this is mostly the view/service/serializer layer.
- [ ] **Enable `chat_api` routing** (uncomment in `prompeteer_server/urls.py`; fill `chat_api/urls.py`).
- [ ] **Conversation endpoints**: list/create/retrieve/update/delete, user‑scoped, paginated.
- [ ] **Message endpoints**: create (accepts prompt + params → persists `MessageRequest`), list/retrieve; wire `Message`↔`MessageRequest/Response/Output` O2O.
- [ ] **LLM execution service**: a provider‑agnostic executor (use the already‑present **`litellm`**/`openai`) that reads a `MessageRequest`, calls the model, and writes `MessageResponse` + `MessageOutput` (incl. token usage). Run via **Celery** (async) with a status the client polls or receives over WebSocket. Keep prompts/keys server‑side.
- [ ] **Attachment upload/download**: multipart endpoint → validate → store in **MinIO** → persist `Attachment` (sha256, size, mime). Support the existing encryption metadata fields.
- [ ] **Serializers/service layer**: factor the giant `UnifiedSyncView` (~1,260 LOC) chat logic into reusable services shared with the new endpoints (avoid divergence). Address the in‑code `#TODO: break into profile sync and chat sync`.
- [ ] Finish `crypto_api` UMK **rotation** (currently returns "not implemented") to complete the client‑side‑encryption story.

### Phase 5 — Real‑time (optional for first MVP) 🟡
- [ ] Configure `CHANNEL_LAYERS` with `channels-redis` (currently commented out); ASGI is already wired (`asgi.py`).
- [ ] Add a conversation consumer to stream LLM output tokens and push new‑message events for multi‑device sync.
- [ ] Authenticate WebSocket connections via JWT.

### Phase 6 — Performance 🟠
- [ ] **N+1 audit** of `UnifiedSyncView` and new chat endpoints — add `select_related`/`prefetch_related` for the Conversation→Message→Attachment/Request/Response/Output graph; verify with `django-silk` / `EXPLAIN`.
- [ ] **Paginate** every list (sync currently returns *everything* for a user — unbounded).
- [ ] **Cache** hot reads in Redis (profile, conversation lists) with explicit invalidation.
- [ ] **Async offload** (Phase 2 Celery): exports, emails, LLM calls never block a request.
- [ ] DB indexes for common filters (user‑scoped queries); tune gunicorn workers + `CONN_MAX_AGE`; use `orjson` renderer (already a dep).

### Phase 7 — Testing & CI/CD 🟠
- [ ] Raise coverage; **add `chat_api` tests** (the MVP feature currently has only a stub) and mocked OAuth integration tests.
- [ ] `pytest-cov` gate; `factory_boy` fixtures.
- [ ] **GitHub Actions**: lint (`ruff`), type/`check --deploy`, test+coverage, `pip-audit`, build Docker image. Block merge on failure.
- [ ] `pre-commit`: ruff + gitleaks.

### Phase 8 — Observability & VPS deploy 🔴
- [ ] **`docker-compose.prod.yml`** for the VPS: `web` (gunicorn WSGI) + `asgi` (uvicorn/daphne, if Phase 5) + `celery` worker + `beat` + `nginx`/`Caddy` (TLS). Connect to the **existing** Postgres/Redis/MinIO via env (or include them if you prefer co‑located).
- [ ] Entry pipeline: `migrate` + `collectstatic` (**no** `makemigrations`).
- [ ] **Sentry** (`sentry-sdk`) for errors; expose `prometheus_client` metrics (already a dep); structured JSON logging; readiness/liveness (health endpoint exists).
- [ ] Backups: automated `pg_dump` + MinIO bucket versioning; documented restore.
- [ ] Decide whether to keep the DigitalOcean `.do/app.yaml` path or retire it in favor of the VPS (see §7).

### Phase 9 — Docs & handoff 🟡
- [ ] Rewrite `README.md` (VPS setup, env, architecture); commit `.env.example`.
- [ ] Publish the drf‑spectacular OpenAPI docs (already configured) and keep the Postman collection in sync.
- [ ] Short ADRs for the load‑bearing decisions (Postgres/Redis/MinIO, Argon2, JWT model, history rewrite). Keep the `docs/` design PDFs as the reference.

---

## 6. Dependency strategy (summary)

**Add:** `psycopg[binary]`, `channels-redis`, `django-storages[s3]`, `boto3`, `celery[redis]`, `django-environ`, `sentry-sdk`, `ruff`, `pytest-cov`, `factory_boy`, `pip-audit`/`gitleaks`, `uv` (tooling).
**Remove / dev‑only:** `Flask`, `tornado`, `SQLAlchemy`; gate `Crawl4AI`/`playwright`/`selenium`/`pytube`/`yt-dlp` behind actual need; move `jupyter*`/`ipython`/`notebook`/`debugpy` to `requirements/dev.txt`.
**Already present, will use:** `argon2-cffi` (hashing), `litellm`/`openai` (LLM exec), `orjson`, `prometheus_client`, `drf-spectacular`, `whitenoise`.

---

## 7. Open decisions (need your call before/at execution)

1. **Git history rewrite** — full `git filter-repo` purge + force‑push (cleanest, disrupts any clones/forks), **or** rotate‑and‑move‑on with a fresh clean commit going forward? Rotation makes the leak harmless either way; the rewrite is about hygiene.
2. **Password‑hashing migration** — the custom `user_password`/SHA‑256 scheme is woven into auth. Migrate to Django‑standard Argon2 now (higher risk, correct long‑term) or keep custom for MVP and revisit? Recommended: migrate, with re‑hash‑on‑login so no user is forced to reset.
3. **Deploy target** — retire DigitalOcean App Platform (`.do/app.yaml`) in favor of the VPS compose, or keep both?
4. **Real‑time (Phase 5)** — in the first MVP, or fast‑follow? LLM streaming is much nicer over WebSocket, but polling works to ship sooner.
5. **Data migration** — is anything in the current `db.sqlite3` worth preserving into Postgres, or start clean?

---

## 8. Verification strategy

Each phase ships with an explicit "how we know it works":
- **Phase 0/1:** fresh clone → `uv sync` → `migrate` (no `makemigrations` diff) → `runserver` boots; `gitleaks` clean.
- **Phase 2:** app reads/writes against VPS Postgres; a test upload lands in the MinIO bucket; `redis-cli MONITOR` shows cache/broker traffic.
- **Phase 3:** `manage.py check --deploy` clean; expired access token is rejected; blacklisted refresh token can't refresh; login throttle triggers; a re‑logged‑in user's hash is upgraded to Argon2.
- **Phase 4 (MVP acceptance):** end‑to‑end via Postman/curl — register → create conversation → send message → **receive a real model completion** → upload an attachment (verify in MinIO) → GET sync returns it. This is the MVP done‑definition.
- **Phase 6:** `django-silk` shows bounded query counts (no N+1) and paginated responses on the sync + chat endpoints.
- **Phase 7:** CI green on a PR; coverage gate holds; `pip-audit` reports no criticals.
- **Phase 8:** deploy to VPS, hit it over HTTPS, trigger an error → appears in Sentry; `pg_dump` restore rehearsed.

---

## 9. Suggested execution order

**Ship‑blocking spine:** Phase 0 → 1 → 2 → 3 → 4 → 8.
**Strongly recommended alongside:** 6 (perf) and 7 (CI) folded into 2–4 as you touch each area.
**Fast‑follow:** 5 (real‑time), 9 (docs polish).

Start point when you approve: **Phase 0** (rotate the exposed Google + Zeruh credentials), because those are the only findings that are actively exploitable right now.

---

### Appendix — verified evidence
- Secret file tracked in git: `client_secret_2_16029884030-…apps.googleusercontent.com.json` (since `897388d`).
- `settings.py:33` `ZERUH_API_KEY` literal · `:76` salt fallback · `:99` SECRET_KEY fallback · `:137-138` 30‑day access / 1‑day refresh · `:378-379` `CORS_ALLOW_ALL_ORIGINS` (DEBUG‑gated, acceptable).
- `.gitignore:118` `**/migrations/`; 0 migration files tracked.
- `.do/app.yaml:24,90` run `makemigrations` at deploy.
- `requirements.txt` UTF‑16 encoded; `argon2-cffi` present.
- Stack: Django 5.1.7, Python 3.13 (Docker 3.11), DRF 3.15.2, Channels 4.2, SimpleJWT 5.5, SQLite datastore.
