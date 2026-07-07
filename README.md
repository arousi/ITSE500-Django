# Prompeteer Server

Django 5.1.7 / DRF backend for a privacy-focused, multi-provider **LLM chat**
application (course project ITSE500). It ships multi-provider OAuth
authentication, user/profile sync, and a chat MVP (conversations, messages,
async LLM execution, attachment upload).

> **Change log**
> | Updated on | Feature / change | Reason |
> |---|---|---|
> | 2026-07-07 | Full rewrite: chat_api MVP, env-gated infra, JWT hardening, CI/contract | Backend modernization + chat MVP branch (`claude/wizardly-stonebraker-716af6`) shipped 25 commits since the last README pass |

---

## Setup

### Requirements
- Python **3.13**
- SQLite is fine for local dev (default); Postgres/Redis/MinIO are optional
  and env-gated (see [Infrastructure](#infrastructure) below).

### Install

```sh
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # Mac/Linux

pip install -r requirements/dev.txt    # local development (includes test/lint tooling)
# pip install -r requirements/prod.txt # production image (no dev/test extras)
```

`requirements/base.txt` holds the shared runtime deps; `dev.txt` and
`prod.txt` each extend it.

### Configure environment

Copy `.env.example` to `.env` and fill in what you need. With **`DEBUG=True`**
(the default when `DJANGO_DEBUG` is unset) the app falls back to safe local
defaults for everything:

- an ephemeral dev-only `SECRET_KEY` / password salt if none is set,
- **SQLite** (no `DB_HOST`),
- **local-memory cache**, **in-memory Channels layer**, **filesystem media
  storage** (no `REDIS_URL` / `AWS_S3_ENDPOINT_URL`),
- Celery tasks run **inline** (no broker configured).

With **`DJANGO_DEBUG=False`**, missing `SECRET_KEY` / `BACKEND_PASSWORD_SALT`
cause the app to **fail fast at startup** rather than silently run insecure —
see [Security](#security--auth).

### Migrate & run

```sh
python manage.py migrate
python manage.py createsuperuser   # optional, for /admin/
python manage.py runserver
```

- App: http://127.0.0.1:8000/
- Admin: http://127.0.0.1:8000/admin/
- OpenAPI docs (when `drf-spectacular` is installed): `/api/docs/` (Swagger),
  `/api/redoc/`, raw schema at `/api/schema/`.

Migrations are **committed to git** — `manage.py migrate` only *applies* them;
nothing runs `makemigrations` at deploy time.

---

## API surface

All endpoints are namespaced under `/api/v1/<app>/`.

| App | Base path | Purpose |
|---|---|---|
| `auth_api` | `/api/v1/auth_api/` | Registration, login, OAuth (Google/GitHub/Microsoft/OpenRouter), visitor login, email-PIN/OTP, health check |
| `user_mang` | `/api/v1/user_mang/` | Profile + chat sync (`UnifiedSyncView`), CSV/PDF export, soft-delete |
| `chat_api` | `/api/v1/chat_api/` | Conversations, messages, LLM execution, attachments (new MVP) |
| `crypto_api` | `/api/v1/crypto_api/` | Client-side-encryption key material (UMK) |

### `chat_api` (new)

| Method | Path | Behavior |
|---|---|---|
| `GET/POST` | `/api/v1/chat_api/conversations/` | List (paginated) / create the caller's conversations |
| `GET/PATCH/DELETE` | `/api/v1/chat_api/conversations/{id}/` | Retrieve/update/delete a conversation (user-scoped — 404s on another user's resource) |
| `GET/POST` | `/api/v1/chat_api/conversations/{id}/messages/` | List (paginated) / create messages in a conversation |
| `GET/POST` | `/api/v1/chat_api/conversations/{id}/messages/{mid}/attachments/` | List / upload attachments on a message (MinIO or local filesystem, ownership-gated, 25 MB cap, MIME allow-list, server-computed size + sha256) |

Posting a message with a `request` payload (prompt + params) triggers
**asynchronous LLM inference**: the `Message` is created with
`status=pending`, execution runs via Celery (or inline if no broker is
configured) against the configured LLM provider (`litellm`/`openai`), and the
message transitions to `complete` (with a persisted `MessageResponse` +
`MessageOutput`) or `error` — a single sole-authority state-machine guard
enforces that transition idempotently.

See [`api/schema.yaml`](api/schema.yaml) for the full, generated OpenAPI
contract — it is the source of truth consumed by the Flutter and React
clients (see [`CI_SYNC.md`](CI_SYNC.md)).

---

## Infrastructure

Postgres, Redis, MinIO, and Celery are **env-gated**: each activates only
when its environment variable is set, with a safe local fallback otherwise.

| Service | Activates on | Local fallback |
|---|---|---|
| PostgreSQL | `DB_HOST` set | SQLite |
| Redis (cache/channels/broker) | `REDIS_URL` set | LocMemCache / in-memory channel layer |
| MinIO (S3-compatible media) | `AWS_S3_ENDPOINT_URL` set | Filesystem `MEDIA_ROOT` |
| Celery | broker configured | Tasks run inline (synchronously) |

For a real production deploy against your own VPS's Postgres/Redis/MinIO,
see **[`DEPLOY.md`](DEPLOY.md)** (runbook, `docker-compose.prod.yml`,
Caddy reverse-proxy example, backups/rollback).

For the overall modernization scope, phased status, and open decisions, see
**[`MODERNIZATION_PLAN.md`](MODERNIZATION_PLAN.md)**.

For how this backend's OpenAPI contract stays in sync with the Flutter and
React client repos (codegen + drift-checked CI), see **[`CI_SYNC.md`](CI_SYNC.md)**.

---

## Security / auth

- **Secrets are environment-only.** `SECRET_KEY` and `BACKEND_PASSWORD_SALT`
  fail fast at startup when `DJANGO_DEBUG=False` and unset (in `DEBUG=True`
  an ephemeral dev-only default is used, with a warning). No secrets are
  committed to the repo.
- **JWT**: 15-minute access tokens (`JWT_ACCESS_MINUTES`, default 15), 7-day
  refresh tokens (`JWT_REFRESH_DAYS`), refresh-token **rotation** and
  **blacklisting after rotation** enabled.
- **Throttling**: DRF request throttling is configured, with a dedicated
  `auth` scope (10/min) applied to login/register/OTP endpoints to slow
  brute-force attempts.
- **Ownership enforcement**: `chat_api` endpoints and `user_mang`'s
  `UnifiedSyncView` are user-scoped (two IDOR holes in the sync view were
  closed and covered by regression tests).

---

## Testing

```sh
pytest
```

The active suite is green; three pre-refactor suites that no longer match
the current models/views are quarantined under `legacy_tests/` (excluded
from collection — see [`legacy_tests/README.md`](legacy_tests/README.md)).

CI (`.github/workflows/ci.yml`) runs `ruff`, `pytest --cov`, an OpenAPI
schema-drift check against `api/schema.yaml`, and `pip-audit`.

---

## Project layout

```
auth_api/       # Authentication, registration, OAuth
user_mang/      # User profile + chat sync
chat_api/       # Conversations, messages, LLM execution, attachments
crypto_api/     # Client-side-encryption key material (UMK)
core/           # Landing page / shared views
prompeteer_server/  # Django project settings, URLs, ASGI/WSGI, Celery app
api/            # Published OpenAPI contract (api/schema.yaml)
deploy/         # Reverse-proxy examples (Caddyfile, etc.)
legacy_tests/   # Quarantined pre-refactor test suites (reference only)
requirements/   # base.txt / dev.txt / prod.txt
```
