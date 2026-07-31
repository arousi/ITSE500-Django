# Testing & Contract Guide (prompeteer_server / Django)


*pushing to test deploy bot!*

This repo is the **contract source of truth** for the ITSE500 project. The Flutter
desktop client and the React web client both consume the OpenAPI schema this
repo publishes at `contract/openapi.yaml`. See the sibling repos'
`TESTING.md` for how each client verifies against it.

> **CRITICAL, currently-blocking bug (not fixed here -- see below):** the
> tracked migration history **cannot run against a fresh Postgres database**.
> `user_mang.0002_remove_visitor_groups_and_more` does
> `AlterField(user_id, AutoField -> UUIDField)` with no `USING`-cast data
> migration; Postgres rejects it with
> `django.db.utils.ProgrammingError: cannot cast type integer to uuid`.
> SQLite silently tolerates the cast (it isn't strictly typed), which is why
> this was never caught until this delivery. **CI's `test` job will fail at
> the `migrate` step until this migration is fixed** (a real second migration
> that manually alters the column with `USING gen_random_uuid()` or backfills
> UUIDs first is required) -- this is intentional: it surfaces the bug rather
> than hiding it behind a green build.

## Running tests locally

```bash
pip install -r requirements/dev.txt

# Fast path (SQLite, matches local dev DB):
pytest

# With coverage:
pytest --cov --cov-report=term-missing

# Against Postgres (matches production DATABASES branch + CI):
docker run --rm -d --name pg-test -p 5432:5432 \
  -e POSTGRES_DB=prompeteer_test -e POSTGRES_USER=prompeteer -e POSTGRES_PASSWORD=prompeteer_test_pw \
  postgres:16
export POSTGRES_DB=prompeteer_test POSTGRES_USER=prompeteer POSTGRES_PASSWORD=prompeteer_test_pw \
       POSTGRES_HOST=localhost POSTGRES_PORT=5432 BACKEND_PASSWORD_SALT=local-test-salt
python manage.py migrate --noinput
pytest --cov
docker stop pg-test
```

## Test layout

| Path | Covers |
|---|---|
| `conftest.py` | Shared fixtures: `api_client`, `make_user` (factory), `verified_user`, `auth_client`. |
| `auth_api/tests.py` | register -> verify-email-pin -> set-password -> login -> token/refresh -> logout lifecycle, health checks, otp-login deprecation (410). |
| `auth_api/test_oauth_views.py` | Google/OpenRouter OAuth authorize + callback + `oauth/result/<state>/`, all provider network calls mocked via `unittest.mock.patch`. No real network traffic. |
| `auth_api/test_unit_serializers.py` | Unit tests for `RegisterSerializer`/`LoginSerializer`, `Custom_User.set_password`/`check_password`, and `pyotp` TOTP generate/verify contract. |
| `user_mang/tests.py` | `UnifiedSyncView` ("me/" sync endpoint) GET/POST/PATCH: auth gating, visitor (`temp_id`) flow, and IDOR/ownership guards. |
| `crypto_api/tests.py` | `UserUMKView` (user master key provisioning) state machine: unprovisioned -> provisioned -> conflict-on-reprovision. |

External services (SMTP/email PIN send, OAuth providers, any AI-provider calls)
are **always mocked** — the suite makes no real network calls and is safe to
run offline/in CI.

## Known bugs surfaced by this suite (documented via `xfail(strict=True)`, not silently patched)

Per the "don't change business logic to make tests pass" guardrail, the
following real bugs are captured as `xfail(strict=True)` tests so they fail
loudly if silently fixed elsewhere, and are tracked here for follow-up:

0. **[BLOCKING] Migration history cannot run against Postgres** -- see the
   callout at the top of this document. `user_mang.0002_remove_visitor_groups_and_more`
   does an unsafe `AutoField -> UUIDField` `AlterField` with no data-migration
   `USING` cast. This must be fixed (via a corrective migration) before the
   `test` CI job's Postgres path -- or any real Postgres deployment -- can
   succeed. Reproduced locally against `postgres:16-alpine`:
   `django.db.utils.ProgrammingError: cannot cast type integer to uuid`.

1. **`LoginView`/`LoginSerializer` never checks `user.is_active`.** Inactive/locked
   accounts still authenticate successfully and receive valid JWTs, even though
   `LoginView`'s docstring and its `if "inactive" in error_detail` branch imply a
   403 should be returned. That branch is unreachable because the serializer
   never raises an "inactive" `ValidationError`.
   (`auth_api/tests.py::TestLoginView::test_login_inactive_user_403`)

2. **`UserUMKView.post()` / `UserKeyMaterialSerializer` reference a non-existent
   `user` field.** The model's actual field is `user_id` (a `OneToOneField`).
   `UserKeyMaterialSerializer.Meta.fields = ["user", ...]` raises
   `ImproperlyConfigured` the moment it's instantiated, and the view's
   `UserKeyMaterial.objects.create(user=request.user, ...)` raises `TypeError`.
   **`POST /api/v1/crypto_api/umk/` is completely non-functional today** (always
   500s), and `GET` also 500s for any user who already has key material.
   (`crypto_api/tests.py`, three `xfail` cases)

3. **`ConversationSerializer.conversation_id` is silently read-only on create.**
   The `Conversation.conversation_id` model field is `editable=False`, so DRF's
   `ModelSerializer` auto-derives `read_only=True` for it despite the serializer's
   own comment claiming client-supplied IDs are accepted for upsert. Every
   "upsert" that supplies a `conversation_id` actually creates a new row with a
   fresh random UUID, breaking idempotent/offline-first sync semantics for
   clients.
   (documented via `test_post_creates_conversation_owned_by_caller`)

4. **IDOR: `UnifiedSyncView.post()` conversation upsert has no ownership check.**
   `Conversation.objects.filter(conversation_id=conv_id).first()` looks up by ID
   alone (no `user_id=request.user` filter), then unconditionally reassigns the
   row to the caller via `serializer.save(user_id=user)`. Any authenticated user
   who learns/guesses another user's `conversation_id` can hijack (reassign) it.
   This is the same class of IDOR that commit `b6391e3` fixed for two other
   paths — this one is still open.
   (`user_mang/tests.py::TestUnifiedSyncPost::test_post_cannot_hijack_existing_conversation_owned_by_another_user`)

5. **Dead code referencing a removed field:** `EnableTOTPView`/`VerifyTOTPView`
   in `auth_api/views.py` reference `user.totp_secret`, but that field was
   removed from `Custom_User` in migration `0007_remove_custom_user_device_id_and_more`.
   These views are not wired into any URL (`auth_api/urls.py` has no `totp`
   route), so they are unreachable dead code rather than a live bug, but would
   crash immediately if ever wired up.

None of the above were "fixed" by this test suite — only documented. Do not
remove the `xfail` markers without actually fixing the underlying bug and
confirming with a stakeholder.

## The OpenAPI contract

- Served live at `/api/schema/` (`drf-spectacular`, via `SpectacularAPIView`),
  with human-readable UIs at `/api/docs/` (Swagger) and `/api/redoc/` (ReDoc).
- Checked-in sync artifact: **`contract/openapi.yaml`**. Regenerate with:

  ```bash
  python manage.py spectacular --file contract/openapi.yaml --validate
  ```

- CI's `contract` job regenerates the schema and runs
  `git diff --exit-code contract/openapi.yaml` — any schema drift not
  committed alongside the code change **fails CI**. Always regenerate and
  commit the schema in the same PR as any endpoint/serializer change.
- The schema currently documents all 29 real, wired endpoints across
  `auth_api`, `user_mang`, and `crypto_api` (see the "live API contract" list
  in this repo's delivery notes). `chat_api` is intentionally not wired into
  `urls.py` yet and is excluded.

## CI (GitHub Actions, `.github/workflows/ci.yml`)

Triggers on push to `main` and on every PR; `concurrency` cancels superseded
runs. Jobs:

- **`lint`** — `ruff check .` (narrow F821/E9 ratchet — see `pyproject.toml`)
  + `python manage.py check` + a non-blocking `pip-audit` dependency scan.
- **`test`** — spins up a real **Postgres 16** service container (so CI
  exercises the production `DATABASES` branch that local SQLite dev and the
  container healthcheck don't touch), runs migrations, then `pytest --cov`
  with coverage uploaded as an artifact (`coverage.xml` + `htmlcov/`).
- **`build`** — builds the production Docker image as a smoke test, then runs
  `manage.py check --deploy`.
- **`contract`** — regenerates `contract/openapi.yaml` and fails on drift
  (see above); uploads the schema as an artifact for downstream consumers.

## Coverage

Current baseline (this delivery): **62%** line coverage across
`auth_api` + `user_mang` + `crypto_api` (the three apps in the live contract).
`chat_api` and `core` are not yet covered by dedicated tests in this pass —
follow-up work should add coverage there before raising the CI coverage gate.
