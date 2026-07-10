# Handoff: Django 6 + django-bolt port

> **STATUS 2026-07-10: PORT COMPLETE.** All of auth_api (14 endpoints incl. 4-provider
> OAuth on async httpx), user_mang `/me` (GET/POST/PATCH/DELETE + exports), and
> crypto_api run on django-bolt; DRF/simplejwt/spectacular/oauth-toolkit/channels are
> removed; the container serves via `manage.py runbolt`. Validated by
> `scripts/bolt_poc_test.sh` — 26/26 checks green in the built image.
>
> **Corrections to this doc discovered during the port:**
> - §2's "runbolt ASGI-mounts the entire Django app" is WRONG — runbolt only
>   auto-mounts Django *admin*. The rest of the URLconf (React `/`, Flutter `/app/`,
>   `/healthz`, `/team/`) needed an explicit `api.mount_django("/", clear_root_path=True)`
>   in `prompeteer_server/api.py`.
> - §3's "mint via `create_jwt_for_user`" is WRONG for this project — it hardcodes
>   `sub=str(user.id)` and `Custom_User.id` is None (UUID pk is `user_id`). Minting
>   lives in `auth_api/tokens.py` (`sub=str(user.pk)`, access 30d / refresh 1d).
> - Bolt's default `trailing_slash="strip"` 308-redirects the DRF-canonical slashed
>   paths; the APIs use `trailing_slash="keep"` + both slash variants registered.
> - DRF's ScopedRateThrottle on the 4 auth endpoints did NOT survive the port —
>   reintroduce rate limiting at nginx or via `django_bolt.middleware.rate_limit`.
> - Old simplejwt tokens (no `sub`) are invalid after cutover: existing sessions
>   must re-login once.

**Branch:** `feat/django6-bolt` (off `Django-Starter` @ `f3ac601`).

---

## 0. Environment & access (read first)

- **VPS:** `ssh -o BatchMode=yes -p 6934 deploy@102.203.201.196` — user `deploy` has **passwordless sudo**. Shared platform: `platform-postgres`, `platform-minio`, Traefik, Prometheus/Grafana, a `health-reactor` daemon that restarts/quarantines any container labelled `swe.autoheal=true` (itse500-app has it).
- **App repo:** `github.com/arousi/ITSE500-Django`. **Push as the `arousi` gh account** — `swe-sanad` has NO write access. The gh active account *drifts back* to swe-sanad, so **before every push**:
  ```bash
  gh auth switch --hostname github.com --user arousi
  git -c credential.helper= -c credential.helper='!gh auth git-credential' push origin HEAD
  ```
- **File transfer to the box is FLAKY for anything >~5 MB** (scp times out; even 5 MB chunks hung). **Do NOT scp tarballs.** The box→GitHub link is fast — deploy/test by having the box **`git clone`/`git pull`** the branch. `/opt/apps/itse500/app` on the box is already a shallow git checkout of `Django-Starter`.
- **Line endings:** this is a Windows checkout (autocrlf). Files created here are CRLF. `git archive`/`git clone` on the box give LF (good). If you ever scp a shell script, `sed -i 's/\r$//'` it on the box first (a CRLF `entrypoint.sh` breaks `sh`).

---

## 1. Current state

### Done & shipped (not your concern, context only)
- Full production deploy of the app to the VPS (nginx→gunicorn, shared Postgres/MinIO, `/app` Flutter, `/` React, `/api`, admin). Live + healthy on `Django-Starter`.
- Secure redeploy: live app runs current code + patched deps (cryptography 46.0.7, Django 5.1.15, gunicorn 22.0, pillow 12.2). Migrations applied.
- VPS platform work (health-reactor, monitoring, uptime-kuma) — separate repo `SWE-Pioneers/vps-infra`, PR #3.

### This branch (`feat/django6-bolt`)
| Commit | What |
|---|---|
| `b749ce4` | **Phase 1 — Django 6.0.7 / Python 3.12.** Dockerfile.vps `FROM python:3.12-slim`; requirements bumped to the Django-6 set (DRF 3.17.1, channels 4.3.2, jazzmin 3.0.5, oauth-toolkit 3.3.0, storages 1.14.6, cors-headers 4.9.0, spectacular 0.30.0, whitenoise 6.12.0, psycopg 3.3.4, pillow 12.3.0, asgiref 3.11.1). **Validated:** image builds, `manage.py check` = 0 errors. |
| `8274453` | **Phase 2 start.** `django-bolt==0.9.0` added to requirements + `INSTALLED_APPS`; `crypto_api/api.py` written. |
| `f28d3fb` | **crypto_api PoC VALIDATED end-to-end** under runbolt (GET→200, POST→201, GET→200). |

---

## 2. django-bolt: the validated pattern (COPY THIS FOR EVERY ENDPOINT)

See `crypto_api/api.py` for a complete working example. Key facts, all runtime-verified:

- **Install:** `django-bolt==0.9.0` ships a **prebuilt cp312 manylinux wheel** — no Rust toolchain needed. Requires **Python 3.12+**.
- **Registration:** `django_bolt` in `INSTALLED_APPS`. Put a `BoltAPI(prefix="/api/v1/<app>")` in each app's `api.py`; `runbolt` auto-discovers every app-level `api.py` and merges them.
- **Handler:**
  ```python
  from django_bolt import BoltAPI
  from django_bolt.auth import JWTAuthentication, IsAuthenticated
  from django_bolt.params import Query, Header, Cookie, Path, Depends
  from django_bolt.responses import Response, JSON, HTML, Redirect, PlainText, FileResponse, StreamingResponse
  import msgspec

  api = BoltAPI(prefix="/api/v1/crypto_api")

  class Out(msgspec.Struct): ...           # response schema (return it, or annotate -> Out)
  class In(msgspec.Struct): ...            # request body: `body: In` param

  @api.get("/umk", auth=[JWTAuthentication()], guards=[IsAuthenticated()])
  async def handler(request, body: In, rotate: Annotated[str|None, Query()] = None):
      uid = request.context.get("user_id")          # <-- authenticated user id (see §3)
      obj = await Model.objects.filter(...).afirst() # async ORM: afirst/aexists/acreate/aget
      return Response({"...": ...}, status_code=201) # custom status/headers; or return the Struct for 200
  ```
- **Serving (BIG finding):** `runbolt` **ASGI-mounts the entire Django app** (admin, static, media, and all non-Bolt URLs: React `/`, Flutter `/app`, `/team`) *alongside* the Bolt API. Startup prints `Framework +9 (admin, docs)` and `Admin http://.../admin/`. **So Phase 3 is just `gunicorn → runbolt` — NO hybrid, no nginx split.**
- **Responses available:** `JSON, PlainText, HTML, Redirect, File, FileResponse, StreamingResponse` (from `django_bolt.responses`) — enough for OAuth's SSR-HTML/redirect/deep-link and the user_mang export streaming.
- Bolt also has `django_bolt.views.APIView/ViewSet/ModelViewSet`, `django_bolt.serializers.Serializer`, and `django_bolt.pagination` if you want DRF-shaped classes instead of function handlers.

## 3. 🔴 The JWT `sub` requirement (the one gotcha that bit the PoC)

Bolt's Rust verifier reads the **`sub`** claim (= user pk) and exposes it as `request.context["user_id"]`. The app's **simplejwt** tokens use a `user_id` claim and **no `sub`** (`SIMPLE_JWT` in settings: `USER_ID_CLAIM='user_id'`, `USER_ID_FIELD='user_id'`). Result before the fix: **401 "Authentication required"** on every request.

**Fix (do this as part of the auth_api port):** mint tokens with Bolt's `from django_bolt.auth import create_jwt_for_user` (it sets `sub = str(user.id)`). Once login/register/OAuth mint via that, every token is Bolt-native. `Custom_User.user_id` **is a UUID PK**, so `sub` = the UUID string; never `int()` it.
> Interim (if you port crypto_api-like endpoints before auth_api): add `access["sub"] = str(user.pk)` wherever the code does `RefreshToken.for_user(user).access_token`.

## 4. Other gotchas discovered

- **DEBUG=True logging crash:** `settings.LOGGING` configures a dev-only file handler `auth_api_file → /app/auth_api.log` that the unprivileged container user can't write. So `manage.py <cmd>` under `DJANGO_DEBUG=True` as `appuser` → `PermissionError`. **Test with `DJANGO_DEBUG=False -e SECRET_KEY=dummy` (prod path, console logging) OR `docker run --user root`.**
- **Docker build must use BuildKit** (compose does) so `Dockerfile.vps.dockerignore` (which *keeps* `flutter_build/`+`frontend_build/`) is honored. A plain `docker build` uses the default `.dockerignore` (which *excludes* them) → the SPA/Flutter dirs go missing (harmless `staticfiles.W004` warnings during API-only tests, but broken `/app` if deployed that way). For real deploys, always `docker compose ... up -d --build`.
- **OAuth is hand-rolled, NOT django-oauth-toolkit** — that package is in requirements but unused (`oauth2_provider` not in INSTALLED_APPS). **Drop `django-oauth-toolkit`** when you clean up.
- **No pagination anywhere** today; the sync endpoints return whole payloads.

---

## 5. Remaining plan

### API inventory (what to port) — under `/api/v1/`
All current views are **DRF `APIView` subclasses**. Global config: JWT-only auth, `IsAuthenticated` default (public views set `AllowAny`), `ScopedRateThrottle` on 4 auth endpoints, no pagination.

**`crypto_api`** — ✅ DONE (`crypto_api/api.py`): `GET/POST /api/v1/crypto_api/umk`.

**`auth_api`** (`auth_api/{urls,views,serializers,authentication}.py`, ~1850 lines) — ~14 endpoints:
- Simple: `POST login/`, `POST register/`, `POST verify-email-pin/`, `POST set-password-after-email-verify/`, `POST logout/`, `GET health/`, `POST token/refresh/`. Password = `sha256(frontend_hash + settings.BACKEND_PASSWORD_SALT)` (NOT Django hashers). Email PIN = 5-digit, 600s TTL. **Mint via `create_jwt_for_user` (fixes §3).** login/register also assemble a first-sync payload (conversations+attachments — see user_mang serializers).
- OAuth (hardest): `google|openrouter|github|microsoft` × `authorize/` + `callback/` (+ `/ssr/` + no-slash aliases) + `GET oauth/result/<state>/`. **Rewrite blocking `requests` → async `httpx`.** Google/OpenRouter use PKCE (S256), GitHub/Microsoft don't. State/PKCE persisted in `OAuthState` (one-time `mark_used()`, 600s TTL). **Three response shapes per callback:** JSON, SSR-HTML (`postMessage`/`window.close`), and a mobile deep-link bridge (`prompeteer://…` HTML+JS page) — use `HTML`/`Redirect`/`Response` accordingly. Provider tokens are Fernet-encrypted at rest (`auth_api/models/provider_oauth_token.py`). OTP endpoints all return 410 (leave them 410).

**`user_mang`** (`user_mang/{urls,views,serializers}.py`, ~1311 lines) — ONE god-endpoint `/me` with 4 verbs:
- `authentication=[JWT]`, `permission=AllowAny` (supports unauthenticated **visitor** flows via `temp_id` + short-lived visitor JWTs).
- `GET`: nested profile+chat (conversations→messages→request/response/output + attachments). `POST`: **`transaction.atomic` 6-model upsert with IDOR ownership guards** — hardest item; `transaction.atomic` in an async handler needs `asgiref.sync.sync_to_async` wrapping (async-transactions are a Bolt doc gap). `PATCH`: whitelisted profile update. `DELETE`: soft-delete + CSV(`csv`)+PDF(`reportlab`)+zip(`zipfile`) export, Zeruh-verified email, `FileResponse`/`StreamingResponse` streaming.
- 9 serializers over `chat_api` models (Conversation/Message/MessageRequest/Response/Output/Attachment). Media (`img_Url`, `doc_url`, `encrypted_blob`) → `STORAGES` default = S3Boto3Storage/MinIO in prod.

**`chat_api`** — models-only, 0 endpoints (its API lives in user_mang). Leave it.

### Phase 3 — serving & cleanup
1. `entrypoint.sh` + `Dockerfile.vps` CMD: replace `gunicorn prompeteer_server.wsgi:application …` with **`python manage.py runbolt --host 0.0.0.0 --port 8000 --processes 2`** (confirm flag names with `runbolt --help` in the image). Keep the migrate/collectstatic/superuser steps.
2. Remove DRF ecosystem from `requirements/base.txt` + `requirements.prod.txt`: `djangorestframework`, `djangorestframework_simplejwt`, `drf-spectacular`, `drf-spectacular-sidecar`, **and `django-oauth-toolkit`** (unused). Remove `'rest_framework'` from `INSTALLED_APPS` and the `REST_FRAMEWORK`/`SIMPLE_JWT`/`SPECTACULAR_SETTINGS` blocks in settings.py once nothing imports them. Delete each app's `urls.py`/`views.py`/`serializers.py` after its `api.py` replaces them (and drop the `path('api/v1/…', include(...))` lines in `prompeteer_server/urls.py`). Keep `channels` only if you wire websockets; otherwise it can go too.
3. nginx.conf is unchanged (still nginx → app:8000; runbolt listens on 8000).

---

## 6. Test recipe (validated — use for every endpoint)

`scripts/bolt_poc_test.sh` (committed with this handoff) is the template. On the box:
```bash
# get the branch (fast; do NOT scp)
cd /tmp && rm -rf itse500-d6 && git clone --depth 1 -b feat/django6-bolt https://github.com/arousi/ITSE500-Django.git itse500-d6 && cd itse500-d6
# build (API-only test tolerates legacy builder; for a real deploy use compose/BuildKit)
docker build -f Dockerfile.vps -t itse500-d6-bolt .
# run the harness: migrate(SQLite) -> mint token(+sub) -> runbolt:8001 -> curl the endpoints (python urllib; slim has no curl)
docker run --rm --user root -e DJANGO_DEBUG=True -v /tmp/itse500-d6/scripts/bolt_poc_test.sh:/t.sh:ro --entrypoint sh itse500-d6-bolt /t.sh
```
Expected: runbolt prints `API N routes from M apps`, `Admin …/admin/`; the round-trip returns 200/201. If 401 → the `sub` claim is missing (§3).

## 7. Cutover (only after full green)
The live `/opt/apps/itse500/app` is a git checkout. To deploy: merge `feat/django6-bolt` → `Django-Starter` (or a release tag), then on the box:
```bash
cd /opt/apps/itse500/app && git pull && docker compose -f docker-compose.vps.yml up -d --build
```
`.env` there holds the live creds (DB/MinIO/SECRET_KEY/admin/ALLOWED_HOSTS incl. 127.0.0.1). The health-reactor will restart itse500-app on unhealthy and quarantine+Telegram on a flap — so a broken deploy is caught, but verify `/healthz`, `/`, `/app`, `/api/docs`, `/admin` return 200 and check the running deps with `docker exec itse500-app pip freeze | grep -iE 'django|bolt'`.

**Phase 1 (Django 6) is independently mergeable to `Django-Starter` right now** if you want just the framework upgrade live before the Bolt rewrite is finished.
