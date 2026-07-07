# Deploying Prompeteer Server to your VPS

Backend deploy runbook. The app is a Docker image (WSGI via gunicorn) that connects to
**PostgreSQL, Redis, and MinIO already running on your VPS**, with a reverse proxy
(Caddy or nginx) terminating TLS in front of it.

> Everything is env-gated: with no infra env vars set the app runs on SQLite / LocMemCache /
> in-memory channels / filesystem storage (dev). Set the vars below to switch each backend on.

## 0. Prerequisites (on the VPS)
- Docker + Docker Compose.
- PostgreSQL, Redis, and MinIO reachable from the app container (same host or network).
- A MinIO bucket created for media (e.g. `prompeteer-media`).
- DNS A records for `itse500-ok.ly` / `www.itse500-ok.ly` → the VPS IP.

## 1. Rotate & set secrets
The previously-leaked keys are already rotated. Create `.env` next to `docker-compose.prod.yml`
(never commit it) from `.env.example`, filling **at least**:

```bash
# Django core
SECRET_KEY=<long random>            # python -c "import secrets;print(secrets.token_urlsafe(64))"
BACKEND_PASSWORD_SALT=<long random>
DJANGO_DEBUG=False
ALLOWED_HOSTS=itse500-ok.ly,www.itse500-ok.ly
SECURE_SSL=True                     # HSTS + https redirect (proxy sets X-Forwarded-Proto)

# PostgreSQL  (presence of DB_HOST switches the app onto Postgres)
DB_HOST=... DB_NAME=... DB_USER=... DB_PASSWORD=... DB_PORT=5432
DB_SSL=True            # if your PG requires TLS
DB_CONN_MAX_AGE=60

# Redis (cache + channels + Celery broker/result)
REDIS_URL=redis://:<password>@<host>:6379/0

# MinIO / S3 media (presence of AWS_S3_ENDPOINT_URL switches media onto MinIO)
AWS_S3_ENDPOINT_URL=https://<minio-host>
AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=...
AWS_STORAGE_BUCKET_NAME=prompeteer-media
AWS_S3_REGION_NAME=us-east-1

# Providers / email (rotated) + JWT tuning
ZERUH_API_KEY=... MAILEROO_API_KEY=...
GOOGLE_OAUTH_CLIENT_ID=... GOOGLE_OAUTH_CLIENT_SECRET=... GOOGLE_OAUTH_REDIRECT_URI=https://itse500-ok.ly/api/v1/auth_api/google/callback/
# ...GitHub / Microsoft / OpenRouter equivalents; EMAIL_* ; JWT_ACCESS_MINUTES / JWT_REFRESH_DAYS
```

Optional bootstrap superuser (the entrypoint creates it if all three are set):
`DJANGO_SUPERUSER_USERNAME`, `DJANGO_SUPERUSER_EMAIL`, `DJANGO_SUPERUSER_PASSWORD`.

## 2. Bring it up
```bash
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
```
`entrypoint.sh` runs `migrate --noinput` then `collectstatic --noinput` before gunicorn starts.
Migrations are committed to the repo (deploy only **applies** them — it never runs
`makemigrations`). Services: `web` (gunicorn, bound to `127.0.0.1:8000`), `celery-worker`,
`celery-beat` (uncomment the `channels` ASGI service if/when you enable WebSockets).

## 3. Reverse proxy + TLS
The app is bound to loopback only — do **not** expose 8000 publicly. Put Caddy (auto-TLS) or
nginx in front. A ready Caddyfile is at `deploy/Caddyfile.example`:
```bash
sudo cp deploy/Caddyfile.example /etc/caddy/Caddyfile   # edit the domain if needed
sudo systemctl reload caddy
```
Caddy provisions Let's Encrypt certs automatically and forwards `X-Forwarded-Proto: https`,
which satisfies Django's `SECURE_PROXY_SSL_HEADER` (so `SECURE_SSL_REDIRECT` behaves).

## 4. Post-deploy checks
```bash
curl -fsS https://itse500-ok.ly/api/v1/auth_api/health/         # {"status":"ok",...}
docker compose -f docker-compose.prod.yml ps                    # web = healthy
```
- Admin: `https://itse500-ok.ly/admin/` (log in as the superuser).
- API docs (if DRF-spectacular UI is served): `/api/docs/`, schema at `/api/schema/`.
- Confirm a chat attachment upload lands an object in the MinIO bucket, and `redis-cli MONITOR`
  shows cache/broker traffic.
- Run Django's own deploy audit: `docker compose -f docker-compose.prod.yml exec web python manage.py check --deploy` (expect no ERRORs).

## 5. Backups & rollback
- **Postgres**: schedule `pg_dump` (daily) + test a restore. **MinIO**: enable bucket versioning.
- **Rollback** (app only, DB/Redis/MinIO untouched):
  `docker compose -f docker-compose.prod.yml up -d --no-deps web` with the previous image tag.
  Safe as long as schema changes follow expand→contract (add nullable/new first, remove later)
  so the previous app version still runs against the migrated DB.

## Notes
- The Flutter/React clients call this API; keep their vendored `openapi/schema.yaml` in sync
  (their CI drift jobs enforce it — see `CI_SYNC.md`).
- Real-time (WebSocket) streaming is not enabled yet; the Redis channel layer + ASGI service
  are ready for when it is (uncomment the `channels` service + wire consumers).
