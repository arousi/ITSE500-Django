# Deployment runbook: prompeteer_server on a self-hosted VPS (Traefik + Postgres)

This is the production deployment path for `prompeteer_server`, the Django
backend powering the Flutter desktop AI-chat client. It runs behind
**Traefik**, which terminates TLS via **Let's Encrypt** and reverse-proxies to
the Django app over plain HTTP inside a private Docker network. Postgres runs
as a sibling container on the same host.

This document assumes a fresh Ubuntu/Debian VPS with Docker + Docker Compose
v2 installed and a domain you control.

---

## 0. What you (the human) must provide before going live

These cannot be filled in by this branch - they require access this task did
not have (a live VPS, DNS control, and cloud consoles):

| Item | Why | Where |
|---|---|---|
| **A fresh Django `SECRET_KEY`** | The repo never had a real one in version control; generate a new one for prod | `python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"` |
| **Rotate the Google OAuth client secret** | The old one (`client_secret_2_16029884030-*.apps.googleusercontent.com.json`) was committed to git history and is no longer trustworthy even though it's now untracked | Google Cloud Console -> APIs & Services -> Credentials -> reset secret |
| A domain name pointed at the VPS | Traefik's Let's Encrypt HTTP-01 challenge needs a resolvable A record | Your DNS provider |
| Postgres password | `POSTGRES_PASSWORD` in `.env` | Generate a strong random value |
| SMTP credentials | The login-PIN email flow (pyotp-backed) needs a real mail provider | Your SMTP/transactional email provider |
| OAuth client IDs/secrets for OpenRouter/GitHub/Microsoft (if used) | Same reasoning as Google | Each provider's developer console |
| `OPENAI_API_KEY` / any LLM provider key `chat_api` calls | Needed if/when chat_api's model-calling code is wired to a live endpoint | Provider console |

---

## 1. DNS

Create an A record pointing your chosen subdomain (e.g. `api.yourdomain.com`)
at the VPS's public IPv4 address. Wait for propagation before starting
Traefik, or the ACME HTTP-01 challenge will fail.

```
api.yourdomain.com.  A   <VPS_PUBLIC_IP>
```

## 2. Prepare the server

```bash
# On the VPS
sudo apt update && sudo apt install -y docker.io docker-compose-plugin git
sudo usermod -aG docker $USER   # re-login after this

git clone <this-repo-url> /opt/prompeteer_server
cd /opt/prompeteer_server
git checkout main   # or whichever branch is being deployed
```

## 3. Create the real `.env`

```bash
cp .env.example .env
nano .env   # fill in every value - see .env.example for the full list
```

Minimum required for a working boot: `SECRET_KEY`, `ALLOWED_HOSTS`, `DOMAIN`,
`ACME_EMAIL`, `POSTGRES_DB`/`POSTGRES_USER`/`POSTGRES_PASSWORD`,
`CORS_ALLOWED_ORIGINS`, `CSRF_TRUSTED_ORIGINS`. Everything else (OAuth, SMTP,
AI provider keys) is required for those specific features to work but the
server will still boot without them.

`.env` must never be committed - it is both `.gitignore`d and
`.dockerignore`d.

## 4. First-time bring-up

```bash
docker compose -f docker-compose.prod.yml build
docker compose -f docker-compose.prod.yml up -d
docker compose -f docker-compose.prod.yml ps
```

What happens automatically:
- `db` starts and reports healthy once Postgres accepts connections
  (`pg_isready`).
- `web` waits for `db` to be healthy, then `entrypoint.sh` waits for the TCP
  port too (belt-and-suspenders), runs `manage.py migrate --noinput`
  (creating all tables from the tracked migration files), runs
  `collectstatic --noinput`, then starts gunicorn.
- `traefik` requests a Let's Encrypt certificate for `${DOMAIN}` via the
  HTTP-01 challenge (needs port 80 reachable from the internet) and starts
  routing HTTPS traffic to `web` on port 8000 once its healthcheck
  (`/healthz`) passes.

Watch the logs during first bring-up:

```bash
docker compose -f docker-compose.prod.yml logs -f traefik
docker compose -f docker-compose.prod.yml logs -f web
```

## 5. Create the Django superuser (first run only)

Either set `DJANGO_SUPERUSER_USERNAME`/`_EMAIL`/`_PASSWORD` in `.env` before
first bring-up (entrypoint.sh creates it automatically and is idempotent -
`|| true` swallows the "already exists" error on subsequent restarts), or run
it manually:

```bash
docker compose -f docker-compose.prod.yml exec web python manage.py createsuperuser
```

## 6. Verify

```bash
curl -I https://api.yourdomain.com/healthz
curl -I https://api.yourdomain.com/api/v1/auth_api/health/
```

Both should return `200`. Check the certificate is valid (issued by Let's
Encrypt, not self-signed):

```bash
curl -vI https://api.yourdomain.com/healthz 2>&1 | grep -i "SSL certificate"
```

## 7. How Let's Encrypt issues/renews the certificate

Traefik's `leresolver` certificate resolver (configured in
`docker-compose.prod.yml`) handles this entirely automatically:
- On first request to `${DOMAIN}`, Traefik requests a certificate via the
  ACME HTTP-01 challenge (a temporary token served on port 80).
- The certificate is stored in the `letsencrypt` named volume
  (`/letsencrypt/acme.json` inside the `traefik` container) so it survives
  container restarts.
- Traefik automatically renews certificates ~30 days before expiry with no
  manual intervention required, as long as the `traefik` container keeps
  running and port 80 stays reachable.

If the volume is ever lost, Traefik will simply re-request a fresh
certificate on the next request (rate-limited by Let's Encrypt to 50
certs/domain/week - not a concern for a single domain).

## 8. Rolling out an update

```bash
git pull
docker compose -f docker-compose.prod.yml build web
docker compose -f docker-compose.prod.yml up -d web
```

This rebuilds only the `web` image and recreates that one container;
`traefik` and `db` are untouched. `entrypoint.sh` re-runs `migrate` on every
start, so any new migrations in the pulled commit are applied automatically.
Because Django migrations in this app follow an additive/expand-first
pattern in practice (no destructive migration currently ships without a
prior expand step), the currently-running old container keeps working
right up until Traefik's healthcheck flips traffic to the new one - there is
no window where the app is down.

## 9. Rollback

Since there is a single `web` container (no blue-green pool provisioned in
this compose file), rollback means redeploying the previous image:

```bash
git checkout <previous-commit-or-tag>
docker compose -f docker-compose.prod.yml build web
docker compose -f docker-compose.prod.yml up -d web
```

**Database rollback caveat:** Django does not auto-generate a safe
down-migration. If the commit you are rolling back from added a migration
that is additive (new nullable column/table), the old code ignores the new
column and works fine with no DB changes needed - just roll the app back.
If a migration was destructive (dropped a column/table the old code needs),
there is no automated safe rollback; restore from a `pg_dump` backup taken
before the migration ran. Take a backup before every deploy that includes a
migration:

```bash
docker compose -f docker-compose.prod.yml exec db pg_dump -U ${POSTGRES_USER} ${POSTGRES_DB} > backup-$(date +%Y%m%d-%H%M%S).sql
```

## 10. Migrating existing `db.sqlite3` data to Postgres (optional)

Only needed if there is existing production data in SQLite to preserve
(not required for a fresh launch with no existing users):

```bash
# Against the old SQLite-backed instance:
python manage.py dumpdata --natural-foreign --natural-primary \
  -e contenttypes -e auth.Permission > dump.json

# Against the new Postgres-backed instance (after migrate has run):
docker compose -f docker-compose.prod.yml exec web python manage.py loaddata /server/dump.json
# (copy dump.json into the container first, e.g. via `docker cp`)
```

## 11. Secrets checklist (rotate/provide before launch)

- [ ] Fresh Django `SECRET_KEY` (never reuse the placeholder from `.env.example` or any value that ever touched git history)
- [ ] Rotated Google OAuth client secret (mandatory - the old one is in git history)
- [ ] Postgres password
- [ ] SMTP/email provider credentials for the login PIN flow
- [ ] Any OAuth secrets actually used in production (OpenRouter/GitHub/Microsoft)
- [ ] AI provider API key(s) if chat_api's model-calling path is enabled
- [ ] `ACME_EMAIL` (a real, monitored inbox - Let's Encrypt sends expiry-related notices here)

## 12. Known gaps / follow-ups (not blocking this launch)

- **WebSockets are not wired end-to-end.** `channels` is installed and
  `auth_api/consumers.py` defines a real `UserNotificationConsumer`, but
  `prompeteer_server/asgi.py`'s `ProtocolTypeRouter` only routes `"http"` -
  there is no `"websocket"` key, no `URLRouter`, and no `CHANNEL_LAYERS`
  backend configured (the Redis layer is commented out in settings.py). The
  app is correctly served over gunicorn/WSGI for now. If/when WebSocket
  push notifications are wired up, this will need: (1) a `routing.py`
  mapping `ws/...` paths to `UserNotificationConsumer`, (2) a
  `channels_redis` layer (a `redis` service would need to be added to
  docker-compose.prod.yml), (3) switching `web`'s command to `daphne` or
  `uvicorn --workers N prompeteer_server.asgi:application` instead of
  gunicorn/WSGI, and (4) a `traefik` websocket-upgrade label (Traefik
  handles this automatically via its HTTP router once the backend
  understands Upgrade/Connection headers).
