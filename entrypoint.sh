#!/bin/sh
set -e

# Wait for Postgres to accept connections before migrating. The SWE-Pioneers VPS sets DB_HOST
# (platform-postgres is a separate stack, so compose depends_on cannot gate it); the prod
# compose sets POSTGRES_*. No-op when neither is set (local SQLite dev).
_PG_HOST="${DB_HOST:-$POSTGRES_HOST}"
if [ -n "$_PG_HOST" ] || [ -n "$POSTGRES_DB" ]; then
  _PG_HOST="${_PG_HOST:-db}"
  _PG_PORT="${DB_PORT:-${POSTGRES_PORT:-5432}}"
  echo "Waiting for Postgres at ${_PG_HOST}:${_PG_PORT}..."
  for i in $(seq 1 30); do
    if python -c "import socket,sys; s=socket.socket(); s.settimeout(2); s.connect(('${_PG_HOST}', ${_PG_PORT})); s.close()" 2>/dev/null; then
      echo "Postgres is reachable."
      break
    fi
    echo "  ...not ready yet ($i/30)"
    sleep 2
  done
fi

echo "Running migrations..."
python manage.py migrate --noinput

echo "Collecting static..."
python manage.py collectstatic --noinput

if [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
  python manage.py createsuperuser --noinput || true
fi

exec "$@"
