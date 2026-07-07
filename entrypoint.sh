#!/bin/sh
set -e

# When running against Postgres (docker-compose.prod.yml), the `db` service
# healthcheck already gates startup via `depends_on: condition: service_healthy`,
# but wait a little longer here too in case the app container races the DB's
# listener coming up right after the healthcheck passes.
if [ -n "$POSTGRES_DB" ]; then
  echo "Waiting for Postgres at ${POSTGRES_HOST:-db}:${POSTGRES_PORT:-5432}..."
  for i in $(seq 1 30); do
    python - <<'PYEOF' && break
import os, socket, sys
host = os.environ.get("POSTGRES_HOST", "db")
port = int(os.environ.get("POSTGRES_PORT", "5432"))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect((host, port))
    sys.exit(0)
except OSError:
    sys.exit(1)
finally:
    s.close()
PYEOF
    echo "Postgres not ready yet, retrying ($i/30)..."
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
