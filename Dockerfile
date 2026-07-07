# syntax=docker/dockerfile:1
#
# Production image for prompeteer_server (Django backend).
# Multi-stage build: compile deps in `build`, ship a slim runtime layer.
# Served over WSGI (gunicorn) behind Traefik, which terminates TLS.
# See DEPLOYMENT.md for the full runbook.

FROM python:3.13-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /server

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements/base.txt /server/requirements/base.txt
RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r requirements/base.txt

COPY . /server

# Build-time collectstatic needs a SECRET_KEY and DEBUG so settings.py
# does not raise; the value is never used at runtime (a real SECRET_KEY
# is injected via env_file at container start).
RUN DJANGO_DEBUG=1 SECRET_KEY=build-time-only-not-used-at-runtime \
    python manage.py collectstatic --noinput

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 1000 django \
 && useradd --uid 1000 --gid django --shell /usr/sbin/nologin --create-home django

WORKDIR /server

COPY --from=build /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
COPY --from=build /server /server

RUN chmod +x /server/entrypoint.sh \
 && mkdir -p /server/media /server/staticfiles \
 && chown -R django:django /server

USER django

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/v1/auth_api/health/ || exit 1

ENTRYPOINT ["/server/entrypoint.sh"]
CMD ["gunicorn", "prompeteer_server.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
