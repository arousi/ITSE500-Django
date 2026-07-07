"""
Celery application entry point.

Import of this module (and of the `celery` package itself) is gated by
`prompeteer_server/__init__.py`, which only wires it in when `celery` is
actually installed (i.e. in production, where requirements/prod.txt's
Phase 2 deps are active). This keeps local dev / the pytest suite working
without the `celery[redis]` package installed.
"""
import os

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'prompeteer_server.settings')

app = Celery('prompeteer_server')

# Read CELERY_* settings from Django settings (see settings.py "Celery" section).
app.config_from_object('django.conf:settings', namespace='CELERY')

# Auto-discover tasks.py in each installed app.
app.autodiscover_tasks()
