import importlib.util as _imp

# Only wire in the Celery app when the `celery` package is actually installed.
# `celery[redis]` is a Phase 2 dependency (see requirements/prod.txt) that is
# NOT present in local dev / the pytest venv; importing it unconditionally
# here would break `manage.py check` and the test suite on every import of
# this package. CELERY_TASK_ALWAYS_EAGER (settings.py) already makes task
# `.delay()`/`.apply_async()` calls run inline without a broker, independent
# of whether this app object exists.
if _imp.find_spec('celery') is not None:
    from .celery import app as celery_app

    __all__ = ('celery_app',)
else:
    __all__ = ()
