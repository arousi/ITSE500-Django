"""Root Bolt module: mounts the whole Django ASGI app as the fallback for every
path no Bolt route claims.

runbolt only auto-mounts Django *admin* (at /admin) — it does NOT serve the rest
of the Django URLconf by itself. Without this mount, the React SPA at '/', the
Flutter build at '/app/', '/team/', '/landing/', '/healthz' and DEBUG media all
404 under runbolt. Autodiscovered because 'prompeteer_server' is in INSTALLED_APPS.

clear_root_path=True so Django resolves against the full request path (the
URLconf patterns are root-level).
"""
from django_bolt import BoltAPI

api = BoltAPI()

api.mount_django("/", clear_root_path=True)
