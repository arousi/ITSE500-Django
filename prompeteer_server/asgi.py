"""
ASGI config for prompeteer_server project.

It exposes the ASGI callable as a module-level variable named ``application``.
(channels' ProtocolTypeRouter was removed with the django-bolt cutover — no
websocket route was ever wired; runbolt mounts this Django app for all
non-Bolt HTTP routes.)
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'prompeteer_server.settings')

application = get_asgi_application()
