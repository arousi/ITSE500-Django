"""Throttle identity must come from X-Forwarded-For behind a reverse proxy.

Security review SHOULD-FIX: with the app behind Traefik, DRF's default
REMOTE_ADDR is the proxy's container IP, so every client would collapse into a
single throttle bucket (defeating the brute-force protection). Setting
NUM_PROXIES makes DRF derive the real client IP from X-Forwarded-For.
"""
from unittest import mock

from rest_framework.settings import api_settings
from rest_framework.test import APIRequestFactory
from rest_framework.throttling import ScopedRateThrottle


def test_num_proxies_uses_forwarded_for_client_ip():
    throttle = ScopedRateThrottle()
    req = APIRequestFactory().get("/", HTTP_X_FORWARDED_FOR="9.9.9.9", REMOTE_ADDR="10.0.0.1")

    with mock.patch.object(api_settings, "NUM_PROXIES", 1):
        # behind 1 trusted proxy (Traefik): the real client, not the proxy
        assert throttle.get_ident(req) == "9.9.9.9"

    with mock.patch.object(api_settings, "NUM_PROXIES", 0):
        # local/dev: no proxy, fall back to REMOTE_ADDR
        assert throttle.get_ident(req) == "10.0.0.1"
