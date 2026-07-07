"""Project-wide pytest fixtures."""
import pytest


@pytest.fixture(autouse=True)
def _reset_throttle_cache():
    """Clear the cache (which backs DRF's rate-limit counters) around every test.

    Throttle state is keyed by scope + client IP and lives in the cache. In the
    test runner every request comes from the same client, so without this reset
    the ``auth`` scope (10/min) could accumulate across test methods in a single
    process and spuriously 429 a later, unrelated test.
    """
    from django.core.cache import cache
    cache.clear()
    yield
    cache.clear()
