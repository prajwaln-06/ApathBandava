"""Live security suites (Phase 6). They need the running stack + mock bridge: `make security`."""
import httpx
import pytest

from helpers import MOCK, N8N, _up


@pytest.fixture(scope="session")
def stack():
    if not (_up(f"{N8N}/healthz") and _up(f"{MOCK}/api/health")):
        pytest.skip("live stack not running (make up + mock-bridge)")
    return True


@pytest.fixture
def http():
    with httpx.Client(timeout=30) as c:
        yield c
