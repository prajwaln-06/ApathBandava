"""NFR-2 / NFR-3 / rule 5: every user-URL fetch happens in the sandbox, and the sandbox refuses
internal targets (metadata IP, Docker service names, RFC1918, loopback, odd IP encodings, DNS tricks)."""
import httpx
import pytest

from helpers import ANALYZER, SANDBOX

INTERNAL = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254.nip.io/latest/meta-data/",
    "http://postgres:5432",
    "http://redis:6379",
    "http://analyzer:8000/health",
    "http://n8n:5678/healthz",
    "http://wa-bridge:8080/api/health",
    "http://llm-gateway:4000/health",
    "http://localhost:9000/health",
    "http://127.0.0.1:9000/health",
    "http://[::1]:9000/",
    "http://0x7f000001/",
    "http://2130706433/",
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.17.0.1/",
    "http://user:pass@127.0.0.1:9000/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "http://metadata.google.internal/computeMetadata/v1/",
]


def _sandbox_up() -> bool:
    try:
        return httpx.get(f"{SANDBOX}/health", timeout=3).status_code == 200
    except httpx.HTTPError:
        return False


@pytest.fixture(scope="module")
def sandbox():
    if not _sandbox_up():
        pytest.skip("sandbox not reachable (run inside the tests container on sandbox_net)")


@pytest.mark.parametrize("mode", ["expand", "full"])
@pytest.mark.parametrize("url", INTERNAL)
def test_sandbox_refuses_internal_targets(sandbox, url, mode):
    r = httpx.post(f"{SANDBOX}/detonate", json={"url": url, "mode": mode}, timeout=40)
    if r.status_code == 200:  # only acceptable if nothing internal was reached
        body = r.json()
        assert not body.get("title") and not (body.get("forms") or {}).get("password")
        assert body.get("final_url") is None or "169.254" not in str(body.get("redirects"))
    else:
        assert r.status_code in (422, 504), r.text


def test_redirect_into_metadata_is_blocked(sandbox):
    """A public URL that redirects to the metadata IP must stop at the redirect (needs internet)."""
    url = "http://httpbin.org/redirect-to?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F"
    r = httpx.post(f"{SANDBOX}/detonate", json={"url": url, "mode": "expand"}, timeout=40)
    if r.status_code == 200 and r.json().get("error"):
        pytest.skip("no internet egress from sandbox")
    assert r.status_code == 422 or "169.254.169.254" not in str(r.json().get("final_url"))


def test_analyzer_proxies_and_degrades(sandbox):
    import os

    h = {"X-Internal-Token": os.environ["ANALYZER_TOKEN"]}
    r = httpx.post(f"{ANALYZER}/url/detonate", json={"url": "http://169.254.169.254/"}, headers=h, timeout=40)
    assert r.status_code == 200 and r.json()["status"] == "unknown" and r.json()["title"] is None


def test_analyzer_static_and_reputation_never_fetch_internal(sandbox):
    """/url/static is pure parsing; /url/reputation only queries lookup services, never the URL itself."""
    import os

    h = {"X-Internal-Token": os.environ["ANALYZER_TOKEN"]}
    r = httpx.post(f"{ANALYZER}/url/static", json={"url": "http://169.254.169.254/latest"}, headers=h, timeout=10)
    assert r.json()["ip_host"] is True
    r = httpx.post(f"{ANALYZER}/url/reputation", json={"url": "http://postgres:5432"}, headers=h, timeout=30)
    assert r.status_code == 200 and r.json()["domain_age_days"] is None


def test_network_layout():
    import yaml

    try:
        compose = yaml.safe_load(open("/repo/docker-compose.yml", encoding="utf-8"))
    except FileNotFoundError:
        pytest.skip("compose file not mounted")
    svc = compose["services"]
    assert svc["sandbox"]["networks"] == ["sandbox_net"]
    assert set(svc["analyzer"]["networks"]) == {"core_net", "sandbox_net"}
    for name in ("n8n", "wa-bridge", "postgres", "redis", "llm-gateway"):
        assert "sandbox_net" not in svc[name]["networks"], name
    assert svc["sandbox"]["read_only"] is True and "no-new-privileges:true" in svc["sandbox"]["security_opt"]
    assert not any("secret" in str(v).lower() or "token" in str(v).lower() for v in (svc["sandbox"].get("environment") or {}))
