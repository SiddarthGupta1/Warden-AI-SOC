"""Rate limiting must actually reject, and must never throttle health probes."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.middleware import rate_limit
from app.middleware.rate_limit import LIMITS

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_counters():
    """
    Counters are process-wide, so other test modules calling the login route would
    otherwise consume this module's budget before it runs.
    """
    rate_limit.reset()
    yield
    rate_limit.reset()


def test_login_brute_force_is_throttled():
    """
    The login route compares passwords for unauthenticated callers, so it is the
    brute-force surface. Exceeding the window must return 429 with Retry-After.
    """
    max_requests, _ = LIMITS["/api/auth/json-login"]
    body = {"username": "no_such_user", "password": "wrong"}

    statuses = [
        client.post("/api/auth/json-login", json=body).status_code
        for _ in range(max_requests + 4)
    ]

    assert 429 in statuses, f"never throttled after {len(statuses)} attempts: {statuses}"
    assert statuses.index(429) == max_requests, \
        f"throttled at attempt {statuses.index(429)}, expected exactly after {max_requests}"

    blocked = client.post("/api/auth/json-login", json=body)
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert blocked.json()["retry_after_seconds"] >= 1


def test_health_probes_are_never_throttled():
    """
    A throttled /healthz would make Kubernetes restart a pod that is merely busy,
    turning a load spike into an outage.
    """
    codes = {client.get("/healthz").status_code for _ in range(60)}
    assert codes == {200}, f"health probe was throttled or failed: {codes}"


def test_allowed_requests_carry_budget_headers():
    r = client.post("/api/auth/json-login", json={"username": "x", "password": "y"})
    assert r.status_code != 429
    assert r.headers["X-RateLimit-Limit"] == str(LIMITS["/api/auth/json-login"][0])
    assert int(r.headers["X-RateLimit-Remaining"]) >= 0


def test_limits_are_per_endpoint_not_global():
    """Exhausting one endpoint's budget must not lock the caller out of others."""
    max_requests, _ = LIMITS["/api/auth/json-login"]
    for _ in range(max_requests + 2):
        client.post("/api/auth/json-login", json={"username": "x", "password": "y"})

    assert client.post("/api/auth/json-login", json={"username": "x", "password": "y"}).status_code == 429
    assert client.get("/healthz").status_code == 200
    # A different path has its own bucket and must still be reachable.
    assert client.get("/api/incidents").status_code != 429
