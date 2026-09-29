"""
Request rate limiting.

Two distinct risks are addressed, with different budgets:

  - Authentication endpoints are the brute-force surface. The login routes accept
    unauthenticated requests and compare passwords, so without a limit an attacker
    can test credentials as fast as the server responds.
  - Triage and remediation are the expensive surface. Each triage is a model call
    costing real money and roughly 35 seconds; remediation mutates a live SIEM.
    A loop against either is a cost and integrity problem, not just a load problem.

Implementation is a dependency-free sliding window held in process memory. That is
the right size for the single-replica deployment this application supports (see
aks/pvc.yaml): the store does not need to be shared because there is one writer.
If this is ever scaled out behind a load balancer, the counters must move to Redis
or the limit becomes per-pod rather than per-cluster.
"""

import logging
import time
from collections import defaultdict, deque
from typing import Deque, Dict, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("warden.ratelimit")

# (max_requests, window_seconds) per bucket, matched by longest path prefix.
LIMITS: Dict[str, Tuple[int, int]] = {
    "/api/auth/login":          (10, 60),
    "/api/auth/json-login":     (10, 60),
    "/api/auth/reset-password": (10, 60),
    "/api/triage":              (20, 60),   # model spend
    "/api/incidents":           (60, 60),   # includes /remediate
}
DEFAULT_LIMIT: Tuple[int, int] = (240, 60)

# Hard ceiling on tracked keys so a spray of spoofed sources cannot grow memory
# without bound.
MAX_TRACKED_KEYS = 20_000


# Counters live at module scope rather than on the middleware instance so that
# tests (and an admin endpoint, if one is ever added) can clear them without
# reaching into the ASGI middleware stack to find the instance.
_HITS: Dict[str, Deque[float]] = defaultdict(deque)


def reset() -> None:
    """Drop all rate-limit counters. Used by tests to isolate cases."""
    _HITS.clear()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._hits = _HITS

    @staticmethod
    def _client_id(request: Request) -> str:
        # Prefer the authenticated subject so one user cannot evade the limit by
        # changing source address; fall back to peer address for anonymous calls.
        auth = request.headers.get("authorization", "")
        if auth.startswith("Bearer "):
            return f"tok:{hash(auth[7:]) & 0xFFFFFFFF}"
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return f"ip:{fwd.split(',')[0].strip()}"
        return f"ip:{request.client.host if request.client else 'unknown'}"

    @staticmethod
    def _limit_for(path: str) -> Tuple[int, int]:
        match = ""
        for prefix in LIMITS:
            if path.startswith(prefix) and len(prefix) > len(match):
                match = prefix
        return LIMITS[match] if match else DEFAULT_LIMIT

    def _prune(self) -> None:
        if len(self._hits) <= MAX_TRACKED_KEYS:
            return
        now = time.monotonic()
        for key in [k for k, v in self._hits.items() if not v or now - v[-1] > 300]:
            self._hits.pop(key, None)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Probes must never be throttled: a rate-limited /healthz would make
        # Kubernetes restart a pod that is merely busy.
        if path in ("/healthz", "/readyz"):
            return await call_next(request)

        max_requests, window = self._limit_for(path)
        key = f"{self._client_id(request)}|{path}"
        now = time.monotonic()

        bucket = self._hits[key]
        cutoff = now - window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= max_requests:
            retry_after = max(1, int(window - (now - bucket[0])))
            logger.warning(f"Rate limit hit: {key} ({len(bucket)}/{max_requests} in {window}s)")
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Rate limit exceeded: {max_requests} requests per {window}s for this endpoint.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        bucket.append(now)
        self._prune()

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(max_requests)
        response.headers["X-RateLimit-Remaining"] = str(max(0, max_requests - len(bucket)))
        return response
