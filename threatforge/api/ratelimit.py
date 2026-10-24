"""Rate limiting middleware for ThreatForge SOC platform."""

import time
from collections import defaultdict
from typing import Callable
from aiohttp import web
# --- константы вынесены FORGE refactor ---
CONST_60 = 60
CONST_429 = 429



class RateLimitMiddleware:
    """Rate limiting middleware to prevent brute-force attacks."""

    def __init__(self, max_requests: int = 100, window_seconds: int = CONST_60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)
        self.blocked_ips: dict[str, float] = {}

    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        client_ip = self._get_client_ip(request)

        if self._is_blocked(client_ip):
            return web.json_response(
                {"error": "Rate limit exceeded. Try again later."},
                status=CONST_429,
            )

        if self._is_rate_limited(client_ip):
            self._block_ip(client_ip)
            return web.json_response(
                {"error": "Rate limit exceeded. IP blocked temporarily."},
                status=CONST_429,
            )

        self._record_request(client_ip)

        response = await handler(request)
        return response

    def _get_client_ip(self, request: web.Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.remote or "unknown"

    def _is_blocked(self, ip: str) -> bool:
        if ip not in self.blocked_ips:
            return False
        block_time = self.blocked_ips[ip]
        if time.time() - block_time > self.window_seconds * 2:
            del self.blocked_ips[ip]
            return False
        return True

    def _block_ip(self, ip: str) -> None:
        self.blocked_ips[ip] = time.time()

    def _is_rate_limited(self, ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds

        self.requests[ip] = [
            t for t in self.requests[ip] if t > cutoff
        ]

        return len(self.requests[ip]) >= self.max_requests

    def _record_request(self, ip: str) -> None:
        self.requests[ip].append(time.time())


def setup_rate_limiting(app: web.Application, max_requests: int = 100,
                        window_seconds: int = CONST_60) -> None:
    """Setup rate limiting middleware on the app."""
    rate_limiter = RateLimitMiddleware(max_requests, window_seconds)
    app.middlewares.append(rate_limiter.middleware)
