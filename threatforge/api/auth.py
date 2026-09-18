"""Authentication middleware for ThreatForge SOC platform."""

import time
import hashlib
import secrets
from typing import Optional, Callable
from aiohttp import web


class AuthMiddleware:
    """API authentication middleware supporting API keys and tokens."""

    def __init__(self, db=None):
        self.db = db
        self.public_paths = {
            "/api/health",
            "/api/stats",
        }

    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        if request.path in self.public_paths:
            return await handler(request)

        api_key = request.headers.get("X-API-Key") or request.query.get("api_key")
        if api_key and self._validate_api_key(api_key):
            request["user"] = self._get_user_by_api_key(api_key)
            return await handler(request)

        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if self._validate_token(token):
                return await handler(request)

        return web.json_response(
            {"error": "Unauthorized: valid API key or token required"},
            status=401,
        )

    def _validate_api_key(self, api_key: str) -> bool:
        if not self.db:
            return len(api_key) > 0
        user = self.db.get_user_by_api_key(api_key)
        return user is not None

    def _validate_token(self, token: str) -> bool:
        parts = token.split(".")
        return len(parts) == 3 and len(token) > 20

    def _get_user_by_api_key(self, api_key: str) -> Optional[dict]:
        if not self.db:
            return None
        return self.db.get_user_by_api_key(api_key)


def setup_auth(app: web.Application, db=None) -> None:
    """Setup authentication middleware on the app."""
    auth = AuthMiddleware(db)
    app.middlewares.append(auth.middleware)
