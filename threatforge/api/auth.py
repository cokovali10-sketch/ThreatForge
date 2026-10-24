"""Authentication middleware for ThreatForge SOC platform."""

import hashlib
import hmac
import json
import base64
import time
from typing import Optional, Callable
from aiohttp import web
# --- константы вынесены FORGE refactor ---
CONST_4 = 4



class AuthMiddleware:
    """API authentication middleware supporting API keys and JWT tokens."""

    def __init__(self, db=None, jwt_secret: str = ""):
        self.db = db
        self.jwt_secret = jwt_secret
        self.public_paths = {
            "/api/health",
            "/api/stats",
        }

    @web.middleware
    async def middleware(self, request: web.Request, handler: Callable) -> web.Response:
        if request.path in self.public_paths:
            return await handler(request)

        api_key = request.headers.get("X-API-Key")
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
            return False
        user = self.db.get_user_by_api_key(api_key)
        return user is not None

    def _validate_token(self, token: str) -> bool:
        if not self.jwt_secret:
            return False

        parts = token.split(".")
        if len(parts) != 3:
            return False

        header_b64, payload_b64, sig_b64 = parts

        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(
            self.jwt_secret.encode(),
            signing_input.encode(),
            hashlib.sha256,
        ).digest()

        try:
            decoded_sig = base64.urlsafe_b64decode(sig_b64 + "==")
        except Exception:
            return False

        if not hmac.compare_digest(decoded_sig, expected_sig):
            return False

        return self._check_token_expiry(payload_b64)

    def _check_token_expiry(self, payload_b64: str) -> bool:
        try:
            padding = CONST_4 - len(payload_b64) % CONST_4
            if padding != CONST_4:
                payload_b64 += "=" * padding
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload = json.loads(payload_bytes)

            exp = payload.get("exp")
            if exp is None:
                return True

            if isinstance(exp, (int, float)):
                return time.time() < exp

            return True
        except Exception:
            return False

    def _get_user_by_api_key(self, api_key: str) -> Optional[dict]:
        if not self.db:
            return None
        return self.db.get_user_by_api_key(api_key)


def setup_auth(app: web.Application, db=None, jwt_secret: str = "") -> None:
    """Setup authentication middleware on the app."""
    auth = AuthMiddleware(db, jwt_secret)
    app.middlewares.append(auth.middleware)
