"""JWT authentication against the local Wazuh manager API."""

from __future__ import annotations

import base64
import json
import time

import httpx

from app.core.config import WazuhSettings

_EXPIRY_SAFETY_MARGIN_SECONDS = 30.0
_FALLBACK_TOKEN_TTL_SECONDS = 900.0  # Wazuh's documented default JWT lifetime


def _decode_jwt_exp(token: str) -> float | None:
    """Best-effort read of the JWT's exp claim, without verifying the signature.

    This token is only ever used to talk to our own configured Wazuh
    manager over a connection we already trust (TLS + our own
    credentials) -- reading exp here is purely to know when to
    proactively refresh, not a security boundary.
    """
    try:
        _, payload_b64, _ = token.split(".")
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        exp = payload.get("exp")
        return float(exp) if exp is not None else None
    except (ValueError, KeyError, TypeError, UnicodeDecodeError):
        return None


class WazuhAuthenticator:
    """Holds the current JWT in memory only. Never persisted, never logged."""

    def __init__(self, settings: WazuhSettings, http_client: httpx.AsyncClient) -> None:
        self._settings = settings
        self._http = http_client
        self._token: str | None = None
        self._expires_at: float = 0.0

    def _needs_refresh(self) -> bool:
        return self._token is None or time.monotonic() >= self._expires_at

    async def get_token(self, force_refresh: bool = False) -> str:
        if force_refresh or self._needs_refresh():
            await self._authenticate()
        assert self._token is not None
        return self._token

    async def _authenticate(self) -> None:
        response = await self._http.post(
            self._settings.authenticate_path,
            auth=(self._settings.resolved_username(), self._settings.resolved_password()),
        )
        response.raise_for_status()
        body = response.json()
        token = body.get("data", {}).get("token")
        if not token:
            raise ValueError("Wazuh authenticate response did not include a token")

        exp = _decode_jwt_exp(token)
        now = time.monotonic()
        if exp is not None:
            ttl = max(exp - time.time(), 0.0)
        else:
            ttl = _FALLBACK_TOKEN_TTL_SECONDS
        self._token = token
        self._expires_at = now + max(ttl - _EXPIRY_SAFETY_MARGIN_SECONDS, 0.0)

    def invalidate(self) -> None:
        """Force the next get_token() call to re-authenticate."""
        self._token = None
        self._expires_at = 0.0
