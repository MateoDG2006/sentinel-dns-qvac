"""TLS verify value for the local Wazuh httpx client."""

from __future__ import annotations

import ssl
from pathlib import Path

from app.core.config import WazuhSettings


class WazuhTls:
    """Build httpx `verify=` from settings without crashing on a missing CA file."""

    @staticmethod
    def verify(settings: WazuhSettings) -> bool | ssl.SSLContext:
        if settings.ca_path is None:
            return settings.verify_tls
        path = Path(settings.ca_path)
        if not path.is_file():
            return settings.verify_tls
        try:
            context = ssl.create_default_context(cafile=str(path))
        except (OSError, ssl.SSLError):
            return settings.verify_tls
        # The manager image cert SAN is DNS:localhost. Compose uses
        # wazuh-manager; the host may use 127.0.0.1. Pin the CA, skip hostname.
        context.check_hostname = False
        return context
