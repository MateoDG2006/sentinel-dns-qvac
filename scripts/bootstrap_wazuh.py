"""Local Wazuh manager bootstrap: wait for the API, export the TLS cert, smoke ingest."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

import httpx

from app.core.config import Settings


class WazuhBootstrap:
    """One-shot helper so the host API can talk to Compose's wazuh-manager."""

    CONTAINER: str = "sentinel-wazuh"
    CERT_CANDIDATES: tuple[str, ...] = (
        "/var/ossec/api/configuration/ssl/server.crt",
        "/etc/ssl/certs/server.crt",
        "/var/ossec/etc/sslmanager.cert",
    )

    def run(self, argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(
            description="Wait for local Wazuh, export its TLS cert, and POST a fixture."
        )
        parser.add_argument("--skip-ingest", action="store_true")
        args = parser.parse_args(argv)
        settings = Settings(_env_file=".env")
        cert_path = Path("data/wazuh/root-ca.pem")
        if not self._wait_for_api():
            print("wazuh-manager API did not become ready on :55000", file=sys.stderr)
            return 2
        exported = self._export_cert(cert_path)
        if exported is None:
            print("could not export the Wazuh API certificate", file=sys.stderr)
            return 2
        print(f"TLS cert written to {exported}")
        if args.skip_ingest:
            return 0
        return self._ingest_fixture(settings, exported)

    def _wait_for_api(self, attempts: int = 36) -> bool:
        for _ in range(attempts):
            try:
                httpx.get("https://localhost:55000", verify=False, timeout=3.0)
                return True
            except httpx.HTTPError:
                time.sleep(5)
        return False

    def _export_cert(self, dest: Path) -> Path | None:
        dest.parent.mkdir(parents=True, exist_ok=True)
        for remote in self.CERT_CANDIDATES:
            completed = subprocess.run(
                ["docker", "cp", f"{self.CONTAINER}:{remote}", str(dest)],
                capture_output=True,
                text=True,
                check=False,
            )
            if completed.returncode == 0 and dest.is_file() and dest.stat().st_size > 0:
                return dest
        pem = self._openssl_peer_cert()
        if pem:
            dest.write_text(pem, encoding="ascii")
            return dest
        return None

    @staticmethod
    def _openssl_peer_cert() -> str | None:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                "sentinel-wazuh",
                "openssl",
                "s_client",
                "-connect",
                "127.0.0.1:55000",
                "-showcerts",
            ],
            input="",
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
        text = completed.stdout
        start = text.find("-----BEGIN CERTIFICATE-----")
        end = text.find("-----END CERTIFICATE-----")
        if start == -1 or end == -1:
            return None
        return text[start : end + len("-----END CERTIFICATE-----")] + "\n"

    def _ingest_fixture(self, settings: Settings, ca_path: Path) -> int:
        fixture = Path("tests/fixtures/wazuh_events/dga_medium.json")
        event = fixture.read_text(encoding="utf-8").strip()
        try:
            username = settings.wazuh.resolved_username()
            password = settings.wazuh.resolved_password()
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        with httpx.Client(
            base_url=settings.wazuh.base_url, verify=str(ca_path), timeout=15.0
        ) as client:
            auth = client.post(
                settings.wazuh.authenticate_path,
                auth=(username, password),
            )
            if auth.status_code != 200:
                print(f"authenticate failed: {auth.status_code} {auth.text}", file=sys.stderr)
                return 1
            token = auth.json().get("data", {}).get("token")
            if not token:
                print("authenticate response had no token", file=sys.stderr)
                return 1
            posted = client.post(
                settings.wazuh.events_path,
                headers={"Authorization": f"Bearer {token}"},
                json={"events": [event]},
            )
        print(f"POST /events -> {posted.status_code} {posted.text[:500]}")
        if posted.status_code >= 400:
            return 1
        if not self._logtest(event):
            return 1
        return 0

    @staticmethod
    def _logtest(event: str) -> bool:
        completed = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                "sentinel-wazuh",
                "/var/ossec/bin/wazuh-logtest",
            ],
            input=event + "\n",
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        output = (completed.stdout or "") + (completed.stderr or "")
        print(output[-2000:] if output else "wazuh-logtest produced no output")
        if "100199" in output or "100200" in output or "100201" in output:
            print("logtest matched Sentinel-DNS rules")
            return True
        print("logtest did not match Sentinel-DNS rules 100199-100201", file=sys.stderr)
        return False


if __name__ == "__main__":
    raise SystemExit(WazuhBootstrap().run())
