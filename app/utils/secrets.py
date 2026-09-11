"""Read secrets from mounted files without logging the value."""

from __future__ import annotations

from pathlib import Path


class SecretFile:
    @staticmethod
    def read(path: Path) -> str:
        return path.read_text(encoding="utf-8").strip()
