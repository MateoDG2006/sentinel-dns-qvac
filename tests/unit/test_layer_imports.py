"""Guardrails: domain contracts must not import infrastructure."""

from __future__ import annotations

import ast
from pathlib import Path

DOMAIN_DIR = Path("app/domain")
CONFIG_PATH = Path("app/core/config.py")

FORBIDDEN_ROOTS = frozenset(
    {
        "fastapi",
        "starlette",
        "uvicorn",
        "aiokafka",
        "kafka",
        "tetherto",
        "httpx",
        "clickhouse_connect",
        "clickhouse",
        "aiosqlite",
        "sqlite3",
        "prometheus_client",
        "yaml",
        "numpy",
        "rapidfuzz",
    }
)
FORBIDDEN_PREFIXES = (
    "app.infrastructure",
    "app.api",
    "app.services",
    "app.observability",
    "tetherto",
)


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def _assert_allowed(path: Path, names: set[str], *, allow_core: bool) -> None:
    for name in names:
        root = name.split(".", 1)[0]
        assert root not in FORBIDDEN_ROOTS, f"{path} imports {name}"
        for prefix in FORBIDDEN_PREFIXES:
            assert not name.startswith(prefix), f"{path} imports {name}"
        if not allow_core:
            assert not name.startswith("app.core"), f"{path} imports {name}"


def test_domain_does_not_import_infrastructure_or_frameworks() -> None:
    files = [path for path in DOMAIN_DIR.glob("*.py") if path.name != "__pycache__"]
    assert files
    for path in files:
        _assert_allowed(path, _imported_modules(path), allow_core=False)


def test_config_does_not_import_adapters() -> None:
    names = _imported_modules(CONFIG_PATH)
    _assert_allowed(CONFIG_PATH, names, allow_core=True)
    assert "app.domain.enums" in names
    assert any(name.startswith("app.constants.") for name in names)


def test_only_qvac_adapter_imports_sdk() -> None:
    offenders: list[str] = []
    for path in Path("app").rglob("*.py"):
        names = _imported_modules(path)
        if any(name == "tetherto" or name.startswith("tetherto.") for name in names):
            if path.parts[:3] != ("app", "infrastructure", "qvac"):
                offenders.append(str(path))
    assert offenders == []


def test_services_do_not_import_qvac_sdk() -> None:
    for path in Path("app/services").glob("*.py"):
        names = _imported_modules(path)
        assert all(not name.startswith("tetherto") for name in names), path
        assert "tetherto.qvac_sdk" not in names
