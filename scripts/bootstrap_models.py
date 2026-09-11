"""Prepare the local QVAC model cache.

Requires network. Never invoked by the runtime adapter. Run this before
enabling no-egress / demo mode. Use --smoke to load an existing cache only.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from app.infrastructure.qvac.client import QvacLocalSmoke, QvacModelBootstrap


class BootstrapModelsScript:
    """CLI for one-time model download or a local-only smoke check."""

    def run(self, argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(
            description=(
                "Download the QVAC GGUF into QVAC_CACHE_DIR (requires network) "
                "or smoke-test an existing local cache."
            )
        )
        parser.add_argument(
            "--smoke",
            action="store_true",
            help="Load the local cache only. Skip with exit 2 if empty. Never downloads.",
        )
        args = parser.parse_args(argv)
        if args.smoke:
            return asyncio.run(QvacLocalSmoke().run())
        print(
            "WARNING: bootstrap_models.py requires network and must not run "
            "during the no-egress demo.",
            file=sys.stderr,
        )
        path = asyncio.run(QvacModelBootstrap().prepare())
        print(f"Model ready at {path}")
        return 0


if __name__ == "__main__":
    raise SystemExit(BootstrapModelsScript().run())
