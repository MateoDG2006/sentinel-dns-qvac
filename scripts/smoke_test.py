"""Render Compose/Kustomize and fail fast on an empty overlay (I1 smoke)."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

import yaml
from scripts.validate_manifests import ManifestPolicy, ManifestValidator

from app.constants.kubernetes import OVERLAY_LOCAL


class SmokeTestScript:
    """CLI for the pre-demo checks that do not require a live cluster."""

    def run(self, argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(description="Smoke-check Compose and Kubernetes overlays.")
        parser.add_argument(
            "--repo-root",
            default=str(Path(__file__).resolve().parents[1]),
        )
        args = parser.parse_args(argv)
        repo = Path(args.repo_root).resolve()
        code = self._compose_config(repo)
        if code != 0:
            return code
        overlay = repo / OVERLAY_LOCAL
        try:
            rendered = ManifestValidator().render(overlay)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as exc:
            print(exc.stderr or exc.stdout or str(exc), file=sys.stderr)
            return 1
        findings = ManifestPolicy().findings(list(yaml.safe_load_all(rendered)))
        if findings:
            print("static policy failed:", file=sys.stderr)
            for item in findings:
                print(f"  - {item}", file=sys.stderr)
            return 1
        print("compose config and kustomize overlay are valid")
        return 0

    @staticmethod
    def _compose_config(repo: Path) -> int:
        docker = shutil.which("docker")
        if docker is None:
            print("docker not on PATH; skipping compose config", file=sys.stderr)
            return 0
        completed = subprocess.run(
            [docker, "compose", "--profile", "full", "config"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            print(completed.stderr or completed.stdout, file=sys.stderr)
            return 1
        print("docker compose --profile full config: ok")
        return 0


if __name__ == "__main__":
    raise SystemExit(SmokeTestScript().run())
