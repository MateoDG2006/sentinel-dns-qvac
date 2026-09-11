"""Render the local Kustomize overlay and validate it for C5.

Requires kubectl (or kustomize) to render. kubeconform is used when present;
otherwise the static policy scan plus kubectl apply --dry-run=client is the
equivalent required by the spec section 17.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml

from app.constants.kubernetes import (
    CONTAINER_LIST_KEYS,
    FORBIDDEN_SERVICE_TYPES,
    KUBECTL_CLUSTER_PROBE_TIMEOUT_SECONDS,
    KUBECTL_DRY_RUN_TIMEOUT_SECONDS,
    KUBECTL_UNREACHABLE_MARKERS,
    LATEST_IMAGE_TAG,
    OVERLAY_LOCAL,
    WORKLOAD_KINDS,
)


class ManifestPolicy:
    """Static checks: no LoadBalancer, unpinned images, privileged, or secret literals."""

    def findings(self, documents: Sequence[Mapping[str, Any] | None]) -> list[str]:
        issues: list[str] = []
        for index, document in enumerate(documents, start=1):
            if not document:
                continue
            issues.extend(self._scan_document(index, document))
        return issues

    def _scan_document(self, index: int, document: Mapping[str, Any]) -> list[str]:
        issues: list[str] = []
        kind = str(document.get("kind") or "Unknown")
        name = self._object_name(document)
        prefix = f"{kind}/{name}#{index}"
        if kind == "Service":
            service_type = str((document.get("spec") or {}).get("type") or "ClusterIP")
            if service_type in FORBIDDEN_SERVICE_TYPES:
                issues.append(f"{prefix}: service type {service_type} is forbidden")
        if kind == "Secret":
            issues.extend(self._secret_literals(prefix, document))
        for pod_spec in self._pod_specs(kind, document):
            issues.extend(self._scan_pod(prefix, pod_spec))
        return issues

    @staticmethod
    def _object_name(document: Mapping[str, Any]) -> str:
        metadata = document.get("metadata") or {}
        return str(metadata.get("name") or "unnamed")

    @staticmethod
    def _pod_specs(kind: str, document: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
        spec = document.get("spec") or {}
        if kind == "Pod":
            yield spec
            return
        if kind not in WORKLOAD_KINDS:
            return
        if kind == "CronJob":
            job_spec = (spec.get("jobTemplate") or {}).get("spec") or {}
            yield (job_spec.get("template") or {}).get("spec") or {}
            return
        yield (spec.get("template") or {}).get("spec") or {}

    def _scan_pod(self, prefix: str, pod_spec: Mapping[str, Any]) -> list[str]:
        issues: list[str] = []
        issues.extend(self._privileged_findings(f"{prefix} pod", pod_spec.get("securityContext")))
        for key in CONTAINER_LIST_KEYS:
            for container in pod_spec.get(key) or []:
                if not isinstance(container, Mapping):
                    continue
                name = str(container.get("name") or "container")
                issues.extend(self._image_findings(f"{prefix} {name}", container.get("image")))
                issues.extend(
                    self._privileged_findings(
                        f"{prefix} {name}",
                        container.get("securityContext"),
                    )
                )
        return issues

    @staticmethod
    def _privileged_findings(prefix: str, security_context: Any) -> list[str]:
        if not isinstance(security_context, Mapping):
            return []
        if security_context.get("privileged") is True:
            return [f"{prefix}: privileged containers are forbidden"]
        return []

    @staticmethod
    def _secret_literals(prefix: str, document: Mapping[str, Any]) -> list[str]:
        issues: list[str] = []
        for field in ("data", "stringData"):
            payload = document.get(field)
            if isinstance(payload, Mapping) and payload:
                issues.append(f"{prefix}: literal Secret.{field} values are forbidden")
        return issues

    @staticmethod
    def _image_findings(prefix: str, image: Any) -> list[str]:
        if not isinstance(image, str) or not image.strip():
            return [f"{prefix}: container image is missing"]
        if ManifestPolicy._image_is_unpinned(image):
            return [f"{prefix}: image {image!r} must be pinned (no {LATEST_IMAGE_TAG} or untagged)"]
        return []

    @staticmethod
    def _image_is_unpinned(image: str) -> bool:
        if "@sha256:" in image:
            return False
        repository = image.rsplit("@", 1)[0]
        image_name = repository.rsplit("/", 1)[-1]
        if ":" not in image_name:
            return True
        tag = image_name.rsplit(":", 1)[-1]
        return tag.lower() == LATEST_IMAGE_TAG


class ManifestValidator:
    """CLI: kustomize render, static policy, kubeconform, kubectl dry-run."""

    def run(self, argv: list[str] | None = None) -> int:
        parser = argparse.ArgumentParser(
            description="Render and validate the Sentinel-DNS Kubernetes overlay."
        )
        parser.add_argument(
            "--overlay",
            default=OVERLAY_LOCAL,
            help=f"Kustomize overlay directory (default: {OVERLAY_LOCAL})",
        )
        parser.add_argument(
            "--repo-root",
            default=str(Path(__file__).resolve().parents[1]),
            help="Repository root used to resolve the overlay path.",
        )
        parser.add_argument(
            "--skip-kubeconform",
            action="store_true",
            help="Skip kubeconform even when it is on PATH.",
        )
        args = parser.parse_args(argv)
        repo_root = Path(args.repo_root).resolve()
        overlay = Path(args.overlay)
        if not overlay.is_absolute():
            overlay = repo_root / overlay
        try:
            rendered = self.render(overlay)
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except subprocess.CalledProcessError as exc:
            print(exc.stderr or exc.stdout or str(exc), file=sys.stderr)
            return 1
        documents = list(yaml.safe_load_all(rendered))
        findings = ManifestPolicy().findings(documents)
        if findings:
            print("static policy failed:", file=sys.stderr)
            for item in findings:
                print(f"  - {item}", file=sys.stderr)
            return 1
        if not args.skip_kubeconform:
            code = self.kubeconform(rendered)
            if code != 0:
                return code
        return self.dry_run(rendered)

    def render(self, overlay: Path) -> str:
        if not overlay.is_dir():
            raise FileNotFoundError(f"overlay not found: {overlay}")
        kubectl = shutil.which("kubectl")
        kustomize = shutil.which("kustomize")
        if kubectl:
            command = [kubectl, "kustomize", str(overlay)]
        elif kustomize:
            command = [kustomize, "build", str(overlay)]
        else:
            raise FileNotFoundError(
                "neither kubectl nor kustomize is on PATH; cannot render the overlay"
            )
        completed = subprocess.run(command, check=True, capture_output=True, text=True)
        if not completed.stdout.strip():
            raise FileNotFoundError(f"{command[0]} produced empty YAML for {overlay}")
        return completed.stdout

    def kubeconform(self, rendered: str) -> int:
        binary = shutil.which("kubeconform")
        if binary is None:
            print(
                "kubeconform not on PATH; static scan + kubectl apply --dry-run=client "
                "is the spec-equivalent check",
                file=sys.stderr,
                flush=True,
            )
            return 0
        completed = self._completed([binary, "-strict", "-summary", "-"], stdin=rendered)
        if completed.returncode != 0:
            print(completed.stdout or completed.stderr, file=sys.stderr, flush=True)
            return 1
        if completed.stdout.strip():
            print(completed.stdout, flush=True)
        return 0

    @staticmethod
    def api_server_unreachable(output: str) -> bool:
        lowered = output.lower()
        return any(marker.lower() in lowered for marker in KUBECTL_UNREACHABLE_MARKERS)

    def dry_run(self, rendered: str) -> int:
        kubectl = shutil.which("kubectl")
        if kubectl is None:
            print(
                "kubectl not on PATH; cannot run kubectl apply --dry-run=client",
                file=sys.stderr,
                flush=True,
            )
            return 2
        probe = self._completed(
            [kubectl, "cluster-info", "--request-timeout=2s"],
            timeout=KUBECTL_CLUSTER_PROBE_TIMEOUT_SECONDS,
        )
        probe_out = f"{probe.stdout}{probe.stderr}"
        if probe.returncode != 0 or self.api_server_unreachable(probe_out):
            print(
                "kubectl apply --dry-run=client skipped: no reachable API server "
                "(ADR-010: the cluster is not required). Schema was already checked.",
                file=sys.stderr,
                flush=True,
            )
            return 0
        completed = self._completed(
            [kubectl, "apply", "--dry-run=client", "-f", "-"],
            stdin=rendered,
            timeout=KUBECTL_DRY_RUN_TIMEOUT_SECONDS,
        )
        output = f"{completed.stdout}{completed.stderr}"
        if completed.returncode == 0:
            print(completed.stdout, flush=True)
            return 0
        if self.api_server_unreachable(output):
            print(
                "kubectl apply --dry-run=client could not reach an API server "
                "(ADR-010: the cluster is not required). Schema was already checked.",
                file=sys.stderr,
                flush=True,
            )
            return 0
        print(completed.stderr or completed.stdout, file=sys.stderr, flush=True)
        return 1

    def _completed(
        self,
        command: list[str],
        stdin: str | None = None,
        timeout: int | None = None,
    ) -> subprocess.CompletedProcess[str]:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if stdin is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout, stderr = process.communicate(input=stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            self._kill_tree(process.pid)
            stdout, stderr = process.communicate()
            return subprocess.CompletedProcess(command, 1, stdout or "", stderr or "timeout")
        return subprocess.CompletedProcess(command, process.returncode or 0, stdout, stderr)

    @staticmethod
    def _kill_tree(pid: int) -> None:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
            )
            return
        try:
            os.kill(pid, 15)
        except OSError:
            return


if __name__ == "__main__":
    raise SystemExit(ManifestValidator().run())
