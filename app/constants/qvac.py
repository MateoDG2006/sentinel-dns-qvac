"""QVAC prompt version and local-model cache names. Changing these is a detector change."""

from pathlib import Path
from typing import Final

PROMPT_VERSION: Final[str] = "1.0"
HEALTH_DEPENDENCY_NAME: Final[str] = "qvac"
MODEL_TYPE_COMPLETION: Final[str] = "llamacpp-completion"
BOOTSTRAP_MODEL_CONSTANT: Final[str] = "QWEN3_600M_INST_Q4"
MANIFEST_FILENAME: Final[str] = "sentinel-qvac-manifest.json"
GGUF_SUFFIX: Final[str] = ".gguf"
COMPLETION_MAX_TOKENS: Final[int] = 256
RESPONSE_SCHEMA_NAME: Final[str] = "qvac_verdict"
SDK_PACKAGE_DIR: Final[Path] = Path("node_modules") / "@qvac" / "sdk"
