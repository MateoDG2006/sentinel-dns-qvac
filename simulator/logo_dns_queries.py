"""Load synthetic DNS fixtures from LogoDNSQueries without mixing in ground truth.

Raw dumps belong in ``data/LogoDNSQueries/`` (gitignored). Curated allowlisted
samples live in ``tests/fixtures/dns/``. Both are discovered as CSV/JSON/JSONL.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from app.constants.dns import SCHEMA_VERSION
from app.constants.logo_dns import (
    ALLOWED_SUFFIXES,
    CURATED_RELATIVE,
    DEFAULT_CLIENT_HASH,
    DEFAULT_RESOLVER_ID,
    DEFAULT_SITE_ID,
    DEFAULT_ZONE_ID,
    EVENT_ID_NAMESPACE,
    GROUND_TRUTH_FIELDS,
    QNAME_ALIASES,
    SCENARIO_NAME,
    SOURCE_DIRNAME,
)
from app.domain.enums import ThreatType
from app.domain.schemas import NormalizedDnsEvent
from app.utils.time import UtcDateTime

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_SOURCE = _REPO_ROOT / "data" / SOURCE_DIRNAME
_DEFAULT_CURATED = _REPO_ROOT / CURATED_RELATIVE
_EVENT_FIELDS = frozenset(NormalizedDnsEvent.model_fields)
_THREAT_VALUES = {item.value for item in ThreatType}


@dataclass(frozen=True, slots=True)
class LogoDnsSample:
    """One fixture row: analyzable event plus sidecar labels."""

    event: NormalizedDnsEvent
    threat_type: str
    technique: str | None
    scenario: str
    source_path: str


class LogoDNSQueries:
    """Discover and map LogoDNS dumps/fixtures to NormalizedDnsEvent + sidecar."""

    def __init__(
        self,
        source_dir: Path | None = None,
        fixtures_dir: Path | None = None,
    ) -> None:
        self._source_dir = source_dir if source_dir is not None else _DEFAULT_SOURCE
        self._fixtures_dir = fixtures_dir if fixtures_dir is not None else _DEFAULT_CURATED

    @property
    def source_dir(self) -> Path:
        return self._source_dir

    @property
    def fixtures_dir(self) -> Path:
        return self._fixtures_dir

    def discover(self, directory: Path | None = None) -> list[Path]:
        root = directory if directory is not None else self._source_dir
        if not root.is_dir():
            return []
        found = [
            path
            for path in root.iterdir()
            if path.is_file()
            and path.suffix.lower() in ALLOWED_SUFFIXES
            and not path.name.startswith(".")
        ]
        return sorted(found, key=lambda item: item.name.lower())

    def load(self) -> list[LogoDnsSample]:
        """Curated fixtures first, then optional dumps under data/LogoDNSQueries."""
        samples: list[LogoDnsSample] = []
        seen: set[UUID] = set()
        for path in (*self.discover(self._fixtures_dir), *self.discover(self._source_dir)):
            for sample in self._load_file(path):
                if sample.event.event_id in seen:
                    continue
                seen.add(sample.event.event_id)
                samples.append(sample)
        return samples

    def load_curated(self) -> list[LogoDnsSample]:
        samples: list[LogoDnsSample] = []
        for path in self.discover(self._fixtures_dir):
            samples.extend(self._load_file(path))
        return samples

    def labels(self, sample: LogoDnsSample) -> dict[str, str | None]:
        """Ground-truth sidecar. Never copy these fields onto the DNS event."""
        return {
            "scenario": sample.scenario,
            "threat_type": sample.threat_type,
            "technique": sample.technique,
        }

    @staticmethod
    def take_stratified(samples: Sequence[LogoDnsSample], limit: int) -> list[LogoDnsSample]:
        if limit <= 0:
            return []
        buckets: dict[str, list[LogoDnsSample]] = {}
        for sample in samples:
            buckets.setdefault(sample.threat_type, []).append(sample)
        order: list[str] = [str(item.value) for item in ThreatType if str(item.value) in buckets]
        order.extend(sorted(key for key in buckets if key not in order))
        picked: list[LogoDnsSample] = []
        indexes = {key: 0 for key in buckets}
        while len(picked) < limit:
            progressed = False
            for key in order:
                group = buckets[key]
                cursor = indexes[key]
                if cursor < len(group):
                    picked.append(group[cursor])
                    indexes[key] = cursor + 1
                    progressed = True
                    if len(picked) >= limit:
                        break
            if not progressed:
                break
        return picked

    @staticmethod
    def stamp(sample: LogoDnsSample, *, now: datetime) -> LogoDnsSample:
        stamped = UtcDateTime.ensure(now)
        event = sample.event.model_copy(update={"event_ts": stamped, "observed_at": stamped})
        return LogoDnsSample(
            event=event,
            threat_type=sample.threat_type,
            technique=sample.technique,
            scenario=sample.scenario,
            source_path=sample.source_path,
        )

    @staticmethod
    def report(samples: Sequence[LogoDnsSample]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for sample in samples:
            counts[sample.threat_type] = counts.get(sample.threat_type, 0) + 1
        return counts

    def _load_file(self, path: Path) -> list[LogoDnsSample]:
        suffix = path.suffix.lower()
        if suffix == ".csv":
            rows = list(self._read_csv(path))
        elif suffix == ".jsonl":
            rows = list(self._read_jsonl(path))
        else:
            rows = list(self._read_json(path))
        samples: list[LogoDnsSample] = []
        for index, row in enumerate(rows):
            sample = self._map_row(row, path=path, index=index)
            if sample is not None:
                samples.append(sample)
        return samples

    @staticmethod
    def _read_csv(path: Path) -> Iterator[dict[str, Any]]:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for row in reader:
                yield {key: value for key, value in row.items() if key}

    @staticmethod
    def _read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                text = line.strip()
                if not text or text.startswith("#"):
                    continue
                payload = json.loads(text)
                if not isinstance(payload, dict):
                    raise ValueError(f"{path} jsonl row must be an object")
                yield payload

    @staticmethod
    def _read_json(path: Path) -> Iterator[dict[str, Any]]:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(payload, dict) and isinstance(payload.get("records"), list):
            rows = payload["records"]
        elif isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict):
            rows = [payload]
        else:
            raise ValueError(f"{path} must be a JSON object or array")
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(f"{path} contains a non-object record")
            yield row

    def _map_row(self, row: dict[str, Any], *, path: Path, index: int) -> LogoDnsSample | None:
        qname = self._first_text(row, QNAME_ALIASES)
        if qname is None:
            return None
        synthetic = self._as_bool(row.get("synthetic"), default=True)
        if not synthetic:
            return None
        threat_type = self._threat_type(row)
        technique = self._optional_text(row.get("technique"))
        scenario = self._optional_text(row.get("scenario")) or SCENARIO_NAME
        event_id = self._event_id(row, qname=qname, index=index)
        payload: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "event_id": event_id,
            "event_ts": self._timestamp(row.get("event_ts")),
            "observed_at": self._timestamp(row.get("observed_at") or row.get("event_ts")),
            "site_id": self._optional_text(row.get("site_id")) or DEFAULT_SITE_ID,
            "zone_id": self._optional_text(row.get("zone_id")) or DEFAULT_ZONE_ID,
            "resolver_id": self._optional_text(row.get("resolver_id")) or DEFAULT_RESOLVER_ID,
            "client_hash": self._optional_text(row.get("client_hash")) or DEFAULT_CLIENT_HASH,
            "qname": qname,
            "qtype": self._optional_text(row.get("qtype") or row.get("type")) or "A",
            "rcode": self._optional_text(row.get("rcode")) or "NOERROR",
            "latency_ms": self._as_float(row.get("latency_ms")),
            "response_bytes": self._as_int(row.get("response_bytes")),
            "timed_out": self._as_bool(row.get("timed_out"), default=False),
            "synthetic": True,
        }
        extra = {
            key: value
            for key, value in row.items()
            if key in _EVENT_FIELDS and key not in payload and key not in GROUND_TRUTH_FIELDS
        }
        payload.update(extra)
        if payload["timed_out"]:
            payload["rcode"] = "TIMEOUT"
            payload["latency_ms"] = None
        event = NormalizedDnsEvent.model_validate(payload)
        return LogoDnsSample(
            event=event,
            threat_type=threat_type,
            technique=technique,
            scenario=scenario,
            source_path=path.name,
        )

    @staticmethod
    def _first_text(row: dict[str, Any], keys: Sequence[str]) -> str | None:
        for key in keys:
            text = LogoDNSQueries._optional_text(row.get(key))
            if text:
                return text
        return None

    @staticmethod
    def _threat_type(row: dict[str, Any]) -> str:
        raw = row.get("threat_type") or row.get("expected_threat") or row.get("label") or "none"
        text = str(raw).strip().lower()
        if text not in _THREAT_VALUES:
            return ThreatType.NONE.value
        return text

    @staticmethod
    def _event_id(row: dict[str, Any], *, qname: str, index: int) -> UUID:
        raw = row.get("event_id")
        if raw:
            return UUID(str(raw))
        qtype = LogoDNSQueries._optional_text(row.get("qtype") or row.get("type")) or "A"
        return uuid5(EVENT_ID_NAMESPACE, f"{qname}|{qtype}|{index}")

    @staticmethod
    def _timestamp(value: Any) -> datetime:
        if value is None or value == "":
            return datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
        if isinstance(value, datetime):
            return UtcDateTime.ensure(value)
        return UtcDateTime.ensure(datetime.fromisoformat(str(value).replace("Z", "+00:00")))

    @staticmethod
    def _optional_text(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.lower() in {"none", "null"}:
            return None
        return text

    @staticmethod
    def _as_bool(value: Any, *, default: bool) -> bool:
        if value is None or value == "":
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def _as_float(value: Any) -> float | None:
        if value is None or value == "":
            return None
        return float(value)

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if value is None or value == "":
            return None
        return int(value)


if __name__ == "__main__":
    loaded = LogoDNSQueries().load()
    histogram = LogoDNSQueries.report(loaded)
    print(f"samples={len(loaded)} by_threat={histogram}")
