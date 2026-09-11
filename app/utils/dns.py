"""DNS name normalization used by contracts and later feature extraction."""

from __future__ import annotations

from app.constants.dns import LABEL_MAX_LENGTH, QNAME_MAX_LENGTH


class Qname:
    """Normalize and validate a DNS query name without depending on Pydantic."""

    @staticmethod
    def normalize(raw: str) -> str:
        if not raw or not raw.strip():
            raise ValueError("qname is required")
        stripped = raw.strip().rstrip(".")
        if not stripped:
            raise ValueError("qname cannot be empty")
        if ".." in stripped:
            raise ValueError("qname contains an empty label")
        try:
            punycode = stripped.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("qname is not a valid IDN") from exc
        if len(punycode) > QNAME_MAX_LENGTH:
            raise ValueError(f"qname exceeds {QNAME_MAX_LENGTH} characters")
        labels = punycode.split(".")
        if any(len(label) == 0 or len(label) > LABEL_MAX_LENGTH for label in labels):
            raise ValueError("qname label length is invalid")
        return punycode

    @staticmethod
    def split_labels(qname: str) -> list[str]:
        return [label for label in qname.split(".") if label]

    @staticmethod
    def sld(qname: str) -> str:
        labels = Qname.split_labels(qname)
        if len(labels) >= 2:
            return labels[-2]
        return labels[0] if labels else ""

    @staticmethod
    def without_dots(qname: str) -> str:
        return qname.replace(".", "")
