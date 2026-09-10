"""Lexical statistics used by DNS feature extraction and heuristic scoring."""

from __future__ import annotations

from typing import ClassVar

import numpy as np


class DomainText:
    """Character-level ratios and Shannon entropy for a domain string."""

    _VOWELS: ClassVar[frozenset[str]] = frozenset("aeiou")

    @staticmethod
    def shannon_entropy(text: str) -> float:
        if not text:
            return 0.0
        codes = np.array([ord(ch) for ch in text], dtype=np.int32)
        counts = np.unique(codes, return_counts=True)[1]
        probs = counts.astype(np.float64) / float(len(text))
        return float(-np.sum(probs * np.log2(probs)))

    @staticmethod
    def digit_ratio(text: str) -> float:
        if not text:
            return 0.0
        digits = sum(1 for ch in text if ch.isdigit())
        return digits / len(text)

    @staticmethod
    def vowel_ratio(text: str) -> float:
        letters = [ch for ch in text.lower() if ch.isalpha()]
        if not letters:
            return 0.0
        vowels = sum(1 for ch in letters if ch in DomainText._VOWELS)
        return vowels / len(letters)


class HomoglyphFolder:
    """Fold lookalike characters using substitutions loaded from YAML."""

    def __init__(self, substitutions: dict[str, str], sequences: dict[str, str]) -> None:
        self._substitutions = {src.lower(): dst.lower() for src, dst in substitutions.items()}
        self._sequences = tuple(
            sorted(
                ((src.lower(), dst.lower()) for src, dst in sequences.items()),
                key=lambda item: len(item[0]),
                reverse=True,
            )
        )

    def fold(self, text: str) -> str:
        lowered = text.lower()
        for src, dst in self._sequences:
            lowered = lowered.replace(src, dst)
        return "".join(self._substitutions.get(ch, ch) for ch in lowered)

    def contains_mapped_glyph(self, text: str) -> bool:
        return self.fold(text) != text.lower()
