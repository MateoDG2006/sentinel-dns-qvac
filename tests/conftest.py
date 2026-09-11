"""Deterministic test defaults."""

from __future__ import annotations

import random

import pytest


@pytest.fixture(autouse=True)
def _fixed_seed() -> None:
    random.seed(42)
