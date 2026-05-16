from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class Finding:
    """A redacted finding produced by a scan."""

    category: str
    path: str
    line: int
    fingerprint: str
    key: str | None = None
