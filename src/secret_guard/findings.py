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


@dataclass(frozen=True, order=True)
class SkippedFile:
    """A file that could not be fully scanned."""

    path: str
    reason: str
    size: int | None = None


@dataclass(frozen=True)
class ScanReport:
    """Scan findings plus skipped-file metadata."""

    findings: tuple[Finding, ...]
    skipped: tuple[SkippedFile, ...] = ()
