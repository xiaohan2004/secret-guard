from __future__ import annotations

import hmac
import secrets
from hashlib import sha256
from pathlib import Path
from typing import Iterable

from .findings import Finding
from .identify import (
    SensitiveKind,
    classify_key_name,
    classify_value,
    is_high_confidence_secret_value,
    looks_like_placeholder,
    parse_assignment,
)


MAX_TEXT_BYTES = 5 * 1024 * 1024


def fingerprint_secret(raw_value: object, *, salt: bytes | None = None, length: int = 10) -> str:
    """Return a non-reversible fingerprint for a sensitive value."""
    data = str(raw_value).encode("utf-8", errors="ignore")
    run_salt = salt if salt is not None else secrets.token_bytes(32)
    return hmac.new(run_salt, data, sha256).hexdigest()[:length]


def scan_text(
    text: str,
    *,
    path: str = "<text>",
    salt: bytes | None = None,
) -> list[Finding]:
    """Scan text and return redacted findings without exposing raw values."""
    findings: set[Finding] = set()
    scan_salt = salt if salt is not None else secrets.token_bytes(32)

    for line_no, line in enumerate(text.splitlines(), start=1):
        assignment = parse_assignment(line)
        if assignment is not None and not looks_like_placeholder(assignment.value):
            kind = classify_key_name(assignment.key) or classify_value(assignment.value)
            if kind is not None:
                findings.add(
                    Finding(
                        category=kind.value,
                        path=path,
                        line=line_no,
                        key=assignment.key,
                        fingerprint=fingerprint_secret(assignment.value, salt=scan_salt),
                    )
                )
                continue

        value_kind = classify_value(line)
        if value_kind is not None:
            findings.add(
                Finding(
                    category=value_kind.value,
                    path=path,
                    line=line_no,
                    fingerprint=fingerprint_secret(line, salt=scan_salt),
                )
            )
            continue

        if is_high_confidence_secret_value(line):
            findings.add(
                Finding(
                    category=SensitiveKind.SECRET.value,
                    path=path,
                    line=line_no,
                    fingerprint=fingerprint_secret(line, salt=scan_salt),
                )
            )

    return sorted(findings)


def has_findings(findings: Iterable[Finding]) -> bool:
    return any(True for _ in findings)


def scan_file(
    path: str | Path,
    *,
    salt: bytes | None = None,
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> list[Finding]:
    """Scan one UTF-8-like text file and skip binary or oversized files."""
    file_path = Path(path)
    try:
        data = file_path.read_bytes()
    except OSError:
        return []

    if b"\0" in data[:4096] or len(data) > max_text_bytes:
        return []

    text = data.decode("utf-8", errors="ignore")
    return scan_text(text, path=file_path.as_posix(), salt=salt)
