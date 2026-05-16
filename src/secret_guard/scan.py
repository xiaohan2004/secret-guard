from __future__ import annotations

import hmac
import os
import secrets
import sqlite3
from hashlib import sha256
from pathlib import Path
from enum import Enum
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
EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    "target",
    "out",
}
CONFIG_SUFFIXES = {".env", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".json", ".toml", ".properties"}
CODE_SUFFIXES = {".py", ".js", ".jsx", ".ts", ".tsx", ".vue", ".java", ".go", ".rs", ".cs", ".cpp", ".c", ".h", ".php", ".rb"}
SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3", ".bak"}


class FileKind(str, Enum):
    """File type buckets used by scanners."""

    CONFIG = "config"
    CODE = "code"
    SQLITE = "sqlite"
    TEXT = "text"


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


def scan_high_confidence_text(
    text: str,
    *,
    path: str = "<text>",
    salt: bytes | None = None,
) -> list[Finding]:
    """Scan text with only high-confidence secret value rules."""
    findings: set[Finding] = set()
    scan_salt = salt if salt is not None else secrets.token_bytes(32)
    for line_no, line in enumerate(text.splitlines(), start=1):
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

    is_binary_or_large = b"\0" in data[:4096] or len(data) > max_text_bytes
    if is_binary_or_large:
        text = data.decode("latin1", errors="ignore")
        return scan_high_confidence_text(text, path=file_path.as_posix(), salt=salt)

    text = data.decode("utf-8", errors="ignore")
    return scan_text(text, path=file_path.as_posix(), salt=salt)


def classify_file(path: str | Path) -> FileKind:
    """Classify a path into a scanner file kind."""
    file_path = Path(path)
    name = file_path.name.lower()
    suffix = file_path.suffix.lower()
    if name == ".env" or name.startswith(".env.") or name.endswith(".env"):
        return FileKind.CONFIG
    if suffix in CONFIG_SUFFIXES:
        return FileKind.CONFIG
    if suffix in SQLITE_SUFFIXES:
        return FileKind.SQLITE
    if suffix in CODE_SUFFIXES:
        return FileKind.CODE
    return FileKind.TEXT


def _is_excluded(path: Path, root: Path, excluded_paths: set[Path]) -> bool:
    resolved = path.resolve()
    if any(resolved == excluded or excluded in resolved.parents for excluded in excluded_paths):
        return True
    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        relative_parts = path.parts
    return any(part in EXCLUDED_DIRS for part in relative_parts)


def iter_scan_files(
    root: str | Path,
    *,
    excluded_paths: Iterable[str | Path] | None = None,
) -> Iterable[Path]:
    """Yield files under a root while skipping common dependency and cache paths."""
    root_path = Path(root)
    excluded = {Path(item).resolve() for item in excluded_paths or ()}

    if root_path.is_file():
        if not _is_excluded(root_path, root_path.parent, excluded):
            yield root_path
        return

    for dirpath, dirnames, filenames in os.walk(root_path):
        current = Path(dirpath)
        dirnames[:] = [
            dirname
            for dirname in dirnames
            if dirname not in EXCLUDED_DIRS
            and not _is_excluded(current / dirname, root_path, excluded)
        ]
        if _is_excluded(current, root_path, excluded):
            continue
        for filename in filenames:
            path = current / filename
            if not _is_excluded(path, root_path, excluded):
                yield path


def scan_path(
    root: str | Path,
    *,
    salt: bytes | None = None,
    excluded_paths: Iterable[str | Path] | None = None,
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> list[Finding]:
    """Scan a file or directory tree."""
    findings: list[Finding] = []
    for path in iter_scan_files(root, excluded_paths=excluded_paths):
        findings.extend(
            scan_file(path, salt=salt, max_text_bytes=max_text_bytes)
        )
    return sorted(findings)


def scan_sqlite(
    path: str | Path,
    *,
    salt: bytes | None = None,
) -> list[Finding]:
    """Scan SQLite key/value tables without exposing raw values."""
    file_path = Path(path)
    scan_salt = salt if salt is not None else secrets.token_bytes(32)
    findings: set[Finding] = set()

    try:
        conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
    except sqlite3.Error:
        return []

    try:
        cursor = conn.cursor()
        tables = [
            row[0]
            for row in cursor.execute("select name from sqlite_master where type='table'")
        ]
        for table in tables:
            columns = [row[1] for row in cursor.execute(f'pragma table_info("{table}")')]
            lower_columns = {column.lower(): column for column in columns}
            if "key" not in lower_columns or "value" not in lower_columns:
                continue

            key_col = lower_columns["key"]
            value_col = lower_columns["value"]
            for row_no, (key, value) in enumerate(
                cursor.execute(f'select "{key_col}", "{value_col}" from "{table}"'),
                start=1,
            ):
                key_text = "" if key is None else str(key)
                value_text = "" if value is None else str(value)
                if looks_like_placeholder(value_text):
                    continue

                kind = classify_key_name(key_text) or classify_value(value_text)
                if kind is None:
                    continue

                findings.add(
                    Finding(
                        category=kind.value,
                        path=file_path.as_posix(),
                        line=row_no,
                        key=f"{table}.{key_text}",
                        fingerprint=fingerprint_secret(value_text, salt=scan_salt),
                    )
                )
    except sqlite3.Error:
        return []
    finally:
        conn.close()

    return sorted(findings)
