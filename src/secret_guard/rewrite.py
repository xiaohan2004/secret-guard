from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from .identify import is_sensitive_key, looks_like_placeholder, parse_assignment
from .redaction import DEFAULT_REPLACEMENT
from .scan import EXCLUDED_DIRS, MAX_TEXT_BYTES, fingerprint_secret


ORIGINAL_PLACEHOLDER = "[secret original]"


@dataclass(frozen=True)
class RewriteChange:
    """One planned line-level rewrite."""

    line: int
    key: str
    original_fingerprint: str
    replacement: str


@dataclass(frozen=True)
class RewritePlan:
    """A dry-run rewrite plan."""

    path: str
    original_preview: str
    rewritten_text: str
    changes: tuple[RewriteChange, ...]

    def has_changes(self) -> bool:
        return bool(self.changes)

    def diff(self) -> str:
        return "".join(
            difflib.unified_diff(
                self.original_preview.splitlines(keepends=True),
                self.rewritten_text.splitlines(keepends=True),
                fromfile=self.path,
                tofile=self.path,
            )
        )


@dataclass(frozen=True)
class RewriteApplyResult:
    """Result of applying or previewing a rewrite plan."""

    path: str
    changed: bool
    backup_path: str | None = None


def can_rewrite_path(path: str | Path) -> bool:
    """Return whether a path is safe to rewrite."""
    file_path = Path(path)
    return not any(part in EXCLUDED_DIRS for part in file_path.parts)


def build_rewrite_plan(
    path: str | Path,
    *,
    replacement: str = DEFAULT_REPLACEMENT,
    remove: bool = False,
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> RewritePlan:
    """Build a dry-run rewrite plan for one text file."""
    file_path = Path(path)
    if not can_rewrite_path(file_path):
        return RewritePlan(file_path.as_posix(), "", "", ())

    data = file_path.read_bytes()
    if b"\0" in data[:4096] or len(data) > max_text_bytes:
        return RewritePlan(file_path.as_posix(), "", "", ())

    original_text = data.decode("utf-8", errors="ignore")
    lines = original_text.splitlines(keepends=True)
    preview_lines = list(lines)
    rewritten_lines = list(lines)
    changes: list[RewriteChange] = []

    for index, line in enumerate(lines):
        assignment = parse_assignment(line.rstrip("\r\n"))
        if assignment is None:
            continue
        if not is_sensitive_key(assignment.key) or looks_like_placeholder(assignment.value):
            continue

        target_value = "" if remove else replacement
        rewritten_line = line.replace(assignment.value, target_value, 1)
        if rewritten_line == line:
            continue

        preview_lines[index] = line.replace(assignment.value, ORIGINAL_PLACEHOLDER, 1)
        rewritten_lines[index] = rewritten_line
        changes.append(
            RewriteChange(
                line=index + 1,
                key=assignment.key,
                original_fingerprint=fingerprint_secret(assignment.value),
                replacement=target_value,
            )
        )

    return RewritePlan(
        path=file_path.as_posix(),
        original_preview="".join(preview_lines),
        rewritten_text="".join(rewritten_lines),
        changes=tuple(changes),
    )


def apply_rewrite_plan(
    plan: RewritePlan,
    *,
    in_place: bool = False,
    backup: bool = False,
) -> RewriteApplyResult:
    """Apply a rewrite plan only when explicitly requested."""
    if not in_place or not plan.has_changes():
        return RewriteApplyResult(path=plan.path, changed=False)

    file_path = Path(plan.path)
    backup_path: Path | None = None
    if backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        backup_path.write_text(file_path.read_text(encoding="utf-8"), encoding="utf-8")

    temp_path = file_path.with_suffix(file_path.suffix + ".tmp")
    temp_path.write_text(plan.rewritten_text, encoding="utf-8")
    temp_path.replace(file_path)

    return RewriteApplyResult(
        path=plan.path,
        changed=True,
        backup_path=backup_path.as_posix() if backup_path is not None else None,
    )
