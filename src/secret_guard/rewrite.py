from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from .identify import is_sensitive_key, looks_like_placeholder, parse_assignment
from .redaction import DEFAULT_REPLACEMENT
from .scan import MAX_TEXT_BYTES, fingerprint_secret


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


def build_rewrite_plan(
    path: str | Path,
    *,
    replacement: str = DEFAULT_REPLACEMENT,
    max_text_bytes: int = MAX_TEXT_BYTES,
) -> RewritePlan:
    """Build a dry-run rewrite plan for one text file."""
    file_path = Path(path)
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

        rewritten_line = line.replace(assignment.value, replacement, 1)
        if rewritten_line == line:
            continue

        preview_lines[index] = line.replace(assignment.value, ORIGINAL_PLACEHOLDER, 1)
        rewritten_lines[index] = rewritten_line
        changes.append(
            RewriteChange(
                line=index + 1,
                key=assignment.key,
                original_fingerprint=fingerprint_secret(assignment.value),
                replacement=replacement,
            )
        )

    return RewritePlan(
        path=file_path.as_posix(),
        original_preview="".join(preview_lines),
        rewritten_text="".join(rewritten_lines),
        changes=tuple(changes),
    )
