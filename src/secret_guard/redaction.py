from __future__ import annotations

import json
import re
from typing import Any

from .identify import is_sensitive_key


DEFAULT_REPLACEMENT = "[secret hidden]"
INLINE_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|token|password|passwd|credential)"
    r"(\s*[:=]\s*)"
    r"([^\s,;&\"'}]+)"
)
URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(://[^/\s:@]+:)([^@\s/]+)(@)")


def redact_text(text: str, *, replacement: str = DEFAULT_REPLACEMENT) -> str:
    """Redact inline secret-looking values from text."""
    text = URL_CREDENTIAL_PATTERN.sub(rf"\1{replacement}\3", text)
    return INLINE_SECRET_PATTERN.sub(rf"\1\2{replacement}", text)


def one_line_preview(text: str) -> str:
    """Render text as a single-line preview."""
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def redact_value(
    key: str,
    value: Any,
    *,
    replacement: str = DEFAULT_REPLACEMENT,
    max_length: int | None = 80,
    multiline: bool = False,
    extra_sensitive_keys: set[str] | None = None,
    ignored_keys: set[str] | None = None,
) -> str:
    """Render a value safely based on its key and content."""
    if is_sensitive_key(
        key,
        extra_sensitive_keys=extra_sensitive_keys,
        ignored_keys=ignored_keys,
    ):
        return replacement

    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = redact_text(text, replacement=replacement)
    if not multiline:
        text = one_line_preview(text)
    if max_length is None or max_length < 0 or len(text) <= max_length:
        return text
    return text[:max_length] + f"... [truncated, {len(text)} chars total]"
