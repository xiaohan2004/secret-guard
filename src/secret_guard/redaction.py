from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from .identify import is_sensitive_key
from .scan import fingerprint_secret


DEFAULT_REPLACEMENT = "[secret hidden]"
INLINE_SECRET_PATTERN = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|secret|token|password|passwd|credential)"
    r"(\s*[:=]\s*)"
    r"([^\s,;&\"'}]+)"
)
URL_CREDENTIAL_PATTERN = re.compile(r"(?i)(://[^/\s:@]+:)([^@\s/]+)(@)")


@dataclass(frozen=True)
class RedactedValue:
    """A safe-to-render redaction result."""

    key: str
    text: str
    redacted: bool
    fingerprint: str | None = None

    def as_text(self) -> str:
        return self.text

    def as_dict(self) -> dict[str, str | bool | None]:
        return {
            "key": self.key,
            "text": self.text,
            "redacted": self.redacted,
            "fingerprint": self.fingerprint,
        }

    def as_json(self) -> str:
        return json.dumps(self.as_dict(), ensure_ascii=False)


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


def redact_result(
    key: str,
    value: Any,
    *,
    replacement: str = DEFAULT_REPLACEMENT,
    max_length: int | None = 80,
    multiline: bool = False,
    extra_sensitive_keys: set[str] | None = None,
    ignored_keys: set[str] | None = None,
    salt: bytes | None = None,
) -> RedactedValue:
    """Return a structured redaction result that never includes the raw secret."""
    original = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    text = redact_value(
        key,
        value,
        replacement=replacement,
        max_length=max_length,
        multiline=multiline,
        extra_sensitive_keys=extra_sensitive_keys,
        ignored_keys=ignored_keys,
    )
    redacted = text != (original if multiline else one_line_preview(original))
    fingerprint = fingerprint_secret(original, salt=salt) if redacted else None
    return RedactedValue(
        key=key,
        text=text,
        redacted=redacted,
        fingerprint=fingerprint,
    )
