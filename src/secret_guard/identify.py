from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Iterable


SECRET_KEY_PARTS = (
    "api_key",
    "apikey",
    "access_key",
    "accesskey",
    "secret",
    "token",
    "password",
    "passwd",
    "credential",
    "private_key",
    "privatekey",
    "client_secret",
    "clientsecret",
    "refresh_token",
    "refreshtoken",
    "access_token",
    "accesstoken",
    "id_token",
    "idtoken",
    "auth_token",
    "authtoken",
    "bearer",
    "authorization",
    "signing_secret",
    "signingsecret",
    "webhook_secret",
    "webhooksecret",
)

SECRET_KEY_PATTERNS = (
    re.compile(r"api.*key"),
    re.compile(r"key.*api"),
    re.compile(r"access.*key"),
    re.compile(r"secret.*key"),
    re.compile(r"private.*key"),
    re.compile(r"client.*secret"),
    re.compile(r"refresh.*token"),
    re.compile(r"access.*token"),
    re.compile(r"auth.*token"),
    re.compile(r"id.*token"),
    re.compile(r"signing.*secret"),
    re.compile(r"webhook.*secret"),
)

TOKEN_COUNT_KEYS = {
    "maxtokens",
    "mintokens",
    "tokencount",
    "tokenscount",
    "totaltokens",
    "numtokens",
}

ASSIGNMENT_PATTERN = re.compile(
    r"^\s*"
    r"(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)"
    r"\s*(?P<operator>[:=])\s*"
    r"(?P<quote>[\"']?)"
    r"(?P<value>.*?)"
    r"(?P=quote)"
    r"\s*(?:#.*)?$"
)


@dataclass(frozen=True)
class Assignment:
    """A simple key/value assignment parsed from one text line."""

    key: str
    value: str
    operator: str
    quote: str


def normalize_key_name(key: str) -> str:
    """Normalize a field name for fuzzy secret-key matching."""
    return re.sub(r"[^a-z0-9]", "", key.lower())


def is_sensitive_key(
    key: str,
    *,
    extra_sensitive_keys: Iterable[str] | None = None,
) -> bool:
    """Return whether a field name looks like it may contain sensitive data."""
    normalized = key.lower()
    compact = normalize_key_name(key)
    explicit_keys = {item.lower() for item in extra_sensitive_keys or ()}
    explicit_compact_keys = {normalize_key_name(item) for item in explicit_keys}

    if compact in TOKEN_COUNT_KEYS:
        return False

    return (
        normalized in explicit_keys
        or compact in explicit_compact_keys
        or any(part in normalized or part in compact for part in SECRET_KEY_PARTS)
        or any(
            pattern.search(normalized) or pattern.search(compact)
            for pattern in SECRET_KEY_PATTERNS
        )
    )


def parse_assignment(line: str) -> Assignment | None:
    """Parse a simple key/value assignment from one text line."""
    match = ASSIGNMENT_PATTERN.match(line)
    if not match:
        return None

    quote = match.group("quote")
    value = match.group("value")
    if quote:
        value = value.rstrip()
    else:
        value = value.strip()

    return Assignment(
        key=match.group("key"),
        value=value,
        operator=match.group("operator"),
        quote=quote,
    )
