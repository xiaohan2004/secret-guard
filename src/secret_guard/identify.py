from __future__ import annotations

import re
import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass


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

SECRET_VALUE_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ASIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    re.compile(r"ghp_[0-9A-Za-z]{36}"),
    re.compile(r"gho_[0-9A-Za-z]{36}"),
    re.compile(r"github_pat_[0-9A-Za-z_]{20,}"),
    re.compile(r"glpat-[0-9A-Za-z_-]{20,}"),
    re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |)PRIVATE KEY-----"),
)

TOKEN_COUNT_KEYS = {
    "maxtokens",
    "mintokens",
    "tokencount",
    "tokenscount",
    "totaltokens",
    "numtokens",
}

COMMON_PUBLIC_IPS = {
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
}

COMMON_PORTS = {
    20,
    21,
    22,
    25,
    53,
    80,
    110,
    123,
    143,
    443,
    465,
    587,
    993,
    995,
    3000,
    3306,
    5000,
    5432,
    6379,
    8000,
    8080,
    8443,
    9000,
    27017,
}

IP_PORT_PATTERN = re.compile(
    r"^(?P<ip>(?:\d{1,3}\.){3}\d{1,3}):(?P<port>\d{1,5})$"
)

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


@dataclass(frozen=True)
class PublicEndpoint:
    """A public IP address with a TCP/UDP port."""

    ip: str
    port: int


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


def is_high_confidence_secret_value(value: str) -> bool:
    """Return whether a value matches a high-confidence secret pattern."""
    return any(pattern.search(value) for pattern in SECRET_VALUE_PATTERNS)


def is_public_ip(value: str) -> bool:
    """Return whether a value is a public IPv4 address."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def is_common_public_ip(value: str, *, common_public_ips: Iterable[str] | None = None) -> bool:
    """Return whether a public IP is in the common allow-list."""
    common_ips = set(common_public_ips or COMMON_PUBLIC_IPS)
    return value in common_ips


def is_interesting_public_ip(
    value: str,
    *,
    common_public_ips: Iterable[str] | None = None,
) -> bool:
    """Return whether an IPv4 address is public and not a common public service IP."""
    return is_public_ip(value) and not is_common_public_ip(
        value,
        common_public_ips=common_public_ips,
    )


def parse_ip_port(value: str) -> PublicEndpoint | None:
    """Parse an IPv4 host:port string."""
    match = IP_PORT_PATTERN.match(value.strip())
    if not match:
        return None

    try:
        port = int(match.group("port"))
    except ValueError:
        return None
    if not 0 < port <= 65535:
        return None

    return PublicEndpoint(ip=match.group("ip"), port=port)


def is_unusual_public_endpoint(
    value: str,
    *,
    common_public_ips: Iterable[str] | None = None,
    common_ports: Iterable[int] | None = None,
) -> bool:
    """Return whether a value is a public IP with an uncommon port."""
    endpoint = parse_ip_port(value)
    if endpoint is None:
        return False

    ports = set(common_ports or COMMON_PORTS)
    return (
        is_interesting_public_ip(endpoint.ip, common_public_ips=common_public_ips)
        and endpoint.port not in ports
    )
