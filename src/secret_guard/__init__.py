"""secret-guard public API."""

from .identify import (
    Assignment,
    PublicEndpoint,
    SensitiveKind,
    classify_key_name,
    classify_value,
    is_high_confidence_secret_value,
    is_common_public_ip,
    is_interesting_public_ip,
    is_public_ip,
    is_sensitive_key,
    is_unusual_public_endpoint,
    looks_like_placeholder,
    normalize_key_name,
    parse_assignment,
    parse_ip_port,
)
from .findings import Finding
from .scan import FileKind, classify_file, fingerprint_secret, has_findings, iter_scan_files, scan_file, scan_path, scan_text

__all__ = [
    "Assignment",
    "Finding",
    "FileKind",
    "PublicEndpoint",
    "SensitiveKind",
    "classify_key_name",
    "classify_value",
    "is_common_public_ip",
    "is_high_confidence_secret_value",
    "is_interesting_public_ip",
    "is_public_ip",
    "is_sensitive_key",
    "is_unusual_public_endpoint",
    "looks_like_placeholder",
    "normalize_key_name",
    "parse_assignment",
    "parse_ip_port",
    "classify_file",
    "fingerprint_secret",
    "has_findings",
    "iter_scan_files",
    "scan_file",
    "scan_path",
    "scan_text",
]
