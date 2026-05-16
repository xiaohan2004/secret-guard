"""secret-guard public API."""

from .identify import Assignment, is_sensitive_key, normalize_key_name, parse_assignment

__all__ = ["Assignment", "is_sensitive_key", "normalize_key_name", "parse_assignment"]
