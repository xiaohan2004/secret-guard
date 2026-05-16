"""secret-guard public API."""

from .identify import is_sensitive_key, normalize_key_name

__all__ = ["is_sensitive_key", "normalize_key_name"]
