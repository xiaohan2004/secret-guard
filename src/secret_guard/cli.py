from __future__ import annotations

import argparse
from collections.abc import Sequence

from .redaction import redact_text


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Redact secret-looking values from text.")
    parser.add_argument("text", nargs="?", default="", help="Text to redact.")
    args = parser.parse_args(argv)
    print(redact_text(args.text))
    return 0
