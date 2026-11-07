"""Helpers for terminal output."""

from __future__ import annotations

import os
from typing import TextIO

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33", "cyan": "36"}
_RESET = "\033[0m"
_WINDOWS_ANSI_HINTS = ("WT_SESSION", "ANSICON", "TERM_PROGRAM", "COLORTERM")


def supports_color(stream: TextIO) -> bool:
    """Return True if ANSI colors can safely be used on ``stream``."""
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None or not isatty():
        return False
    if os.name == "nt":
        return any(os.environ.get(name) for name in _WINDOWS_ANSI_HINTS)
    return True


def paint(text: str, *styles: str, enabled: bool) -> str:
    """Wrap ``text`` in ANSI styles when ``enabled`` is true."""
    if not enabled or not styles:
        return text
    codes = ";".join(_CODES[style] for style in styles)
    return f"\033[{codes}m{text}{_RESET}"
