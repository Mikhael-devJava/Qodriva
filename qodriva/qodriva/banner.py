"""Welcome banner shown when Qodriva is started from the terminal."""

from __future__ import annotations

from typing import TextIO

from qodriva import __version__
from qodriva.terminal import paint, supports_color

# Plain ASCII, so it prints correctly on any terminal encoding.
LOGO = (
    r"  ___              _        _",
    r" / _ \   ___    __| | _ __ (_)__   __  __ _",
    r"| | | | / _ \  / _` || '__|| |\ \ / / / _` |",
    r"| |_| || (_) || (_| || |   | | \ V / | (_| |",
    r" \__\_\ \___/  \__,_||_|   |_|  \_/   \__,_|",
)
WELCOME = "Bem-vindo ao Qodriva!"
TAGLINE = "Local static analysis for your projects"


def render_banner(*, use_color: bool = False) -> str:
    lines = [""]
    lines += ["  " + paint(line, "cyan", "bold", enabled=use_color) for line in LOGO]
    lines += [
        "",
        "  " + paint(WELCOME, "bold", enabled=use_color),
        f"  {TAGLINE}  |  v{__version__}",
        "",
    ]
    return "\n".join(lines)


def print_banner(stream: TextIO) -> None:
    stream.write(render_banner(use_color=supports_color(stream)) + "\n")
    stream.flush()
