"""Tests for the welcome banner."""

from qodriva import __version__
from qodriva.banner import LOGO, WELCOME, render_banner


def test_banner_welcomes_the_user_and_shows_the_version():
    banner = render_banner()
    assert "Bem-vindo ao Qodriva!" in banner
    assert WELCOME == "Bem-vindo ao Qodriva!"
    assert f"v{__version__}" in banner


def test_banner_is_plain_ascii_so_it_prints_on_any_terminal():
    assert render_banner().isascii()
    assert all(line.isascii() for line in LOGO)


def test_banner_colors_are_optional():
    assert "\x1b[" not in render_banner(use_color=False)
    assert "\x1b[" in render_banner(use_color=True)
