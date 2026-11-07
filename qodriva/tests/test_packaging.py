"""Consistency checks for the project metadata."""

import tomllib
from pathlib import Path

from qodriva import __version__

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def load_project():
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def test_version_matches_the_package():
    assert load_project()["version"] == __version__


def test_there_are_no_runtime_dependencies():
    assert load_project()["dependencies"] == []


def test_license_is_mit():
    assert load_project()["license"] == "MIT"
