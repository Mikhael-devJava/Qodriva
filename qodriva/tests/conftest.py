"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def make_project(tmp_path):
    """Build a project directory from a {relative path: text | bytes} mapping.

    A key ending with "/" creates an empty directory.
    """

    def _make(files: dict[str, str | bytes] | None = None, name: str = "project") -> Path:
        root = tmp_path / name
        root.mkdir()
        for relative, content in (files or {}).items():
            target = root / relative
            if relative.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")
        return root

    return _make
