"""Tests for the command-line interface skeleton."""

import subprocess
import sys
from pathlib import Path

import pytest

from qodriva import __version__
from qodriva.main import EXIT_ERROR, EXIT_OK, main

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_help_exits_successfully(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "--json" in capsys.readouterr().out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_missing_path_argument_is_rejected():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_nonexistent_directory_returns_error(tmp_path, capsys):
    code = main([str(tmp_path / "does-not-exist")])
    assert code == EXIT_ERROR
    assert "does not exist" in capsys.readouterr().err


def test_file_instead_of_directory_returns_error(tmp_path, capsys):
    a_file = tmp_path / "file.txt"
    a_file.write_text("hello")
    code = main([str(a_file)])
    assert code == EXIT_ERROR
    assert "not a directory" in capsys.readouterr().err


def test_valid_directory_returns_ok(tmp_path):
    assert main([str(tmp_path)]) == EXIT_OK


def test_module_entry_point_shows_help():
    result = subprocess.run(
        [sys.executable, "-m", "qodriva", "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "usage: qodriva" in result.stdout
