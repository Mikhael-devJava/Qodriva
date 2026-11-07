"""Tests for the command-line interface."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from qodriva import __version__
from qodriva.main import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests import fakes

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_help_shows_the_banner_and_exits_successfully(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Bem-vindo ao Qodriva!" in out
    assert "--json" in out and "--output" in out


def test_without_arguments_shows_welcome_and_usage(capsys):
    assert main([]) == EXIT_OK
    out = capsys.readouterr().out
    assert "Bem-vindo ao Qodriva!" in out
    assert "usage: qodriva" in out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_nonexistent_directory_returns_an_error(tmp_path, capsys):
    assert main([str(tmp_path / "does-not-exist")]) == EXIT_ERROR
    assert "does not exist" in capsys.readouterr().err


def test_file_instead_of_directory_returns_an_error(make_project, capsys):
    root = make_project({"file.txt": "x"})
    assert main([str(root / "file.txt")]) == EXIT_ERROR
    assert "not a directory" in capsys.readouterr().err


def test_text_report_goes_to_stdout_and_the_banner_to_stderr(make_project, capsys):
    root = make_project({"main.py": "print('hi')\n"})
    assert main([str(root)]) == EXIT_OK
    captured = capsys.readouterr()
    assert "Qodriva report for 'project'" in captured.out
    assert "Bem-vindo ao Qodriva!" not in captured.out
    assert "Bem-vindo ao Qodriva!" in captured.err


def test_no_banner_option(make_project, capsys):
    root = make_project({"main.py": "x = 1\n"})
    main([str(root), "--no-banner"])
    assert "Bem-vindo" not in capsys.readouterr().err


def test_json_output_is_valid_and_has_no_banner(make_project, capsys):
    root = make_project({"main.py": "x = 1\n"})
    assert main([str(root), "--json"]) == EXIT_OK
    captured = capsys.readouterr()
    assert json.loads(captured.out)["tool"]["name"] == "qodriva"
    assert captured.err == ""


def test_exit_code_signals_error_level_findings(make_project, capsys):
    root = make_project({"app.py": f'key = "{fakes.AWS_ACCESS_KEY_ID}"\n'})
    assert main([str(root), "--json"]) == EXIT_FINDINGS
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert any(f["rule"] == "secrets.aws-access-key-id" and f["line"] == 1 for f in findings)


def test_output_option_saves_a_json_report(make_project, tmp_path, capsys):
    root = make_project({"main.py": "x = 1\n"})
    target = tmp_path / "report.json"
    assert main([str(root), "--output", str(target)]) == EXIT_OK
    assert json.loads(target.read_text(encoding="utf-8"))["project"]["name"] == "project"
    assert "Qodriva report for" in capsys.readouterr().out  # the terminal report is still printed


def test_output_never_overwrites_without_force(make_project, tmp_path, capsys):
    root = make_project({"main.py": "x = 1\n"})
    target = tmp_path / "report.json"
    target.write_text("precious data", encoding="utf-8")
    assert main([str(root), "--output", str(target)]) == EXIT_ERROR
    assert "already exists" in capsys.readouterr().err
    assert target.read_text(encoding="utf-8") == "precious data"
    assert main([str(root), "--output", str(target), "--force"]) == EXIT_OK
    assert json.loads(target.read_text(encoding="utf-8"))["tool"]["name"] == "qodriva"


def test_output_in_a_missing_directory_is_an_error(make_project, tmp_path, capsys):
    root = make_project({"main.py": "x = 1\n"})
    assert main([str(root), "--output", str(tmp_path / "missing" / "r.json")]) == EXIT_ERROR
    assert "does not exist" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_invalid_large_file_threshold_is_rejected(make_project, value):
    root = make_project()
    with pytest.raises(SystemExit) as exc:
        main([str(root), "--large-file-mb", value])
    assert exc.value.code == 2


def test_large_file_threshold_option(make_project, capsys):
    root = make_project({"data.bin": b"x" * 200_000})
    main([str(root), "--json", "--large-file-mb", "0.1"])
    findings = json.loads(capsys.readouterr().out)["findings"]
    assert [f["path"] for f in findings if f["rule"] == "structure.large-file"] == ["data.bin"]


def test_no_default_excludes_option(make_project, capsys):
    root = make_project({"main.py": "x", "node_modules/lib.js": "x"})
    main([str(root), "--json"])
    assert json.loads(capsys.readouterr().out)["structure"]["total_files"] == 1
    main([str(root), "--json", "--no-default-excludes"])
    assert json.loads(capsys.readouterr().out)["structure"]["total_files"] == 2


def test_module_entry_point():
    result = subprocess.run(
        [sys.executable, "-m", "qodriva", "--help"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "usage: qodriva" in result.stdout
    assert "Bem-vindo ao Qodriva!" in result.stdout
