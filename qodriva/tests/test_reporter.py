"""Tests for report generation and the guarantees about its content."""

import json
import os
import socket
import subprocess

import pytest

from qodriva.main import run_analysis
from qodriva.models import Severity
from qodriva.reporter import render_json, render_text, write_json_report
from tests import fakes


@pytest.fixture
def secret_project(make_project):
    return make_project(
        {
            ".git/HEAD": "ref: refs/heads/main\n",
            ".gitignore": "__pycache__/\n",
            ".env": f"SERVICE_TOKEN={fakes.PASSWORD}\n",
            "src/app.py": f'AWS_KEY = "{fakes.AWS_ACCESS_KEY_ID}"\nDB = "postgres://app_user:{fakes.PASSWORD}@db.internal/app"\n',
            "config/prod.yml": f"password: {fakes.PASSWORD}\n",
            "keys/server.pem": fakes.PRIVATE_KEY_HEADER + "\n",
            "notes.tmp": "x\n",
            "requirements.txt": "requests==2.31.0\n",
        }
    )


def test_report_never_contains_secret_values(secret_project):
    report = run_analysis(secret_project)
    assert len([f for f in report.findings if f.category == "secrets"]) >= 4  # the test is not vacuous
    for output in (render_text(report), render_text(report, use_color=True), render_json(report)):
        for secret in fakes.ALL_SECRETS:
            assert secret not in output


def test_report_does_not_expose_absolute_paths(secret_project):
    report = run_analysis(secret_project)
    for output in (render_text(report), render_json(report)):
        assert str(secret_project) not in output
        assert str(secret_project.parent) not in output
    assert report.to_dict()["project"] == {"name": "project"}


def test_json_structure(secret_project):
    data = json.loads(render_json(run_analysis(secret_project)))
    assert list(data) == [
        "tool", "generated_at", "project", "notice", "summary", "structure",
        "secret_scan", "git", "dependencies", "findings",
    ]  # fmt: skip
    assert data["tool"]["name"] == "qodriva"
    assert data["summary"]["total"] == len(data["findings"])
    assert data["summary"]["errors"] == sum(1 for f in data["findings"] if f["severity"] == "ERROR")
    assert data["structure"]["total_files"] == 7
    assert data["dependencies"]["vulnerability_check"] == "not performed"
    assert set(data["findings"][0]) == {"severity", "category", "rule", "message", "path", "line", "suggestion"}


def test_findings_are_sorted_from_most_to_least_severe(secret_project):
    ranks = [f.severity.rank for f in run_analysis(secret_project).findings]
    assert ranks == sorted(ranks)
    assert ranks[0] == Severity.ERROR.rank


def test_text_report_uses_the_three_levels_and_shows_suggestions(secret_project):
    text = render_text(run_analysis(secret_project))
    for label in ("[ERROR]", "[WARNING]", "[INFO]"):
        assert label in text
    assert "-> " in text
    assert "Summary:" in text
    assert "does not check dependencies for known vulnerabilities" in text
    assert "not a complete security solution" in text


def test_colors_are_optional(secret_project):
    report = run_analysis(secret_project)
    assert "\x1b[" not in render_text(report, use_color=False)
    assert "\x1b[" in render_text(report, use_color=True)


def test_terminal_output_caps_findings_per_rule_but_json_keeps_all(make_project):
    report = run_analysis(make_project({f"file{i}.tmp": "x" for i in range(30)}))
    assert "10 more 'structure.temporary-file'" in render_text(report)
    temporary = [f for f in json.loads(render_json(report))["findings"] if f["rule"] == "structure.temporary-file"]
    assert len(temporary) == 30


def test_empty_project(make_project):
    report = run_analysis(make_project())
    assert not report.has_errors
    assert report.counts == {"errors": 0, "warnings": 0, "info": 1}
    assert "Files: 0" in render_text(report)


def test_write_json_report_never_overwrites_by_default(make_project, tmp_path):
    report = run_analysis(make_project({"a.py": "x = 1\n"}))
    target = tmp_path / "report.json"
    write_json_report(report, target)
    assert json.loads(target.read_text(encoding="utf-8"))["tool"]["name"] == "qodriva"
    with pytest.raises(FileExistsError):
        write_json_report(report, target)
    write_json_report(report, target, overwrite=True)


def snapshot(root):
    state = {}
    for folder, directories, files in os.walk(root):
        for name in directories:
            state[os.path.join(folder, name)] = None
        for name in files:
            path = os.path.join(folder, name)
            with open(path, "rb") as handle:
                state[path] = (handle.read(), os.stat(path).st_mtime_ns)
    return state


def test_analysis_does_not_modify_the_project(secret_project):
    before = snapshot(secret_project)
    report = run_analysis(secret_project)
    render_text(report)
    render_json(report)
    assert snapshot(secret_project) == before


def test_analysis_is_local_only(secret_project, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access or an external process was attempted")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    report = run_analysis(secret_project)
    render_text(report)
    render_json(report)
