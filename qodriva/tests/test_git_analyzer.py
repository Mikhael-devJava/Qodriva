"""Tests for the read-only Git analysis."""

import os
import subprocess

import pytest

from qodriva import git_analyzer
from qodriva.git_analyzer import GitIgnore, analyze_git, sensitive_description
from qodriva.models import Severity
from qodriva.scanner import scan_project


def run(root):
    return analyze_git(root, scan_project(root).files)


def rules(analysis):
    return [finding.rule for finding in analysis.findings]


@pytest.mark.parametrize(
    "patterns,path,is_dir,expected",
    [
        ([".env"], ".env", False, True),
        ([".env"], "config/.env", False, True),
        ([".env"], ".env.local", False, False),
        ([".env*"], ".env.local", False, True),
        (["*.pem"], "certs/server.pem", False, True),
        (["node_modules/"], "node_modules/pkg/index.js", False, True),
        (["node_modules/"], "node_modules", False, False),
        (["/secrets.json"], "secrets.json", False, True),
        (["/secrets.json"], "sub/secrets.json", False, False),
        (["docs/*.md"], "docs/a.md", False, True),
        (["docs/*.md"], "docs/sub/a.md", False, False),
        (["**/id_rsa"], "a/b/id_rsa", False, True),
        (["logs/**"], "logs/a/b.log", False, True),
        (["a/**/b.txt"], "a/x/y/b.txt", False, True),
        (["a/**/b.txt"], "a/b.txt", False, True),
        (["*.log", "!keep.log"], "keep.log", False, False),
        (["*.log", "!keep.log"], "other.log", False, True),
        (["build/", "!build/keep.txt"], "build/keep.txt", False, True),
        (["# comment", "", "   "], "comment", False, False),
        (["\\#literal"], "#literal", False, True),
        (["file?.txt"], "file1.txt", False, True),
        (["file?.txt"], "file10.txt", False, False),
        (["[ab].txt"], "a.txt", False, True),
        (["[!ab].txt"], "a.txt", False, False),
        (["[!ab].txt"], "c.txt", False, True),
        (["*.pyc"], "README.md", False, False),
    ],
)
def test_gitignore_matching(patterns, path, is_dir, expected):
    assert GitIgnore(patterns).is_ignored(path, is_dir) is expected


@pytest.mark.parametrize(
    "name",
    [".env", ".env.local", "server.pem", "private.key", "id_rsa", "credentials.json", "service-account-prod.json", ".pypirc", "main.tfstate"],
)
def test_known_sensitive_names(name):
    assert sensitive_description(name) is not None


@pytest.mark.parametrize(
    "name", [".env.example", ".env.sample", "id_rsa.pub", "main.py", "README.md", "environment.py", "keyboard.py"]
)
def test_other_names_are_not_sensitive(name):
    assert sensitive_description(name) is None


def test_detects_repository(make_project):
    analysis = run(make_project({".git/HEAD": "ref: refs/heads/main\n", ".gitignore": "*.pyc\n"}))
    assert analysis.is_repository
    assert analysis.has_gitignore


def test_a_git_file_counts_as_a_repository(make_project):
    # Worktrees and submodules use a ".git" file instead of a directory.
    assert run(make_project({".git": "gitdir: ../elsewhere\n"})).is_repository


def test_directory_without_repository(make_project):
    analysis = run(make_project({"main.py": "x"}))
    assert not analysis.is_repository
    assert rules(analysis) == ["git.no-repository"]


def test_repository_without_gitignore_is_warned(make_project):
    analysis = run(make_project({".git/HEAD": "x"}))
    finding = next(f for f in analysis.findings if f.rule == "git.missing-gitignore")
    assert finding.severity is Severity.WARNING


def test_sensitive_file_that_is_not_ignored_is_an_error(make_project):
    analysis = run(make_project({".git/HEAD": "x", ".gitignore": "*.pyc\n", ".env": "A=1\n"}))
    errors = [f for f in analysis.findings if f.rule == "git.sensitive-file-not-ignored"]
    assert [(f.path, f.severity) for f in errors] == [(".env", Severity.ERROR)]
    assert analysis.sensitive_files == [
        {"path": ".env", "description": "environment file", "ignored_by_gitignore": False}
    ]


def test_sensitive_file_that_is_ignored_is_informational(make_project):
    analysis = run(make_project({".git/HEAD": "x", ".gitignore": ".env\n", ".env": "A=1\n"}))
    assert "git.sensitive-file-ignored" in rules(analysis)
    assert "git.sensitive-file-not-ignored" not in rules(analysis)


def test_template_files_are_not_reported(make_project):
    analysis = run(make_project({".git/HEAD": "x", ".gitignore": "*.pyc\n", ".env.example": "A=\n"}))
    assert analysis.sensitive_files == []


def test_without_a_repository_sensitive_files_are_informational(make_project):
    analysis = run(make_project({".env": "A=1\n"}))
    present = [f for f in analysis.findings if f.rule == "git.sensitive-file-present"]
    assert [f.severity for f in present] == [Severity.INFO]
    assert analysis.sensitive_files[0]["ignored_by_gitignore"] is None


def test_unprotected_patterns_are_reported(make_project):
    analysis = run(make_project({".git/HEAD": "x", ".gitignore": ".env\n"}))
    assert analysis.unprotected_patterns == [".env.*", "*.pem", "*.key", "id_rsa"]
    assert "git.unprotected-patterns" in rules(analysis)


def test_fully_protected_repository_has_no_pattern_warning(make_project):
    gitignore = ".env\n.env.*\n*.pem\n*.key\nid_rsa\n"
    analysis = run(make_project({".git/HEAD": "x", ".gitignore": gitignore}))
    assert analysis.unprotected_patterns == []
    assert "git.unprotected-patterns" not in rules(analysis)


def test_unreadable_gitignore_is_reported(make_project, monkeypatch):
    root = make_project({".git/HEAD": "x", ".gitignore": ".env\n", ".env": "A=1\n"})
    real_open = open

    def fake_open(path, *args, **kwargs):
        if os.fspath(path).endswith(".gitignore"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(git_analyzer, "open", fake_open, raising=False)
    analysis = run(root)
    assert "git.unreadable-gitignore" in rules(analysis)
    assert "git.sensitive-file-not-ignored" in rules(analysis)  # the analysis still completes


def test_no_external_process_is_ever_started(make_project, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("an external process was started")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    run(make_project({".git/HEAD": "x", ".gitignore": ".env\n", ".env": "A=1\n"}))
