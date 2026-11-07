"""Tests for secret detection."""

import dataclasses
import json
import os

import pytest

from qodriva import secret_detector
from qodriva.models import Finding, Severity
from qodriva.scanner import scan_project
from qodriva.secret_detector import MAX_SCAN_BYTES, scan_files, scan_text
from tests import fakes


@pytest.mark.parametrize("rule,line", fakes.DETECTION_CASES)
def test_detects_known_patterns(rule, line):
    findings = scan_text("first line\n" + line + "\nlast line", "src/app.py")
    assert [(f.rule, f.line, f.path) for f in findings] == [(rule, 2, "src/app.py")]


def test_severities():
    assert scan_text(fakes.PRIVATE_KEY_HEADER, "k.pem")[0].severity is Severity.ERROR
    assert scan_text(f'key = "{fakes.AWS_ACCESS_KEY_ID}"', "a.py")[0].severity is Severity.ERROR
    assert scan_text(f'db_password = "{fakes.PASSWORD}"', "a.py")[0].severity is Severity.WARNING


@pytest.mark.parametrize(
    "line",
    [
        'password = os.getenv("DB_PASSWORD")',
        'api_key = "your-api-key-here"',
        'token = "${TOKEN_VALUE}"',
        'password = "********"',
        'secret = "changeme"',
        '"password": "<password>"',
        'password_hash = "pbkdf2:sha256:abcdefghijklmnop"',
        'tokenizer = "bert-base-uncased-model"',
        'secret_path = "/run/secrets/database"',
        "The password must contain at least eight characters",
        "https://github.com/org/repo",
        "AKIA is a prefix",
    ],
)
def test_ignores_placeholders_and_benign_code(line):
    assert scan_text(line, "a.py") == []


def test_reports_one_finding_per_line():
    line = f'x = "{fakes.AWS_ACCESS_KEY_ID}"; db_password = "{fakes.PASSWORD}"'
    assert len(scan_text(line, "a.py")) == 1


def test_real_secret_after_a_placeholder_on_the_same_line_is_found():
    line = f'a_password = "changeme-pass", b_password = "{fakes.PASSWORD}"'
    assert [f.rule for f in scan_text(line, "a.py")] == ["secrets.hardcoded-credential"]


def test_line_numbers_are_accurate_with_windows_line_endings():
    text = "one\r\ntwo\r\n" + f'db_password = "{fakes.PASSWORD}"\r\nfour\r\n'
    assert [f.line for f in scan_text(text, "a.py")] == [3]


def test_unquoted_values_are_only_detected_in_config_like_files():
    line = f"DB_PASSWORD={fakes.PASSWORD}"
    assert [f.rule for f in scan_text(line, ".env", config_like=True)] == ["secrets.config-credential"]
    assert scan_text(line, "script.py", config_like=False) == []


def test_config_rules_apply_by_file_type(make_project):
    pw = fakes.PASSWORD
    root = make_project(
        {
            ".env": f"DB_PASSWORD={pw}\n",
            "prod.env": f"API_TOKEN={pw}\n",
            "config/app.yml": f"password: {pw}\n",
            "app.py": f"DB_PASSWORD={pw}\n",
        }
    )
    findings, _ = scan_files(root, scan_project(root).files)
    assert sorted(f.path for f in findings) == [".env", "config/app.yml", "prod.env"]


def test_findings_never_contain_secret_values():
    text = "\n".join(line for _, line in fakes.DETECTION_CASES)
    findings = scan_text(text, "all.txt")
    assert len(findings) == len(fakes.DETECTION_CASES)
    dumped = json.dumps([f.to_dict() for f in findings]) + repr(findings) + "".join(str(f) for f in findings)
    for secret in fakes.ALL_SECRETS:
        assert secret not in dumped
        for start in range(len(secret) - 7):
            assert secret[start : start + 8] not in dumped


def test_finding_has_no_field_that_could_hold_a_secret():
    names = {field.name for field in dataclasses.fields(Finding)}
    assert names == {"severity", "category", "rule", "message", "path", "line", "suggestion"}


def test_binary_files_are_skipped(make_project):
    header = fakes.PRIVATE_KEY_HEADER.encode()
    root = make_project({"blob.dat": b"\x00\x01" + header, "image.png": header})
    findings, summary = scan_files(root, scan_project(root).files)
    assert findings == []
    assert (summary.skipped_binary, summary.files_scanned) == (2, 0)


def test_oversized_files_are_skipped(make_project):
    root = make_project({"huge.txt": "a" * (MAX_SCAN_BYTES + 1)})
    findings, summary = scan_files(root, scan_project(root).files)
    assert findings == []
    assert summary.skipped_too_large == 1


def test_invalid_utf8_is_tolerated(make_project):
    root = make_project({"legacy.txt": b"caf\xe9 \xff\n" + fakes.PRIVATE_KEY_HEADER.encode() + b"\n"})
    findings, summary = scan_files(root, scan_project(root).files)
    assert [f.rule for f in findings] == ["secrets.private-key"]
    assert summary.files_scanned == 1


def test_unreadable_file_is_reported_and_scan_continues(make_project, monkeypatch):
    root = make_project({"locked.txt": "x", "ok.py": f'db_password = "{fakes.PASSWORD}"\n'})
    real_open = open

    def fake_open(path, *args, **kwargs):
        if os.fspath(path).endswith("locked.txt"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(secret_detector, "open", fake_open, raising=False)
    findings, summary = scan_files(root, scan_project(root).files)
    assert summary.unreadable == 1
    assert {f.rule for f in findings} == {"secrets.unreadable-file", "secrets.hardcoded-credential"}


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a POSIX user that is not root",
)
def test_real_permission_denied_on_a_file(make_project):
    root = make_project({"locked.txt": "x"})
    locked = root / "locked.txt"
    locked.chmod(0)
    try:
        findings, summary = scan_files(root, scan_project(root).files)
    finally:
        locked.chmod(0o600)
    assert summary.unreadable == 1
    assert [f.rule for f in findings] == ["secrets.unreadable-file"]


def test_very_long_lines_do_not_hang():
    assert scan_text("a" * 300_000 + "://" + "b" * 300_000, "minified.js") == []


def test_empty_text():
    assert scan_text("", "empty.txt") == []
