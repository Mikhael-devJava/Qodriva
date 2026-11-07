"""Tests for project structure analysis."""

import os

import pytest

from qodriva import scanner
from qodriva.models import Severity
from qodriva.scanner import DEFAULT_LARGE_FILE_BYTES, format_size, scan_project


def paths(result):
    return [entry.path for entry in result.files]


def test_lists_files_and_directories(make_project):
    root = make_project(
        {"main.py": "print(1)\n", "src/util.py": "x = 1\n", "src/pkg/mod.py": "y = 2\n", "docs/readme.md": "# hi\n"}
    )
    result = scan_project(root)
    assert paths(result) == ["docs/readme.md", "main.py", "src/pkg/mod.py", "src/util.py"]
    assert result.directories == ["docs", "src", "src/pkg"]
    assert result.max_depth == 2
    assert result.top_level == ["docs/", "main.py", "src/"]


def test_statistics(make_project):
    root = make_project({"a.py": "12345", "b.py": "123", "c.md": "1", "Makefile": "x"})
    stats = scan_project(root).statistics()
    assert stats["total_files"] == 4
    assert stats["total_size_bytes"] == 10
    assert stats["files_by_extension"] == {".py": 2, ".md": 1, "(no extension)": 1}
    assert stats["largest_files"][0] == {"path": "a.py", "size_bytes": 5}


@pytest.mark.parametrize(
    "excluded",
    ["node_modules", ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".tox", "package.egg-info"],
)
def test_dependency_and_environment_directories_are_skipped_by_default(make_project, excluded):
    root = make_project({"main.py": "x", f"{excluded}/inner.py": "x"})
    result = scan_project(root)
    assert paths(result) == ["main.py"]
    assert result.skipped_directories[excluded] == 1


def test_virtual_environment_with_custom_name_is_skipped(make_project):
    root = make_project({"main.py": "x", "my-env/pyvenv.cfg": "home = /usr", "my-env/lib/a.py": "x"})
    assert paths(scan_project(root)) == ["main.py"]


def test_default_excludes_can_be_disabled_but_git_is_never_scanned(make_project):
    root = make_project({"node_modules/x.js": "x", ".git/HEAD": "ref", "a.py": "x"})
    assert paths(scan_project(root)) == ["a.py"]
    assert paths(scan_project(root, include_default_excluded=True)) == ["a.py", "node_modules/x.js"]


def test_large_files_are_flagged(make_project):
    root = make_project({"big.bin": b"x" * 2000, "small.txt": "x"})
    result = scan_project(root, large_file_bytes=1000)
    large = [f for f in result.findings if f.rule == "structure.large-file"]
    assert [f.path for f in large] == ["big.bin"]
    assert large[0].severity is Severity.WARNING
    assert large[0].suggestion


def test_default_large_file_threshold_is_five_megabytes():
    assert DEFAULT_LARGE_FILE_BYTES == 5 * 1024 * 1024


@pytest.mark.parametrize(
    "name",
    ["notes.tmp", "backup.bak", ".main.py.swp", "draft.txt~", "module.pyc", "debug.log", ".DS_Store", "Thumbs.db", "a.orig"],
)
def test_temporary_files_are_flagged(make_project, name):
    result = scan_project(make_project({name: "x"}))
    assert [f.rule for f in result.findings] == ["structure.temporary-file"]
    assert result.findings[0].severity is Severity.INFO


@pytest.mark.parametrize("name", ["main.py", "README.md", "logfile.txt", "tmp.py", "Makefile"])
def test_regular_files_are_not_flagged(make_project, name):
    assert scan_project(make_project({name: "x"})).findings == []


def test_nonexistent_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_project(tmp_path / "missing")


def test_file_instead_of_directory_raises(make_project):
    root = make_project({"file.txt": "x"})
    with pytest.raises(NotADirectoryError):
        scan_project(root / "file.txt")


def test_unreadable_directory_is_reported_and_scan_continues(make_project, monkeypatch):
    root = make_project({"ok.txt": "x", "locked/inner.txt": "x"})
    real_scandir = os.scandir

    def fake_scandir(path):
        if os.path.basename(os.fspath(path)) == "locked":
            raise PermissionError(13, "Permission denied")
        return real_scandir(path)

    monkeypatch.setattr(scanner, "_scandir", fake_scandir)
    result = scan_project(root)
    assert paths(result) == ["ok.txt"]
    finding = next(f for f in result.findings if f.rule == "structure.unreadable-path")
    assert finding.path == "locked"
    assert finding.severity is Severity.WARNING
    assert "Permission denied" in finding.message


@pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs a POSIX user that is not root",
)
def test_real_permission_denied_is_handled(make_project):
    root = make_project({"ok.txt": "x", "locked/inner.txt": "x"})
    locked = root / "locked"
    locked.chmod(0)
    try:
        result = scan_project(root)
    finally:
        locked.chmod(0o700)
    assert paths(result) == ["ok.txt"]
    assert any(f.rule == "structure.unreadable-path" for f in result.findings)


def test_symbolic_links_are_not_followed(make_project, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "outside.txt").write_text("x")
    root = make_project({"a.txt": "x"})
    try:
        (root / "dir-link").symlink_to(outside, target_is_directory=True)
        (root / "file-link").symlink_to(outside / "outside.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available")
    result = scan_project(root)
    assert paths(result) == ["a.txt"]
    assert result.symlinks_skipped == 2


@pytest.mark.parametrize(
    "size,expected",
    [(0, "0 B"), (1023, "1023 B"), (1024, "1.0 KB"), (5 * 1024**2, "5.0 MB"), (3 * 1024**3, "3.0 GB")],
)
def test_format_size(size, expected):
    assert format_size(size) == expected
