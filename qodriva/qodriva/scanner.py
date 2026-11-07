"""Project structure analysis: files, directories, statistics and findings.

The scanner only lists names and sizes. It never opens, executes or modifies a
file, and it never follows symbolic links.
"""

from __future__ import annotations

import fnmatch
import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from qodriva.models import CATEGORY_STRUCTURE, Finding, Severity

DEFAULT_LARGE_FILE_BYTES = 5 * 1024 * 1024
MAX_TOP_LEVEL_ENTRIES = 50

# Git internals are never scanned, not even with include_default_excluded=True.
ALWAYS_EXCLUDED_DIRS = frozenset({".git"})

# Dependency, virtual environment and cache directories skipped by default.
DEFAULT_EXCLUDED_DIRS = frozenset(
    {
        "node_modules",
        "bower_components",
        "__pypackages__",
        "site-packages",
        ".venv",
        "venv",
        "env",
        "ENV",
        ".tox",
        ".nox",
        ".eggs",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
    }
)

# (lowercase fnmatch pattern, description)
TEMPORARY_FILE_PATTERNS = (
    ("*.tmp", "temporary file"),
    ("*.temp", "temporary file"),
    ("*.bak", "backup file"),
    ("*.swp", "editor swap file"),
    ("*.swo", "editor swap file"),
    ("*~", "editor backup file"),
    ("*.orig", "merge leftover"),
    ("*.rej", "rejected patch"),
    ("*.log", "log file"),
    ("*.pyc", "compiled Python file"),
    ("*.pyo", "compiled Python file"),
    (".ds_store", "macOS metadata file"),
    ("thumbs.db", "Windows thumbnail cache"),
    ("desktop.ini", "Windows folder settings file"),
)

# Indirection used by the tests to simulate permission errors.
_scandir = os.scandir


@dataclass(frozen=True)
class FileEntry:
    path: str  # relative to the project root, always with "/" separators
    size: int

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]


@dataclass
class ScanResult:
    root: Path
    files: list[FileEntry] = field(default_factory=list)
    directories: list[str] = field(default_factory=list)
    skipped_directories: Counter[str] = field(default_factory=Counter)
    top_level: list[str] = field(default_factory=list)
    symlinks_skipped: int = 0
    max_depth: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def total_size(self) -> int:
        return sum(entry.size for entry in self.files)

    def statistics(self, top_n: int = 5) -> dict[str, object]:
        extensions = Counter(_extension(entry.name) for entry in self.files)
        largest = sorted(self.files, key=lambda entry: (-entry.size, entry.path))[:top_n]
        return {
            "total_files": len(self.files),
            "total_directories": len(self.directories),
            "total_size_bytes": self.total_size,
            "max_depth": self.max_depth,
            "files_by_extension": dict(extensions.most_common(10)),
            "largest_files": [{"path": e.path, "size_bytes": e.size} for e in largest],
            "skipped_directories": dict(sorted(self.skipped_directories.items())),
            "symlinks_skipped": self.symlinks_skipped,
            "top_level_entries": self.top_level[:MAX_TOP_LEVEL_ENTRIES],
        }


def format_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def scan_project(
    root: Path | str,
    *,
    large_file_bytes: int = DEFAULT_LARGE_FILE_BYTES,
    include_default_excluded: bool = False,
) -> ScanResult:
    """Walk ``root`` and describe its structure.

    Raises FileNotFoundError or NotADirectoryError if ``root`` is not a directory.
    Paths that cannot be read are skipped and reported as findings.
    """
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"Directory does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    result = ScanResult(root=root)
    pending = [(os.fspath(root), "", 0)]
    while pending:
        directory, relative_dir, depth = pending.pop()
        result.max_depth = max(result.max_depth, depth)
        try:
            with _scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError as exc:
            _record_unreadable(result, relative_dir or ".", exc)
            continue

        for entry in entries:
            relative_path = f"{relative_dir}/{entry.name}" if relative_dir else entry.name
            try:
                if entry.is_symlink():
                    result.symlinks_skipped += 1
                elif entry.is_dir(follow_symlinks=False):
                    if not relative_dir:
                        result.top_level.append(f"{entry.name}/")
                    if _is_excluded_dir(entry.name, entry.path, include_default_excluded):
                        result.skipped_directories[entry.name] += 1
                    else:
                        result.directories.append(relative_path)
                        pending.append((entry.path, relative_path, depth + 1))
                elif entry.is_file(follow_symlinks=False):
                    if not relative_dir:
                        result.top_level.append(entry.name)
                    size = entry.stat(follow_symlinks=False).st_size
                    result.files.append(FileEntry(relative_path, size))
                    result.findings.extend(_file_findings(relative_path, entry.name, size, large_file_bytes))
            except OSError as exc:
                _record_unreadable(result, relative_path, exc)

    result.files.sort(key=lambda item: item.path)
    result.directories.sort()
    result.top_level.sort()
    return result


def _is_excluded_dir(name: str, path: str, include_default_excluded: bool) -> bool:
    if name in ALWAYS_EXCLUDED_DIRS:
        return True
    if include_default_excluded:
        return False
    if name in DEFAULT_EXCLUDED_DIRS or name.endswith(".egg-info"):
        return True
    # A virtual environment with a custom name still has a pyvenv.cfg.
    return os.path.isfile(os.path.join(path, "pyvenv.cfg"))


def _file_findings(path: str, name: str, size: int, large_file_bytes: int) -> list[Finding]:
    findings = []
    if size >= large_file_bytes:
        findings.append(
            Finding(
                Severity.WARNING,
                CATEGORY_STRUCTURE,
                "structure.large-file",
                f"Large file ({format_size(size)}).",
                path=path,
                suggestion=(
                    "Avoid versioning large binaries. Consider Git LFS or external "
                    "storage, or add the file to .gitignore."
                ),
            )
        )
    description = _temporary_description(name)
    if description is not None:
        findings.append(
            Finding(
                Severity.INFO,
                CATEGORY_STRUCTURE,
                "structure.temporary-file",
                f"Temporary or unnecessary file ({description}).",
                path=path,
                suggestion="Delete it if it is not needed and add it to .gitignore.",
            )
        )
    return findings


def _temporary_description(name: str) -> str | None:
    lowered = name.lower()
    for pattern, description in TEMPORARY_FILE_PATTERNS:
        if fnmatch.fnmatchcase(lowered, pattern):
            return description
    return None


def _extension(name: str) -> str:
    extension = os.path.splitext(name)[1].lower()
    return extension or "(no extension)"


def _record_unreadable(result: ScanResult, path: str, exc: OSError) -> None:
    reason = exc.strerror or type(exc).__name__
    result.findings.append(
        Finding(
            Severity.WARNING,
            CATEGORY_STRUCTURE,
            "structure.unreadable-path",
            f"Could not access this path ({reason}); it was skipped.",
            path=path,
            suggestion="Check the permissions of this path if it should be analyzed.",
        )
    )
