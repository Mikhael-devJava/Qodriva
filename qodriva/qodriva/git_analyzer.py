"""Read-only Git checks: repository presence, .gitignore coverage, sensitive files.

Qodriva never runs the ``git`` command. Running Git inside a repository you do
not control can execute commands defined in its own configuration, so this
module only checks that ``.git`` exists and interprets ``.gitignore`` in pure
Python. Nothing inside ``.git`` is read.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from qodriva.models import CATEGORY_GIT, Finding, Severity
from qodriva.scanner import FileEntry

MAX_GITIGNORE_BYTES = 1024 * 1024

# (lowercase fnmatch pattern, description)
SENSITIVE_FILE_PATTERNS = (
    (".env", "environment file"),
    (".env.*", "environment file"),
    ("*.pem", "PEM certificate or private key"),
    ("*.key", "private key file"),
    ("*.p12", "PKCS#12 keystore"),
    ("*.pfx", "PKCS#12 keystore"),
    ("*.jks", "Java keystore"),
    ("*.keystore", "keystore file"),
    ("id_rsa", "SSH private key"),
    ("id_dsa", "SSH private key"),
    ("id_ecdsa", "SSH private key"),
    ("id_ed25519", "SSH private key"),
    ("credentials.json", "credentials file"),
    ("service-account*.json", "cloud service account key"),
    (".pypirc", "PyPI credentials"),
    (".netrc", "netrc credentials"),
    (".htpasswd", "htpasswd file"),
    ("*.tfstate", "Terraform state"),
    ("terraform.tfvars", "Terraform variables"),
)
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".tpl")

# (sample file name, label shown to the user). If .gitignore would not ignore the
# sample, the known pattern is reported as unprotected.
_PROTECTION_PROBES = (
    (".env", ".env"),
    (".env.local", ".env.*"),
    ("private.pem", "*.pem"),
    ("private.key", "*.key"),
    ("id_rsa", "id_rsa"),
)


@dataclass(frozen=True)
class _Rule:
    regex: re.Pattern[str]
    negated: bool
    dir_only: bool
    anchored: bool


class GitIgnore:
    """A pure-Python interpreter for the root ``.gitignore`` file.

    Supports comments, negation (``!``), directory-only patterns (``foo/``),
    anchored patterns (``/foo`` or ``a/b``), ``*``, ``?``, ``[...]`` and ``**``.
    Nested ``.gitignore`` files and ``.git/info/exclude`` are not read.
    """

    def __init__(self, lines: Iterable[str]) -> None:
        self._rules = [rule for line in lines if (rule := _parse_line(line)) is not None]

    def is_ignored(self, path: str, is_dir: bool = False) -> bool:
        """Return True if ``path`` (relative, "/" separators) would be ignored."""
        parts = path.split("/")
        for count in range(1, len(parts) + 1):
            prefix_is_dir = is_dir if count == len(parts) else True
            if self._matches("/".join(parts[:count]), prefix_is_dir):
                return True  # a file inside an ignored directory cannot be re-included
        return False

    def _matches(self, path: str, is_dir: bool) -> bool:
        basename = path.rsplit("/", 1)[-1]
        ignored = False
        for rule in self._rules:
            if rule.dir_only and not is_dir:
                continue
            target = path if rule.anchored else basename
            if rule.regex.fullmatch(target):
                ignored = not rule.negated
        return ignored


def _parse_line(line: str) -> _Rule | None:
    line = line.rstrip("\r\n")
    if not line.endswith("\\ "):
        line = line.rstrip(" ")
    if not line or line.startswith("#"):
        return None
    negated = False
    if line.startswith("!"):
        negated = True
        line = line[1:]
    elif line.startswith(("\\#", "\\!")):
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    anchored = "/" in line
    line = line.lstrip("/")
    if not line:
        return None
    return _Rule(re.compile(_translate(line)), negated, dir_only, anchored)


def _translate(pattern: str) -> str:
    """Translate a gitignore glob into a regular expression."""
    parts: list[str] = []
    index, length = 0, len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if pattern.startswith("**", index):
                at_boundary = index == 0 or pattern[index - 1] == "/"
                if at_boundary and pattern.startswith("**/", index):
                    parts.append("(?:.*/)?")
                    index += 3
                    continue
                if at_boundary and index + 2 == length:
                    parts.append(".*")
                    index += 2
                    continue
                parts.append("[^/]*")  # "**" elsewhere behaves like "*"
                index += 2
                continue
            parts.append("[^/]*")
            index += 1
        elif char == "?":
            parts.append("[^/]")
            index += 1
        elif char == "[":
            end = index + 1
            if end < length and pattern[end] in "!^":
                end += 1
            if end < length and pattern[end] == "]":
                end += 1
            while end < length and pattern[end] != "]":
                end += 1
            if end >= length:
                parts.append(re.escape(char))
                index += 1
            else:
                content = pattern[index + 1 : end].replace("\\", "\\\\")
                if content.startswith(("!", "^")):
                    content = "^" + content[1:]
                parts.append(f"[{content}]")
                index = end + 1
        elif char == "\\" and index + 1 < length:
            parts.append(re.escape(pattern[index + 1]))
            index += 2
        else:
            parts.append(re.escape(char))
            index += 1
    return "".join(parts)


def sensitive_description(name: str) -> str | None:
    """Describe ``name`` if it is a known sensitive file name, else return None."""
    lowered = name.lower()
    if lowered.endswith(_TEMPLATE_SUFFIXES):  # e.g. .env.example is meant to be committed
        return None
    for pattern, description in SENSITIVE_FILE_PATTERNS:
        if fnmatch.fnmatchcase(lowered, pattern):
            return description
    return None


@dataclass
class GitAnalysis:
    is_repository: bool
    has_gitignore: bool
    sensitive_files: list[dict[str, object]] = field(default_factory=list)
    unprotected_patterns: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "is_repository": self.is_repository,
            "has_gitignore": self.has_gitignore,
            "sensitive_files": self.sensitive_files,
            "unprotected_patterns": self.unprotected_patterns,
        }


def analyze_git(root: str | os.PathLike[str], files: Iterable[FileEntry]) -> GitAnalysis:
    """Check Git-related hygiene of the project located at ``root``."""
    is_repository = os.path.lexists(os.path.join(root, ".git"))
    gitignore, gitignore_error = _load_gitignore(root)
    analysis = GitAnalysis(is_repository=is_repository, has_gitignore=gitignore is not None)
    findings = analysis.findings

    if is_repository:
        findings.append(Finding(Severity.INFO, CATEGORY_GIT, "git.repository", "Git repository detected."))
    else:
        findings.append(
            Finding(
                Severity.INFO,
                CATEGORY_GIT,
                "git.no-repository",
                "No Git repository found in this directory.",
                suggestion=(
                    "If this folder is part of a larger repository, analyze the repository "
                    "root so its .gitignore is taken into account."
                ),
            )
        )

    if gitignore_error is not None:
        findings.append(
            Finding(
                Severity.WARNING,
                CATEGORY_GIT,
                "git.unreadable-gitignore",
                f"Could not read .gitignore ({gitignore_error}).",
                path=".gitignore",
            )
        )
    elif is_repository and gitignore is None:
        findings.append(
            Finding(
                Severity.WARNING,
                CATEGORY_GIT,
                "git.missing-gitignore",
                "This Git repository has no .gitignore file.",
                suggestion="Create a .gitignore that excludes secrets, local environments and build output.",
            )
        )

    for entry in files:
        description = sensitive_description(entry.name)
        if description is None:
            continue
        ignored = gitignore.is_ignored(entry.path) if gitignore is not None else False
        analysis.sensitive_files.append(
            {
                "path": entry.path,
                "description": description,
                "ignored_by_gitignore": ignored if is_repository else None,
            }
        )
        findings.append(_sensitive_file_finding(entry.path, description, is_repository, ignored))

    if is_repository and gitignore is not None:
        analysis.unprotected_patterns = [
            label for sample, label in _PROTECTION_PROBES if not gitignore.is_ignored(sample)
        ]
        if analysis.unprotected_patterns:
            findings.append(
                Finding(
                    Severity.WARNING,
                    CATEGORY_GIT,
                    "git.unprotected-patterns",
                    "Known sensitive file patterns are not covered by .gitignore: "
                    + ", ".join(analysis.unprotected_patterns)
                    + ".",
                    path=".gitignore",
                    suggestion="Add these patterns to .gitignore so such files are not committed by accident.",
                )
            )
    return analysis


def _sensitive_file_finding(path: str, description: str, is_repository: bool, ignored: bool) -> Finding:
    if not is_repository:
        return Finding(
            Severity.INFO,
            CATEGORY_GIT,
            "git.sensitive-file-present",
            f"Potentially sensitive file present ({description}).",
            path=path,
            suggestion="Keep it out of version control and out of shared archives.",
        )
    if ignored:
        return Finding(
            Severity.INFO,
            CATEGORY_GIT,
            "git.sensitive-file-ignored",
            f"Potentially sensitive file ({description}) is ignored by .gitignore.",
            path=path,
        )
    return Finding(
        Severity.ERROR,
        CATEGORY_GIT,
        "git.sensitive-file-not-ignored",
        f"Potentially sensitive file ({description}) is not ignored by .gitignore and could be committed.",
        path=path,
        suggestion=(
            "Add it to .gitignore. If it was already committed, remove it from the index "
            "(git rm --cached) and rotate any credentials it contains."
        ),
    )


def _load_gitignore(root: str | os.PathLike[str]) -> tuple[GitIgnore | None, str | None]:
    """Return (parsed .gitignore or None, error reason or None)."""
    try:
        with open(os.path.join(root, ".gitignore"), "rb") as handle:
            data = handle.read(MAX_GITIGNORE_BYTES)
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, exc.strerror or type(exc).__name__
    return GitIgnore(data.decode("utf-8-sig", errors="replace").split("\n")), None
