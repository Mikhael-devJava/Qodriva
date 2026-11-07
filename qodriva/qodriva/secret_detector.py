"""Detection of possible exposed secrets using regular expressions.

Findings carry only the file, the line and the type of alert. Matched text is
inspected in memory (to filter out placeholders) and then discarded: it is
never stored in a result, a log or a report.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from dataclasses import dataclass

from qodriva.models import CATEGORY_SECRETS, Finding, Severity
from qodriva.scanner import FileEntry

MAX_SCAN_BYTES = 1024 * 1024  # files larger than this are not scanned
MAX_LINE_LENGTH = 2000  # longer lines are truncated (keeps regex matching fast)
_BINARY_PROBE_BYTES = 8192

_BINARY_EXTENSIONS = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".pdf",
        ".zip", ".gz", ".tar", ".tgz", ".bz2", ".xz", ".7z", ".rar",
        ".jar", ".war", ".class", ".exe", ".dll", ".so", ".dylib", ".bin",
        ".o", ".a", ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".otf", ".eot",
        ".mp3", ".mp4", ".mov", ".avi", ".mkv", ".wav", ".flac",
        ".sqlite", ".db", ".iso", ".dmg", ".p12", ".pfx", ".jks",
    }
)  # fmt: skip

_CONFIG_EXTENSIONS = frozenset({".env", ".ini", ".cfg", ".conf", ".properties", ".toml", ".yml", ".yaml"})

SUGGESTION = (
    "Remove the value from the code, revoke or rotate the credential if it was ever "
    "committed or shared, and load it from an environment variable or a secret manager."
)

_KEYWORDS = (
    r"(?:passw(?:or)?d|pwd|passphrase|secret(?:[_-]?key)?|api[_-]?key|apikey"
    r"|access[_-]?key|private[_-]?key|auth[_-]?token|token)"
)


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    label: str
    pattern: re.Pattern[str]
    severity: Severity
    value_group: int | None = None  # group checked against the placeholder filter
    config_only: bool = False  # only applied to config-like files (.env, .yml, ...)


# Ordered from the most specific to the most generic. Only the first rule that
# matches a line is reported.
RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "private-key",
        "private key block",
        re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY(?: BLOCK)?-----"),
        Severity.ERROR,
    ),
    SecretRule(
        "aws-access-key-id",
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.ERROR,
    ),
    SecretRule(
        "aws-secret-access-key",
        "AWS secret access key",
        re.compile(
            r'''aws_?secret_?access_?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])''',
            re.IGNORECASE,
        ),
        Severity.ERROR,
    ),
    SecretRule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        Severity.ERROR,
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
        Severity.ERROR,
    ),
    SecretRule(
        "stripe-live-key",
        "Stripe live secret key",
        re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b"),
        Severity.ERROR,
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.WARNING,
    ),
    SecretRule(
        "jwt",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        Severity.WARNING,
    ),
    SecretRule(
        "url-credentials",
        "password embedded in a URL",
        re.compile(r'''\b[A-Za-z][A-Za-z0-9+.-]{1,20}://[^\s/:@'"<>]{1,100}:([^\s/@'"<>]{3,100})@'''),
        Severity.WARNING,
        value_group=1,
    ),
    SecretRule(
        "hardcoded-credential",
        "hardcoded password, token or key",
        re.compile(
            _KEYWORDS + r'''["']?\s*(?:=>|:=|[:=])\s*["']([^"'\s]{8,200})["']''',
            re.IGNORECASE,
        ),
        Severity.WARNING,
        value_group=1,
    ),
    SecretRule(
        "config-credential",
        "password, token or key in a configuration file",
        re.compile(_KEYWORDS + r'''["']?\s*[:=]\s*([^\s"'#,;]{8,200})''', re.IGNORECASE),
        Severity.WARNING,
        value_group=1,
        config_only=True,
    ),
)

_PLACEHOLDER_WORDS = (
    "changeme", "change-me", "change_me", "example", "your", "placeholder", "dummy",
    "sample", "redacted", "insert", "replace", "todo", "fixme", "xxxx", "password",
    "secret", "token", "none", "null", "undefined", "test",
)  # fmt: skip
_CONSTANT_NAME = re.compile(r"[A-Z][A-Z0-9_]{5,}")


@dataclass
class SecretScanSummary:
    files_scanned: int = 0
    skipped_binary: int = 0
    skipped_too_large: int = 0
    unreadable: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "files_scanned": self.files_scanned,
            "skipped_binary": self.skipped_binary,
            "skipped_too_large": self.skipped_too_large,
            "unreadable": self.unreadable,
        }


def scan_text(text: str, path: str, *, config_like: bool = False) -> list[Finding]:
    """Return one finding per line that looks like it contains a secret."""
    findings = []
    for line_number, raw_line in enumerate(text.split("\n"), start=1):
        rule = _first_matching_rule(raw_line[:MAX_LINE_LENGTH], config_like)
        if rule is None:
            continue
        findings.append(
            Finding(
                rule.severity,
                CATEGORY_SECRETS,
                f"secrets.{rule.rule_id}",
                f"Possible {rule.label} detected.",
                path=path,
                line=line_number,
                suggestion=SUGGESTION,
            )
        )
    return findings


def scan_files(root: str | os.PathLike[str], files: Iterable[FileEntry]) -> tuple[list[Finding], SecretScanSummary]:
    """Scan the given project files for possible secrets."""
    findings: list[Finding] = []
    summary = SecretScanSummary()
    for entry in files:
        if os.path.splitext(entry.path)[1].lower() in _BINARY_EXTENSIONS:
            summary.skipped_binary += 1
            continue
        if entry.size > MAX_SCAN_BYTES:
            summary.skipped_too_large += 1
            continue
        try:
            with open(os.path.join(root, entry.path), "rb") as handle:
                data = handle.read(MAX_SCAN_BYTES + 1)
        except OSError as exc:
            summary.unreadable += 1
            reason = exc.strerror or type(exc).__name__
            findings.append(
                Finding(
                    Severity.WARNING,
                    CATEGORY_SECRETS,
                    "secrets.unreadable-file",
                    f"Could not read this file ({reason}); it was not checked for secrets.",
                    path=entry.path,
                    suggestion="Check the permissions of this file if it should be analyzed.",
                )
            )
            continue
        if len(data) > MAX_SCAN_BYTES:
            summary.skipped_too_large += 1
            continue
        if b"\0" in data[:_BINARY_PROBE_BYTES]:
            summary.skipped_binary += 1
            continue
        summary.files_scanned += 1
        text = data.decode("utf-8", errors="replace")
        findings.extend(scan_text(text, entry.path, config_like=_is_config_like(entry.path)))
    return findings, summary


def _first_matching_rule(line: str, config_like: bool) -> SecretRule | None:
    for rule in RULES:
        if rule.config_only and not config_like:
            continue
        for match in rule.pattern.finditer(line):
            if rule.value_group is None or not _looks_like_placeholder(match.group(rule.value_group)):
                return rule
    return None


def _looks_like_placeholder(value: str) -> bool:
    """Heuristic filter for values that are obviously not real credentials."""
    lowered = value.lower()
    if len(set(lowered)) <= 2:  # "********", "aaaaaaaa"
        return True
    if value[0] in "${<%[(@/~.":  # variable reference, template or path
        return True
    if "://" in value or _CONSTANT_NAME.fullmatch(value):  # URL or environment variable name
        return True
    return any(word in lowered for word in _PLACEHOLDER_WORDS)


def _is_config_like(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name == ".env" or name.startswith(".env."):
        return True
    return os.path.splitext(name)[1] in _CONFIG_EXTENSIONS
