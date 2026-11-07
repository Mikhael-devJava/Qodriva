"""Data structures shared by all analyzers."""

from __future__ import annotations

import enum
from dataclasses import dataclass

CATEGORY_STRUCTURE = "structure"
CATEGORY_SECRETS = "secrets"
CATEGORY_GIT = "git"
CATEGORY_DEPENDENCIES = "dependencies"


class Severity(enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"

    @property
    def rank(self) -> int:
        """Lower rank means more severe. Used to sort findings."""
        return _RANKS[self]


_RANKS = {Severity.ERROR: 0, Severity.WARNING: 1, Severity.INFO: 2}


@dataclass(frozen=True)
class Finding:
    """One result shown to the user.

    There is deliberately no field for matched text: a detected secret can only
    be described by its file, line and type, so a value cannot leak into a
    report by accident.
    """

    severity: Severity
    category: str
    rule: str
    message: str
    path: str | None = None
    line: int | None = None
    suggestion: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity.value,
            "category": self.category,
            "rule": self.rule,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "suggestion": self.suggestion,
        }
