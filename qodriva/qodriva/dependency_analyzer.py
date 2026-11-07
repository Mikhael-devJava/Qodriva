"""Static reading of declared dependencies (names and declared versions only).

Supports requirements*.txt, pyproject.toml (PEP 621, dependency groups and
Poetry) and package.json. Nothing is installed, updated or executed, and no
vulnerability database is consulted: Qodriva never claims that a dependency is
vulnerable.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field

from qodriva.models import CATEGORY_DEPENDENCIES, Finding, Severity
from qodriva.scanner import FileEntry

MAX_MANIFEST_BYTES = 2 * 1024 * 1024
DIRECT_REFERENCE = "(direct reference)"  # URLs may embed credentials, so they are never shown
VULNERABILITY_NOTE = (
    "Qodriva does not check dependencies for known vulnerabilities. Use a dedicated "
    "tool for that (for example pip-audit or npm audit)."
)

_REQUIREMENTS_FILE = re.compile(r"^requirements(?:[-_.].+)?\.txt$", re.IGNORECASE)
_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_SPECIFIER_START = re.compile(r"^(?:===|==|~=|!=|<=|>=|<|>)")
_URL_START = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_NPM_SECTIONS = (
    ("dependencies", "main"),
    ("devDependencies", "dev"),
    ("peerDependencies", "peer"),
    ("optionalDependencies", "optional"),
)
_UNPINNED = ("", "*", "latest", "x")


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str  # declared specifier, empty when none was declared
    group: str

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "version": self.version, "group": self.group}


@dataclass
class Manifest:
    path: str
    kind: str  # "requirements.txt", "pyproject.toml" or "package.json"
    ecosystem: str  # "python" or "node"
    dependencies: list[Dependency] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "ecosystem": self.ecosystem,
            "error": self.error,
            "dependencies": [dependency.to_dict() for dependency in self.dependencies],
        }


@dataclass
class DependencyAnalysis:
    manifests: list[Manifest] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "vulnerability_check": "not performed",
            "note": VULNERABILITY_NOTE,
            "manifests": [manifest.to_dict() for manifest in self.manifests],
        }


def parse_requirement(text: str) -> tuple[str, str] | None:
    """Parse one PEP 508 style requirement into (name, declared version).

    Returns None for blank lines, comments, pip options and unrecognized text.
    """
    text = text.strip()
    if not text or text.startswith(("#", "-")):
        return None
    text = re.split(r"\s+#", text, maxsplit=1)[0]  # inline comment
    text = re.split(r"\s+--", text, maxsplit=1)[0]  # per-requirement options such as --hash
    if _URL_START.match(text):
        egg = re.search(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)", text)
        return (egg.group(1) if egg else DIRECT_REFERENCE), DIRECT_REFERENCE
    text = text.split(";", 1)[0].strip()  # environment markers
    match = _REQUIREMENT.match(text)
    if match is None:
        return None
    name, rest = match.group(1), match.group(2).strip()
    if rest.startswith("@"):
        return name, DIRECT_REFERENCE
    if rest and not _SPECIFIER_START.match(rest):
        return None
    return name, re.sub(r"\s+", "", rest)


def analyze_dependencies(root: str | os.PathLike[str], files: Iterable[FileEntry]) -> DependencyAnalysis:
    """Read every supported dependency file among ``files``."""
    analysis = DependencyAnalysis()
    for entry in files:
        kind = _manifest_kind(entry.path)
        if kind is None:
            continue
        manifest = _read_manifest(root, entry, kind)
        analysis.manifests.append(manifest)
        analysis.findings.extend(_manifest_findings(manifest))
    return analysis


def _manifest_kind(path: str) -> str | None:
    parts = path.split("/")
    name = parts[-1]
    lowered = name.lower()
    if lowered == "pyproject.toml":
        return "pyproject.toml"
    if lowered == "package.json":
        return "package.json"
    in_requirements_dir = len(parts) > 1 and parts[-2].lower() == "requirements" and lowered.endswith(".txt")
    if _REQUIREMENTS_FILE.match(name) or in_requirements_dir:
        return "requirements.txt"
    return None


def _read_manifest(root: str | os.PathLike[str], entry: FileEntry, kind: str) -> Manifest:
    ecosystem = "node" if kind == "package.json" else "python"
    manifest = Manifest(path=entry.path, kind=kind, ecosystem=ecosystem)
    try:
        with open(os.path.join(root, entry.path), "rb") as handle:
            data = handle.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        manifest.error = f"could not read file ({exc.strerror or type(exc).__name__})"
        return manifest
    if len(data) > MAX_MANIFEST_BYTES:
        manifest.error = "file is too large to analyze"
        return manifest
    text = data.decode("utf-8-sig", errors="replace")
    try:
        if kind == "requirements.txt":
            manifest.dependencies = _parse_requirements_txt(text, _requirements_group(entry.path))
        elif kind == "pyproject.toml":
            manifest.dependencies = _parse_pyproject(text)
        else:
            manifest.dependencies = _parse_package_json(text)
    except (tomllib.TOMLDecodeError, json.JSONDecodeError, ValueError) as exc:
        manifest.error = f"could not parse file ({exc})"
    return manifest


def _manifest_findings(manifest: Manifest) -> list[Finding]:
    if manifest.error is not None:
        return [
            Finding(
                Severity.WARNING,
                CATEGORY_DEPENDENCIES,
                "dependencies.unparseable",
                f"Could not analyze {manifest.kind}: {manifest.error}.",
                path=manifest.path,
                suggestion="Check that the file is valid.",
            )
        ]
    total = len(manifest.dependencies)
    findings = [
        Finding(
            Severity.INFO,
            CATEGORY_DEPENDENCIES,
            "dependencies.declared",
            f"{total} declared {'dependency' if total == 1 else 'dependencies'} found in {manifest.kind}.",
            path=manifest.path,
        )
    ]
    unpinned = sum(1 for dependency in manifest.dependencies if dependency.version in _UNPINNED)
    if unpinned:
        findings.append(
            Finding(
                Severity.INFO,
                CATEGORY_DEPENDENCIES,
                "dependencies.unpinned",
                f"{unpinned} of {total} dependencies declare no version constraint.",
                path=manifest.path,
                suggestion="Constrain or pin versions to keep builds reproducible.",
            )
        )
    return findings


def _requirements_group(path: str) -> str:
    parts = path.split("/")
    stem = parts[-1].rsplit(".", 1)[0].lower()
    if len(parts) > 1 and parts[-2].lower() == "requirements":
        return stem
    if stem == "requirements":
        return "main"
    return re.sub(r"^requirements[-_.]", "", stem)


def _parse_requirements_txt(text: str, group: str) -> list[Dependency]:
    dependencies = []
    for line in _logical_lines(text):
        parsed = parse_requirement(line)
        if parsed is not None:
            dependencies.append(Dependency(parsed[0], parsed[1], group))
    return dependencies


def _logical_lines(text: str) -> Iterable[str]:
    """Join lines that end with a backslash continuation."""
    buffer = ""
    for raw_line in text.splitlines():
        stripped = raw_line.rstrip()
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        yield buffer + stripped
        buffer = ""
    if buffer:
        yield buffer


def _parse_pyproject(text: str) -> list[Dependency]:
    data = tomllib.loads(text)
    project = _as_dict(data.get("project"))
    dependencies = _from_requirement_list(project.get("dependencies"), "main")
    for extra, requirements in _as_dict(project.get("optional-dependencies")).items():
        dependencies += _from_requirement_list(requirements, f"optional:{extra}")
    for name, requirements in _as_dict(data.get("dependency-groups")).items():
        dependencies += _from_requirement_list(requirements, f"group:{name}")
    dependencies += _from_requirement_list(_as_dict(data.get("build-system")).get("requires"), "build")

    poetry = _as_dict(_as_dict(data.get("tool")).get("poetry"))
    dependencies += _from_poetry_table(poetry.get("dependencies"), "main")
    dependencies += _from_poetry_table(poetry.get("dev-dependencies"), "dev")
    for name, group in _as_dict(poetry.get("group")).items():
        dependencies += _from_poetry_table(_as_dict(group).get("dependencies"), f"group:{name}")
    return dependencies


def _from_requirement_list(value: object, group: str) -> list[Dependency]:
    if not isinstance(value, list):
        return []
    dependencies = []
    for item in value:
        parsed = parse_requirement(item) if isinstance(item, str) else None
        if parsed is not None:
            dependencies.append(Dependency(parsed[0], parsed[1], group))
    return dependencies


def _from_poetry_table(value: object, group: str) -> list[Dependency]:
    return [
        Dependency(name, _poetry_version(spec), group)
        for name, spec in _as_dict(value).items()
        if name.lower() != "python"  # the Python version constraint is not a dependency
    ]


def _poetry_version(spec: object) -> str:
    if isinstance(spec, str):
        return DIRECT_REFERENCE if "://" in spec else spec
    if isinstance(spec, dict):
        if any(key in spec for key in ("git", "path", "url")):
            return DIRECT_REFERENCE
        return _poetry_version(spec.get("version", ""))
    if isinstance(spec, list):
        return " | ".join(_poetry_version(item) for item in spec)
    return ""


def _parse_package_json(text: str) -> list[Dependency]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("top-level value is not an object")
    dependencies = []
    for key, group in _NPM_SECTIONS:
        for name, version in sorted(_as_dict(data.get(key)).items()):
            if isinstance(version, str):
                dependencies.append(Dependency(name, DIRECT_REFERENCE if "://" in version else version, group))
    return dependencies


def _as_dict(value: object) -> dict[str, object]:
    return value if isinstance(value, dict) else {}
