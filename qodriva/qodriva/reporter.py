"""Report assembly and rendering: terminal text (INFO / WARNING / ERROR) and JSON."""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from qodriva import __version__
from qodriva.dependency_analyzer import VULNERABILITY_NOTE, DependencyAnalysis
from qodriva.git_analyzer import GitAnalysis
from qodriva.models import Finding, Severity
from qodriva.scanner import ScanResult, format_size
from qodriva.secret_detector import SecretScanSummary
from qodriva.terminal import paint

DISCLAIMER = (
    "Qodriva is a preventive and educational tool. It is not a complete security "
    "solution and cannot guarantee the absence of vulnerabilities."
)
MAX_FINDINGS_PER_RULE_IN_TERMINAL = 20
MAX_DEPENDENCIES_PER_MANIFEST_IN_TERMINAL = 15

_CATEGORY_ORDER = {"secrets": 0, "git": 1, "structure": 2, "dependencies": 3}
_SEVERITY_STYLES = {
    Severity.ERROR: ("red", "bold"),
    Severity.WARNING: ("yellow",),
    Severity.INFO: ("cyan",),
}


@dataclass
class Report:
    project_name: str
    generated_at: str
    scan: ScanResult
    secret_scan: SecretScanSummary
    git: GitAnalysis
    dependencies: DependencyAnalysis
    findings: list[Finding]

    @property
    def counts(self) -> dict[str, int]:
        by_severity = Counter(finding.severity for finding in self.findings)
        return {
            "errors": by_severity[Severity.ERROR],
            "warnings": by_severity[Severity.WARNING],
            "info": by_severity[Severity.INFO],
        }

    @property
    def has_errors(self) -> bool:
        return self.counts["errors"] > 0

    def to_dict(self) -> dict[str, object]:
        # Only relative paths and the project folder name are exported: absolute
        # paths could reveal personal information such as a user name.
        return {
            "tool": {"name": "qodriva", "version": __version__},
            "generated_at": self.generated_at,
            "project": {"name": self.project_name},
            "notice": DISCLAIMER,
            "summary": {**self.counts, "total": len(self.findings)},
            "structure": self.scan.statistics(),
            "secret_scan": self.secret_scan.to_dict(),
            "git": self.git.to_dict(),
            "dependencies": self.dependencies.to_dict(),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def build_report(
    root: str | os.PathLike[str],
    scan: ScanResult,
    secret_findings: list[Finding],
    secret_scan: SecretScanSummary,
    git: GitAnalysis,
    dependencies: DependencyAnalysis,
    generated_at: str | None = None,
) -> Report:
    findings = sorted(
        [*scan.findings, *secret_findings, *git.findings, *dependencies.findings],
        key=_sort_key,
    )
    if generated_at is None:
        generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return Report(
        project_name=Path(os.path.abspath(root)).name or "(root)",
        generated_at=generated_at,
        scan=scan,
        secret_scan=secret_scan,
        git=git,
        dependencies=dependencies,
        findings=findings,
    )


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=True)


def write_json_report(report: Report, path: str | os.PathLike[str], *, overwrite: bool = False) -> None:
    """Write the JSON report. Without ``overwrite`` an existing file is never replaced."""
    mode = "w" if overwrite else "x"
    with open(path, mode, encoding="utf-8", newline="\n") as handle:
        handle.write(render_json(report) + "\n")


def render_text(report: Report, *, use_color: bool = False) -> str:
    def style(text: str, *styles: str) -> str:
        return paint(text, *styles, enabled=use_color)

    scan = report.scan
    lines = [style(f"Qodriva report for '{report.project_name}'", "bold"), "=" * 60]

    lines += ["", style("Structure", "bold")]
    lines.append(
        f"  Files: {len(scan.files)}   Directories: {len(scan.directories)}   "
        f"Size: {format_size(scan.total_size)}   Max depth: {scan.max_depth}"
    )
    extensions = scan.statistics()["files_by_extension"]
    if extensions:
        lines.append("  File types: " + ", ".join(f"{ext} ({count})" for ext, count in extensions.items()))
    if scan.skipped_directories:
        skipped = ", ".join(f"{name} ({count})" for name, count in sorted(scan.skipped_directories.items()))
        lines.append(f"  Skipped directories: {skipped}")
    for entry in sorted(scan.files, key=lambda item: (-item.size, item.path))[:3]:
        lines.append(f"  Largest: {entry.path} ({format_size(entry.size)})")
    summary = report.secret_scan
    lines.append(
        f"  Secret scan: {summary.files_scanned} files checked, {summary.skipped_binary} binary and "
        f"{summary.skipped_too_large} oversized skipped, {summary.unreadable} unreadable"
    )

    lines += ["", style("Git", "bold")]
    lines.append(
        f"  Repository: {'yes' if report.git.is_repository else 'no'}   "
        f".gitignore: {'found' if report.git.has_gitignore else 'not found'}   "
        f"Potentially sensitive files: {len(report.git.sensitive_files)}"
    )

    lines += ["", style("Dependencies", "bold")]
    if not report.dependencies.manifests:
        lines.append("  No supported dependency files found (requirements*.txt, pyproject.toml, package.json).")
    for manifest in report.dependencies.manifests:
        count = len(manifest.dependencies)
        lines.append(f"  {manifest.path} ({manifest.ecosystem}, {count} declared)")
        if manifest.error:
            lines.append(f"      {manifest.error}")
        for dependency in manifest.dependencies[:MAX_DEPENDENCIES_PER_MANIFEST_IN_TERMINAL]:
            version = dependency.version or "(no version)"
            lines.append(f"      {dependency.name} {version} [{dependency.group}]")
        hidden = count - MAX_DEPENDENCIES_PER_MANIFEST_IN_TERMINAL
        if hidden > 0:
            lines.append(f"      ... and {hidden} more (see the JSON report)")
    lines.append(style(f"  {VULNERABILITY_NOTE}", "dim"))

    lines += ["", style("Findings", "bold")]
    lines += _render_findings(report.findings, style)

    counts = report.counts
    lines += [
        "",
        "=" * 60,
        f"Summary: {counts['errors']} error(s), {counts['warnings']} warning(s), {counts['info']} info",
        style(DISCLAIMER, "dim"),
    ]
    return "\n".join(lines)


def _render_findings(findings: list[Finding], style) -> list[str]:
    if not findings:
        return ["  No findings."]
    lines: list[str] = []
    shown: Counter[str] = Counter()
    omitted: Counter[str] = Counter()
    for finding in findings:
        if shown[finding.rule] >= MAX_FINDINGS_PER_RULE_IN_TERMINAL:
            omitted[finding.rule] += 1
            continue
        label = style(f"[{finding.severity.value}]".ljust(9), *_SEVERITY_STYLES[finding.severity])
        location = _location(finding)
        lines.append(f"  {label} {location + '  ' if location else ''}{finding.message}")
        if finding.suggestion and shown[finding.rule] == 0:  # once per rule keeps the output short
            lines.append(f"            -> {finding.suggestion}")
        shown[finding.rule] += 1
    for rule, count in omitted.items():
        lines.append(f"  ... {count} more '{rule}' finding(s) not shown (see the JSON report)")
    return lines


def _location(finding: Finding) -> str:
    if finding.path is None:
        return ""
    return f"{finding.path}:{finding.line}" if finding.line is not None else finding.path


def _sort_key(finding: Finding) -> tuple[int, int, str, int, str]:
    return (
        finding.severity.rank,
        _CATEGORY_ORDER.get(finding.category, 99),
        finding.path or "",
        finding.line or 0,
        finding.rule,
    )
