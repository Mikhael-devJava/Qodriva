"""Command-line interface for Qodriva."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from qodriva import __version__
from qodriva.banner import print_banner
from qodriva.dependency_analyzer import analyze_dependencies
from qodriva.git_analyzer import analyze_git
from qodriva.reporter import Report, build_report, render_json, render_text, write_json_report
from qodriva.scanner import DEFAULT_LARGE_FILE_BYTES, scan_project
from qodriva.secret_detector import scan_files
from qodriva.terminal import supports_color

EXIT_OK = 0
EXIT_FINDINGS = 1  # the analysis finished and found at least one ERROR
EXIT_ERROR = 2  # invalid usage or an error that prevented the analysis
EXIT_INTERRUPTED = 130

_BYTES_PER_MB = 1024 * 1024


class _Parser(argparse.ArgumentParser):
    def print_help(self, file=None) -> None:
        stream = file or sys.stdout
        print_banner(stream)
        super().print_help(stream)


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if number <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(
        prog="qodriva",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Local static analysis for programming projects.\n"
            "Qodriva only reads the files you point it at: it never sends data anywhere,\n"
            "never runs project code and never modifies your files."
        ),
        epilog=(
            "examples:\n"
            "  python -m qodriva ./my-project\n"
            "  python -m qodriva ./my-project --json\n"
            "  python -m qodriva ./my-project --output report.json\n"
            "\n"
            "exit codes: 0 = no errors found, 1 = errors found, 2 = usage or runtime error\n"
            "\n"
            "Qodriva is a preventive and educational tool. It is not a complete security\n"
            "solution and cannot guarantee the absence of vulnerabilities."
        ),
    )
    parser.add_argument("path", nargs="?", type=Path, help="path to the project directory to analyze")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="print the report as JSON instead of text (the welcome banner is hidden)",
    )
    parser.add_argument("-o", "--output", type=Path, metavar="FILE", help="also save the JSON report to FILE")
    parser.add_argument("--force", action="store_true", help="allow --output to overwrite an existing file")
    parser.add_argument(
        "--large-file-mb",
        type=_positive_float,
        default=DEFAULT_LARGE_FILE_BYTES / _BYTES_PER_MB,
        metavar="MB",
        help="size from which a file is reported as large (default: %(default)s)",
    )
    parser.add_argument(
        "--no-default-excludes",
        action="store_true",
        help="also analyze dependency, virtual environment and cache directories (.git is never analyzed)",
    )
    parser.add_argument("--no-banner", action="store_true", help="do not show the welcome banner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def validate_project_path(path: Path) -> str | None:
    """Return an error message if ``path`` cannot be analyzed, else ``None``."""
    try:
        if not path.exists():
            return f"path does not exist: {path}"
        if not path.is_dir():
            return f"path is not a directory: {path}"
    except OSError as exc:
        return f"cannot access path {path}: {exc.strerror or exc}"
    return None


def validate_output_path(path: Path, force: bool) -> str | None:
    """Return an error message if the report cannot be written to ``path``."""
    try:
        if path.is_dir():
            return f"output path is a directory: {path}"
        if path.exists() and not force:
            return f"output file already exists: {path} (use --force to overwrite it)"
        if not path.parent.is_dir():
            return f"output directory does not exist: {path.parent}"
    except OSError as exc:
        return f"cannot access output path {path}: {exc.strerror or exc}"
    return None


def run_analysis(
    root: Path,
    *,
    large_file_bytes: int = DEFAULT_LARGE_FILE_BYTES,
    include_default_excluded: bool = False,
) -> Report:
    """Run every analyzer on ``root`` and assemble the report."""
    scan = scan_project(root, large_file_bytes=large_file_bytes, include_default_excluded=include_default_excluded)
    secret_findings, secret_summary = scan_files(root, scan.files)
    git = analyze_git(root, scan.files)
    dependencies = analyze_dependencies(root, scan.files)
    return build_report(root, scan, secret_findings, secret_summary, git, dependencies)


def _make_output_safe() -> None:
    """Never crash on file names the terminal encoding cannot represent."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except Exception:  # best effort only
                pass


def main(argv: list[str] | None = None) -> int:
    _make_output_safe()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.path is None:  # no arguments: welcome screen with usage help
        parser.print_help()
        return EXIT_OK

    error = validate_project_path(args.path)
    if error is None and args.output is not None:
        error = validate_output_path(args.output, args.force)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_ERROR

    try:
        if not args.json_output and not args.no_banner:
            print_banner(sys.stderr)
        report = run_analysis(
            args.path,
            large_file_bytes=int(args.large_file_mb * _BYTES_PER_MB),
            include_default_excluded=args.no_default_excludes,
        )
        if args.output is not None:
            try:
                write_json_report(report, args.output, overwrite=args.force)
            except OSError as exc:
                print(f"ERROR: could not write report to {args.output}: {exc.strerror or exc}", file=sys.stderr)
                return EXIT_ERROR
            print(f"INFO: JSON report saved to {args.output}", file=sys.stderr)
        if args.json_output:
            print(render_json(report))
        else:
            print(render_text(report, use_color=supports_color(sys.stdout)))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return EXIT_INTERRUPTED

    return EXIT_FINDINGS if report.has_errors else EXIT_OK
