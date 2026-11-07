"""Command-line interface for Qodriva."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from qodriva import __version__

EXIT_OK = 0
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qodriva",
        description=(
            "Local static analysis for programming projects. Qodriva only reads "
            "the files you point it at: it never sends data anywhere, never runs "
            "project code and never modifies files."
        ),
        epilog=(
            "Qodriva is a preventive and educational tool. It is not a complete "
            "security solution and cannot guarantee the absence of vulnerabilities."
        ),
    )
    parser.add_argument(
        "path",
        type=Path,
        help="path to the project directory to analyze",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="print the report as JSON instead of human-readable text",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="FILE",
        help="write the JSON report to FILE",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def validate_project_path(path: Path) -> Optional[str]:
    """Return an error message if ``path`` cannot be analyzed, else ``None``."""
    try:
        if not path.exists():
            return f"path does not exist: {path}"
        if not path.is_dir():
            return f"path is not a directory: {path}"
    except OSError as exc:
        return f"cannot access path {path}: {exc.strerror or exc}"
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    error = validate_project_path(args.path)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_ERROR

    # Stage 1 skeleton: analysis modules are added in the next stages.
    print("INFO: Qodriva skeleton is ready; analysis is not implemented yet.", file=sys.stderr)
    return EXIT_OK
