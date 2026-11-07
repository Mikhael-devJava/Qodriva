"""Tests for the static dependency analysis."""

import json

import pytest

from qodriva import dependency_analyzer
from qodriva.dependency_analyzer import DIRECT_REFERENCE, analyze_dependencies, parse_requirement
from qodriva.models import Severity
from qodriva.scanner import scan_project


def analyze(root):
    return analyze_dependencies(root, scan_project(root).files)


def manifest(analysis, path):
    return next(item for item in analysis.manifests if item.path == path)


def triples(item):
    return [(d.name, d.version, d.group) for d in item.dependencies]


@pytest.mark.parametrize(
    "line,expected",
    [
        ("requests==2.31.0", ("requests", "==2.31.0")),
        ("requests >= 2.0, < 3", ("requests", ">=2.0,<3")),
        ("flask[async]~=2.3", ("flask", "~=2.3")),
        ("numpy", ("numpy", "")),
        ('pandas ; python_version < "3.9"', ("pandas", "")),
        ("django==4.2 --hash=sha256:abc", ("django", "==4.2")),
        ("pytest>=7  # dev tool", ("pytest", ">=7")),
        ("mylib @ https://user:pw@example.invalid/mylib.whl", ("mylib", DIRECT_REFERENCE)),
        ("git+https://example.invalid/org/repo.git#egg=repopkg", ("repopkg", DIRECT_REFERENCE)),
        ("https://example.invalid/pkg.whl", (DIRECT_REFERENCE, DIRECT_REFERENCE)),
    ],
)
def test_parse_requirement(line, expected):
    assert parse_requirement(line) == expected


@pytest.mark.parametrize(
    "line",
    ["", "# comment", "-r base.txt", "--index-url https://user:pw@example.invalid/simple", "-e .", "not a requirement"],
)
def test_parse_requirement_ignores_non_requirements(line):
    assert parse_requirement(line) is None


def test_requirements_files(make_project):
    root = make_project(
        {
            "requirements.txt": "# deps\nrequests==2.31.0\nflask>=2.0\nnumpy\n-r other.txt\ndjango==4.2 \\\n    --hash=sha256:abc\n",
            "requirements-dev.txt": "pytest==8.0.0\n",
            "requirements/base.txt": "click>=8\n",
        }
    )
    analysis = analyze(root)
    assert triples(manifest(analysis, "requirements.txt")) == [
        ("requests", "==2.31.0", "main"),
        ("flask", ">=2.0", "main"),
        ("numpy", "", "main"),
        ("django", "==4.2", "main"),
    ]
    assert triples(manifest(analysis, "requirements-dev.txt")) == [("pytest", "==8.0.0", "dev")]
    assert triples(manifest(analysis, "requirements/base.txt")) == [("click", ">=8", "base")]


PYPROJECT = """
[build-system]
requires = ["setuptools>=68"]

[project]
name = "demo"
dependencies = ["click>=8", "rich"]

[project.optional-dependencies]
docs = ["sphinx==7.0"]

[dependency-groups]
dev = ["pytest>=8", {include-group = "docs"}]

[tool.poetry.dependencies]
python = "^3.11"
httpx = {version = "^0.27"}
internal = {git = "https://example.invalid/x.git"}

[tool.poetry.group.test.dependencies]
coverage = "^7.0"
"""


def test_pyproject(make_project):
    analysis = analyze(make_project({"pyproject.toml": PYPROJECT}))
    assert triples(manifest(analysis, "pyproject.toml")) == [
        ("click", ">=8", "main"),
        ("rich", "", "main"),
        ("sphinx", "==7.0", "optional:docs"),
        ("pytest", ">=8", "group:dev"),
        ("setuptools", ">=68", "build"),
        ("httpx", "^0.27", "main"),
        ("internal", DIRECT_REFERENCE, "main"),
        ("coverage", "^7.0", "group:test"),
    ]


def test_package_json(make_project):
    package = {
        "name": "demo",
        "dependencies": {"express": "^4.18.0", "lib": "git+https://user:pw@example.invalid/lib.git"},
        "devDependencies": {"jest": "*"},
        "peerDependencies": {"react": ">=18"},
    }
    analysis = analyze(make_project({"web/package.json": json.dumps(package)}))
    assert triples(manifest(analysis, "web/package.json")) == [
        ("express", "^4.18.0", "main"),
        ("lib", DIRECT_REFERENCE, "main"),
        ("jest", "*", "dev"),
        ("react", ">=18", "peer"),
    ]
    assert manifest(analysis, "web/package.json").ecosystem == "node"


@pytest.mark.parametrize(
    "path,content",
    [("package.json", "{ broken"), ("package.json", "[1, 2]"), ("pyproject.toml", "[project\nname = ")],
)
def test_invalid_files_produce_a_warning_instead_of_crashing(make_project, path, content):
    analysis = analyze(make_project({path: content}))
    item = analysis.manifests[0]
    assert item.error and item.dependencies == []
    assert [(f.rule, f.severity) for f in analysis.findings] == [("dependencies.unparseable", Severity.WARNING)]


def test_oversized_manifest_is_not_analyzed(make_project, monkeypatch):
    monkeypatch.setattr(dependency_analyzer, "MAX_MANIFEST_BYTES", 10)
    analysis = analyze(make_project({"requirements.txt": "requests==2.31.0\nflask==3.0\n"}))
    assert "too large" in analysis.manifests[0].error


def test_dependency_directories_are_ignored(make_project):
    root = make_project(
        {
            "package.json": '{"dependencies": {"a": "1"}}',
            "node_modules/pkg/package.json": '{"dependencies": {"b": "1"}}',
            ".venv/requirements.txt": "c==1\n",
        }
    )
    assert [m.path for m in analyze(root).manifests] == ["package.json"]


def test_unpinned_dependencies_are_reported_once_per_file(make_project):
    analysis = analyze(make_project({"requirements.txt": "numpy\npandas\nflask==3.0\n"}))
    unpinned = [f for f in analysis.findings if f.rule == "dependencies.unpinned"]
    assert [f.message for f in unpinned] == ["2 of 3 dependencies declare no version constraint."]


def test_no_vulnerability_claims_are_made(make_project):
    analysis = analyze(make_project({"requirements.txt": "django==1.0\nrequests==2.0\n"}))
    assert analysis.to_dict()["vulnerability_check"] == "not performed"
    assert all("vulnerab" not in f.message.lower() for f in analysis.findings)


def test_urls_and_credentials_never_reach_the_output(make_project):
    root = make_project(
        {
            "requirements.txt": "--index-url https://user:pw@example.invalid/simple\nmylib @ https://user:pw@example.invalid/m.whl\n",
            "package.json": '{"dependencies": {"lib": "git+https://user:pw@example.invalid/l.git"}}',
        }
    )
    dumped = json.dumps(analyze(root).to_dict())
    assert "example.invalid" not in dumped
    assert "user:pw" not in dumped
