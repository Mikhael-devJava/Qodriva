# Qodriva

**Local static analysis for programming projects.** Qodriva looks at a project folder on your machine and reports
problems with its structure, possible exposed secrets, Git hygiene and declared dependencies, without sending anything anywhere.

```text
    ___              _        _
   / _ \   ___    __| | _ __ (_)__   __  __ _
  | | | | / _ \  / _` || '__|| |\ \ / / / _` |
  | |_| || (_) || (_| || |   | | \ V / | (_| |
   \__\_\ \___/  \__,_||_|   |_|  \_/   \__,_|

  Bem-vindo ao Qodriva!
  Local static analysis for your projects  |  v0.1.0
```

> Qodriva is a **preventive and educational** tool. It is **not** a complete security solution and cannot guarantee the
> absence of vulnerabilities. Treat its results as hints to review, not as a verdict.
>
> This project was made with the help of an AI and was **not directly reviewed**. **Read the code and the
> [Important notice and disclaimer](#important-notice-and-disclaimer) before running it.**

## Important notice and disclaimer

**Please read this section before downloading, installing or running Qodriva.**

1. **Made with AI, not directly reviewed.** Qodriva was written with the help of Claude, an AI assistant developed by
   Anthropic. The code has **not been directly reviewed** by a human. AI-generated code can contain mistakes, bugs or
   security flaws that are not obvious.
2. **Read the code before you run it.** You should read and understand the source code before executing it. It is small,
   uses only the Python standard library and has no runtime dependencies, so reviewing it is realistic: start with
   `qodriva/main.py` and the modules it imports. If you cannot review it yourself, ask someone you trust, and consider
   trying it first on a copy of a project that holds no sensitive data. Keep backups of anything that matters.
3. **Provided "as is".** The software is delivered as it is, without warranty of any kind, express or implied. There is
   no guarantee that it works correctly, is free of errors or is suitable for any particular purpose. It can fail or crash,
   report things that are not problems (false positives) and miss real secrets or problems (false negatives).
4. **No liability.** The author is not responsible for any malfunction, incorrect or incomplete results, missed secrets or
   vulnerabilities, loss of data, damage, or any other consequence, direct or indirect, of downloading, running, modifying
   or relying on this software. You use it **at your own risk**. This notice is consistent with the [MIT License](LICENSE),
   whose text prevails.
5. **Not a security guarantee.** Do not rely on Qodriva as your only protection. A clean report does not mean that a
   project is safe.
6. **Runs locally, under your responsibility.** Qodriva is designed to run only on your computer: it does not connect to the
   internet, does not send data anywhere and only reads the folder you point it at. You are responsible for choosing which
   folders to analyze (analyze only projects you own or have permission to analyze), for where you save reports (they can
   reveal file and folder names) and for what you do with the results. These behaviors are design goals checked by
   automated tests, but they come from code that has not been directly reviewed, which is one more reason to read it first.
7. **Tests are not proof.** The repository includes automated tests, but passing tests does not prove the absence of bugs.
   Run them yourself (see [Development](#development)).
8. **No support obligation.** The author has no obligation to provide support, fixes or updates. Issues and pull requests
   are welcome, but there is no guaranteed response time.

## Purpose

Many leaks are not sophisticated attacks: a `.env` file committed by accident, a token pasted into a script, a 200 MB
file nobody meant to version. Qodriva is a small, dependency-free tool that catches this kind of mistake early, before the
code is shared or published, and explains how to fix it.

## Features

- **Structure analysis**: lists files and directories, reports statistics (counts, sizes, file types, depth), large files
  and temporary or unnecessary files (`*.tmp`, `*.bak`, `.DS_Store`, `*.pyc`, logs, ...).
- **Possible secrets**: regular-expression rules for private keys, cloud and service tokens, passwords embedded in URLs and
  hardcoded credentials. Findings show **only the file, the line and the type of alert**.
- **Git checks**: detects a Git repository, checks whether known sensitive files and patterns (`.env`, `*.pem`, SSH keys, ...)
  are protected by `.gitignore`, and lists potentially sensitive files present in the project.
- **Dependencies**: reads names and declared versions from `requirements*.txt`, `pyproject.toml` (PEP 621, dependency
  groups and Poetry) and `package.json`.
- **Reports**: colored terminal output with `INFO`, `WARNING` and `ERROR` levels and fix suggestions, plus JSON export.

## What Qodriva never does

These rules are part of the design, and most of them are verified by automated tests:

1. Works **locally** only: no network connections, no telemetry, nothing is uploaded.
2. Never executes code or commands found in the analyzed project, and never starts external processes (it does not even
   run `git`).
3. Never modifies, creates or deletes files in the analyzed project. The only file it can write is the JSON report you ask
   for with `--output`, and it refuses to overwrite an existing file unless you pass `--force`.
4. Never stores or prints secret values. Results have no field that could hold one.
5. Never follows symbolic links and skips dependency directories and virtual environments by default.
6. Never installs, updates or runs dependencies, and never claims that a dependency is vulnerable.

## Technologies

Python 3.11+ and its standard library only: `argparse`, `pathlib`, `re`, `json`, `tomllib`. Tests use `pytest`.

## Requirements

- Python **3.11 or newer**
- No runtime dependencies. `pytest` is needed only to run the tests.

## Installation

```bash
git clone <repository-url>
cd qodriva

python -m venv .venv
source .venv/bin/activate          # Windows (PowerShell): .venv\Scripts\Activate.ps1

python -m pip install -e .         # adds the `qodriva` command
```

Installing is optional: from the repository root you can run `python -m qodriva ...` directly.

## Usage

```bash
python -m qodriva ./my-project                      # terminal report
python -m qodriva ./my-project --json               # JSON on stdout (pipe-friendly, no banner)
python -m qodriva ./my-project --output report.json # terminal report + JSON file
python -m qodriva --help
```

If you installed the package you can use `qodriva` instead of `python -m qodriva`. Running it without arguments shows the
welcome screen and the usage help.

| Option | Description |
| --- | --- |
| `PATH` | Project directory to analyze. |
| `--json` | Print the report as JSON instead of text. The welcome banner is hidden so the output stays valid JSON. |
| `-o FILE`, `--output FILE` | Also save the JSON report to `FILE`. The file must not exist unless `--force` is used. |
| `--force` | Allow `--output` to overwrite an existing file. |
| `--large-file-mb MB` | Size from which a file is reported as large (default: `5.0`). |
| `--no-default-excludes` | Also analyze dependency, virtual environment and cache directories. `.git` is never analyzed. |
| `--no-banner` | Do not show the welcome banner. |
| `--version` | Show the version. |

Directories skipped by default: `node_modules`, `bower_components`, `.venv`, `venv`, `env`, `ENV`, any folder containing a
`pyvenv.cfg`, `site-packages`, `__pypackages__`, `.tox`, `.nox`, `.eggs`, `*.egg-info` and common caches
(`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`).

**Exit codes:** `0` analysis finished without `ERROR` findings, `1` analysis finished with at least one `ERROR` finding
(handy in CI), `2` invalid usage or an error that prevented the analysis.

The welcome banner is printed to **stderr**, so redirecting the report (`> report.txt`) never captures it.

## Example report

This is the real output for a small demo project containing **fictitious** credentials (the values never appear in the
report):

```text
Qodriva report for 'demo-project'
============================================================

Structure
  Files: 8   Directories: 1   Size: 6.0 MB   Max depth: 1
  File types: (no extension) (2), .md (1), .bin (1), .log (1), .json (1), .txt (1), .py (1)
  Skipped directories: .git (1), node_modules (1)
  Largest: data.bin (6.0 MB)
  Largest: src/app.py (144 B)
  Largest: package.json (76 B)
  Secret scan: 7 files checked, 1 binary and 0 oversized skipped, 0 unreadable

Git
  Repository: yes   .gitignore: found   Potentially sensitive files: 1

Dependencies
  package.json (node, 2 declared)
      express ^4.18.0 [main]
      jest ^29.0.0 [dev]
  requirements.txt (python, 3 declared)
      requests ==2.31.0 [main]
      flask >=2.0 [main]
      numpy (no version) [main]
  Qodriva does not check dependencies for known vulnerabilities. Use a dedicated tool for that (for example pip-audit or npm audit).

Findings
  [ERROR]   src/app.py:3  Possible AWS access key ID detected.
            -> Remove the value from the code, revoke or rotate the credential if it was ever committed or shared, and load it from an environment variable or a secret manager.
  [ERROR]   .env  Potentially sensitive file (environment file) is not ignored by .gitignore and could be committed.
            -> Add it to .gitignore. If it was already committed, remove it from the index (git rm --cached) and rotate any credentials it contains.
  [WARNING] .env:2  Possible password, token or key in a configuration file detected.
            -> Remove the value from the code, revoke or rotate the credential if it was ever committed or shared, and load it from an environment variable or a secret manager.
  [WARNING] src/app.py:4  Possible password embedded in a URL detected.
            -> Remove the value from the code, revoke or rotate the credential if it was ever committed or shared, and load it from an environment variable or a secret manager.
  [WARNING] .gitignore  Known sensitive file patterns are not covered by .gitignore: .env, .env.*, *.pem, *.key, id_rsa.
            -> Add these patterns to .gitignore so such files are not committed by accident.
  [WARNING] data.bin  Large file (6.0 MB).
            -> Avoid versioning large binaries. Consider Git LFS or external storage, or add the file to .gitignore.
  [INFO]    Git repository detected.
  [INFO]    debug.log  Temporary or unnecessary file (log file).
            -> Delete it if it is not needed and add it to .gitignore.
  [INFO]    package.json  2 declared dependencies found in package.json.
  [INFO]    requirements.txt  3 declared dependencies found in requirements.txt.
  [INFO]    requirements.txt  1 of 3 dependencies declare no version constraint.
            -> Constrain or pin versions to keep builds reproducible.

============================================================
Summary: 2 error(s), 4 warning(s), 5 info
Qodriva is a preventive and educational tool. It is not a complete security solution and cannot guarantee the absence of vulnerabilities.
```

An excerpt of the JSON report (`--json` or `--output`); lists are shortened here, the real file contains everything:

```json
{
  "tool": {
    "name": "qodriva",
    "version": "0.1.0"
  },
  "generated_at": "2026-11-07T17:17:35Z",
  "project": {
    "name": "demo-project"
  },
  "summary": {
    "errors": 2,
    "warnings": 4,
    "info": 5,
    "total": 11
  },
  "structure": {
    "total_files": 8,
    "total_directories": 1,
    "total_size_bytes": 6291784,
    "skipped_directories": {
      ".git": 1,
      "node_modules": 1
    }
  },
  "secret_scan": {
    "files_scanned": 7,
    "skipped_binary": 1,
    "skipped_too_large": 0,
    "unreadable": 0
  },
  "git": {
    "is_repository": true,
    "has_gitignore": true,
    "sensitive_files": [
      {
        "path": ".env",
        "description": "environment file",
        "ignored_by_gitignore": false
      }
    ],
    "unprotected_patterns": [
      ".env",
      ".env.*",
      "*.pem",
      "*.key",
      "id_rsa"
    ]
  },
  "dependencies": {
    "vulnerability_check": "not performed",
    "manifests": [
      {
        "path": "package.json",
        "kind": "package.json",
        "ecosystem": "node",
        "error": null,
        "dependencies": [
          {
            "name": "express",
            "version": "^4.18.0",
            "group": "main"
          },
          {
            "name": "jest",
            "version": "^29.0.0",
            "group": "dev"
          }
        ]
      }
    ]
  },
  "findings": [
    {
      "severity": "ERROR",
      "category": "secrets",
      "rule": "secrets.aws-access-key-id",
      "message": "Possible AWS access key ID detected.",
      "path": "src/app.py",
      "line": 3,
      "suggestion": "Remove the value from the code, revoke or rotate the credential if it was ever committed or shared, and load it from an environment variable or a secret manager."
    },
    {
      "severity": "ERROR",
      "category": "git",
      "rule": "git.sensitive-file-not-ignored",
      "message": "Potentially sensitive file (environment file) is not ignored by .gitignore and could be committed.",
      "path": ".env",
      "line": null,
      "suggestion": "Add it to .gitignore. If it was already committed, remove it from the index (git rm --cached) and rotate any credentials it contains."
    }
  ]
}
```

Paths are always relative to the analyzed folder and the report only contains the folder name, never an absolute path.

## Detection rules

Only the first matching rule is reported for each line. Values that look like placeholders (`changeme`, `${VAR}`,
`<password>`, `os.getenv(...)`, ...) are ignored.

| Rule | Detects | Level |
| --- | --- | --- |
| `secrets.private-key` | Private key block | ERROR |
| `secrets.aws-access-key-id` | AWS access key ID | ERROR |
| `secrets.aws-secret-access-key` | AWS secret access key | ERROR |
| `secrets.github-token` | GitHub token | ERROR |
| `secrets.slack-token` | Slack token | ERROR |
| `secrets.stripe-live-key` | Stripe live secret key | ERROR |
| `secrets.google-api-key` | Google API key | WARNING |
| `secrets.jwt` | JSON Web Token | WARNING |
| `secrets.url-credentials` | Password embedded in a URL | WARNING |
| `secrets.hardcoded-credential` | Hardcoded password, token or key | WARNING |
| `secrets.config-credential` | Password, token or key in a configuration file (configuration-like files only) | WARNING |

Other findings: `structure.large-file`, `structure.temporary-file`, `structure.unreadable-path`,
`git.sensitive-file-not-ignored`, `git.sensitive-file-ignored`, `git.sensitive-file-present`, `git.unprotected-patterns`,
`git.missing-gitignore`, `git.repository`, `git.no-repository`, `dependencies.declared`, `dependencies.unpinned`,
`dependencies.unparseable`.

## Design notes

- **Git without Git.** Running `git` inside a repository you do not control can execute commands defined in that
  repository's own configuration. Qodriva therefore never runs it: it checks that `.git` exists and interprets
  `.gitignore` in pure Python (comments, negation, directory patterns, anchoring, `*`, `?`, `[...]`, `**`).
- **Secrets cannot leak by construction.** `Finding` has no field for matched text. Matched text is only inspected in memory
  to filter out placeholders and is then discarded.
- **Privacy-friendly reports.** URLs found in dependency files (they can embed credentials) are shown as
  `(direct reference)`, and reports never contain absolute paths.

## Known limitations

- Detection is **heuristic**. Expect false positives (for example documentation examples such as `passwd='...'`) and false
  negatives (secrets in unusual formats). Dedicated tools such as gitleaks, TruffleHog or detect-secrets are more thorough.
- Only the **current files** are analyzed, not the Git history. A secret that was committed and later deleted is not found.
- Qodriva does not read the Git index, so it cannot tell whether a file was **already committed** before being ignored.
- Only the **root `.gitignore`** is interpreted (no nested `.gitignore`, `.git/info/exclude` or global ignore file), and
  matching is case-sensitive. If the folder is part of a larger repository, analyze the repository root.
- Files larger than 1 MiB are not scanned for secrets, lines longer than 2000 characters are truncated, and binary files
  (including UTF-16 text) are skipped. Counts are shown in the report.
- Dependency analysis reads **declared** versions only. It does not resolve or lock them, does not follow `-r` includes, and
  does not support lock files, `Pipfile`, `setup.py` or other ecosystems.
- **No vulnerability check** is performed. Use a dedicated tool such as `pip-audit` or `npm audit`.
- Requires Python 3.11 or newer.

## Privacy notice

Qodriva runs entirely on your computer. It does not connect to the internet, does not send files or information to any
server, does not collect personal information and does not store the secrets it detects. The report can still reveal your
**file and folder names**; review it before sharing it publicly.

## Contributing

Contributions are welcome.

1. Open an issue to discuss larger changes.
2. Fork the repository and create a branch.
3. Add or update tests. Never use real credentials: build fictitious values in `tests/fakes.py`, assembled at runtime.
4. Run the test suite and make sure it passes.
5. Open a pull request describing what changed and why.

Please keep the project within its principles: standard library only, local only, read-only on the analyzed project, and no
secret values in any output.

### Development

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

## License

Released under the [MIT License](LICENSE). The software is provided "as is", without warranty of any kind; see the
[Important notice and disclaimer](#important-notice-and-disclaimer).
