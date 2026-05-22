# AGENTS.md

## Scope

These instructions apply to the entire repository.

## Project Overview

- `aura-inspector` is a small Python CLI for auditing Salesforce Experience Cloud Aura exposure.
- The CLI entry point is `src/aura_cli.py`.
- Core request, response parsing, and Salesforce-specific behavior live in `src/aura_helper.py`.
- Logging behavior and colorized console output live in `src/colored_logger.py`.

## Working In This Repo

- Prefer the workspace virtual environment on Windows: `.venv\Scripts\python.exe`.
- Install dependencies with `.venv\Scripts\python.exe -m pip install -r requirements.txt`.
- Use `.venv\Scripts\python.exe src/aura_cli.py -h` as the fastest smoke test after changes.
- There is no automated test suite in the repository today, so validate changes with focused CLI runs.

## Workspace Git Setup

- The workspace-local Git username is `phanimca`.
- The workspace-local Git email is `phani.dummy@hotmail.com`.
- The `origin` remote for this workspace points to `https://github.com/phanimca/aura-inspector.git`.
- Prefer changing Git identity with repo-local `git config` in this workspace instead of changing the global Git profile.

## Code Boundaries

- Keep argument parsing, prompting, and file output changes in `src/aura_cli.py`.
- Keep Aura endpoint discovery, request construction, response parsing, and Salesforce object retrieval logic in `src/aura_helper.py`.
- Keep terminal formatting and logger customization in `src/colored_logger.py`.
- Do not treat `scripts/` as application code; those files are Burp-related helper assets.

## Repo-Specific Conventions

- Preserve the existing Apache 2.0 license header in Python source files.
- Match the current style: small helper methods, straightforward control flow, and minimal abstraction.
- Reuse the existing global logger pattern instead of introducing a new logging setup.
- Keep new dependencies to a minimum; the project currently depends only on `requests`.

## Validation Guidance

- Prefer behavior-scoped validation over broad changes.
- For CLI changes, run the help command first, then a targeted scan command if the change affects request flow.
- If a change could trigger the save prompt, pass `-o` during validation to avoid interactive blocking.

## Known Pitfalls

- The CLI becomes interactive unless `-o` is supplied.
- Aura auto-detection probes only a fixed set of root-relative endpoints. Experience Cloud sites hosted under a custom prefix may require explicit `--app` and `--aura` values.
- The `-u/--url` argument works best as the site root when `--app` and `--aura` are supplied separately.
- Guest and authenticated scans behave differently; authenticated runs should use `-c` or `-r` rather than new ad hoc auth handling.

## Existing Docs

- Usage and option reference: [README.md](README.md)
- Contribution process: [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)
- Community guidelines: [docs/CODE-OF-CONDUCT.md](docs/CODE-OF-CONDUCT.md)