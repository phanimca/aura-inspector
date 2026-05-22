---
description: "Use when editing Python CLI files in this repo, especially aura_cli.py, aura_helper.py, or colored_logger.py. Covers validation, file boundaries, and non-interactive scan behavior."
name: "Python CLI Guidance"
applyTo: "src/**/*.py"
---

# Python CLI Guidance

- Use the workspace virtualenv on Windows: `.venv\\Scripts\\python.exe`.
- Validate Python changes with `.venv\\Scripts\\python.exe src/aura_cli.py -h` before broader runs.
- If a validation run could reach the save prompt, pass `-o` to keep the command non-interactive.
- Keep CLI parsing, prompting, and output-directory behavior in `src/aura_cli.py`.
- Keep Aura endpoint logic, request construction, context handling, and record retrieval in `src/aura_helper.py`.
- Keep logger formatting and console color behavior in `src/colored_logger.py`.
- Preserve the Apache 2.0 header already used in Python source files.
- Prefer small, local edits over new abstractions; this repo uses straightforward helper methods and direct control flow.
- Avoid adding dependencies unless the current `requests`-only setup is clearly insufficient.
- For Experience Cloud targets under a custom site prefix, prefer explicit `--app` and `--aura` values instead of changing detection heuristics unless the user asked for a code fix.
