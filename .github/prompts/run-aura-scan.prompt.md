---
description: "Run an aura-inspector scan against a Salesforce Experience Cloud target URL or Aura request file. Normalizes custom site prefixes, avoids interactive hangs, and summarizes findings."
name: "Run Aura Scan"
argument-hint: "Target URL, plus optional notes like guest/authenticated, --no-gql, or output folder"
agent: "agent"
---

Run an `aura-inspector` scan for the provided target.

Requirements:
- Treat the argument as the target URL or an authenticated Aura request file path.
- Use the workspace virtualenv Python on Windows: `.venv\Scripts\python.exe`.
- If the target is an Experience Cloud URL with a custom site prefix such as `/producttesterprogram/s`, normalize the command so `-u` is the site root and pass explicit `--app` and `--aura` values when needed.
- Prefer `-o` for output to avoid the interactive save prompt unless the user explicitly wants an interactive run.
- Preserve any user-requested flags such as `--no-gql`, `-k`, `-c`, or `-r`.
- Do not edit source files unless the user explicitly asks for a fix.

Workflow:
1. Inspect the target shape and decide whether plain `-u` is enough or whether explicit `--app` and `--aura` are needed.
2. Run the narrowest command that matches the request.
3. If the scan fails because the Aura endpoint cannot be identified, retry once with normalized root URL plus explicit `--app` and `--aura` derived from the Experience Cloud path.
4. Summarize the meaningful results, including whether the run was guest or authenticated, accessible object counts, GraphQL status, and where outputs were written.

In the final response, include the exact command used and point to any saved result files.
