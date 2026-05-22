---
name: salesforce-experience-cloud-targeting
description: 'Detect and normalize Salesforce Experience Cloud target URLs for aura-inspector scans. Use for custom site prefixes, explicit --app/--aura retries, guest versus authenticated scan setup, and avoiding interactive output prompts.'
argument-hint: 'Experience Cloud URL or scan command to normalize'
user-invocable: true
---

# Salesforce Experience Cloud Targeting

## When to Use

- The user provides a Salesforce Experience Cloud URL and wants to run `aura-inspector`.
- A scan fails with `Could not identify aura endpoint.`
- The target appears to live under a custom site prefix such as `/<site-name>/s`.
- The user needs help choosing between guest, cookie-based, or request-file-based scans.

## What This Skill Does

- Converts Experience Cloud URLs into the most reliable `aura-inspector` command shape.
- Separates the site root from the app path.
- Derives an explicit Aura endpoint when auto-detection is likely to fail.
- Recommends non-interactive scan commands when output should be saved automatically.

## Procedure

1. Parse the provided URL.
2. If the path contains a site prefix such as `/<prefix>/s`, treat the hostname root as `-u`.
3. Set `--app` to the visible Experience Cloud app path, for example `/<prefix>/s`.
4. Set `--aura` to the matching Aura endpoint, usually `/<prefix>/s/sfsites/aura`.
5. Preserve user intent for flags like `-k`, `--no-gql`, `-c`, `-r`, and `-o`.
6. Prefer `.venv\Scripts\python.exe src/aura_cli.py ...` for workspace-local execution on Windows.
7. If the user wants saved results, pass `-o` up front so the CLI does not block on its save prompt.

## Normalization Pattern

Given a target like:

`https://example.my.site.com/producttesterprogram/s/?language=en_IN&locale=en_IN`

Prefer:

```powershell
.\.venv\Scripts\python.exe src/aura_cli.py -u "https://example.my.site.com" --app "/producttesterprogram/s" --aura "/producttesterprogram/s/sfsites/aura"
```

## Notes

- `aura-inspector` only probes a fixed set of root-relative Aura endpoints during auto-detection.
- Custom site prefixes often require explicit `--app` and `--aura` values.
- Guest scans and authenticated scans can produce materially different results.
- For authenticated runs, prefer `-c` with cookies or `-r` with an Aura request file instead of inventing new auth flows.