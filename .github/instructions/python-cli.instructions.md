---
description: "Use when editing any Python source file in this repo — CLI, scanners, AI agents, web app, UI, MCP server, or Prefect flows. Covers validation, file boundaries, exception handling, logging, AI agent patterns, FastMCP server development, and Prefect Horizon deployment."
name: "Python Development Guidance"
applyTo: "src/**/*.py"
---

# Python Development Guidance

## Environment and Validation

- Use the workspace virtualenv on Windows: `.venv\Scripts\python.exe`.
- Validate Python changes with `.venv\Scripts\python.exe src/aura_cli.py -h` after any
  change to `src/aura_cli.py`, `src/aura_helper.py`, or `src/colored_logger.py`.
- For all other new modules, run `.venv\Scripts\python.exe -m py_compile <file>` before
  declaring a task complete.
- If a validation run could reach the interactive save prompt, pass `-o` to stay
  non-interactive.

## Code Quality

- Target **Python 3.11+**. Prefer `match/case`, walrus operator (`:=`), and
  `dataclass(slots=True)` where they simplify code.
- Add **type annotations** to every new function signature and class attribute.
- Use **`pydantic` v2** (`BaseModel`, `model_validator`, `Field`) for data crossing I/O
  boundaries (API payloads, config objects, DB rows passed to templates).
- Use **`dataclasses(slots=True)`** for internal value objects that do not need Pydantic
  serialisation (e.g., `ScanFinding`).
- Follow PEP 8: 4-space indent, 100-character line limit.
- Preserve the Apache 2.0 license header present in existing Python source files.

## Exception Handling

- **Never use a bare `except:`**. Catch the narrowest applicable exception type.
- Re-raise with context to preserve the full call chain:
  ```python
  try:
      result = aura_helper.send_aura_bulk(actions)
  except requests.Timeout as exc:
      raise AuraScanError("Aura endpoint timed out") from exc
  ```
- Define project-specific exception classes in `src/exceptions.py` for errors that
  cross module boundaries. Derive from `Exception`, not `BaseException`.
- When calling `AuraHelper` from the web or UI layer, **always wrap in
  `try/except SystemExit`** — the constructor calls `exit()` on init failure.
- Use `contextlib.suppress` only for genuinely ignorable errors (cleanup paths).
- Log `exc_info=True` at ERROR level whenever an exception is swallowed:
  ```python
  logger.error("Scan failed for job %d", scan_id, exc_info=True)
  ```

## Logging

- **Never use `print()` for diagnostics.** Always use the logger.
- In `src/` root modules, reuse the existing global logger:
  ```python
  from colored_logger import logger
  ```
- In sub-packages (`scanners/`, `ai_agents/`, `web/`, `ui/`, `mcp/`, `flows/`), use
  the standard module-level pattern:
  ```python
  import logging
  logger = logging.getLogger(__name__)
  ```
- Apply structured context with the `extra` kwarg:
  ```python
  logger.info("Scan started", extra={"scan_id": scan_id, "target": url})
  ```
- Use **`structlog`** for new standalone services (MCP servers, Prefect flows) —
  configure it once at the entry-point, not inside library modules.
- Log levels: DEBUG for per-request wire traces, INFO for lifecycle events, WARNING for
  recoverable issues, ERROR for failures, CRITICAL for fatal startup errors only.
- **Never log raw credentials.** Use `_secret_fingerprint()` / `_secret_summary()` from
  `aura_helper.py` for any token, cookie, or API key that appears in log output.

## AI Agent Development

- Keep orchestration in `src/ai_agents/scan_agent.py`. New AI capabilities go in new
  files under `src/ai_agents/`.
- Use the **OpenAI Python SDK v1+** (`openai.OpenAI` sync or `openai.AsyncOpenAI` for
  async). Do **not** use the deprecated `openai.ChatCompletion.create()` pattern.
- Prefer **`gpt-4o`** with `response_format={"type": "json_object"}` for structured
  output; parse with `json.loads()` and validate with a Pydantic model before use.
- Always provide a **rule-based fallback** when `OPENAI_API_KEY` is absent or the call
  raises `openai.APIError`. Never let missing AI credentials abort a scan.
- Encapsulate prompts as **module-level UPPER_SNAKE_CASE string constants** — not
  inline f-strings — so they are reviewable and testable independently.
- Add **retry with exponential back-off** using `tenacity`:
  ```python
  from tenacity import retry, wait_exponential, retry_if_exception_type
  import openai

  @retry(
      wait=wait_exponential(min=1, max=16),
      retry=retry_if_exception_type(openai.RateLimitError),
  )
  def _call_openai(client: openai.OpenAI, messages: list[dict]) -> str:
      ...
  ```
- Use `progress_callback` hooks to emit status updates without coupling the agent to
  any specific UI framework.

## FastMCP Server Development

- Use the **`fastmcp`** library for all MCP server work (`pip install fastmcp`).
- Place MCP server entry-points under `src/mcp/` — never mix MCP code into the core
  scanner, CLI, or web-app modules.
- Declare tools with `@mcp.tool()` on type-annotated functions; FastMCP derives the
  JSON schema automatically from the signature and docstring:
  ```python
  from fastmcp import FastMCP

  mcp = FastMCP("aura-inspector-mcp")

  @mcp.tool()
  def run_guest_scan(target_url: str, no_gql: bool = False) -> dict:
      """Run a guest-mode Aura scan and return structured findings."""
      ...
  ```
- Use `@mcp.resource()` for **read-only** data access (e.g., fetching a saved scan by
  ID from the database) and `@mcp.tool()` for actions with side effects.
- Return plain Python `dict` objects or Pydantic models; FastMCP serialises them
  automatically.
- Run with `mcp.run(transport="stdio")` for Claude Desktop / VS Code integration and
  `mcp.run(transport="sse", host="0.0.0.0", port=8765)` for network access.
- Add MCP dependencies to `requirements-mcp.txt` and
  `[project.optional-dependencies] mcp` in `pyproject.toml`.

## Prefect Horizon Deployment

- Use **Prefect 3.x** APIs. Do not use legacy Prefect 2.x `@flow(task_runner=...)`
  patterns.
- Decorate scan pipelines with `@flow` and individual scanner invocations with `@task`:
  ```python
  from prefect import flow, task
  from prefect.logging import get_run_logger

  @task(retries=2, retry_delay_seconds=10)
  def run_aura_fuzzer(config: ScanConfig) -> list[ScanFinding]:
      logger = get_run_logger()
      logger.info("Starting AuraFuzzer for %s", config.target_url)
      ...

  @flow(name="aura-security-scan")
  def aura_security_scan_flow(config: ScanConfig) -> ScanReport:
      ...
  ```
- **Always use `get_run_logger()` inside flows and tasks** — not `logging.getLogger()`.
  Outside flow context (module level, helpers), standard `logging` is fine.
- Use **`ConcurrentTaskRunner`** (default in Prefect 3) to run `AuraFuzzer`,
  `IDORScanner`, and `ApexScanner` in parallel via `asyncio`.
- Persist scan results as **Prefect artifacts** for traceability:
  ```python
  from prefect.artifacts import create_markdown_artifact
  await create_markdown_artifact(key="scan-report", markdown=report_md)
  ```
- Deploy with `flow.deploy()` targeting a **Prefect work pool**. Store deployment
  config in `prefect.yaml` at the repo root. Keep all secrets in **Prefect Blocks**
  (Secret block) — never embed them in `prefect.yaml` directly.
- For scheduled recurring scans, define an `interval_schedule` or `cron_schedule`
  under the `deployments:` key in `prefect.yaml`.
- Place all Prefect flow definitions under `src/flows/` to keep them separate from the
  web app and CLI layers.
- Add Prefect dependencies to `requirements-flows.txt` and
  `[project.optional-dependencies] flows` in `pyproject.toml`.

## File Boundaries

| What changes | File to edit |
|---|---|
| CLI flags, arg parsing, output saving | `src/aura_cli.py` |
| Aura HTTP, endpoint discovery, context | `src/aura_helper.py` |
| Terminal colour / logger config | `src/colored_logger.py` |
| Scanner rules and findings | `src/scanners/*.py` |
| AI orchestration, GPT prompts | `src/ai_agents/*.py` |
| FastMCP tool server | `src/mcp/*.py` |
| Prefect scan flows | `src/flows/*.py` |
| Web routes, auth, DB | `src/web/*.py` |
| Gradio UI, OAuth handler | `src/ui/*.py` |

Do not introduce circular imports across these boundaries.

## Dependency Policy

- **Base CLI**: `requests` only (see `requirements.txt`).
- **Web app**: add to `requirements-web.txt` and `[project.optional-dependencies] web`.
- **AI / LLM**: add to `requirements-ai.txt` and `[project.optional-dependencies] ai`.
- **MCP server**: add to `requirements-mcp.txt` and `[project.optional-dependencies] mcp`.
- **Prefect flows**: add to `requirements-flows.txt` and `[project.optional-dependencies] flows`.
- Every new optional dependency must be pinned to a minimum compatible version
  (`fastmcp>=2.0.0`, `prefect>=3.0.0`, `tenacity>=8.2.0`).
- Avoid adding dependencies unless the current setup is clearly insufficient for the task.
