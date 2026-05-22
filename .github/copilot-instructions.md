# GitHub Copilot Instructions — Aura Inspector

## Project Identity

`aura-inspector` is a Python security auditing tool for Salesforce Experience Cloud (Aura)
exposure. The codebase spans four layers:

| Layer | Location | Purpose |
|---|---|---|
| CLI | `src/aura_cli.py`, `src/aura_helper.py`, `src/colored_logger.py` | Core scanner CLI |
| Scanners | `src/scanners/` | Modular security scanner library |
| AI agents | `src/ai_agents/` | GPT-4o orchestration + remediation advisor |
| Web app | `src/web/` | FastAPI webapp with auth + dashboard |
| Gradio UI | `src/ui/` | Desktop-style scan UI |

---

## Python Version and Environment

- Target **Python 3.11+**. Use modern language features: `match/case`, `TypeAlias`,
  `Self`, `ParamSpec`, `dataclass(slots=True)`.
- Always use the workspace virtualenv: `.venv\Scripts\python.exe` (Windows).
- Run `.venv\Scripts\python.exe src/aura_cli.py -h` as the smoke test after any
  `src/**/*.py` change.

---

## Code Quality and Style

- Follow **PEP 8**. Use 4-space indentation, 100-character line limit.
- Add **type annotations** to every new function signature and class attribute.
- Use **`pydantic` v2** (`BaseModel`, `model_validator`, `Field`) for data that crosses
  I/O boundaries (API request/response, config, DB rows exposed to templates).
- Use **`dataclasses`** (`@dataclass(slots=True)`) for internal value objects that do not
  need Pydantic's serialisation (e.g., `ScanFinding`).
- Prefer **composition** over inheritance. Add base classes only when there are ≥2
  concrete subclasses that share non-trivial logic.

---

## Exception Handling

- **Never use a bare `except:`**. Catch the narrowest applicable exception type.
- Re-raise with context to preserve the call chain:
  ```python
  try:
      result = aura_helper.send_aura_bulk(actions)
  except requests.Timeout as exc:
      raise AuraScanError("Aura endpoint timed out") from exc
  ```
- Define project-specific exception classes in `src/exceptions.py` for errors that
  cross module boundaries. Derive from `Exception`, not `BaseException`.
- When calling `AuraHelper` from the web or UI layer, **always wrap in a
  `try/except SystemExit`** — the constructor calls `exit()` on init failure.
- Use `contextlib.suppress` only for truly ignorable errors (e.g., cleanup paths).
- Log `exc_info=True` at ERROR level when swallowing exceptions:
  ```python
  logger.error("Scan failed for job %d", scan_id, exc_info=True)
  ```

---

## Logging

- Use Python's built-in `logging` module. **Never use `print()` for diagnostics.**
- Access the module logger via the existing global pattern:
  ```python
  from colored_logger import logger   # in src/ root modules
  import logging
  logger = logging.getLogger(__name__)  # in sub-packages (scanners/, ai_agents/, web/)
  ```
- Apply **structured context** with `logger.info("...", extra={"scan_id": sid})`.
- Use **`structlog`** when adding new standalone services (MCP servers, Prefect flows)
  — configure it once at entry-point level, not inside library modules.
- Log levels: DEBUG for per-request wire traces, INFO for scan lifecycle events,
  WARNING for recoverable issues, ERROR for failures, CRITICAL only for fatal startup
  errors.
- **Never log secrets.** Use the existing `_secret_fingerprint()` / `_secret_summary()`
  helpers from `aura_helper.py` for any token or cookie value that appears in log output.

---

## AI Agent Development

- Keep orchestration logic in `src/ai_agents/scan_agent.py`. New AI capabilities go
  in new files under `src/ai_agents/`.
- Use the **OpenAI Python SDK v1+** (`openai.OpenAI` sync client or
  `openai.AsyncOpenAI` for async flows). Do **not** use the deprecated module-level
  `openai.ChatCompletion.create()` pattern.
- Prefer **`gpt-4o`** with `response_format={"type": "json_object"}` for structured
  output; parse with `json.loads()` and validate with a Pydantic model before use.
- Always provide a **rule-based fallback** that fires when `OPENAI_API_KEY` is absent
  or the API call raises `openai.APIError`. Never let missing AI credentials abort a
  scan — degrade gracefully.
- Encapsulate prompts as **module-level constants** (UPPER_SNAKE_CASE strings), not
  inline f-strings. This makes prompts reviewable and testable.
- Add **retry with exponential back-off** for transient API errors using
  `tenacity.retry` with `wait_exponential(min=1, max=16)` and
  `retry_if_exception_type(openai.RateLimitError)`.
- Use `progress_callback` hooks (already wired in `SecurityScanAgent.run_full_scan`)
  to emit status updates without coupling the agent to any UI framework.

---

## FastMCP Server Development

- Use the **`fastmcp`** library (`pip install fastmcp`) for all MCP tool server work.
- Declare tools with `@mcp.tool()` on type-annotated functions — FastMCP auto-generates
  the JSON schema from the signature:
  ```python
  from fastmcp import FastMCP
  mcp = FastMCP("aura-inspector-mcp")

  @mcp.tool()
  def run_guest_scan(target_url: str, no_gql: bool = False) -> dict:
      """Run a guest-mode Aura scan and return structured findings."""
      ...
  ```
- Place MCP server entry-points under `src/mcp/` as separate modules; never mix MCP
  server code into the core scanner or web-app modules.
- Use `mcp.resource()` for read-only lookup tools (e.g., fetching a saved scan by ID
  from the database) and `mcp.tool()` for actions with side effects.
- Return plain Python dicts or Pydantic models from tool functions; FastMCP serialises
  them automatically.
- Start the server with `mcp.run(transport="stdio")` for Claude Desktop / VS Code
  integration; use `mcp.run(transport="sse", host="0.0.0.0", port=8765)` for network
  access.

---

## Prefect Horizon Deployment

- Use **Prefect 3.x** APIs. Do not use Prefect 2.x `@flow(task_runner=...)` legacy
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
- **Always use `get_run_logger()` inside flows and tasks** — never the module-level
  `logging.getLogger()` inside flow/task bodies. Outside flow context, use standard
  `logging`.
- Use **`ConcurrentTaskRunner`** (default in Prefect 3) to run the three scanners
  (`AuraFuzzer`, `IDORScanner`, `ApexScanner`) in parallel via `asyncio`.
- Persist scan results as **Prefect artifacts** for traceability:
  ```python
  from prefect.artifacts import create_markdown_artifact
  await create_markdown_artifact(key="scan-report", markdown=report_md)
  ```
- Deploy flows with `flow.deploy()` targeting a **Prefect work pool**. Store
  deployment config in `prefect.yaml` at the repo root; keep all secrets in
  **Prefect Blocks** (Secret block), never in `prefect.yaml` directly.
- For scheduled recurring scans, define an `interval_schedule` or `cron_schedule`
  in `prefect.yaml` under the `deployments:` key.
- Place all Prefect flow definitions under `src/flows/` to keep them separate from
  the web app and CLI layers.

---

## Security

- Apply OWASP Top 10 checks to all new code.
- Never log, print, or embed raw credentials, tokens, cookies, or API keys.
- Validate and sanitise all user inputs at system boundaries (CLI args, web form
  fields, API parameters) before passing deeper into the stack.
- Use `SECRET_KEY` from environment variables for JWT signing; reject startup if the
  key matches the insecure development default in production (`WEB_ENV=production`).
- Parameterise all SQLAlchemy queries; never use string interpolation for SQL.
- Set `HttpOnly` and `SameSite=Strict` on session cookies.

---

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

---

## Dependency Policy

- **Base CLI**: `requests` only.
- **Web app**: add to `requirements-web.txt` and `[project.optional-dependencies] web`.
- **AI / LLM**: add to `requirements-ai.txt` and `[project.optional-dependencies] ai`.
- **MCP server**: add to `requirements-mcp.txt` and `[project.optional-dependencies] mcp`.
- **Prefect flows**: add to `requirements-flows.txt` and `[project.optional-dependencies] flows`.
- Every new optional dependency must be pinned to a minimum compatible version
  (e.g., `fastmcp>=2.0.0`, `prefect>=3.0.0`, `tenacity>=8.2.0`).
