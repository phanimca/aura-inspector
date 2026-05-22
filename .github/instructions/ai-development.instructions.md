---
description: "Use when editing AI agent, MCP server, or Prefect flow files. Covers OpenAI SDK v1+ patterns, FastMCP tool/resource definition, Prefect 3.x flow/task decoration, retry strategies, structured logging in async and flow contexts, and graceful degradation."
name: "AI, MCP, and Prefect Guidance"
applyTo: "src/{ai_agents,mcp,flows}/**/*.py"
---

# AI, MCP, and Prefect Development Guidance

## OpenAI SDK (v1+)

- Always import from `openai` directly — **never** use the deprecated module-level API:
  ```python
  # CORRECT
  from openai import OpenAI, AsyncOpenAI, APIError, RateLimitError
  client = OpenAI()                          # reads OPENAI_API_KEY from env
  async_client = AsyncOpenAI()

  # WRONG — deprecated pre-v1 pattern
  import openai
  openai.ChatCompletion.create(...)
  ```
- Use `response_format={"type": "json_object"}` for structured responses. Validate the
  parsed dict with a **Pydantic model** before touching any field:
  ```python
  import json
  from pydantic import BaseModel

  class AiAnalysisResult(BaseModel):
      risk_score: int
      risk_summary: str
      critical_patterns: list[str]
      priority_actions: list[dict]

  raw = client.chat.completions.create(
      model="gpt-4o",
      response_format={"type": "json_object"},
      messages=messages,
  )
  result = AiAnalysisResult.model_validate(json.loads(raw.choices[0].message.content))
  ```
- Prefer **`gpt-4o`** as the default model. Allow override via env var
  `OPENAI_MODEL` for future-proofing.
- Define all prompts as **module-level string constants**:
  ```python
  ANALYSIS_SYSTEM_PROMPT = (
      "You are a Salesforce security expert. Analyse the provided scan findings "
      "and return a JSON object with keys: risk_score, risk_summary, "
      "critical_patterns, priority_actions."
  )
  ```

## Retry and Rate-Limit Handling

- Add `tenacity` retry to every function that calls the OpenAI API:
  ```python
  from tenacity import (
      retry,
      stop_after_attempt,
      wait_exponential,
      retry_if_exception_type,
  )
  from openai import RateLimitError, APIConnectionError

  @retry(
      stop=stop_after_attempt(4),
      wait=wait_exponential(multiplier=1, min=1, max=16),
      retry=retry_if_exception_type((RateLimitError, APIConnectionError)),
      reraise=True,
  )
  def _call_openai(client: OpenAI, messages: list[dict]) -> str:
      ...
  ```
- Always provide a **rule-based fallback** that fires when `OPENAI_API_KEY` is unset
  or when `openai.APIError` is raised after all retries. The fallback must return the
  same shape as the AI path — never let the caller know which path ran.

## Graceful Degradation

- Check for the API key at call time, not at import time:
  ```python
  def _analyze(self, findings: list[ScanFinding]) -> AiAnalysisResult:
      if not self._api_key:
          return self._rule_based_analysis(findings)
      try:
          return self._analyze_with_ai(findings)
      except openai.APIError:
          logger.warning("OpenAI API unavailable; falling back to rule-based analysis")
          return self._rule_based_analysis(findings)
  ```
- Never raise an unhandled `openai.APIError` to the caller.

## FastMCP Server Patterns

- Install with `pip install fastmcp` and pin `fastmcp>=2.0.0` in `requirements-mcp.txt`.
- One `FastMCP` instance per server module; place server entry-points under `src/mcp/`.
- Tool annotations flow directly from Python type hints — keep them precise:
  ```python
  from fastmcp import FastMCP
  from pydantic import AnyHttpUrl

  mcp = FastMCP("aura-inspector-mcp")

  @mcp.tool()
  def run_guest_scan(
      target_url: AnyHttpUrl,
      no_gql: bool = False,
      insecure_tls: bool = False,
  ) -> dict:
      """
      Run a guest-mode Aura scan against a Salesforce Experience Cloud site.

      Returns a dict with keys: findings (list), summary (dict), risk_score (int).
      """
      ...
  ```
- Use `@mcp.resource()` for **read-only** access (database lookups, config reads).
- Return `dict` or Pydantic model instances — FastMCP serialises them automatically.
- Transport selection:
  ```python
  if __name__ == "__main__":
      import os
      transport = os.getenv("MCP_TRANSPORT", "stdio")
      if transport == "sse":
          mcp.run(transport="sse", host="0.0.0.0", port=int(os.getenv("MCP_PORT", 8765)))
      else:
          mcp.run(transport="stdio")
  ```
- Never call `exit()` or `sys.exit()` inside a tool function — raise a descriptive
  `ValueError` or `RuntimeError` instead so FastMCP can return a proper error response.

## Prefect 3.x Flows and Tasks

- Install with `pip install prefect>=3.0.0` and pin in `requirements-flows.txt`.
- Place all flow definitions under `src/flows/`; keep them isolated from the web app
  and CLI layers.
- Decorate the top-level pipeline with `@flow` and each scanner invocation with `@task`:
  ```python
  from prefect import flow, task
  from prefect.logging import get_run_logger

  @task(retries=2, retry_delay_seconds=10, name="aura-fuzzer")
  def run_aura_fuzzer(config: ScanConfig) -> list[ScanFinding]:
      logger = get_run_logger()
      logger.info("AuraFuzzer started for %s", config.target_url)
      ...

  @task(retries=2, retry_delay_seconds=10, name="idor-scanner")
  def run_idor_scanner(config: ScanConfig) -> list[ScanFinding]:
      ...

  @flow(name="aura-security-scan", log_prints=False)
  def aura_security_scan_flow(config: ScanConfig) -> ScanReport:
      fuzzer_future  = run_aura_fuzzer.submit(config)
      idor_future    = run_idor_scanner.submit(config)
      apex_future    = run_apex_scanner.submit(config)
      all_findings   = fuzzer_future.result() + idor_future.result() + apex_future.result()
      ...
  ```
- **Inside flows and tasks, always use `get_run_logger()`**. At module level or in
  helpers called outside flow context, use `logging.getLogger(__name__)`.
- Use `.submit()` + `.result()` for concurrent task execution (Prefect 3 default
  `ConcurrentTaskRunner`).
- Persist results as **Prefect artifacts**:
  ```python
  from prefect.artifacts import create_markdown_artifact, create_table_artifact

  await create_markdown_artifact(
      key=f"scan-report-{scan_id}",
      markdown=report_markdown,
      description=f"Security scan report for {config.target_url}",
  )
  ```
- Store secrets in **Prefect Blocks** (Secret block), read at runtime:
  ```python
  from prefect.blocks.system import Secret
  openai_key = Secret.load("openai-api-key").get()
  ```
- Add scheduled deployments in `prefect.yaml`:
  ```yaml
  deployments:
    - name: nightly-scan
      flow_name: aura-security-scan
      schedule:
        cron: "0 2 * * *"
        timezone: "UTC"
      work_pool:
        name: default-agent-pool
  ```

## Structured Logging in AI / Prefect Context

- Use **`structlog`** for new standalone entry-points (MCP server `__main__`, Prefect
  worker bootstrappers):
  ```python
  import structlog

  structlog.configure(
      processors=[
          structlog.stdlib.add_log_level,
          structlog.stdlib.PositionalArgumentsFormatter(),
          structlog.processors.TimeStamper(fmt="iso"),
          structlog.processors.JSONRenderer(),
      ],
      wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
      logger_factory=structlog.PrintLoggerFactory(),
  )
  log = structlog.get_logger()
  ```
- Pass correlation IDs (scan_id, job_id) as bound context:
  ```python
  bound_log = log.bind(scan_id=scan_id, target=config.target_url)
  bound_log.info("scan_started")
  ```
- Never configure `structlog` inside a library module — only at service entry-points.
