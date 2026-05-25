# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Salesforce Security AI Scanner — FastMCP Server
==============================
Exposes the scanner and remediation library as MCP tools and resources so that
AI assistants (Claude Desktop, VS Code Copilot, etc.) can drive security scans
against Salesforce Experience Cloud sites programmatically.

Tools
-----
  run_guest_scan   – Guest-mode Aura scan; no credentials required.
  run_auth_scan    – Authenticated scan using a Salesforce session cookie.
  get_remediation  – Return Salesforce-specific remediation steps for an OWASP ref.
  explain_finding  – Ask GPT-4o to explain a single finding (AI optional).

Resources
---------
  scan://schema    – JSON schema describing a scan result object.
  scan://owasp     – Supported OWASP API Security 2023 references and their titles.

Transport
---------
  stdio  (default) – for Claude Desktop / VS Code Copilot integration.
  sse              – for network-accessible deployments.
  Set MCP_TRANSPORT=sse and MCP_PORT=<port> to switch.

Usage
-----
  python src/mcp/server.py                # stdio (default)
  MCP_TRANSPORT=sse MCP_PORT=8765 python src/mcp/server.py
"""

import json
import logging
import os
import sys

import structlog

# ── make src/ importable when run directly ──────────────────────────────────
_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from fastmcp import FastMCP  # noqa: E402  (import after sys.path patch)

# ── structured logging (entry-point only — no structlog inside library modules) ──
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
_slog = structlog.get_logger("aura-inspector-mcp")

# ── late imports from the aura-inspector library ─────────────────────────────
from aura_helper import AuraHelper  # noqa: E402
from ai_agents.scan_agent import SecurityScanAgent  # noqa: E402
from ai_agents.remediation_advisor import RemediationAdvisor  # noqa: E402

# Optional AI dependency — tool degrades gracefully without it
try:
    import openai as _openai  # noqa: F401 (presence check)
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False

# ── MCP server instance ───────────────────────────────────────────────────────
mcp = FastMCP(
    "aura-inspector-mcp",
    instructions=(
        "This server provides tools to run Salesforce Experience Cloud (Aura) security "
        "scans and retrieve structured remediation guidance. "
        "Use run_guest_scan for unauthenticated assessments and run_auth_scan when you "
        "have a valid Salesforce session cookie. "
        "Always call get_remediation after a scan to attach Salesforce Setup steps and "
        "Apex code examples to each finding."
    ),
)

# ── Shared helper ─────────────────────────────────────────────────────────────

def _build_aura_helper(
    target_url: str,
    cookies: str | None = None,
    proxy: str | None = None,
    insecure_tls: bool = False,
    app_path: str | None = None,
    aura_path: str | None = None,
) -> AuraHelper:
    """
    Construct an AuraHelper instance.

    Raises ValueError on invalid arguments (never calls sys.exit — callers should
    catch SystemExit as a signal that the endpoint is unreachable).
    """
    if not target_url or not target_url.startswith(("http://", "https://")):
        raise ValueError(f"target_url must be a full HTTP(S) URL, got: {target_url!r}")
    return AuraHelper(
        url=target_url.rstrip("/"),
        cookies=cookies or None,
        proxy=proxy or None,
        insecure=insecure_tls,
        app=app_path or None,
        aura=aura_path or None,
    )


# ═════════════════════════════════════════════════════════════════════════════
# TOOLS
# ═════════════════════════════════════════════════════════════════════════════

@mcp.tool()
def run_guest_scan(
    target_url: str,
    no_gql: bool = False,
    insecure_tls: bool = False,
    proxy: str | None = None,
    app_path: str | None = None,
    aura_path: str | None = None,
    openai_api_key: str | None = None,
) -> dict:
    """
    Run a guest-mode (unauthenticated) Aura security scan.

    The scan runs three analysis phases sequentially:
      1. AuraFuzzer   – endpoint fuzzing for over-privileged guest access
      2. IDORScanner  – insecure direct object reference detection
      3. ApexScanner  – custom controller system-mode pattern detection

    After all three phases, an AI analysis pass enriches the findings with
    risk scoring and priority remediation actions (requires OPENAI_API_KEY or
    the openai_api_key argument; degrades gracefully to rule-based analysis).

    Parameters
    ----------
    target_url      : Full URL of the Salesforce Experience Cloud site root.
    no_gql          : Skip GraphQL-based probes (reduces traffic).
    insecure_tls    : Ignore TLS certificate errors (use only in lab environments).
    proxy           : Optional HTTP proxy URL (e.g. "http://127.0.0.1:8080").
    app_path        : Explicit Experience Cloud app path override (e.g. "/s").
    aura_path       : Explicit Aura endpoint path override (e.g. "/s/sfsites/aura").
    openai_api_key  : Override for the OPENAI_API_KEY environment variable.

    Returns
    -------
    dict with keys:
      findings        – list of finding dicts (scanner, title, severity, description,
                        evidence, remediation, owasp_ref, affected_objects)
      ai_analysis     – dict (risk_summary, critical_patterns, priority_actions,
                        estimated_risk_score)
      summary         – dict (total_findings, by_severity, remediation_sections)
      target_url      – echoed back for reference
      scan_type       – "guest"
    """
    _slog.info("run_guest_scan started", target=target_url)
    try:
        aura = _build_aura_helper(target_url, proxy=proxy, insecure_tls=insecure_tls,
                                  app_path=app_path, aura_path=aura_path)
    except (ValueError, SystemExit) as exc:
        raise RuntimeError(f"Failed to initialise Aura connection to {target_url!r}: {exc}") from exc

    agent = SecurityScanAgent(aura, openai_api_key=openai_api_key or os.environ.get("OPENAI_API_KEY"))
    result = agent.run_full_scan()
    result["target_url"] = target_url
    result["scan_type"] = "guest"
    _slog.info("run_guest_scan complete", target=target_url,
               findings=len(result.get("findings", [])))
    return result


@mcp.tool()
def run_auth_scan(
    target_url: str,
    cookies: str,
    proxy: str | None = None,
    no_gql: bool = False,
    insecure_tls: bool = False,
    app_path: str | None = None,
    aura_path: str | None = None,
    openai_api_key: str | None = None,
) -> dict:
    """
    Run an authenticated Aura security scan using a Salesforce session cookie.

    Identical phases to run_guest_scan, but executed with a valid session so
    the scanner can observe authenticated attack surfaces in addition to those
    visible to the guest profile.

    Parameters
    ----------
    target_url      : Full URL of the Salesforce Experience Cloud site root.
    cookies         : Salesforce session cookie string (e.g. "sid=<token>").
                      Obtain from browser DevTools → Application → Cookies after
                      logging in to the Experience Cloud site, or via OAuth.
    proxy           : Optional HTTP proxy URL.
    no_gql          : Skip GraphQL-based probes.
    insecure_tls    : Ignore TLS certificate errors (lab use only).
    app_path        : Explicit Experience Cloud app path override.
    aura_path       : Explicit Aura endpoint path override.
    openai_api_key  : Override for OPENAI_API_KEY env var.

    Returns
    -------
    Same shape as run_guest_scan, with scan_type = "auth".
    """
    if not cookies or not cookies.strip():
        raise ValueError("cookies must be a non-empty Salesforce session cookie string.")
    _slog.info("run_auth_scan started", target=target_url)
    try:
        aura = _build_aura_helper(target_url, cookies=cookies, proxy=proxy,
                                  insecure_tls=insecure_tls, app_path=app_path,
                                  aura_path=aura_path)
    except (ValueError, SystemExit) as exc:
        raise RuntimeError(f"Failed to initialise authenticated Aura connection to {target_url!r}: {exc}") from exc

    agent = SecurityScanAgent(aura, openai_api_key=openai_api_key or os.environ.get("OPENAI_API_KEY"))
    result = agent.run_full_scan()
    result["target_url"] = target_url
    result["scan_type"] = "auth"
    _slog.info("run_auth_scan complete", target=target_url,
               findings=len(result.get("findings", [])))
    return result


@mcp.tool()
def get_remediation(owasp_ref: str) -> dict:
    """
    Return Salesforce-specific remediation guidance for an OWASP API Security ref.

    Parameters
    ----------
    owasp_ref : OWASP API Security 2023 reference, e.g. "API1", "API1:2023",
                or the full string "API1:2023 Broken Object Level Authorization".
                Short codes API1–API8 are normalised automatically.

    Returns
    -------
    dict with keys:
      title       – Vulnerability class name.
      owasp       – Canonical reference string (e.g. "API1:2023").
      setup_steps – Ordered list of Salesforce Setup navigation steps.
      apex_example – Minimal Apex code demonstrating the fix, or null.
    """
    # Normalise: strip everything after the first space, uppercase
    short_ref = owasp_ref.strip().upper().split(":")[0].split(" ")[0]
    advisor = RemediationAdvisor()

    # Create a minimal finding-like object to look up the remediation
    class _F:
        pass

    f = _F()
    f.owasp_ref = short_ref
    sections = advisor.generate_report_sections([f])
    if sections:
        return sections[0]
    return {
        "title": "No remediation guidance found",
        "owasp": owasp_ref,
        "setup_steps": [],
        "apex_example": None,
        "note": f"Supported refs: API1, API3, API5, API8. Received: {owasp_ref!r}",
    }


@mcp.tool()
def explain_finding(
    title: str,
    description: str,
    owasp_ref: str | None = None,
    evidence: str | None = None,
    openai_api_key: str | None = None,
) -> dict:
    """
    Ask GPT-4o to explain a single scan finding in plain language (AI optional).

    When the OpenAI SDK is unavailable or no API key is configured, the tool
    returns a rule-based explanation derived from the OWASP reference.

    Parameters
    ----------
    title         : Finding title from a scan result.
    description   : Finding description from a scan result.
    owasp_ref     : Optional OWASP reference (e.g. "API1:2023").
    evidence      : Optional evidence snippet from the finding.
    openai_api_key: Override for OPENAI_API_KEY env var.

    Returns
    -------
    dict with keys:
      plain_language_summary – One-paragraph plain-language explanation.
      business_impact        – Who is affected and how.
      suggested_next_steps   – Up to 3 concrete actions for the developer.
      source                 – "ai" | "rule_based"
    """
    api_key = openai_api_key or os.environ.get("OPENAI_API_KEY")

    if not (_OPENAI_AVAILABLE and api_key):
        remediation = get_remediation(owasp_ref or "API8")
        return {
            "plain_language_summary": (
                f"The finding '{title}' indicates a {owasp_ref or 'security'} vulnerability. "
                f"{description}"
            ),
            "business_impact": (
                "Unauthenticated or under-privileged users may be able to read, modify, or enumerate "
                "data they should not have access to, leading to data breaches or account takeover."
            ),
            "suggested_next_steps": remediation.get("setup_steps", [])[:3],
            "source": "rule_based",
        }

    import openai  # noqa: PLC0415 — already confirmed available above

    _EXPLAIN_PROMPT = (
        "You are a Salesforce security expert. A scan has detected the following finding:\n\n"
        "Title: {title}\n"
        "Description: {description}\n"
        "OWASP Ref: {owasp_ref}\n"
        "Evidence: {evidence}\n\n"
        "Return a JSON object with exactly these keys:\n"
        "  plain_language_summary – one paragraph for a developer audience.\n"
        "  business_impact        – who is affected and how (one paragraph).\n"
        "  suggested_next_steps   – list of up to 3 concrete Salesforce-specific actions.\n"
    )

    client = openai.OpenAI(api_key=api_key)
    try:
        response = client.chat.completions.create(
            model=os.environ.get("OPENAI_MODEL", "gpt-4o"),
            messages=[
                {"role": "system", "content": "You are a helpful Salesforce security assistant."},
                {"role": "user", "content": _EXPLAIN_PROMPT.format(
                    title=title,
                    description=description,
                    owasp_ref=owasp_ref or "N/A",
                    evidence=evidence or "N/A",
                )},
            ],
            response_format={"type": "json_object"},
            max_tokens=800,
        )
        result = json.loads(response.choices[0].message.content)
        result["source"] = "ai"
        return result
    except openai.APIError as exc:
        _slog.warning("explain_finding: OpenAI API error", error=str(exc))
        return {
            "plain_language_summary": description,
            "business_impact": "See OWASP reference for details.",
            "suggested_next_steps": [],
            "source": "rule_based",
            "error": str(exc),
        }


# ═════════════════════════════════════════════════════════════════════════════
# RESOURCES  (read-only reference data)
# ═════════════════════════════════════════════════════════════════════════════

@mcp.resource("scan://schema")
def scan_result_schema() -> str:
    """
    JSON Schema for a scan result returned by run_guest_scan / run_auth_scan.
    Use this to understand the structure before processing findings programmatically.
    """
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AuraInspectorScanResult",
        "type": "object",
        "properties": {
            "target_url": {"type": "string", "format": "uri"},
            "scan_type": {"type": "string", "enum": ["guest", "auth"]},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "scanner": {"type": "string"},
                        "title": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "description": {"type": "string"},
                        "evidence": {"type": ["string", "null"]},
                        "remediation": {"type": ["string", "null"]},
                        "owasp_ref": {"type": ["string", "null"]},
                        "affected_objects": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["scanner", "title", "severity", "description"],
                },
            },
            "ai_analysis": {
                "type": "object",
                "properties": {
                    "risk_summary": {"type": "string"},
                    "critical_patterns": {"type": "array", "items": {"type": "string"}},
                    "priority_actions": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "action": {"type": "string"},
                                "urgency": {"type": "string", "enum": ["immediate", "short-term", "long-term"]},
                                "type": {"type": "string", "enum": ["config", "code", "policy"]},
                            },
                        },
                    },
                    "estimated_risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
                },
            },
            "summary": {
                "type": "object",
                "properties": {
                    "total_findings": {"type": "integer"},
                    "by_severity": {"type": "object"},
                    "remediation_sections": {"type": "array"},
                },
            },
        },
        "required": ["target_url", "scan_type", "findings", "ai_analysis", "summary"],
    }
    return json.dumps(schema, indent=2)


@mcp.resource("scan://owasp")
def owasp_references() -> str:
    """
    Supported OWASP API Security 2023 references and their vulnerability titles.
    Pass the short code (e.g. "API1") to get_remediation to fetch Salesforce fix steps.
    """
    refs = {
        "API1": "Broken Object Level Authorization (BOLA / IDOR)",
        "API3": "Broken Object Property Level Authorization (Excessive Data Exposure / FLS)",
        "API5": "Broken Function Level Authorization",
        "API8": "Security Misconfiguration",
    }
    return json.dumps(refs, indent=2)


# ═════════════════════════════════════════════════════════════════════════════
# Entry point
# ═════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """Console-script entry point for ``aura-inspector-mcp``."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8765"))
        _slog.info("Starting aura-inspector-mcp SSE server", host=host, port=port)
        mcp.run(transport="sse", host=host, port=port)
    else:
        _slog.info("Starting aura-inspector-mcp stdio server")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
