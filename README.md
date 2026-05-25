# Salesforce Security AI Scanner

> **Built by [phanimca](https://github.com/phanimca)** &mdash; an AI-powered security auditing tool for Salesforce Experience Cloud (Aura).  
> **Live Demo**: [https://phani-aura-inspector.vercel.app](https://phani-aura-inspector.vercel.app)

**Salesforce Security AI Scanner** is a security auditing toolkit for Salesforce Experience Cloud (Aura). It automates the discovery of misconfigured endpoints, over-privileged guest access, IDOR vulnerabilities, and Apex controller weaknesses. It ships as four integrated surfaces: a command-line scanner, a web dashboard, a Gradio desktop UI, and a FastMCP server for AI assistant integration.

For background, see the Mandiant blog post: [Auditing Salesforce Aura Data Exposure](https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure).

---

## Author

| | |
|---|---|
| **Author** | [phanimca](https://github.com/phanimca) |
| **Live App** | [https://phani-aura-inspector.vercel.app](https://phani-aura-inspector.vercel.app) |
| **PyPI** | [phani-aura-inspector](https://pypi.org/project/phani-aura-inspector/) |
| **License** | Apache 2.0 |

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [API Keys and Secrets](#api-keys-and-secrets)
5. [Installation](#installation)
6. [CLI Usage](#cli-usage)
7. [Web Dashboard](#web-dashboard)
8. [Gradio UI](#gradio-ui)
9. [MCP Server](#mcp-server)
10. [Docker Compose](#docker-compose)
11. [Testing](#testing)
12. [Licenses](#licenses)

---

## Features

- **Guest & authenticated scanning** — discovers accessible records from both Guest and Authenticated Salesforce contexts
- **Three scanner engines** running in sequence:
  - `AuraFuzzer` — endpoint fuzzing for over-privileged guest controller access
  - `IDORScanner` — insecure direct object reference detection across Salesforce object prefixes
  - `ApexScanner` — custom controller system-mode execution pattern detection
- **GraphQL probe** — uses the undocumented Aura GraphQL method to count exposed records (skippable with `--no-gql`)
- **AI-powered analysis** — optional GPT-4o enrichment: risk scoring, critical pattern detection, and priority remediation actions; gracefully degrades to rule-based analysis when no API key is present
- **Remediation advisor** — maps each finding to OWASP API Security 2023 refs, Salesforce Setup steps, and Apex code examples
- **Web dashboard** — FastAPI app with SQLite persistence, JWT auth, scan history, and printable HTML reports
- **MCP server** — FastMCP server exposing all scanner capabilities as tools consumable by Claude Desktop, VS Code Copilot, and any MCP-compatible AI assistant

---

## Architecture

```
aura-inspector/
├── src/
│   ├── aura_cli.py            # CLI entry point
│   ├── aura_helper.py         # Aura HTTP client, endpoint discovery
│   ├── colored_logger.py      # Terminal colour / logger config
│   ├── scanners/
│   │   ├── base_scanner.py    # Severity enum, ScanFinding dataclass, BaseScanner
│   │   ├── aura_fuzzer.py     # Guest controller fuzzer
│   │   ├── idor_scanner.py    # IDOR probe across SF object prefixes
│   │   └── apex_scanner.py    # Apex system-mode pattern detector
│   ├── ai_agents/
│   │   ├── scan_agent.py      # SecurityScanAgent — orchestrates all three scanners + GPT-4o
│   │   └── remediation_advisor.py  # OWASP → Salesforce remediation lookup
│   ├── mcp/
│   │   └── server.py          # FastMCP server (4 tools, 2 resources)
│   ├── web/
│   │   ├── main.py            # FastAPI routes (port 8080)
│   │   ├── auth.py            # JWT + bcrypt password hashing
│   │   ├── database.py        # SQLAlchemy models (User, ScanJob, Finding, AiAnalysis)
│   │   ├── scan_runner.py     # Background scan daemon thread
│   │   └── templates/         # Jinja2 templates (Bootstrap 5.3 dark theme)
│   └── ui/
│       └── app.py             # Gradio desktop UI (port 7860)
├── requirements.txt           # Core: requests only
├── requirements-ai.txt        # openai, tenacity
├── requirements-mcp.txt       # fastmcp, structlog
├── requirements-web.txt       # fastapi, uvicorn, sqlalchemy, jinja2, passlib, python-jose
├── Dockerfile                 # Gradio UI image
├── Dockerfile.web             # Web dashboard image
├── Dockerfile.mcp             # MCP server image
└── docker-compose.yml         # All three services
```

---

## Requirements

- **Python 3.12+**
- **Windows**: `.venv\Scripts\python.exe` | **Linux/macOS**: `.venv/bin/python`

| Surface | Extra requirements |
|---|---|
| CLI only | `requests` (base install) |
| AI analysis | `requirements-ai.txt` (`openai>=1.0.0`, `tenacity>=8.2.0`) |
| Gradio UI | `requirements-ai.txt` + `gradio>=4.0.0` |
| MCP server | `requirements-mcp.txt` (`fastmcp>=2.0.0`, `structlog>=24.1.0`) + AI deps |
| Web dashboard | `requirements-web.txt` |

---

## API Keys and Secrets

| Variable | Required for | Where to set |
|---|---|---|
| `OPENAI_API_KEY` | AI-powered scan analysis and `explain_finding` MCP tool | Environment variable or `.env` file |
| `OPENAI_MODEL` | Override GPT model (default: `gpt-4o`) | Environment variable |
| `SECRET_KEY` | JWT signing for the web dashboard | Environment variable — **must be changed in production** |
| Salesforce session cookie (`sid=...`) | Authenticated scans | Passed via `-c` flag or `cookies` tool parameter |
| `SF_INSTANCE_URL` | Gradio OAuth flow (optional) | Environment variable |
| `SF_CLIENT_ID` | Gradio OAuth flow (optional) | Environment variable |

> **Security note:** Never commit `OPENAI_API_KEY` or `SECRET_KEY` to source control. Use a `.env` file (excluded from git) or your OS keychain.

Create a `.env` file at the repo root for local development:
```
OPENAI_API_KEY=sk-...
SECRET_KEY=some-long-random-string
```

---

## Installation

### Clone and set up a virtual environment

```powershell
# Windows
git clone https://github.com/phanimca/aura-inspector
cd aura-inspector
python -m venv .venv
.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
git clone https://github.com/phanimca/aura-inspector
cd aura-inspector
python3 -m venv .venv
source .venv/bin/activate
```

### Install dependencies

```bash
# CLI only (minimal)
pip install -r requirements.txt

# CLI + AI analysis
pip install -r requirements.txt -r requirements-ai.txt

# MCP server
pip install -r requirements.txt -r requirements-ai.txt -r requirements-mcp.txt

# Web dashboard
pip install -r requirements.txt -r requirements-web.txt

# Everything
pip install -r requirements.txt -r requirements-ai.txt -r requirements-mcp.txt -r requirements-web.txt
```

### Install as a package (optional)

```bash
pip install -e ".[ai,mcp,web]"
```

This registers the console scripts: `aura-inspector`, `aura-inspector-web`, `aura-inspector-mcp`.

---

## CLI Usage

### Smoke test

```bash
python src/aura_cli.py -h
```

### Guest scan (unauthenticated)

```bash
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com
```

### Guest scan — save output, skip GraphQL, ignore TLS errors

```bash
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com -k --no-gql -o ./results
```

### Authenticated scan with session cookie

```bash
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com \
  -c "sid=XXXXXXX; other_cookie=..."
```

### Authenticated scan from a captured Aura request file

```bash
python src/aura_cli.py -U phani -r /path/to/aura_request.txt
```

### Explicit app and aura paths (for custom site prefixes)

```bash
# Site hosted at /s with Aura endpoint at /s/sfsites/aura
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com \
  --app /s --aura /s/sfsites/aura -k -o ./results
```

### Proxy through Burp Suite

```bash
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com \
  -p http://127.0.0.1:8080 -k
```

### Full option reference

| Flag | Description |
|---|---|
| `-U / --username` | **Required.** Username to attribute the scan to. Looked up in the web DB; a new CLI-only account is created automatically if not found |
| `-u / --url` | Root URL of the Salesforce Experience Cloud site |
| `-c / --cookies` | Session cookies for authenticated scans |
| `-r / --aura-request-file` | Path to a captured request file (auto-parses cookies/token) |
| `-o / --output-dir` | Directory to save JSON results |
| `-l / --object-list` | Comma-separated list to limit object probing |
| `-p / --proxy` | HTTP proxy (e.g. `http://127.0.0.1:8080`) |
| `-k / --insecure` | Ignore TLS certificate errors |
| `--app` | Explicit app path override (e.g. `/s`, `/myApp`) |
| `--aura` | Explicit Aura endpoint path override (e.g. `/s/sfsites/aura`) |
| `--context` | Custom `aura.context` value for POST requests |
| `--token` | Custom `aura.token` value for POST requests |
| `--no-gql` | Skip GraphQL record-count probes |
| `--no-banner` | Suppress the ASCII banner |
| `-d / --debug` | Print debug-level output |
| `-v / --verbose` | Print verbose output |

---

## Web Dashboard

The web dashboard provides a persistent scan history with authentication, a live scan status page, a severity chart dashboard, and printable HTML reports.

> **Live hosted version:** [https://phani-aura-inspector.vercel.app](https://phani-aura-inspector.vercel.app)
> Default login: `phani.dummy@hotmail.com` / configured via `DEFAULT_ADMIN_PASSWORD` env var.

### Start

```bash
pip install -r requirements-web.txt
python src/web/main.py
# Open http://localhost:8080
```

### First-time setup

1. Open `http://localhost:8080/register` and create an account.
2. Log in at `http://localhost:8080/login`.
3. Go to **New Scan** → enter a target URL, choose guest or authenticated mode → **Start Scan**.
4. The dashboard polls the scan status every 2 seconds and shows findings as they arrive.
5. From a completed scan, click **View Report** for a printable summary.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | `aura-inspector-dev-key-REPLACE-IN-PRODUCTION` | JWT signing key — **must be changed in production** |
| `OPENAI_API_KEY` | *(none)* | Enables AI analysis on scan results |
| `WEB_PORT` | `8080` | Listening port |

### Routes summary

| Method | Path | Description |
|---|---|---|
| GET/POST | `/login` | Login form |
| GET/POST | `/register` | Registration form |
| GET | `/logout` | Clears session cookie |
| GET | `/dashboard` | Scan history + charts |
| GET | `/scans/new` | New scan form |
| POST | `/scans` | Submit and start a scan |
| GET | `/scans/{id}` | Scan detail + live status |
| GET | `/scans/{id}/status` | JSON polling endpoint |
| GET | `/reports/{id}` | Printable HTML report |
| GET | `/api/stats` | JSON stats for dashboard charts |

---

## Gradio UI

The Gradio UI is a desktop-style browser interface on port 7860.

```bash
pip install -r requirements.txt gradio
python src/ui/app.py
# Open http://localhost:7860
```

---

## MCP Server

The FastMCP server exposes all scanner capabilities as tools that any MCP-compatible AI assistant (Claude Desktop, VS Code Copilot, etc.) can call directly.

### Tools

| Tool | Description |
|---|---|
| `run_guest_scan` | Full unauthenticated Aura scan (AuraFuzzer + IDORScanner + ApexScanner + AI analysis) |
| `run_auth_scan` | Same as above but authenticated via a Salesforce session cookie |
| `get_remediation` | Return Salesforce Setup steps and Apex code examples for an OWASP API Security ref (API1–API10) |
| `explain_finding` | Ask GPT-4o to explain a single finding in plain language (degrades to rule-based without an API key) |

### Resources

| URI | Description |
|---|---|
| `scan://schema` | JSON Schema describing the full scan result object |
| `scan://owasp` | Supported OWASP API Security 2023 references and their titles |

### Transport modes

| Mode | Use case | How to start |
|---|---|---|
| `stdio` | Claude Desktop, VS Code Copilot (default) | `python src/mcp/server.py` |
| `sse` | Network-accessible / Docker deployments | `MCP_TRANSPORT=sse MCP_PORT=8765 python src/mcp/server.py` |

### Start the server

```bash
# Install MCP dependencies
pip install -r requirements-mcp.txt

# stdio (default — for VS Code / Claude Desktop)
python src/mcp/server.py

# SSE network mode
$env:MCP_TRANSPORT="sse"; $env:MCP_PORT="8765"
python src/mcp/server.py
```

### VS Code Copilot integration

The repo ships a pre-configured [.vscode/mcp.json](.vscode/mcp.json). After installing MCP dependencies:

1. Restart VS Code (the MCP config is loaded on startup).
2. Open the Command Palette → **MCP: List Servers** → confirm `aura-inspector` is listed.
3. In a Copilot chat, type `#aura-inspector` to attach the server context.

Example prompts:
```
Run a guest scan on https://yoursite.my.salesforce.com

Get the Salesforce remediation steps for API1

Explain this finding: "Guest user can access Account records via LightningRecordList"
```

### Claude Desktop integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aura-inspector": {
      "command": "C:/path/to/aura-inspector/.venv/Scripts/python.exe",
      "args": ["C:/path/to/aura-inspector/src/mcp/server.py"],
      "env": {
        "OPENAI_API_KEY": "sk-..."
      }
    }
  }
}
```

### Testing MCP tools without an AI client

Since the tools are plain Python functions, you can call them directly:

```bash
python -c "
import sys; sys.path.insert(0, 'src')
from mcp.server import get_remediation, owasp_references
print(get_remediation('API1'))
print(owasp_references())
"
```

---

## Docker Compose

The `docker-compose.yml` starts all three services:

| Service | Image | Port | Description |
|---|---|---|---|
| `aura-inspector-gradio` | `Dockerfile` | `7860` | Gradio desktop UI |
| `aura-inspector-web` | `Dockerfile.web` | `8080` | FastAPI web dashboard |
| `aura-inspector-mcp` | `Dockerfile.mcp` | `8765` | MCP server (SSE mode) |

### Start all services

```bash
# Create a .env file with your secrets first (see API Keys section)
docker compose up --build
```

### Start a single service

```bash
docker compose up --build aura-inspector-web
```

### Environment variables for Docker

Create a `.env` file at the repo root (Docker Compose picks it up automatically):

```
OPENAI_API_KEY=sk-...
SECRET_KEY=your-long-random-production-key
SF_INSTANCE_URL=https://yourinstance.my.salesforce.com
SF_CLIENT_ID=your-connected-app-client-id
```

---

## Testing

### CLI smoke test

```bash
python src/aura_cli.py -h
```

### Compile health check

```bash
python -m py_compile \
  src/scanners/aura_fuzzer.py \
  src/scanners/idor_scanner.py \
  src/scanners/apex_scanner.py \
  src/ai_agents/scan_agent.py \
  src/mcp/server.py
```

### Run pytest unit tests

```bash
pip install pytest pytest-mock
python -m pytest tests/ -v
```

### Integration scan against a live target

```bash
# Non-interactive guest scan, results saved to ./results
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com -k --no-gql -o ./results
```

### Web app health check

```bash
# Start the web app, then:
curl http://localhost:8080/api/stats
```

### MCP server health check (SSE mode)

```bash
# Start with MCP_TRANSPORT=sse, then:
curl http://localhost:8765/tools
```

---

## Licenses

| Component | License |
|---|---|
| salesforce-security-ai-scanner core | [Apache License 2.0](LICENSE) |
| `requests` | Apache License 2.0 |
| `openai` Python SDK | Apache License 2.0 |
| `tenacity` | Apache License 2.0 |
| `fastmcp` | Apache License 2.0 |
| `structlog` | Apache License 2.0 / MIT |
| `fastapi` | MIT |
| `uvicorn` | BSD-3-Clause |
| `sqlalchemy` | MIT |
| `jinja2` | BSD-3-Clause |
| `passlib` | BSD |
| `python-jose` | MIT |
| `gradio` | Apache License 2.0 |
| Bootstrap 5.3 (web templates) | MIT |
| Chart.js (web templates) | MIT |

---

## Developed By

- Amine Ismail
- Anirudha Kanodia
- Phani
