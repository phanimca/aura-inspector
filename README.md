# Salesforce Security AI Scanner

> **Built by [phanimca](https://github.com/phanimca)** &mdash; an AI-powered security auditing tool for Salesforce Experience Cloud (Aura).  
> **Live Demo**: [https://phani-aura-inspector.vercel.app](https://phani-aura-inspector.vercel.app)

**Salesforce Security AI Scanner** is a security auditing toolkit for Salesforce Experience Cloud (Aura). It automates the discovery of misconfigured endpoints, over-privileged guest access, IDOR vulnerabilities, and Apex controller weaknesses. It ships as four integrated surfaces: a command-line scanner, a web dashboard, a Gradio desktop UI, and a FastMCP server for AI assistant integration.

For background, see the Mandiant blog post: [Auditing Salesforce Aura Data Exposure](https://cloud.google.com/blog/topics/threat-intelligence/auditing-salesforce-aura-data-exposure).

---

## Author

| | |
|---|---|
| **Author** | Phani |
| **Email** | phani.dummy@hotmail.com |
| **Live App** | [https://phani-aura-inspector.vercel.app](https://phani-aura-inspector.vercel.app) |
| **PyPI** | [phani-aura-inspector](https://pypi.org/project/phani-aura-inspector/) |
| **License** | Apache 2.0 |

---

## Table of Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Requirements](#requirements)
4. [Environment Variables](#environment-variables)
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

## Environment Variables

All configuration is driven by environment variables — no config files are needed.  
For local development, create a `.env` file at the repo root (it is git-ignored).

> **Security note:** Never commit secrets to source control.

### Required — app will not work correctly without these

| Variable | Example | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://user:pass@host/db?sslmode=require` | Persistent storage. Without it the app uses ephemeral SQLite in `/tmp` and **all data is lost on every serverless cold start**. Use [Neon](https://neon.tech) (free tier) or Vercel Postgres. |
| `SECRET_KEY` | `openssl rand -hex 32` output | Signs JWT session cookies. The built-in default is public and **insecure in production** — always override this. |
| `APP_BASE_URL` | `https://phani-aura-inspector.vercel.app` | Canonical public URL of the app. Required for Salesforce OAuth — without it the OAuth redirect URI uses the ephemeral Vercel deployment URL and causes a `redirect_uri_mismatch` error on every new deploy. |

### Required for Salesforce authenticated scans

This tool uses the **OAuth 2.0 Authorization Code + PKCE (S256)** flow — the same
approach used by the Salesforce CLI `sf org login web` command.  
**No Consumer Secret is required or stored.**

Create a Salesforce **Connected App** (or External Client App, Spring '26+) and configure it:

1. **Setup → App Manager → New Connected App**
2. Enable OAuth Settings.
3. Set **Callback URL** to `https://<your-app>.vercel.app/auth/sf/callback`  
   (and `http://localhost:8484/callback` for the CLI browser flow).
4. Add scopes: **api**, **web**.
5. In **OAuth Policies**, uncheck **"Require Secret for Web Server Flow"**  
   *(or enable "Require PKCE")* — this allows PKCE without a client secret.
6. Note the **Consumer Key** only — the Consumer Secret is not needed.

| Variable | Example | Description |
|---|---|---|
| `SF_CLIENT_ID` | `3MVG9...` | Connected App Consumer Key |
| `SF_INSTANCE_URL` | `https://login.salesforce.com` | Login URL — use `https://test.salesforce.com` for sandbox. Defaults to production. |

### Required for AI-powered analysis (GPT-4o / GitHub Models)

Without these, every scan falls back to rule-based risk scoring automatically.

| Variable | Example | Description |
|---|---|---|
| `OPENAI_API_KEY` | `ghp_...` (GitHub PAT) or `sk-...` (OpenAI key) | API key for the AI analysis endpoint |
| `OPENAI_BASE_URL` | `https://models.github.ai/inference` | Base URL for an OpenAI-compatible endpoint. Leave unset to use OpenAI directly. Set to the GitHub Models URL to use GitHub Models (free with a PAT that has `models:read` permission). |
| `OPENAI_MODEL` | `openai/gpt-4o-mini` | Model name. Use `openai/gpt-4o-mini` for GitHub Models or `gpt-4o` for OpenAI. |

#### GitHub Models quick-start (free alternative to OpenAI)

1. Generate a GitHub Personal Access Token with **Models → Read** permission.
2. Set the three variables above in Vercel.
3. No Connected App, no paid subscription needed.

### Optional — have safe defaults

| Variable | Default | Override when |
|---|---|---|
| `DEFAULT_ADMIN_USERNAME` | `phani` | You want a different admin username |
| `DEFAULT_ADMIN_EMAIL` | `phani.dummy@hotmail.com` | You want a different admin email |
| `DEFAULT_ADMIN_PASSWORD` | `Admin@123` | **Change this** — the default is public |
| `WEB_PORT` | `8080` | Running the web server locally on a different port |

### Set automatically by Vercel (do not add manually)

| Variable | Description |
|---|---|
| `VERCEL` | Set to `1` on every serverless invocation |
| `VERCEL_URL` | Deployment-specific URL (changes per deploy — do not use for OAuth redirect URIs) |
| `VERCEL_PROJECT_PRODUCTION_URL` | Stable production alias — used as fallback if `APP_BASE_URL` is not set |
| `WEB_ENV` | Set to `production` via `vercel.json` |

### Vercel setup checklist

Go to your Vercel project → **Settings → Environment Variables** and add:

```
DATABASE_URL          = postgresql://...          (Production + Preview)
SECRET_KEY            = <random 32-byte hex>      (Production + Preview)
APP_BASE_URL          = https://<your-alias>.vercel.app  (Production only)
SF_CLIENT_ID          = <Connected App key>       (Production + Preview)
OPENAI_API_KEY        = <GitHub PAT or sk-...>    (Production + Preview)
OPENAI_BASE_URL       = https://models.github.ai/inference  (Production + Preview)
OPENAI_MODEL          = openai/gpt-4o-mini        (Production + Preview)
DEFAULT_ADMIN_PASSWORD = <strong password>        (Production only)
```

After adding variables, redeploy: `vercel --prod --yes`

### Local `.env` example

```dotenv
# Required
DATABASE_URL=sqlite:///./data/aura_inspector.db
SECRET_KEY=replace-with-a-long-random-string
APP_BASE_URL=http://localhost:8080

# Salesforce OAuth (PKCE — no client secret needed)
SF_CLIENT_ID=3MVG9...

# AI analysis via GitHub Models (free)
OPENAI_API_KEY=ghp_your_github_pat
OPENAI_BASE_URL=https://models.github.ai/inference
OPENAI_MODEL=openai/gpt-4o-mini

# Admin account
DEFAULT_ADMIN_PASSWORD=MyStrongPassword!
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

### Authenticated scan via Salesforce OAuth (PKCE browser flow)

```bash
# Opens your default browser to Salesforce login; session cookie is captured automatically.
# No Consumer Secret needed — PKCE replaces the shared secret.
python src/aura_cli.py -U phani -u https://yoursite.my.salesforce.com \
  --oauth --sf-client-id 3MVG9...

# Sandbox org
python src/aura_cli.py -U phani -u https://yoursite.sandbox.my.salesforce.com \
  --oauth --sf-client-id 3MVG9... --sf-instance-url https://test.salesforce.com
```

> **Connected App requirement:** In the Connected App OAuth Policies, uncheck  
> **"Require Secret for Web Server Flow"** (or enable **"Require PKCE"**).  
> Add `http://localhost:8484/callback` as a Callback URL.

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
| `--oauth` | Authenticate via Salesforce OAuth 2.0 PKCE browser flow (opens browser, no secret required) |
| `--sf-instance-url` | Salesforce login URL for OAuth (default: `https://login.salesforce.com`; use `https://test.salesforce.com` for sandbox) |
| `--sf-client-id` | Connected App Consumer Key (required with `--oauth`) |
| `--no-gql` | Skip GraphQL record-count probes |
| `--no-banner` | Suppress the ASCII banner |
| `-d / --debug` | Print debug-level output |
| `-v / --verbose` | Print verbose output |

---

## Web Dashboard

The web dashboard provides a persistent scan history with authentication, a live scan status page, a severity chart dashboard, printable HTML reports, and Connected Apps management for Salesforce OAuth authenticated scans.

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

See the [Environment Variables](#environment-variables) section for the full reference.
Key variables for the web dashboard:

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | *(insecure default)* | JWT signing key — **must be set in production** |
| `DATABASE_URL` | SQLite in `/tmp` | PostgreSQL URL for persistent storage |
| `APP_BASE_URL` | auto-detected | Canonical public URL — required for Salesforce OAuth |
| `OPENAI_API_KEY` | *(none)* | Enables AI analysis; falls back to rule-based scoring |
| `OPENAI_BASE_URL` | *(OpenAI direct)* | Set to `https://models.github.ai/inference` for GitHub Models |
| `OPENAI_MODEL` | `openai/gpt-4o-mini` | Model name for the AI analysis endpoint |

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
| GET/POST | `/connected-apps` | Admin: manage Connected Apps for OAuth scans |
| GET | `/api/connected-apps` | JSON list of Connected Apps for scan form dropdown |
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

```dotenv
# Required
DATABASE_URL=postgresql://user:pass@host/db?sslmode=require
SECRET_KEY=replace-with-a-long-random-string
APP_BASE_URL=https://your-domain.com

# Salesforce OAuth (PKCE — no client secret needed)
SF_CLIENT_ID=your-connected-app-client-id
SF_INSTANCE_URL=https://yourinstance.my.salesforce.com

# AI analysis via GitHub Models
OPENAI_API_KEY=ghp_your_github_pat
OPENAI_BASE_URL=https://models.github.ai/inference
OPENAI_MODEL=openai/gpt-4o-mini
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
