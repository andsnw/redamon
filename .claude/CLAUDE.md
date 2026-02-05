# RedAmon Project Guidelines

## Project Overview

**RedAmon** - *Unmask the hidden before the world does.*

An automated OSINT reconnaissance and vulnerability scanning framework for comprehensive security assessment. The platform combines multiple security tools orchestrated by AI agents with results stored in a Neo4j graph database and visualized through a Next.js webapp.

---

## Project Structure

```
RedAmon/
├── .claude/              # Claude Code configuration
│   ├── CLAUDE.md         # General project guidelines (this file)
│   └── webapp.md         # Webapp-specific guidelines
│
├── recon/                # Reconnaissance Module (Phase 1)
│   ├── main.py           # Main entry point
│   ├── project_settings.py  # Fetches settings from webapp API
│   ├── domain_recon.py   # Subdomain discovery (crt.sh, HackerTarget, Knockpy)
│   ├── port_scan.py      # Port scanning (naabu)
│   ├── http_probe.py     # HTTP probing (httpx, headers, tech detection)
│   ├── resource_enum.py  # URL discovery (Katana, GAU, Kiterunner)
│   ├── vuln_scan.py      # Vulnerability scanning (nuclei)
│   ├── whois_recon.py    # WHOIS lookups
│   ├── github_secret_hunt.py  # GitHub secret hunting
│   ├── add_mitre.py      # MITRE ATT&CK mapping
│   ├── helpers/          # Utility modules (katana, gau, kiterunner helpers)
│   ├── data/             # Static data files (MITRE DB, IANA services)
│   ├── output/           # Scan results (combined JSON per project)
│   ├── readmes/          # Module documentation
│   ├── Dockerfile        # Kali-based container
│   └── docker-compose.yml
│
├── recon_orchestrator/   # Recon Container Orchestrator (NEW)
│   ├── api.py            # FastAPI with SSE endpoints
│   ├── container_manager.py  # Docker SDK lifecycle management
│   ├── models.py         # Pydantic models (ReconStatus, ReconState)
│   ├── requirements.txt  # Python dependencies
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── postgres_db/          # PostgreSQL Database (NEW)
│   ├── docker-compose.yml  # PostgreSQL container
│   └── .env              # Database credentials
│
├── gvm_scan/             # GVM Vulnerability Scanner (Phase 2)
│   ├── main.py           # Entry point
│   ├── gvm_scanner.py    # GVM API client
│   ├── params.py         # Configuration
│   ├── output/           # Scan results
│   ├── Dockerfile        # GVM container
│   └── docker-compose.yml
│
├── graph_db/             # Neo4j Graph Database
│   ├── neo4j_client.py   # Python client for Neo4j operations
│   ├── update_graph_from_json.py  # Import scan results to Neo4j
│   ├── readmes/          # Database documentation
│   └── docker-compose.yml  # Neo4j container
│
├── mcp/                  # MCP Servers (Model Context Protocol)
│   ├── servers/          # MCP server implementations
│   │   ├── naabu_server.py     # Port scanning tool
│   │   ├── nuclei_server.py    # Vuln scanning tool
│   │   ├── curl_server.py      # HTTP client tool
│   │   ├── metasploit_server.py  # Exploitation tool
│   │   └── run_servers.py      # Server launcher
│   ├── kali-sandbox/     # Kali Docker container
│   ├── nuclei-templates/ # Custom nuclei templates
│   ├── output/           # Scan results
│   └── docker-compose.yml
│
├── agentic/              # AI Agent Orchestrator
│   ├── orchestrator.py   # LangGraph-based agent orchestration
│   ├── api.py            # FastAPI REST endpoints
│   ├── websocket_api.py  # WebSocket API for real-time chat
│   ├── state.py          # LangGraph state definitions
│   ├── tools.py          # MCP tool definitions and execution
│   ├── utils.py          # Utility functions
│   ├── params.py         # Configuration
│   ├── logging_config.py # Logging configuration
│   ├── Dockerfile
│   └── docker-compose.yml
│
├── webapp/               # Next.js Frontend Application
│   ├── prisma/           # Prisma ORM schema
│   │   └── schema.prisma # Database models (Project, User, etc.)
│   ├── src/
│   │   ├── app/          # Next.js App Router pages
│   │   │   ├── api/recon/  # Recon API routes (start, status, logs, download)
│   │   │   └── graph/    # Graph visualization page with recon control
│   │   ├── components/   # React components
│   │   ├── hooks/        # Custom hooks (useReconStatus, useReconSSE)
│   │   ├── lib/          # Utilities, API clients
│   │   ├── providers/    # React context providers
│   │   └── styles/       # Design tokens & themes
│   └── See .claude/webapp.md for frontend guidelines
│
├── guinea_pigs/          # Test Targets (Vulnerable VMs)
│   ├── apache_2.4.25/    # CVE test environment
│   └── apache_2.4.49/    # CVE test environment
│
├── start.sh              # Start entire stack (all containers)
├── stop.sh               # Stop entire stack
├── DISCLAIMER.md         # Legal disclaimer
└── README.md             # Project documentation
```

---

## Component Details

### 1. Reconnaissance Module (`recon/`)

Automated OSINT and scanning framework. Runs entirely in Docker (Kali-based).

**Scan Pipeline:**
```
Domain → Subdomain Discovery → DNS Resolution → Port Scanning
       → HTTP Probing → Tech Detection → Resource Enumeration
       → Vulnerability Scanning → MITRE Mapping → JSON Output → Neo4j Import
```

**Modules:**
| Module | File | Tools Used |
|--------|------|------------|
| domain_discovery | `domain_recon.py` | crt.sh, HackerTarget, Knockpy |
| port_scan | `port_scan.py` | naabu |
| http_probe | `http_probe.py` | httpx |
| resource_enum | `resource_enum.py` | Katana (active crawl), GAU (passive), Kiterunner (API brute) |
| vuln_scan | `vuln_scan.py` | nuclei |
| github | `github_secret_hunt.py` | trufflehog |

**Configuration Sources (in order of precedence):**
1. **Webapp API** - When `PROJECT_ID` and `WEBAPP_API_URL` env vars are set, settings are fetched from PostgreSQL via the webapp API
2. **Environment Variables** - Override individual settings
3. **DEFAULT_SETTINGS** in `project_settings.py` - Default fallback values for CLI usage

**Key Commands:**
```bash
# From CLI (uses DEFAULT_SETTINGS fallback)
cd recon/
docker-compose build --network=host
docker-compose run --rm recon python /app/recon/main.py

# From Webapp (recommended - uses project settings from PostgreSQL)
# Click "Start Recon" in the Graph page
```

### 2. Recon Orchestrator (`recon_orchestrator/`)

FastAPI service that manages recon container lifecycle with real-time log streaming.

**Features:**
- Start/stop recon containers via REST API
- Server-Sent Events (SSE) for real-time log streaming
- Phase detection from log output
- Docker SDK for container management

**Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/recon/{projectId}/start` | POST | Start recon for project |
| `/recon/{projectId}/status` | GET | Get current status |
| `/recon/{projectId}/logs` | GET | SSE log stream |
| `/recon/{projectId}/stop` | POST | Stop running recon |

**Key Commands:**
```bash
cd recon_orchestrator/
docker-compose build
docker-compose up -d
curl http://localhost:8010/health
```

### 3. PostgreSQL Database (`postgres_db/`)

Stores project configurations with 180+ configurable parameters.

**Key Features:**
- Prisma ORM integration with webapp
- Project-specific scan settings
- User and project management

**Key Commands:**
```bash
cd postgres_db/
docker-compose up -d
# Schema managed via Prisma in webapp/
cd ../webapp && npx prisma db push
```

### 4. GVM Scanner (`gvm_scan/`)

Greenbone Vulnerability Management (OpenVAS) for deep vulnerability scanning.

- Consumes IPs/hosts from recon output
- 170,000+ Network Vulnerability Tests (NVTs)
- CVSS scoring and CVE mapping

### 5. Graph Database (`graph_db/`)

Neo4j for storing and querying security data relationships.

**Node Types:**
- Domain, Subdomain, IP, Port, Service
- Technology, Certificate, Header
- Vulnerability, CVE, MITRE ATT&CK

**Key Files:**
- `neo4j_client.py` - Full CRUD operations
- `update_graph_from_json.py` - Import scan results

### 6. MCP Servers (`mcp/`)

Model Context Protocol servers exposing security tools to AI agents.

**Available Tools:**
| Server | Port | Tool | Purpose |
|--------|------|------|---------|
| naabu | 8000 | naabu | Fast port scanning |
| curl | 8001 | curl | HTTP requests |
| nuclei | 8002 | nuclei | Vulnerability scanning |
| metasploit | 8003 | msfconsole | Exploitation |

### 7. Agent Orchestrator (`agentic/`)

LangGraph-based AI agent with REST and WebSocket APIs for autonomous pentesting.

**Features:**
- MCP tool execution (curl, naabu, nuclei, metasploit)
- Neo4j text-to-Cypher queries
- Conversation memory (LangGraph MemorySaver)
- Real-time streaming via WebSocket

**API Endpoints:**
```
# REST API
POST /chat
{
  "question": "What vulnerabilities exist on port 443?",
  "session_id": "optional-session-id"
}

# WebSocket API
WS /ws/{session_id}
```

### 8. Webapp (`webapp/`)

Next.js 16 frontend for graph visualization and recon control.

**Key Features:**
- Interactive graph visualization (2D/3D)
- Recon control panel with real-time log streaming
- AI chat interface with WebSocket
- Project management with PostgreSQL storage

See `.claude/webapp.md` for detailed guidelines.

---

## Development Conventions

### Docker-First Approach

All security tools run in Docker containers. Never install scanning tools on host.

```bash
# Each module has its own docker-compose.yml
cd <module>/
docker-compose build
docker-compose up -d
```

### Adding New Configuration Fields

When adding a new configurable setting (e.g., tool enable/disable toggle), update these 4 files:

| Step | File | Action |
|------|------|--------|
| 1 | `webapp/prisma/schema.prisma` | Add field with `@default()` value |
| 2 | `recon/project_settings.py` | Add to `DEFAULT_SETTINGS` dict AND mapping in `get_project_settings()` |
| 3 | `webapp/src/components/projects/ProjectForm/sections/*.tsx` | Add UI control (Toggle/Input) |
| 4 | `recon/<module>.py` | Load with `settings.get('SETTING_NAME', default)` |

Then run:
```bash
cd webapp && npx prisma db push && npx prisma generate
```

**Note:** Frontend defaults are fetched from backend via `/api/projects/defaults` endpoint (which proxies to `recon_orchestrator/defaults`). No need to hardcode defaults in `ProjectForm.tsx`.

### File Relationships

**Defaults flow (single source of truth):**
```
recon/project_settings.py (DEFAULT_SETTINGS)
         ↓
recon_orchestrator /defaults endpoint
         ↓
webapp /api/projects/defaults
         ↓
ProjectForm.tsx (fetches on create)
```

**Settings flow:** Prisma Schema → Webapp API → project_settings.py → recon modules

| Frontend Section | Schema Prefix | Recon Module |
|-----------------|---------------|--------------|
| KatanaSection.tsx | `katana*` | resource_enum.py |
| GauSection.tsx | `gau*` | resource_enum.py |
| KiterunnerSection.tsx | `kiterunner*` | resource_enum.py |
| NucleiSection.tsx | `nuclei*` | vuln_scan.py |
| NaabuSection.tsx | `naabu*` | port_scan.py |
| HttpxSection.tsx | `httpx*` | http_probe.py |

### Output Format

Recon outputs a single combined JSON file per project:
```
recon/output/
└── recon_{PROJECT_ID}.json    # Combined results from all modules
```

The JSON structure contains nested objects for each module:
```json
{
  "metadata": { "target_domain": "...", "modules_executed": [...] },
  "domain_discovery": { ... },
  "port_scan": { ... },
  "http_probe": { ... },
  "resource_enum": { "discovered_urls": [...], "by_base_url": {...} },
  "vuln_scan": { ... }
}
```

### Neo4j Connection

```python
from graph_db import Neo4jClient

with Neo4jClient() as client:
    client.update_graph_from_domain_discovery(data, user_id, project_id)
```

Environment variables (in each module's `.env`):
```
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=<password>
```

---

## Git Workflow

- Use descriptive commit messages with prefix like fix: feat: and others
- Keep commits atomic and focused
- Branch naming: `feature/`, `fix/`, `refactor/`

---
