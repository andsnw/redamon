# RedAmon

**Unmask the hidden before the world does.**

An automated OSINT reconnaissance and vulnerability scanning framework.

---

## 🔧 Prerequisites

```bash
sudo apt install tor proxychains4 nmap
sudo systemctl start tor
```

---

## 🔍 Phase 1: Reconnaissance

Run domain recon (requires sudo for nmap OS detection):

```bash
sudo PATH="$PATH" "$(pwd)/venv/bin/python" recon/main.py
```

This discovers:
- WHOIS information
- Subdomains & DNS records
- Open ports & services (nmap)

Output: `recon/output/recon_<domain>.json`

---

## 🛡️ Phase 2: Vulnerability Scanning (GVM/OpenVAS)

### What is GVM?

**GVM (Greenbone Vulnerability Management)** is an open-source vulnerability scanner that:
- Tests for **80,000+ known vulnerabilities** (CVEs)
- Detects misconfigurations, outdated software, weak credentials
- Produces detailed reports with severity ratings (Critical/High/Medium/Low)

### Architecture (Minimal API Setup)

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Compose                        │
│                                                          │
│  Python Scanner ──► GVMD (API) ──► OpenVAS-D ──► Redis  │
│                        │                                 │
│                   PostgreSQL                             │
│                                                          │
│  + Data containers: NVTs, SCAP, CERT (vulnerability DB)  │
└─────────────────────────────────────────────────────────┘
```

| Component | Purpose |
|-----------|---------|
| **GVMD** | Management daemon - exposes API for Python |
| **OpenVAS-D** | Scanner daemon - executes vulnerability tests |
| **PostgreSQL** | Stores configs, results, scan history |
| **Redis** | Inter-process communication |
| **Data containers** | Download 80K+ vulnerability tests on first run |

### Quick Start

#### 1. Start GVM containers (first time takes 10-15 min)

```bash
# Pull all required images (first time only)
docker pull registry.community.greenbone.net/community/redis-server
docker pull registry.community.greenbone.net/community/pg-gvm:stable
docker pull registry.community.greenbone.net/community/gvmd:stable
docker pull registry.community.greenbone.net/community/ospd-openvas:stable
docker pull registry.community.greenbone.net/community/vulnerability-tests
docker pull registry.community.greenbone.net/community/notus-data
docker pull registry.community.greenbone.net/community/scap-data
docker pull registry.community.greenbone.net/community/cert-bund-data
docker pull registry.community.greenbone.net/community/dfn-cert-data
docker pull registry.community.greenbone.net/community/data-objects
docker pull registry.community.greenbone.net/community/report-formats
docker pull registry.community.greenbone.net/community/gpg-data

# Start containers
docker compose up -d
```

#### 2. Watch logs until ready

```bash
docker compose logs -f gvmd
# more logs
docker compose logs -f gvmd ospd-openvas python-scanner
# Wait for: "Starting GVMd" or similar ready message
```

#### 3. Create admin user (first time only)

```bash
docker compose exec -u gvmd gvmd gvmd --create-user=admin --password=admin
```

#### 4. Run vulnerability scan

```bash
# Make sure recon was run first for your target domain (Phase 1)
docker compose --profile scanner up python-scanner

# if the file change
docker compose build python-scanner && docker compose --profile scanner up python-scanner
```

Output: `vuln_scan/output/vuln_<domain>.json`

### Docker Commands

```bash
# Start GVM
docker compose up -d

# Stop GVM
docker compose down

# View logs
docker compose logs -f gvmd

# Check status
docker compose ps

# Run Python scanner in container
docker compose --profile scanner up python-scanner

# Reset everything (delete all data)
docker compose down -v
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Failed to connect to GVM" | Wait for gvmd to finish starting (check logs) |
| "OpenVAS scanner not found" | Data sync still in progress, wait 10-15 min |
| Scan takes too long | Reduce targets or use "Discovery" scan config |
| Out of disk space | GVM needs ~20GB for vulnerability data |

---

## 📁 Project Structure

```
RedAmon/
├── params.py              # Global configuration
├── docker-compose.yml     # GVM vulnerability scanner
├── Dockerfile             # Python scanner container
├── requirements.txt       # Python dependencies
├── recon/                 # Reconnaissance modules
│   ├── main.py            # Recon entry point
│   ├── domain_recon.py    # Subdomain discovery
│   ├── whois_recon.py     # WHOIS lookup
│   ├── nmap_scan.py       # Port scanning
│   └── output/            # Recon results (JSON)
└── vuln_scan/             # Vulnerability scanning
    ├── main.py            # Vuln scan entry point
    ├── gvm_scanner.py     # GVM API integration
    └── output/            # Vulnerability results (JSON)
```

---

## 📊 Output Format

### Recon Output (`recon_<domain>.json`)
```json
{
  "whois": { "registrar": "...", "creation_date": "..." },
  "subdomains": ["www.example.com", "api.example.com"],
  "dns": { "A": ["1.2.3.4"], "MX": ["mail.example.com"] },
  "nmap": { "ports": [{ "port": 443, "service": "https" }] }
}
```

### Vulnerability Output (`vuln_<domain>.json`)
```json
{
  "summary": { "critical": 2, "high": 5, "medium": 12 },
  "vulnerabilities": [
    {
      "name": "SSL/TLS: Certificate Expired",
      "severity": 7.5,
      "host": "1.2.3.4",
      "cves": ["CVE-2024-1234"],
      "solution": "Renew the SSL certificate"
    }
  ]
}
```
