"""
RedAmon - Global Parameters
Configure target URL and other settings here.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")

# Target domain for OSINT reconnaissance (e.g., "example.com" - no http/https)
TARGET_DOMAIN = "devergolabs.com"

# Hide your real IP during subdomain enumeration (uses Tor + proxychains)
# Requires: Tor running (sudo systemctl start tor) + proxychains4 installed
USE_TOR_FOR_RECON = False
USE_BRUTEFORCE_FOR_SUBDOMAINS = False

# =============================================================================
# GitHub Secret Hunt Configuration
# =============================================================================

# Enable/disable GitHub secret hunting module
GITHUB_HUNTER_ENABLED = False

# GitHub Personal Access Token (loaded from .env file)
# Generate at: https://github.com/settings/tokens
# Required scopes: repo (for private repos) or public_repo (for public only)
GITHUB_ACCESS_TOKEN = os.getenv("GITHUB_ACCESS_TOKEN", "")

# Target organization or username to scan
GITHUB_TARGET_ORG = "samugit83"

# Also scan repos of organization members (slower but more thorough)
GITHUB_SCAN_MEMBERS = False

# Also scan gists of organization members
GITHUB_SCAN_GISTS = True

# Scan commit history for leaked secrets (much slower but finds deleted secrets)
GITHUB_SCAN_COMMITS = True

# Maximum number of commits to scan per repo (0 = all commits)
GITHUB_MAX_COMMITS = 100

# Output results to JSON file
GITHUB_OUTPUT_JSON = True

# =============================================================================
# Nmap Port Scanner Configuration
# =============================================================================

# Enable/disable nmap port scanning module
NMAP_ENABLED = True

# Scan type: "fast", "thorough", "stealth", or "default"
# - fast: Quick scan with aggressive timing (-T4)
# - thorough: Comprehensive scan with OS/version detection (-T3 -A)
# - stealth: Slow, stealthy SYN scan (-T2 -sS)
# - default: Standard scan (-T3)
NMAP_SCAN_TYPE = "thorough"

# Number of top ports to scan (0 = use nmap default, ignored if CUSTOM_PORTS set)
NMAP_TOP_PORTS = 1000

# Custom port specification (e.g., "22,80,443,8080" or "1-1000")
# Leave empty to use TOP_PORTS setting
NMAP_CUSTOM_PORTS = ""

# Enable service/version detection (-sV)
NMAP_SERVICE_DETECTION = True

# Enable OS fingerprinting (-O) - requires root/sudo
NMAP_OS_DETECTION = True

# Enable safe script scanning (banner, http-title, ssl-cert, etc.)
# NOTE: This does NOT include vulnerability scripts
NMAP_SCRIPT_SCAN = True

# Host timeout in seconds (0 = no timeout)
NMAP_TIMEOUT = 300

# Scan UDP ports (slower but finds more services)
NMAP_SCAN_UDP = False

# Scan hostnames/subdomains in addition to IPs
# Useful for virtual hosts where services respond differently per hostname
NMAP_SCAN_HOSTNAMES = True

# =============================================================================
# GVM/OpenVAS Vulnerability Scanner Configuration
# =============================================================================

# Enable/disable GVM vulnerability scanning module
GVM_ENABLED = True

# GVM connection settings (for Docker deployment)
GVM_SOCKET_PATH = "/run/gvmd/gvmd.sock"  # Unix socket path inside container
GVM_USERNAME = "admin"
GVM_PASSWORD = os.getenv("GVM_PASSWORD", "admin")  # Set in .env for security

# Scan configuration preset:
# - "Full and fast" - Comprehensive scan, good performance (recommended)
# - "Full and fast ultimate" - Most thorough, slower
# - "Full and very deep" - Deep scan, very slow
# - "Full and very deep ultimate" - Maximum coverage, very slow
# - "Discovery" - Network discovery only, no vulnerability tests
# - "Host Discovery" - Basic host enumeration
# - "System Discovery" - System enumeration
GVM_SCAN_CONFIG = "Full and fast"

# Scan targets strategy:
# - "both" - Scan IPs and hostnames separately for thorough coverage
# - "ips_only" - Only scan IP addresses
# - "hostnames_only" - Only scan hostnames/subdomains
GVM_SCAN_TARGETS = "both"

# Maximum time to wait for a single scan task (seconds, 0 = unlimited)
# Note: "Full and fast" scans can take 1-2+ hours per target
GVM_TASK_TIMEOUT = 14400  # 4 hours (increase if needed for many targets)

# Poll interval for checking scan status (seconds)
GVM_POLL_INTERVAL = 30

# Cleanup targets and tasks after scan completion
GVM_CLEANUP_AFTER_SCAN = True

