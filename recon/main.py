#!/usr/bin/env python3
"""
RedAmon - Main Reconnaissance Controller
=========================================
Orchestrates all OSINT reconnaissance modules:
1. WHOIS lookup (integrated into domain recon JSON)
2. Subdomain discovery & DNS resolution
3. Nmap port & service scanning (enriches domain recon JSON)
4. GitHub secret hunting (separate JSON output)

Run this file to execute the full recon pipeline.
"""

import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    TARGET_DOMAIN,
    USE_TOR_FOR_RECON,
    USE_BRUTEFORCE_FOR_SUBDOMAINS,
    GITHUB_HUNTER_ENABLED,
    GITHUB_ACCESS_TOKEN,
    GITHUB_TARGET_ORG,
    NMAP_ENABLED,
)

# Import recon modules
from recon.whois_recon import whois_lookup
from recon.domain_recon import discover_subdomains
from recon.github_secret_hunt import GitHubSecretHunter
from recon.nmap_scan import run_nmap_scan

# Output directory
OUTPUT_DIR = Path(__file__).parent / "output"


def build_scan_type() -> str:
    """Build dynamic scan type based on enabled modules."""
    modules = ["domain_recon"]
    if NMAP_ENABLED:
        modules.append("nmap")
    if GITHUB_HUNTER_ENABLED:
        modules.append("github")
    return "_".join(modules)


def save_recon_file(data: dict, output_file: Path):
    """Save recon data to JSON file."""
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)


def run_domain_recon(domain: str, anonymous: bool = False, bruteforce: bool = False) -> dict:
    """
    Run combined WHOIS + subdomain discovery + DNS resolution.
    Produces a single unified JSON file with incremental saves.
    
    Args:
        domain: Target domain (e.g., "example.com")
        anonymous: Use Tor to hide real IP
        bruteforce: Enable Knockpy bruteforce mode
        
    Returns:
        Complete reconnaissance data including WHOIS and subdomains
    """
    print("\n" + "=" * 70)
    print("               RedAmon - Domain Reconnaissance")
    print("=" * 70)
    print(f"  Target: {domain}")
    print(f"  Anonymous Mode: {anonymous}")
    print(f"  Bruteforce Mode: {bruteforce}")
    print("=" * 70 + "\n")
    
    # Setup output file
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"recon_{domain}.json"
    
    # Initialize result structure with dynamic scan_type and empty modules_executed
    combined_result = {
        "metadata": {
            "scan_type": build_scan_type(),
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain,
            "anonymous_mode": anonymous,
            "bruteforce_mode": bruteforce,
            "modules_executed": []
        },
        "whois": {},
        "subdomains": [],
        "subdomain_count": 0,
        "dns": {}
    }
    
    # Step 1: WHOIS lookup
    print("[PHASE 1] WHOIS Lookup")
    print("-" * 40)
    try:
        whois_result = whois_lookup(domain, save_output=False)
        combined_result["whois"] = whois_result.get("whois_data", {})
        print(f"[+] WHOIS data retrieved successfully")
    except Exception as e:
        print(f"[!] WHOIS lookup failed: {e}")
        combined_result["whois"] = {"error": str(e)}
    
    combined_result["metadata"]["modules_executed"].append("whois")
    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")
    
    # Step 2: Subdomain discovery & DNS resolution
    print(f"\n[PHASE 2] Subdomain Discovery & DNS Resolution")
    print("-" * 40)
    recon_result = discover_subdomains(
        domain,
        anonymous=anonymous,
        bruteforce=bruteforce,
        resolve=True,
        save_output=False
    )
    
    combined_result["subdomains"] = recon_result.get("subdomains", [])
    combined_result["subdomain_count"] = recon_result.get("subdomain_count", 0)
    combined_result["metadata"]["modules_executed"].append("subdomain_discovery")
    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")
    
    # Step 3: DNS resolution (already done in discover_subdomains)
    combined_result["dns"] = recon_result.get("dns", {})
    combined_result["metadata"]["modules_executed"].append("dns_resolution")
    save_recon_file(combined_result, output_file)
    print(f"[+] Saved: {output_file}")
    
    # Step 4: Nmap port scanning (enriches the data, saves incrementally)
    if NMAP_ENABLED:
        combined_result = run_nmap_scan(combined_result, output_file=output_file)
        combined_result["metadata"]["modules_executed"].append("nmap_scan")
        save_recon_file(combined_result, output_file)
    
    print(f"\n{'=' * 70}")
    print(f"[+] DOMAIN RECON COMPLETE")
    print(f"[+] Subdomains found: {combined_result['subdomain_count']}")
    if NMAP_ENABLED and "nmap" in combined_result:
        nmap_data = combined_result["nmap"]
        summary = nmap_data.get("summary", {})
        total_ports = summary.get("total_tcp_ports", 0) + summary.get("total_udp_ports", 0)
        print(f"[+] Open ports found: {total_ports}")
    print(f"[+] Output saved: {output_file}")
    print(f"{'=' * 70}")
    
    return combined_result


def run_github_recon(token: str, target: str) -> list:
    """
    Run GitHub secret hunting.
    Produces a separate JSON file for GitHub findings.
    
    Args:
        token: GitHub personal access token
        target: Organization or username to scan
        
    Returns:
        List of findings
    """
    print("\n" + "=" * 70)
    print("               RedAmon - GitHub Secret Hunt")
    print("=" * 70)
    print(f"  Target: {target}")
    print("=" * 70 + "\n")
    
    if not token:
        print("[!] GitHub access token not configured. Skipping GitHub recon.")
        return []
    
    hunter = GitHubSecretHunter(token, target)
    findings = hunter.run()
    
    return findings


def main():
    """
    Main entry point - runs the complete recon pipeline.
    """
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 20 + "RedAmon OSINT Framework" + " " * 25 + "║")
    print("║" + " " * 15 + "Automated Reconnaissance Pipeline" + " " * 18 + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    start_time = datetime.now()
    
    # Check anonymity status if Tor is enabled
    if USE_TOR_FOR_RECON:
        try:
            from utils.anonymity import print_anonymity_status
            print_anonymity_status()
        except ImportError:
            print("[!] Anonymity module not found, proceeding without Tor status check")
    
    # Phase 1 & 2: Domain recon (WHOIS + Subdomains + DNS) - Combined JSON
    domain_result = run_domain_recon(
        TARGET_DOMAIN,
        anonymous=USE_TOR_FOR_RECON,
        bruteforce=USE_BRUTEFORCE_FOR_SUBDOMAINS
    )
    
    # Phase 3: GitHub secret hunt - Separate JSON (if enabled)
    github_findings = []
    if GITHUB_HUNTER_ENABLED:
        github_findings = run_github_recon(GITHUB_ACCESS_TOKEN, GITHUB_TARGET_ORG)
    else:
        print("\n[*] GitHub Secret Hunt: DISABLED (set GITHUB_HUNTER_ENABLED=True to enable)")
    
    # Final summary
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print("\n")
    print("╔" + "═" * 68 + "╗")
    print("║" + " " * 22 + "RECON PIPELINE COMPLETE" + " " * 23 + "║")
    print("╠" + "═" * 68 + "╣")
    print(f"║  Duration: {duration:.2f} seconds" + " " * (55 - len(f"{duration:.2f}")) + "║")
    print(f"║  Domain: {TARGET_DOMAIN}" + " " * (58 - len(TARGET_DOMAIN)) + "║")
    print(f"║  Subdomains found: {domain_result['subdomain_count']}" + " " * (48 - len(str(domain_result['subdomain_count']))) + "║")
    
    # Nmap stats
    if NMAP_ENABLED and "nmap" in domain_result:
        nmap_data = domain_result["nmap"]
        summary = nmap_data.get("summary", {})
        ips_scanned = summary.get("ips_scanned", 0)
        hostnames_scanned = summary.get("hostnames_scanned", 0)
        total_ports = summary.get("total_tcp_ports", 0) + summary.get("total_udp_ports", 0)
        nmap_info = f"{ips_scanned} IPs, {hostnames_scanned} hosts, {total_ports} ports"
        print(f"║  Nmap: {nmap_info}" + " " * (60 - len(nmap_info)) + "║")
    else:
        nmap_status = "DISABLED" if not NMAP_ENABLED else "N/A"
        print(f"║  Nmap scan: {nmap_status}" + " " * (55 - len(nmap_status)) + "║")
    
    github_status = str(len(github_findings)) if GITHUB_HUNTER_ENABLED else "DISABLED"
    print(f"║  GitHub findings: {github_status}" + " " * (49 - len(github_status)) + "║")
    print("╠" + "═" * 68 + "╣")
    print("║  Output Files:" + " " * 53 + "║")
    nmap_suffix = " + Nmap" if NMAP_ENABLED else ""
    print(f"║    • recon_{TARGET_DOMAIN}.json (WHOIS + DNS + Subs{nmap_suffix})" + " " * max(0, 12 - len(TARGET_DOMAIN) - len(nmap_suffix)) + "║")
    if GITHUB_HUNTER_ENABLED:
        print(f"║    • github_secrets_{GITHUB_TARGET_ORG}.json" + " " * max(0, 24 - len(GITHUB_TARGET_ORG)) + "║")
    print("╚" + "═" * 68 + "╝")
    print()
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

