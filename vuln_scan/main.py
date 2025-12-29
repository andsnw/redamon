#!/usr/bin/env python3
"""
RedAmon - Vulnerability Scanner Main Entry Point
=================================================
Orchestrates GVM/OpenVAS vulnerability scanning using recon data.

Reads targets from recon JSON files and runs vulnerability scans
against discovered IPs and hostnames using GVM.

Usage:
    # From project root (with GVM running in Docker):
    python vuln_scan/main.py
    
    # Or run via Docker Compose:
    docker compose --profile scanner up python-scanner
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
    GVM_ENABLED,
    GVM_SCAN_TARGETS,
    GVM_CLEANUP_AFTER_SCAN,
)

from vuln_scan.gvm_scanner import (
    GVMScanner,
    extract_targets_from_recon,
    load_recon_file,
    save_vuln_results,
    GVM_AVAILABLE,
)


# Output directory for vulnerability results
OUTPUT_DIR = Path(__file__).parent / "output"


def run_vulnerability_scan(
    domain: str = TARGET_DOMAIN,
    scan_targets: str = GVM_SCAN_TARGETS,
    cleanup: bool = GVM_CLEANUP_AFTER_SCAN,
) -> dict:
    """
    Run vulnerability scan against targets from recon data.
    
    Args:
        domain: Target domain (reads from recon_<domain>.json)
        scan_targets: "both", "ips_only", or "hostnames_only"
        cleanup: Delete targets/tasks after scan
        
    Returns:
        Complete vulnerability scan results
    """
    print("\n" + "=" * 70)
    print("           RedAmon - GVM Vulnerability Scanner")
    print("=" * 70)
    print(f"  Target Domain: {domain}")
    print(f"  Scan Strategy: {scan_targets}")
    print(f"  Cleanup After: {cleanup}")
    print("=" * 70 + "\n")
    
    # Check if GVM library is available
    if not GVM_AVAILABLE:
        print("[!] ERROR: python-gvm library not installed")
        print("[!] Install with: pip install python-gvm")
        return {"error": "python-gvm not installed"}
    
    # Load recon data
    print("[*] Loading recon data...")
    try:
        recon_data = load_recon_file(domain)
        print(f"    [+] Loaded: recon_{domain}.json")
    except FileNotFoundError as e:
        print(f"[!] ERROR: {e}")
        print(f"[!] Run domain recon first: python recon/main.py")
        return {"error": str(e)}
    
    # Extract targets
    ips, hostnames = extract_targets_from_recon(recon_data)
    print(f"    [+] Found {len(ips)} unique IPs")
    print(f"    [+] Found {len(hostnames)} unique hostnames")
    
    if not ips and not hostnames:
        print("[!] No targets found in recon data")
        return {"error": "No targets found"}
    
    # Initialize results structure
    results = {
        "metadata": {
            "scan_type": "vulnerability_scan",
            "scan_timestamp": datetime.now().isoformat(),
            "target_domain": domain,
            "scan_strategy": scan_targets,
            "recon_file": f"recon_{domain}.json",
            "targets": {
                "ips": list(ips),
                "hostnames": list(hostnames)
            }
        },
        "scans": [],
        "summary": {
            "total_vulnerabilities": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "log": 0,
            "hosts_scanned": 0,
        }
    }
    
    # Connect to GVM
    print("\n[*] Connecting to GVM...")
    scanner = GVMScanner()
    
    if not scanner.connect():
        print("[!] ERROR: Failed to connect to GVM")
        print("[!] Make sure GVM is running:")
        print("[!]   cd vuln_scan && docker compose up -d")
        print("[!]   docker compose logs -f gvmd  # Wait for 'Starting GVMd'")
        return {"error": "Failed to connect to GVM"}
    
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_file = OUTPUT_DIR / f"vuln_{domain}.json"
    
    def save_incremental():
        """Save current results incrementally."""
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    try:
        # =====================================================================
        # PHASE 1: Scan IPs (one at a time for incremental saving)
        # =====================================================================
        if scan_targets in ("both", "ips_only") and ips:
            ip_list = list(ips)
            print(f"\n[*] PHASE 1: Scanning {len(ip_list)} IP addresses (individually)...")
            print("-" * 50)
            
            for i, ip in enumerate(ip_list, 1):
                print(f"\n[*] IP {i}/{len(ip_list)}: {ip}")
                
                ip_results = scanner.scan_targets(
                    targets=[ip],
                    target_name=f"IP_{ip.replace('.', '_')}",
                    cleanup=cleanup
                )
                ip_results["scan_type"] = "ip_scan"
                ip_results["target_ip"] = ip
                results["scans"].append(ip_results)
                
                # Update summary
                if "severity_summary" in ip_results:
                    for sev, count in ip_results["severity_summary"].items():
                        results["summary"][sev] += count
                results["summary"]["total_vulnerabilities"] += ip_results.get("vulnerability_count", 0)
                results["summary"]["hosts_scanned"] += ip_results.get("hosts_scanned", 0)
                
                # Save after each IP
                save_incremental()
                print(f"    [+] Progress saved to {output_file}")
        
        # =====================================================================
        # PHASE 2: Scan Hostnames (one at a time for incremental saving)
        # =====================================================================
        if scan_targets in ("both", "hostnames_only") and hostnames:
            hostname_list = list(hostnames)
            print(f"\n[*] PHASE 2: Scanning {len(hostname_list)} hostnames (individually)...")
            print("-" * 50)
            
            for i, hostname in enumerate(hostname_list, 1):
                print(f"\n[*] Hostname {i}/{len(hostname_list)}: {hostname}")
                
                hostname_results = scanner.scan_targets(
                    targets=[hostname],
                    target_name=f"Host_{hostname.replace('.', '_')}",
                    cleanup=cleanup
                )
                hostname_results["scan_type"] = "hostname_scan"
                hostname_results["target_hostname"] = hostname
                results["scans"].append(hostname_results)
                
                # Update summary
                if "severity_summary" in hostname_results:
                    for sev, count in hostname_results["severity_summary"].items():
                        results["summary"][sev] += count
                results["summary"]["total_vulnerabilities"] += hostname_results.get("vulnerability_count", 0)
                
                # Save after each hostname
                save_incremental()
                print(f"    [+] Progress saved to {output_file}")
        
        # Final save
        save_vuln_results(results, domain)
        
    finally:
        scanner.disconnect()
    
    # Print summary
    summary = results["summary"]
    print(f"\n{'=' * 70}")
    print(f"[+] VULNERABILITY SCAN COMPLETE")
    print(f"[+] Domain: {domain}")
    print(f"[+] Total vulnerabilities: {summary['total_vulnerabilities']}")
    print(f"    • Critical: {summary['critical']}")
    print(f"    • High: {summary['high']}")
    print(f"    • Medium: {summary['medium']}")
    print(f"    • Low: {summary['low']}")
    print(f"    • Log: {summary['log']}")
    print(f"[+] Hosts scanned: {summary['hosts_scanned']}")
    print(f"[+] Output: {output_file}")
    print(f"{'=' * 70}")
    
    return results


def main():
    """Main entry point."""
    if not GVM_ENABLED:
        print("[*] GVM vulnerability scanning: DISABLED")
        print("[*] Enable in params.py: GVM_ENABLED = True")
        return 0
    
    # Run the scan
    start_time = datetime.now()
    
    try:
        results = run_vulnerability_scan(
            domain=TARGET_DOMAIN,
            scan_targets=GVM_SCAN_TARGETS,
            cleanup=GVM_CLEANUP_AFTER_SCAN,
        )
        
        if "error" in results:
            print(f"\n[!] Scan failed: {results['error']}")
            return 1
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        raise
    
    # Print duration
    duration = (datetime.now() - start_time).total_seconds()
    print(f"\n[*] Total scan time: {duration:.2f} seconds")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

