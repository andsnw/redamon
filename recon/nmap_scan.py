"""
RedAmon - Nmap Port & Service Scanner
======================================
Enriches reconnaissance data with comprehensive nmap scanning:
- Port scanning (TCP/UDP)
- Service/version detection
- OS fingerprinting
- Banner grabbing
- Script scanning (safe scripts only, no vuln scanning)

Scans both IPs and hostnames (subdomains) for complete coverage.
Organizes results by IP and by hostname in the JSON output.
Supports Tor/proxychains for anonymous scanning.
"""

import nmap
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    NMAP_ENABLED,
    NMAP_SCAN_TYPE,
    NMAP_TOP_PORTS,
    NMAP_CUSTOM_PORTS,
    NMAP_SERVICE_DETECTION,
    NMAP_OS_DETECTION,
    NMAP_SCRIPT_SCAN,
    NMAP_TIMEOUT,
    NMAP_SCAN_UDP,
    NMAP_SCAN_HOSTNAMES,
    USE_TOR_FOR_RECON,
)


def get_proxychains_cmd() -> Optional[str]:
    """Get the proxychains command if available."""
    for cmd in ['proxychains4', 'proxychains']:
        if shutil.which(cmd):
            return cmd
    return None


def is_root() -> bool:
    """Check if the script is running with root privileges."""
    import os
    return os.geteuid() == 0


def is_tor_running() -> bool:
    """Check if Tor is running by testing SOCKS proxy."""
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()
        return result == 0
    except Exception:
        return False


def extract_targets_from_recon(recon_data: dict) -> Tuple[Set[str], Set[str], Dict[str, List[str]]]:
    """
    Extract all unique IPs, hostnames, and build IP-to-hostname mapping.
    
    Args:
        recon_data: The domain reconnaissance JSON data
        
    Returns:
        Tuple of (unique_ips, unique_hostnames, ip_to_hostnames_mapping)
    """
    ips = set()
    hostnames = set()
    ip_to_hostnames = {}  # Maps each IP to list of hostnames pointing to it
    
    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames, ip_to_hostnames
    
    # Extract from root domain
    domain = recon_data.get("domain", "")
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ipv4_list = domain_ips.get("ipv4", [])
        ipv6_list = domain_ips.get("ipv6", [])
        
        ips.update(ipv4_list)
        ips.update(ipv6_list)
        
        if domain:
            hostnames.add(domain)
            # Map IPs to this hostname
            for ip in ipv4_list + ipv6_list:
                if ip:
                    if ip not in ip_to_hostnames:
                        ip_to_hostnames[ip] = []
                    if domain not in ip_to_hostnames[ip]:
                        ip_to_hostnames[ip].append(domain)
    
    # Extract from all subdomains
    subdomains_dns = dns_data.get("subdomains", {})
    for subdomain, subdomain_data in subdomains_dns.items():
        if subdomain_data:
            # Add hostname
            if subdomain_data.get("has_records"):
                hostnames.add(subdomain)
            
            # Add IPs and build mapping
            if subdomain_data.get("ips"):
                ipv4_list = subdomain_data["ips"].get("ipv4", [])
                ipv6_list = subdomain_data["ips"].get("ipv6", [])
                
                ips.update(ipv4_list)
                ips.update(ipv6_list)
                
                for ip in ipv4_list + ipv6_list:
                    if ip:
                        if ip not in ip_to_hostnames:
                            ip_to_hostnames[ip] = []
                        if subdomain not in ip_to_hostnames[ip]:
                            ip_to_hostnames[ip].append(subdomain)
    
    # Filter out empty strings
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames, ip_to_hostnames


def build_nmap_arguments(for_hostname: bool = False, use_tor: bool = False) -> str:
    """
    Build nmap command arguments based on configuration.
    
    Args:
        for_hostname: If True, skip OS detection (less reliable for hostnames)
        use_tor: If True, use connect scan (-sT) and disable OS detection (required for proxies)
        
    Returns:
        String of nmap arguments
    """
    args = []
    
    # When using Tor/proxy, force connect scan (SYN scans don't work through proxies)
    if use_tor:
        args.append("-sT")  # Connect scan (works through proxies)
    
    # Scan type
    if NMAP_SCAN_TYPE == "fast":
        args.append("-T4")  # Aggressive timing
    elif NMAP_SCAN_TYPE == "thorough":
        args.append("-T3")  # Normal timing
        # -A includes OS detection which doesn't work through proxies
        if not for_hostname and not use_tor:
            args.append("-A")   # OS detection, version detection, script scanning, traceroute
    elif NMAP_SCAN_TYPE == "stealth":
        if use_tor:
            args.append("-T3")  # Can't use stealth through proxy
        else:
            args.append("-T2")  # Polite timing
            args.append("-sS")  # SYN scan (stealth)
    else:  # default
        args.append("-T3")
    
    # Port specification
    if NMAP_CUSTOM_PORTS:
        args.append(f"-p {NMAP_CUSTOM_PORTS}")
    elif NMAP_TOP_PORTS > 0:
        args.append(f"--top-ports {NMAP_TOP_PORTS}")
    
    # Service/version detection
    if NMAP_SERVICE_DETECTION:
        args.append("-sV")
        args.append("--version-intensity 5")  # Medium intensity
    
    # OS detection (requires root) - only for IPs, not hostnames, and NOT through proxy
    if NMAP_OS_DETECTION and not for_hostname and not use_tor and is_root():
        args.append("-O")
        args.append("--osscan-guess")  # Guess OS if not certain
    
    # Script scanning (safe scripts only - NO vuln scripts)
    if NMAP_SCRIPT_SCAN:
        # Use only safe, non-intrusive scripts
        args.append("--script=default,banner,http-title,ssl-cert,ssh-hostkey")
    
    # Timeout
    if NMAP_TIMEOUT > 0:
        args.append(f"--host-timeout {NMAP_TIMEOUT}s")
    
    # Always include these
    args.append("-Pn")  # Treat all hosts as online (skip host discovery)
    args.append("--open")  # Only show open ports
    
    return " ".join(args)


def parse_nmap_result(nm: nmap.PortScanner, target: str, is_hostname: bool = False) -> Dict:
    """
    Parse nmap scan results for a single target into a structured dictionary.
    
    Args:
        nm: nmap.PortScanner instance with scan results
        target: IP or hostname that was scanned
        is_hostname: Whether the target is a hostname (vs IP)
        
    Returns:
        Dictionary with parsed scan data
    """
    result = {
        "target": target,
        "target_type": "hostname" if is_hostname else "ip",
        "scan_timestamp": datetime.now().isoformat(),
        "status": None,
        "resolved_ips": [],
        "hostnames": [],
        "os_detection": [],
        "ports": {
            "tcp": [],
            "udp": []
        },
        "scripts": {}
    }
    
    # Find the host in results (nmap might resolve hostname to IP)
    all_hosts = nm.all_hosts()
    if not all_hosts:
        result["status"] = "down"
        return result
    
    # Use first host found (for hostname scans, this is the resolved IP)
    host_key = all_hosts[0] if all_hosts else target
    
    if host_key not in nm.all_hosts():
        result["status"] = "down"
        return result
    
    host_data = nm[host_key]
    
    # If scanning hostname, record the resolved IP
    if is_hostname and host_key != target:
        result["resolved_ips"].append(host_key)
    
    # Host status
    result["status"] = host_data.state()
    
    # Hostnames from nmap
    if "hostnames" in host_data:
        result["hostnames"] = [
            {"name": h.get("name", ""), "type": h.get("type", "")}
            for h in host_data["hostnames"]
            if h.get("name")
        ]
    
    # OS detection
    if "osmatch" in host_data:
        for os_match in host_data["osmatch"][:3]:  # Top 3 matches
            result["os_detection"].append({
                "name": os_match.get("name", "Unknown"),
                "accuracy": os_match.get("accuracy", "0"),
                "os_family": os_match.get("osclass", [{}])[0].get("osfamily", "") if os_match.get("osclass") else ""
            })
    
    # TCP ports
    if "tcp" in host_data:
        for port, port_data in host_data["tcp"].items():
            port_info = {
                "port": port,
                "state": port_data.get("state", "unknown"),
                "service": port_data.get("name", "unknown"),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
                "extrainfo": port_data.get("extrainfo", ""),
                "cpe": port_data.get("cpe", "")
            }
            
            # Include script results for this port
            if "script" in port_data:
                port_info["scripts"] = port_data["script"]
            
            result["ports"]["tcp"].append(port_info)
    
    # UDP ports
    if "udp" in host_data:
        for port, port_data in host_data["udp"].items():
            port_info = {
                "port": port,
                "state": port_data.get("state", "unknown"),
                "service": port_data.get("name", "unknown"),
                "product": port_data.get("product", ""),
                "version": port_data.get("version", ""),
            }
            result["ports"]["udp"].append(port_info)
    
    # Host scripts
    if "hostscript" in host_data:
        for script in host_data["hostscript"]:
            result["scripts"][script.get("id", "unknown")] = script.get("output", "")
    
    return result


def scan_with_proxychains(target: str, arguments: str, proxychains_cmd: str) -> Optional[str]:
    """
    Run nmap through proxychains and return XML output.
    
    Args:
        target: IP or hostname to scan
        arguments: nmap arguments string
        proxychains_cmd: proxychains command (proxychains4 or proxychains)
        
    Returns:
        XML output string or None on error
    """
    # Build the command
    cmd = [proxychains_cmd, "-q", "nmap", "-oX", "-"]  # -oX - outputs XML to stdout
    cmd.extend(arguments.split())
    cmd.append(target)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT + 60 if NMAP_TIMEOUT > 0 else 600
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None


def scan_target(nm: nmap.PortScanner, target: str, arguments: str, 
                is_hostname: bool = False, label: str = "",
                proxychains_cmd: Optional[str] = None) -> Dict:
    """
    Scan a single target with nmap, optionally through proxychains.
    
    Args:
        nm: nmap.PortScanner instance
        target: IP or hostname to scan
        arguments: nmap arguments string
        is_hostname: Whether target is a hostname
        label: Optional label for display
        proxychains_cmd: If provided, run nmap through this proxychains command
        
    Returns:
        Dictionary with scan results
    """
    display = label or target
    target_type = "hostname" if is_hostname else "IP"
    tor_indicator = " [🧅]" if proxychains_cmd else ""
    
    try:
        print(f"    [*] Scanning {target_type}: {display}{tor_indicator}...")
        
        if proxychains_cmd:
            # Run through proxychains
            xml_output = scan_with_proxychains(target, arguments, proxychains_cmd)
            if xml_output:
                nm.analyse_nmap_xml_scan(xml_output)
            else:
                raise Exception("Proxychains scan failed or timed out")
        else:
            # Direct scan
            nm.scan(hosts=target, arguments=arguments)
        
        result = parse_nmap_result(nm, target, is_hostname)
        
        # Summary
        tcp_count = len(result["ports"]["tcp"])
        udp_count = len(result["ports"]["udp"])
        if tcp_count > 0 or udp_count > 0:
            print(f"        [+] {display}: {tcp_count} TCP, {udp_count} UDP ports open")
        else:
            print(f"        [-] {display}: No open ports found")
        
        return result
        
    except Exception as e:
        print(f"        [!] Error scanning {display}: {e}")
        return {
            "target": target,
            "target_type": "hostname" if is_hostname else "ip",
            "scan_timestamp": datetime.now().isoformat(),
            "status": "error",
            "error": str(e),
            "ports": {"tcp": [], "udp": []}
        }


def run_nmap_scan(recon_data: dict, output_file: Path = None) -> dict:
    """
    Run nmap scan on all IPs and hostnames from recon data.
    Saves results incrementally after each target scan.
    
    Args:
        recon_data: Domain reconnaissance data dictionary
        output_file: Optional path to save incremental results
        
    Returns:
        Updated recon_data with nmap results added
    """
    if not NMAP_ENABLED:
        print("[*] Nmap scanning: DISABLED")
        return recon_data
    
    print("\n" + "=" * 70)
    print("               RedAmon - Nmap Port Scanner")
    print("=" * 70)
    
    # Check Tor/proxychains status
    use_tor = False
    proxychains_cmd = None
    
    if USE_TOR_FOR_RECON:
        if is_tor_running():
            proxychains_cmd = get_proxychains_cmd()
            if proxychains_cmd:
                use_tor = True
                print(f"  [🧅] ANONYMOUS MODE: Using {proxychains_cmd} + Tor")
                print(f"  [!] Note: OS detection disabled through proxy")
                print(f"  [!] Note: Using connect scan (-sT) for proxy compatibility")
            else:
                print("  [!] Tor is running but proxychains not found")
                print("  [!] Install: sudo apt install proxychains4")
                print("  [!] Falling back to direct scanning")
        else:
            print("  [!] USE_TOR_FOR_RECON enabled but Tor not running")
            print("  [!] Start Tor: sudo systemctl start tor")
            print("  [!] Falling back to direct scanning")
    
    # Extract targets
    ips, hostnames, ip_to_hostnames = extract_targets_from_recon(recon_data)
    
    if not ips and not hostnames:
        print("[!] No targets found in recon data")
        return recon_data
    
    print(f"  Unique IPs: {len(ips)}")
    print(f"  Unique Hostnames: {len(hostnames)}")
    print(f"  Hostname scanning: {'ENABLED' if NMAP_SCAN_HOSTNAMES else 'DISABLED'}")
    print(f"  Scan type: {NMAP_SCAN_TYPE}")
    print(f"  Service detection: {NMAP_SERVICE_DETECTION}")
    
    # Show OS detection status with explanation if disabled
    os_detection_enabled = NMAP_OS_DETECTION and not use_tor and is_root()
    if NMAP_OS_DETECTION and not use_tor and not is_root():
        print(f"  OS detection: DISABLED (requires sudo)")
    else:
        print(f"  OS detection: {os_detection_enabled}")
    print("=" * 70 + "\n")
    
    # Initialize scanner
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError as e:
        print(f"[!] Nmap not found or not installed: {e}")
        print("[!] Install nmap: sudo apt install nmap")
        return recon_data
    
    # Build arguments (with Tor adjustments if needed)
    ip_arguments = build_nmap_arguments(for_hostname=False, use_tor=use_tor)
    hostname_arguments = build_nmap_arguments(for_hostname=True, use_tor=use_tor)
    
    print(f"[*] Nmap arguments (IPs): {ip_arguments}")
    if NMAP_SCAN_HOSTNAMES:
        print(f"[*] Nmap arguments (hostnames): {hostname_arguments}")
    if use_tor:
        print(f"[*] Proxychains: {proxychains_cmd}")
    print()
    
    # Initialize results structure
    nmap_results = {
        "scan_metadata": {
            "scan_timestamp": datetime.now().isoformat(),
            "scanner_version": nm.nmap_version(),
            "scan_type": NMAP_SCAN_TYPE,
            "anonymous_mode": use_tor,
            "proxychains_cmd": proxychains_cmd if use_tor else None,
            "ip_arguments": ip_arguments,
            "hostname_arguments": hostname_arguments if NMAP_SCAN_HOSTNAMES else None,
            "total_ips": len(ips),
            "total_hostnames": len(hostnames) if NMAP_SCAN_HOSTNAMES else 0,
        },
        "by_ip": {},
        "by_hostname": {},
        "ip_to_hostnames": ip_to_hostnames,
        "summary": {
            "ips_scanned": 0,
            "ips_up": 0,
            "hostnames_scanned": 0,
            "hostnames_up": 0,
            "total_tcp_ports": 0,
            "total_udp_ports": 0
        }
    }
    
    def save_incremental():
        """Save current results to file incrementally."""
        if output_file:
            recon_data["nmap"] = nmap_results
            with open(output_file, 'w') as f:
                json.dump(recon_data, f, indent=2)
    
    # =========================================================================
    # PHASE 1: Scan all unique IPs
    # =========================================================================
    if ips:
        print("[*] PHASE 1: Scanning IPs...")
        print("-" * 40)
        
        for ip in sorted(ips):
            result = scan_target(nm, ip, ip_arguments, is_hostname=False, 
                               proxychains_cmd=proxychains_cmd if use_tor else None)
            nmap_results["by_ip"][ip] = result
            nmap_results["summary"]["ips_scanned"] += 1
            if result.get("status") == "up":
                nmap_results["summary"]["ips_up"] += 1
            nmap_results["summary"]["total_tcp_ports"] += len(result["ports"]["tcp"])
            nmap_results["summary"]["total_udp_ports"] += len(result["ports"]["udp"])
            save_incremental()  # Save after each IP
    
    # =========================================================================
    # PHASE 2: Scan all hostnames (if enabled)
    # =========================================================================
    if NMAP_SCAN_HOSTNAMES and hostnames:
        print(f"\n[*] PHASE 2: Scanning Hostnames...")
        print("-" * 40)
        
        for hostname in sorted(hostnames):
            result = scan_target(nm, hostname, hostname_arguments, is_hostname=True, 
                               label=hostname, proxychains_cmd=proxychains_cmd if use_tor else None)
            nmap_results["by_hostname"][hostname] = result
            nmap_results["summary"]["hostnames_scanned"] += 1
            if result.get("status") == "up":
                nmap_results["summary"]["hostnames_up"] += 1
            # Don't double-count ports for summary (already counted in IP scan)
            save_incremental()  # Save after each hostname
    
    # =========================================================================
    # PHASE 3: UDP scan (if enabled)
    # =========================================================================
    if NMAP_SCAN_UDP and ips:
        if use_tor:
            print("\n[!] UDP scans are not reliable through Tor/proxychains - skipping")
        else:
            print("\n[*] PHASE 3: UDP Scans (this may take a while)...")
            print("-" * 40)
            udp_args = "-sU --top-ports 100 -T4 -Pn"
            
            for ip in sorted(ips):
                try:
                    print(f"    [*] UDP scanning {ip}...")
                    nm.scan(hosts=ip, arguments=udp_args)
                    if ip in nm.all_hosts() and "udp" in nm[ip]:
                        for port, port_data in nm[ip]["udp"].items():
                            nmap_results["by_ip"][ip]["ports"]["udp"].append({
                                "port": port,
                                "state": port_data.get("state", "unknown"),
                                "service": port_data.get("name", "unknown"),
                            })
                            nmap_results["summary"]["total_udp_ports"] += 1
                    save_incremental()  # Save after each UDP scan
                except Exception as e:
                    print(f"        [!] UDP scan error for {ip}: {e}")
    
    # Add nmap results to recon data
    recon_data["nmap"] = nmap_results
    
    # Print summary
    summary = nmap_results["summary"]
    print(f"\n{'=' * 70}")
    print(f"[+] NMAP SCAN COMPLETE")
    if use_tor:
        print(f"[+] Anonymous mode: YES (via {proxychains_cmd})")
    print(f"[+] IPs scanned: {summary['ips_scanned']} ({summary['ips_up']} up)")
    if NMAP_SCAN_HOSTNAMES:
        print(f"[+] Hostnames scanned: {summary['hostnames_scanned']} ({summary['hostnames_up']} up)")
    print(f"[+] Total open TCP ports: {summary['total_tcp_ports']}")
    print(f"[+] Total open UDP ports: {summary['total_udp_ports']}")
    print(f"{'=' * 70}")
    
    return recon_data


def enrich_recon_file(recon_file: Path) -> dict:
    """
    Load a recon JSON file, enrich it with nmap data, and save it back.
    
    Args:
        recon_file: Path to the recon JSON file
        
    Returns:
        Enriched recon data
    """
    # Load existing data
    with open(recon_file, 'r') as f:
        recon_data = json.load(f)
    
    # Run nmap scan
    enriched_data = run_nmap_scan(recon_data)
    
    # Save enriched data
    with open(recon_file, 'w') as f:
        json.dump(enriched_data, f, indent=2)
    
    print(f"[+] Enriched data saved to: {recon_file}")
    
    return enriched_data
