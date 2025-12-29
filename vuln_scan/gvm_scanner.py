"""
RedAmon - GVM/OpenVAS Vulnerability Scanner
============================================
Connects to GVM via python-gvm to run vulnerability scans.
Extracts targets from recon JSON data and saves results as JSON.

This module uses the Greenbone Management Protocol (GMP) to:
- Create scan targets from recon data
- Launch vulnerability scan tasks
- Monitor scan progress
- Extract and format results to JSON
"""

import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET
import sys

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from params import (
    GVM_SOCKET_PATH,
    GVM_USERNAME,
    GVM_PASSWORD,
    GVM_SCAN_CONFIG,
    GVM_TASK_TIMEOUT,
    GVM_POLL_INTERVAL,
    GVM_CLEANUP_AFTER_SCAN,
    TARGET_DOMAIN,
)

# GVM imports (handled gracefully if not installed)
try:
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp, GMPv227
    from gvm.protocols.gmp.requests.v224._targets import AliveTest
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False
    GvmError = Exception  # Fallback
    AliveTest = None
    print("[!] python-gvm not installed. Run: pip install python-gvm")


class GVMScanner:
    """
    GVM/OpenVAS vulnerability scanner using python-gvm.
    
    Connects to gvmd via Unix socket and executes vulnerability scans
    against targets extracted from RedAmon recon data.
    """
    
    def __init__(
        self,
        socket_path: str = GVM_SOCKET_PATH,
        username: str = GVM_USERNAME,
        password: str = GVM_PASSWORD,
        scan_config: str = GVM_SCAN_CONFIG,
        task_timeout: int = GVM_TASK_TIMEOUT,
        poll_interval: int = GVM_POLL_INTERVAL,
    ):
        """
        Initialize GVM scanner.
        
        Args:
            socket_path: Path to gvmd Unix socket
            username: GVM username
            password: GVM password
            scan_config: Name of scan configuration to use
            task_timeout: Maximum time to wait for scan completion
            poll_interval: Seconds between status checks
        """
        if not GVM_AVAILABLE:
            raise RuntimeError("python-gvm library not installed")
        
        self.socket_path = socket_path
        self.username = username
        self.password = password
        self.scan_config_name = scan_config
        self.task_timeout = task_timeout
        self.poll_interval = poll_interval
        
        # Connection state
        self._connection = None
        self.gmp = None
        self.connected = False
        
        # Cached IDs
        self.scanner_id: Optional[str] = None
        self.config_id: Optional[str] = None
        self.xml_format_id: Optional[str] = None
        self.port_list_id: Optional[str] = None
    
    def connect(self) -> bool:
        """
        Establish connection to GVMD.
        
        Returns:
            True if connected successfully
        """
        try:
            # Create and establish connection
            self._connection = UnixSocketConnection(path=self.socket_path)
            self._connection.connect()
            
            # Create GMP protocol handler (use version-specific class with authenticate)
            transform = EtreeTransform()
            self.gmp = GMPv227(connection=self._connection, transform=transform)
            
            # Authenticate with GVM
            self.gmp.authenticate(self.username, self.password)
            
            # Cache commonly needed IDs
            self._cache_scanner_id()
            self._cache_config_id()
            self._cache_report_format_id()
            self._cache_port_list_id()
            
            self.connected = True
            print(f"[+] Connected to GVM at {self.socket_path}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to connect to GVM: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Close connection to GVMD."""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._connection = None
        self.connected = False
        self.gmp = None
    
    def _cache_scanner_id(self):
        """Get and cache OpenVAS scanner ID."""
        scanners = self.gmp.get_scanners()
        for scanner in scanners.findall('.//scanner'):
            name = scanner.find('name')
            if name is not None and 'OpenVAS' in name.text:
                self.scanner_id = scanner.get('id')
                return
        raise RuntimeError("OpenVAS scanner not found in GVM")
    
    def _cache_config_id(self):
        """Get and cache scan config ID."""
        configs = self.gmp.get_scan_configs()
        for config in configs.findall('.//config'):
            name = config.find('name')
            if name is not None and self.scan_config_name in name.text:
                self.config_id = config.get('id')
                return
        
        # List available configs for debugging
        available = [c.find('name').text for c in configs.findall('.//config') 
                     if c.find('name') is not None]
        raise RuntimeError(
            f"Scan config '{self.scan_config_name}' not found. "
            f"Available: {available}"
        )
    
    def _cache_report_format_id(self):
        """Get and cache XML report format ID."""
        formats = self.gmp.get_report_formats()
        for fmt in formats.findall('.//report_format'):
            name = fmt.find('name')
            if name is not None and name.text == "XML":
                self.xml_format_id = fmt.get('id')
                return
        # Default XML format UUID
        self.xml_format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"
    
    def _cache_port_list_id(self):
        """Get and cache port list ID (All IANA assigned TCP and UDP)."""
        port_lists = self.gmp.get_port_lists()
        # Prefer "All IANA assigned TCP and UDP" for comprehensive scanning
        preferred_lists = [
            "All IANA assigned TCP and UDP",
            "All IANA assigned TCP",
            "All TCP and Nmap top 1000 UDP",
        ]
        
        for preferred in preferred_lists:
            for pl in port_lists.findall('.//port_list'):
                name = pl.find('name')
                if name is not None and name.text == preferred:
                    self.port_list_id = pl.get('id')
                    print(f"    [+] Using port list: {preferred}")
                    return
        
        # Fallback: use first available port list
        first_pl = port_lists.find('.//port_list')
        if first_pl is not None:
            self.port_list_id = first_pl.get('id')
            name = first_pl.find('name')
            print(f"    [+] Using port list: {name.text if name is not None else 'default'}")
            return
            
        # Default UUID for "All IANA assigned TCP and UDP"
        self.port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
    
    def create_target(self, name: str, hosts: List[str], comment: str = "") -> str:
        """
        Create a scan target in GVM.
        
        Args:
            name: Target name
            hosts: List of IPs or hostnames
            comment: Optional description
            
        Returns:
            Target ID
        """
        # Use CONSIDER_ALIVE to skip ICMP ping check (cloud providers block ICMP)
        response = self.gmp.create_target(
            name=name,
            hosts=hosts,
            port_list_id=self.port_list_id,
            alive_test=AliveTest.CONSIDER_ALIVE,
            comment=comment or f"RedAmon auto-generated - {datetime.now().isoformat()}"
        )
        # Extract ID from XML response (attribute on root element)
        target_id = response.get('id') if hasattr(response, 'get') else None
        if target_id is None and hasattr(response, 'attrib'):
            target_id = response.attrib.get('id')
        
        # Check response status
        status = response.get('status') if hasattr(response, 'get') else None
        if status and status != '201':
            status_text = response.get('status_text', 'Unknown error')
            raise RuntimeError(f"Failed to create target: {status_text}")
        
        if not target_id:
            raise RuntimeError(f"Failed to create target '{name}': No ID returned")
            
        print(f"    [+] Created target '{name}': {target_id}")
        return target_id
    
    def create_task(self, name: str, target_id: str, comment: str = "") -> str:
        """
        Create a scan task in GVM.
        
        Args:
            name: Task name
            target_id: ID of target to scan
            comment: Optional description
            
        Returns:
            Task ID
        """
        if not target_id:
            raise ValueError("create_task requires a target_id argument")
            
        response = self.gmp.create_task(
            name=name,
            config_id=self.config_id,
            target_id=target_id,
            scanner_id=self.scanner_id,
            comment=comment or f"RedAmon scan - {datetime.now().isoformat()}"
        )
        # Extract ID from XML response
        task_id = response.get('id') if hasattr(response, 'get') else None
        if task_id is None and hasattr(response, 'attrib'):
            task_id = response.attrib.get('id')
            
        # Check response status
        status = response.get('status') if hasattr(response, 'get') else None
        if status and status != '201':
            status_text = response.get('status_text', 'Unknown error')
            raise RuntimeError(f"Failed to create task: {status_text}")
            
        if not task_id:
            raise RuntimeError(f"Failed to create task '{name}': No ID returned")
            
        print(f"    [+] Created task '{name}': {task_id}")
        return task_id
    
    def start_task(self, task_id: str) -> str:
        """
        Start a scan task.
        
        Args:
            task_id: Task ID to start
            
        Returns:
            Report ID for the running task
        """
        response = self.gmp.start_task(task_id)
        report_id = response.find('.//report_id')
        report_id_str = report_id.text if report_id is not None else None
        print(f"    [+] Started task {task_id}")
        return report_id_str
    
    def wait_for_task(self, task_id: str) -> Tuple[str, str]:
        """
        Wait for task completion.
        
        Args:
            task_id: Task ID to wait for
            
        Returns:
            Tuple of (status, report_id)
            
        Raises:
            TimeoutError: If task exceeds timeout
            RuntimeError: If task fails
        """
        print(f"    [⏳] Waiting for task {task_id}...")
        start_time = time.time()
        
        while True:
            elapsed = time.time() - start_time
            
            if self.task_timeout > 0 and elapsed > self.task_timeout:
                raise TimeoutError(
                    f"Task {task_id} exceeded timeout of {self.task_timeout}s"
                )
            
            task = self.gmp.get_task(task_id)
            status = task.find('.//status')
            status_text = status.text if status is not None else "Unknown"
            
            progress = task.find('.//progress')
            progress_text = progress.text if progress is not None else "0"
            
            # Get report ID
            report = task.find('.//report')
            report_id = report.get('id') if report is not None else None
            
            print(f"        Status: {status_text} | Progress: {progress_text}% | "
                  f"Elapsed: {int(elapsed)}s")
            
            if status_text == "Done":
                return status_text, report_id
            elif status_text in ("Stopped", "Stop Requested"):
                raise RuntimeError(f"Task was stopped: {status_text}")
            elif "Error" in status_text:
                raise RuntimeError(f"Task failed: {status_text}")
            
            time.sleep(self.poll_interval)
    
    def get_report(self, report_id: str) -> Dict:
        """
        Fetch and parse a scan report.
        
        Args:
            report_id: Report ID to fetch
            
        Returns:
            Parsed report as dictionary
        """
        report = self.gmp.get_report(
            report_id=report_id,
            report_format_id=self.xml_format_id,
            ignore_pagination=True,
            details=True
        )
        return self._parse_report_xml(report)
    
    def _parse_report_xml(self, report_xml: ET.Element) -> Dict:
        """
        Parse GVM XML report into structured dictionary.
        
        Args:
            report_xml: XML Element from GVM
            
        Returns:
            Structured report dictionary
        """
        results = []
        
        for result in report_xml.findall('.//result'):
            severity_text = self._get_text(result, 'severity')
            try:
                severity = float(severity_text) if severity_text else 0.0
            except ValueError:
                severity = 0.0
            
            # Extract NVT OID safely (ElementTree doesn't support @attribute XPath)
            nvt_element = result.find('.//nvt')
            nvt_oid = nvt_element.get('oid') if nvt_element is not None else None
            
            vuln = {
                "id": result.get('id'),
                "name": self._get_text(result, 'name'),
                "host": self._parse_host(result),
                "port": self._get_text(result, 'port'),
                "severity": severity,
                "severity_class": self._classify_severity(severity),
                "threat": self._get_text(result, 'threat'),
                "description": self._get_text(result, 'description'),
                "solution": self._get_text(result, 'solution'),
                "nvt": {
                    "oid": nvt_oid,
                    "name": self._get_text(result, './/nvt/name'),
                    "family": self._get_text(result, './/nvt/family'),
                    "cvss_base": self._get_text(result, './/nvt/cvss_base'),
                },
                "cves": self._extract_cves(result),
                "references": self._extract_refs(result),
                "qod": {
                    "value": self._get_text(result, './/qod/value'),
                    "type": self._get_text(result, './/qod/type'),
                }
            }
            results.append(vuln)
        
        # Sort by severity (highest first)
        results.sort(key=lambda x: x['severity'], reverse=True)
        
        # Build summary statistics
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "log": 0}
        hosts_affected = set()
        
        for r in results:
            severity_counts[r['severity_class']] += 1
            if r['host']:
                hosts_affected.add(r['host'])
        
        # Try to get hosts scanned from report host count (more accurate)
        hosts_count = 0
        hosts_element = report_xml.find('.//hosts')
        if hosts_element is not None:
            count_text = hosts_element.find('count')
            if count_text is not None and count_text.text:
                try:
                    hosts_count = int(count_text.text)
                except ValueError:
                    pass
        
        # Fallback to hosts with results, or report host count
        hosts_scanned = max(len(hosts_affected), hosts_count)
        
        return {
            "report_id": self._get_report_id(report_xml),
            "scan_start": self._get_text(report_xml, './/scan_start'),
            "scan_end": self._get_text(report_xml, './/scan_end'),
            "hosts_scanned": hosts_scanned,
            "vulnerability_count": len(results),
            "severity_summary": severity_counts,
            "vulnerabilities": results
        }
    
    def _get_report_id(self, report_xml: ET.Element) -> Optional[str]:
        """Extract report ID from XML."""
        report = report_xml.find('.//report')
        return report.get('id') if report is not None else None
    
    def _parse_host(self, result: ET.Element) -> Optional[str]:
        """Parse host from result, handling nested structure."""
        host = result.find('host')
        if host is not None:
            # Check for nested text or asset
            if host.text:
                return host.text.strip()
            # Some versions nest the IP differently
            asset = host.find('asset')
            if asset is not None:
                return asset.get('id')
        return None
    
    def _classify_severity(self, severity: float) -> str:
        """Classify severity score into category."""
        if severity >= 9.0:
            return "critical"
        elif severity >= 7.0:
            return "high"
        elif severity >= 4.0:
            return "medium"
        elif severity > 0.0:
            return "low"
        return "log"
    
    def _extract_cves(self, result: ET.Element) -> List[str]:
        """Extract CVE identifiers from result."""
        cves = []
        for ref in result.findall('.//ref'):
            ref_type = ref.get('type', '')
            ref_id = ref.get('id', '')
            if ref_type.lower() == 'cve' and ref_id:
                cves.append(ref_id)
        return cves
    
    def _extract_refs(self, result: ET.Element) -> List[Dict]:
        """Extract all references from result."""
        refs = []
        for ref in result.findall('.//ref'):
            refs.append({
                "type": ref.get('type', ''),
                "id": ref.get('id', '')
            })
        return refs
    
    @staticmethod
    def _get_text(element: ET.Element, path: str) -> Optional[str]:
        """Safely get text from XML element."""
        el = element.find(path)
        if el is not None and el.text:
            return el.text.strip()
        return None
    
    def delete_target(self, target_id: str):
        """Delete a target from GVM."""
        try:
            self.gmp.delete_target(target_id, ultimate=True)
            print(f"    [+] Deleted target {target_id}")
        except Exception as e:
            print(f"    [!] Failed to delete target {target_id}: {e}")
    
    def delete_task(self, task_id: str):
        """Delete a task from GVM."""
        try:
            self.gmp.delete_task(task_id, ultimate=True)
            print(f"    [+] Deleted task {task_id}")
        except Exception as e:
            print(f"    [!] Failed to delete task {task_id}: {e}")
    
    def scan_targets(
        self,
        targets: List[str],
        target_name: str,
        cleanup: bool = GVM_CLEANUP_AFTER_SCAN
    ) -> Dict:
        """
        Run a complete vulnerability scan on targets.
        
        Args:
            targets: List of IPs or hostnames to scan
            target_name: Name for the scan target/task
            cleanup: Delete target and task after scan
            
        Returns:
            Scan results dictionary
        """
        if not targets:
            return {"error": "No targets provided", "vulnerabilities": []}
        
        print(f"\n[*] Scanning {len(targets)} targets: {target_name}")
        print(f"    Targets: {', '.join(targets[:5])}{'...' if len(targets) > 5 else ''}")
        
        target_id = None
        task_id = None
        
        try:
            # Create target
            target_id = self.create_target(
                name=f"RedAmon_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                hosts=targets
            )
            
            # Create and start task
            task_id = self.create_task(
                name=f"RedAmon_Scan_{target_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                target_id=target_id
            )
            self.start_task(task_id)
            
            # Wait for completion
            status, report_id = self.wait_for_task(task_id)
            
            # Get results
            if report_id:
                results = self.get_report(report_id)
                results["scan_name"] = target_name
                results["targets"] = targets
                results["status"] = status
                print(f"    [+] Scan complete: {results['vulnerability_count']} vulnerabilities found")
                return results
            else:
                return {
                    "scan_name": target_name,
                    "targets": targets,
                    "status": status,
                    "error": "No report generated",
                    "vulnerabilities": []
                }
                
        except Exception as e:
            print(f"    [!] Scan failed: {e}")
            return {
                "scan_name": target_name,
                "targets": targets,
                "status": "error",
                "error": str(e),
                "vulnerabilities": []
            }
            
        finally:
            if cleanup:
                if task_id:
                    self.delete_task(task_id)
                if target_id:
                    self.delete_target(target_id)


def extract_targets_from_recon(recon_data: Dict) -> Tuple[Set[str], Set[str]]:
    """
    Extract unique IPs and hostnames from recon JSON data.
    
    Args:
        recon_data: RedAmon recon JSON data
        
    Returns:
        Tuple of (ips_set, hostnames_set)
    """
    ips = set()
    hostnames = set()
    
    dns_data = recon_data.get("dns", {})
    if not dns_data:
        return ips, hostnames
    
    # Main domain
    domain = recon_data.get("metadata", {}).get("target_domain", "")
    if domain:
        hostnames.add(domain)
    
    # Domain IPs
    domain_dns = dns_data.get("domain", {})
    if domain_dns:
        domain_ips = domain_dns.get("ips", {})
        ips.update(domain_ips.get("ipv4", []))
        ips.update(domain_ips.get("ipv6", []))
    
    # Subdomains
    for subdomain, subdomain_data in dns_data.get("subdomains", {}).items():
        if subdomain_data and subdomain_data.get("has_records"):
            hostnames.add(subdomain)
            subdomain_ips = subdomain_data.get("ips", {})
            ips.update(subdomain_ips.get("ipv4", []))
            ips.update(subdomain_ips.get("ipv6", []))
    
    # Filter empty values
    ips = {ip for ip in ips if ip}
    hostnames = {h for h in hostnames if h}
    
    return ips, hostnames


def load_recon_file(domain: str, recon_dir: Path = None) -> Dict:
    """
    Load recon JSON file for a domain.
    
    Args:
        domain: Target domain
        recon_dir: Directory containing recon files
        
    Returns:
        Recon data dictionary
    """
    if recon_dir is None:
        recon_dir = PROJECT_ROOT / "recon" / "output"
    
    recon_file = recon_dir / f"recon_{domain}.json"
    
    if not recon_file.exists():
        raise FileNotFoundError(f"Recon file not found: {recon_file}")
    
    with open(recon_file, 'r') as f:
        return json.load(f)


def save_vuln_results(
    results: Dict,
    domain: str,
    output_dir: Path = None
) -> Path:
    """
    Save vulnerability scan results to JSON file.
    
    Args:
        results: Scan results dictionary
        domain: Target domain
        output_dir: Output directory
        
    Returns:
        Path to saved file
    """
    if output_dir is None:
        output_dir = PROJECT_ROOT / "vuln_scan" / "output"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"vuln_{domain}.json"
    
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to: {output_file}")
    return output_file

