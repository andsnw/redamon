"""Scan-scope host filtering shared by the recon graph mixins.

The mixins must not create nodes for hosts outside the scan scope (a crawler
can wander onto a third-party CDN, and Nuclei follows redirects off-target).
The allowed-host set is assembled here so every mixin agrees on it.
"""
from urllib.parse import urlparse


def _normalize_host(value: str) -> str:
    """Reduce a host-ish string to a bare comparable hostname.

    Accepts what the scanners actually emit: 'example.com', 'example.com:8443',
    'https://example.com/foo' (Nuclei writes the full URL into `host` for some
    template types) and '[::1]:443'.
    """
    if not value:
        return ""
    host = value.strip().lower()
    if "://" in host:
        host = urlparse(host).netloc or host.split("://", 1)[1]
    host = host.split("/")[0]
    if host.startswith("["):                      # IPv6 literal: [::1]:443
        return host[1:].split("]")[0]
    return host.split(":")[0]


def build_host_scope(recon_data: dict) -> set:
    """Hosts the graph is allowed to create nodes for, or an empty set for "no filter".

    IP mode is the reason this is not just `subdomains`: run_ip_recon mints a
    dashed placeholder name per IP ("21.40.250.84" -> "21-40-250-84") because a
    Subdomain node needs a name, but every scanner targets the IP literal and
    reports findings under it. Scoping on `subdomains` alone therefore discards
    100% of an IP-mode scan's results. `metadata.subdomain_filter` is the
    allowed-host list httpx already filters on and holds the real IPs.
    """
    scope = {_normalize_host(h) for h in recon_data.get("subdomains") or []}
    metadata = recon_data.get("metadata") or {}
    scope |= {_normalize_host(h) for h in metadata.get("subdomain_filter") or []}
    scope |= {_normalize_host(ip) for ip in metadata.get("expanded_ips") or []}
    scope.discard("")

    # Bare-domain scan with no subdomains discovered: the apexes are the scope.
    if not scope:
        scope = {_normalize_host(r) for r in scope_roots(recon_data)}
        scope.discard("")
    return scope


def host_in_scope(value: str, scope: set) -> bool:
    """True when `value` (host, host:port or URL) is in scope. Empty scope = no filter."""
    if not scope:
        return True
    return _normalize_host(value) in scope


# ---------------------------------------------------------------------------
# Project roots. A Domain-batch project has one Domain node per root, and a
# write can cover several of them: a partial run over the whole batch, or a full
# run's group, which also carries the other roots (recon/main.py
# run_domain_batch). Mirrors scope_roots/root_for_host in
# recon/partial_recon_modules/helpers.py; graph_db must not import recon.
# ---------------------------------------------------------------------------

def scope_roots(recon_data: dict) -> list:
    """recon_data["domains"], else the single recon_data["domain"]."""
    roots = recon_data.get("domains")
    if isinstance(roots, list):
        cleaned = [r for r in roots if isinstance(r, str) and r.strip()]
        if cleaned:
            return cleaned
    domain = recon_data.get("domain")
    return [domain] if isinstance(domain, str) and domain.strip() else []


def root_for_host(value: str, roots: list, ip_mode: bool = False):
    """The longest root that the host of `value` equals or sits under, or None.

    In IP mode every host belongs to the one synthetic root
    (ip-targets.<project_id>): its Subdomains are dashed IPs, not names under it.
    The root is returned as stored, since it is matched against Domain.name.
    """
    host = _normalize_host(value).strip(".")
    if not host or not roots:
        return None
    if ip_mode:
        return roots[0]
    best, best_len = None, -1
    for root in roots:
        r = str(root or "").strip().strip(".").lower()
        if r and (host == r or host.endswith("." + r)) and len(r) > best_len:
            best, best_len = root, len(r)
    return best


def roots_are_ip_mode(session, roots: list, user_id: str, project_id: str) -> bool:
    """Whether these roots are IP mode's synthetic root, read from Domain.ip_mode.

    One tenant-keyed lookup per write batch, rather than a flag every caller
    would have to remember to stamp on recon_data.
    """
    if not roots:
        return False
    record = session.run(
        """
        MATCH (d:Domain {user_id: $uid, project_id: $pid})
        WHERE d.name IN $roots AND d.ip_mode = true
        RETURN count(d) > 0 AS ip_mode
        """,
        uid=user_id, pid=project_id, roots=list(roots),
    ).single()
    return bool(record and record["ip_mode"])
