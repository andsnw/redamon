"""get_cert_for: the single certificate accessor every consumer uses (Phase 1.0).

Gates on cert-data AVAILABILITY, not on tlsx. With tlsx on it returns the best
cert for any target incl. non-HTTP ports and bare IPs; with tlsx off it falls
back to the 443 certificate httpx already captured. So the takeover / vhost /
hygiene consumers keep working either way -- nothing becomes dead code.
"""

from datetime import datetime, timezone
from typing import Optional


def _is_expired(not_after) -> Optional[bool]:
    if not not_after:
        return None
    try:
        dt = datetime.fromisoformat(str(not_after).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return None


def _from_tlsx(entry: dict) -> dict:
    return {
        "source": "tlsx",
        "subject_cn": entry.get("subject_cn"),
        "issuer": entry.get("issuer_dn") or entry.get("issuer_cn"),
        "san": list(entry.get("san") or []),
        "not_before": entry.get("not_before"),
        "not_after": entry.get("not_after"),
        "expired": bool(entry.get("expired")),
        "self_signed": bool(entry.get("self_signed")),
        "mismatched": bool(entry.get("mismatched")),
        "fingerprint_sha256": entry.get("fingerprint_sha256"),
        "probe_status": entry.get("probe_status"),
    }


def _from_httpx(cert: dict) -> dict:
    issuer = cert.get("issuer")
    issuer_str = ", ".join(issuer) if isinstance(issuer, list) else issuer
    san = cert.get("san") or []
    return {
        "source": "http_probe",
        "subject_cn": cert.get("subject_cn"),
        "issuer": issuer_str,
        "san": [s for s in san if isinstance(s, str)],
        "not_before": cert.get("not_before"),
        "not_after": cert.get("not_after"),
        "expired": _is_expired(cert.get("not_after")),
        "self_signed": None,   # httpx does not compute verdicts
        "mismatched": None,
        "fingerprint_sha256": cert.get("fingerprint_sha256") or cert.get("fingerprint"),
        "probe_status": True,
    }


def get_cert_for(combined_result: dict, host_or_ip: str, port) -> Optional[dict]:
    """Return the best available certificate for a target, or None.

    Priority: tlsx by_target, then http_probe by_url tls.certificate. A tlsx
    entry with probe_status False (handshake failed) is still returned so a
    consumer can treat cert_absent as a positive signal.
    """
    if not host_or_ip:
        return None
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        port_int = None

    # 1. tlsx
    by_target = ((combined_result.get("tlsx") or {}).get("by_target")) or {}
    entry = by_target.get(f"{host_or_ip}:{port}") or by_target.get(f"{host_or_ip}:{port_int}")
    if not entry:
        for e in by_target.values():
            if not isinstance(e, dict):
                continue
            if e.get("port") == port_int and host_or_ip in (
                    e.get("host"), e.get("scanned_ip"), e.get("ip")):
                entry = e
                break
    if isinstance(entry, dict):
        if entry.get("subject_cn") or entry.get("fingerprint_sha256") or not entry.get("probe_status"):
            return _from_tlsx(entry)

    # 2. http_probe by_url
    by_url = ((combined_result.get("http_probe") or {}).get("by_url")) or {}
    for url, info in by_url.items():
        if not isinstance(info, dict):
            continue
        if info.get("host") == host_or_ip or info.get("ip") == host_or_ip or f"//{host_or_ip}" in str(url):
            cert = ((info.get("tls") or {}).get("certificate")) or {}
            if cert.get("subject_cn") or cert.get("san"):
                return _from_httpx(cert)
    return None
