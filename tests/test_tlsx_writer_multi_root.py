"""tlsx writer: certificate SANs across a Domain batch's roots.

update_graph_from_tlsx links a Certificate to each in-scope SAN name with
COVERS_HOST. "In scope" used to mean "under recon_data['domain']", one root, so a
partial run over a batch dropped every SAN of every other root. It now means
"under any of the write's roots" (recon_data['domains']).

IP mode must not change: its synthetic root (ip-targets.<pid>) is no parent of a
real name, so an IP-mode scan still links no SAN at all.

Fixture roots are alpha.test / beta.test / gamma.test only.

Run: python -m pytest tests/test_tlsx_writer_multi_root.py
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.tlsx_mixin import TlsxMixin  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"matched": 1}
        return result


class _Writer(TlsxMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def covered(self):
        return sorted(p["name"] for q, p in self.session.calls if "COVERS_HOST" in q)


def _recon(roots, sans, domain=None):
    return {
        "domain": domain if domain is not None else roots[0],
        "domains": roots,
        "tlsx": {"by_target": {
            "10.0.0.1:993": {
                "scanned_ip": "10.0.0.1", "port": 993, "probe_status": True,
                "fingerprint_sha256": "ab" * 32, "subject_cn": "mail.alpha.test",
                "san": sans,
            },
        }},
    }


SANS = ["mail.alpha.test", "*.beta.test", "imap.gamma.test", "cdn.thirdparty.example"]


class TestSansAcrossRoots(unittest.TestCase):
    def test_a_san_under_the_second_root_gets_covers_host(self):
        w = _Writer()
        w.update_graph_from_tlsx(_recon(["alpha.test", "beta.test", "gamma.test"], SANS), "u1", "p1")
        self.assertEqual(w.covered(), ["beta.test", "imap.gamma.test", "mail.alpha.test"])

    def test_a_name_under_no_root_is_never_linked(self):
        w = _Writer()
        w.update_graph_from_tlsx(_recon(["alpha.test", "beta.test", "gamma.test"], SANS), "u1", "p1")
        self.assertNotIn("cdn.thirdparty.example", w.covered())

    def test_a_single_root_write_is_unchanged(self):
        w = _Writer()
        w.update_graph_from_tlsx({**_recon(["alpha.test"], SANS)}, "u1", "p1")
        self.assertEqual(w.covered(), ["mail.alpha.test"])

    def test_the_legacy_single_domain_key_still_scopes(self):
        w = _Writer()
        recon = _recon(["alpha.test"], SANS)
        del recon["domains"]
        w.update_graph_from_tlsx(recon, "u1", "p1")
        self.assertEqual(w.covered(), ["mail.alpha.test"])

    def test_no_root_links_nothing(self):
        w = _Writer()
        recon = _recon(["x"], SANS, domain="")
        recon["domains"] = []
        w.update_graph_from_tlsx(recon, "u1", "p1")
        self.assertEqual(w.covered(), [])
        # The certificate itself is still written.
        self.assertTrue(any("MERGE (c:Certificate" in q for q, _ in w.session.calls))


class TestIpModeRegression(unittest.TestCase):
    """Same nodes and edges as before the change: certificate, HAS_CERTIFICATE,
    Service enrichment, and no COVERS_HOST for any real name."""

    def test_ip_mode_links_no_san(self):
        w = _Writer()
        w.update_graph_from_tlsx(_recon(["ip-targets.p1"], SANS), "u1", "p1")
        self.assertEqual(w.covered(), [])
        queries = [q for q, _ in w.session.calls]
        self.assertTrue(any("MERGE (c:Certificate" in q and "HAS_CERTIFICATE" in q for q in queries))
        self.assertTrue(any("MATCH (svc:Service" in q for q in queries))


if __name__ == "__main__":
    unittest.main()
