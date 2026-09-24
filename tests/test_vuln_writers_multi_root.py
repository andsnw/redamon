"""Takeover and VHost/SNI writers: apex findings land on the right root.

Both writers used one recon_data["domain"] to decide "is this hostname the
apex" and to attach an apex finding. Over a Domain batch they take the run's
roots (recon_data["domains"]): a finding on a batch root's apex attaches to
that root's Domain, and a hidden vhost under any root is that root's Subdomain.

The vuln-scan writer: a domain-level security finding (SPF, DMARC...) has no
url, host or ip, so every root of a batch hashed to one Vulnerability node. A
batch run (metadata.domain_batch) keys it on its domain; a single-domain
project keeps the id its fix items and mute exemptions reference. With no
subdomains, the writer's scope is every root's apex, not only the first.

Fixture roots are alpha.test / beta.test / gamma.test only.

Run with:
    python3 -m pytest tests/test_vuln_writers_multi_root.py -v
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.scope import build_host_scope  # noqa: E402
from graph_db.mixins.recon.takeover_mixin import TakeoverMixin  # noqa: E402
from graph_db.mixins.recon.vhost_sni_mixin import VhostSniMixin, _is_child_of  # noqa: E402
from graph_db.mixins.recon.vuln_mixin import VulnMixin, stable_vuln_id  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]


class _Session:
    def __init__(self, matched=1):
        self.calls = []
        self._matched = matched

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = {"matched": self._matched, "removed": 0,
                                      "created": 0, "linked": 0}
        return result

    def domain_vuln_links(self):
        """{domain param: True} for each Domain -[:HAS_VULNERABILITY]-> link."""
        return [p["domain"] for q, p in self.calls
                if "MATCH (d:Domain" in q and "HAS_VULNERABILITY" in q]

    def subdomain_domain_links(self):
        return {p["hostname"]: p["domain"] for q, p in self.calls
                if "HAS_SUBDOMAIN" in q and "hostname" in p and "domain" in p}


def _writer(cls, session):
    w = cls()
    w.driver = MagicMock()
    w.driver.session.return_value = session
    return w


class TestTakeoverApex(unittest.TestCase):
    def _run(self, hostname, roots=ROOTS, matched_sub=0):
        # matched_sub=0 means no Subdomain node, so the apex fallback fires.
        session = _Session()
        seen = {"sub": matched_sub}

        def run(query, **params):
            session.calls.append((query, params))
            result = MagicMock()
            if "MATCH (s:Subdomain" in query and "HAS_VULNERABILITY" in query:
                result.single.return_value = {"matched": seen["sub"]}
            else:
                result.single.return_value = {"matched": 1}
            return result

        session.run = run
        w = _writer(TakeoverMixin, session)
        recon = {"domain": roots[0], "domains": roots,
                 "subdomain_takeover": {"findings": [
                     {"id": "v1", "hostname": hostname, "provider": "github", "method": "cname"}]}}
        w.update_graph_from_subdomain_takeover(recon, "u1", "p1")
        return session

    def test_an_apex_finding_on_the_second_root_attaches_to_it(self):
        session = self._run("beta.test")
        self.assertEqual(session.domain_vuln_links(), ["beta.test"])

    def test_an_apex_finding_on_the_third_root(self):
        session = self._run("gamma.test")
        self.assertEqual(session.domain_vuln_links(), ["gamma.test"])

    def test_a_non_apex_host_does_not_hit_the_domain_fallback(self):
        session = self._run("www.beta.test", matched_sub=1)   # a Subdomain owns it
        self.assertEqual(session.domain_vuln_links(), [])


class TestVhostChildOf(unittest.TestCase):
    def test_child_of_any_root(self):
        self.assertTrue(_is_child_of("api.beta.test", ROOTS))
        self.assertTrue(_is_child_of("x.gamma.test", ROOTS))
        self.assertFalse(_is_child_of("beta.test", ROOTS))        # the apex is not its own child
        self.assertFalse(_is_child_of("api.other.test", ROOTS))
        self.assertTrue(_is_child_of("api.beta.test", "beta.test"))   # the single-root form


class TestVhostWriter(unittest.TestCase):
    def _run(self, findings, roots=ROOTS):
        session = _Session()
        w = _writer(VhostSniMixin, session)
        recon = {"domain": roots[0], "domains": roots,
                 "vhost_sni": {"findings": findings, "by_ip": {}, "discovered_baseurls": []}}
        w.update_graph_from_vhost_sni(recon, "u1", "p1")
        return session

    def test_a_child_vhost_of_the_second_root_joins_that_root(self):
        session = self._run([{"id": "v1", "hostname": "hidden.beta.test", "type": "vhost",
                              "ip": "10.0.2.1", "layer": "L7"}])
        self.assertEqual(session.subdomain_domain_links().get("hidden.beta.test"), "beta.test")

    def test_an_apex_vhost_attaches_the_vuln_to_its_root(self):
        session = self._run([{"id": "v2", "hostname": "gamma.test", "type": "vhost",
                              "ip": "10.0.3.1", "layer": "L7"}])
        self.assertIn("gamma.test", session.domain_vuln_links())


class TestDomainLevelFindingIds(unittest.TestCase):
    def _write(self, findings, domain_batch):
        session = _Session()
        w = _writer(VulnMixin, session)
        recon = {"domain": ROOTS[0], "domains": ROOTS, "subdomains": [],
                 "metadata": {"domain_batch": domain_batch},
                 "vuln_scan": {"security_checks": {"findings": findings}}}
        w.update_graph_from_vuln_scan(recon, "u1", "p1")
        return session

    @staticmethod
    def _vuln_ids(session):
        return [p["id"] for q, p in session.calls if "MERGE (v:Vulnerability {id: $id" in q]

    @staticmethod
    def _domain_links(session):
        return [(p["domain"], p["vuln_id"]) for q, p in session.calls
                if "MATCH (d:Domain {name: $domain" in q and "HAS_VULNERABILITY" in q]

    def test_a_batch_keeps_one_finding_per_root(self):
        session = self._write([{"type": "spf_missing", "domain": r} for r in ROOTS], domain_batch=True)
        ids = self._vuln_ids(session)
        self.assertEqual(len(set(ids)), 3)
        self.assertEqual(ids, [stable_vuln_id("spf_missing", "", r, "u1", "p1") for r in ROOTS])
        self.assertEqual(self._domain_links(session), list(zip(ROOTS, ids)))

    def test_a_single_domain_project_keeps_its_id(self):
        session = self._write([{"type": "spf_missing", "domain": "alpha.test"}], domain_batch=False)
        self.assertEqual(self._vuln_ids(session), [stable_vuln_id("spf_missing", "", "", "u1", "p1")])

    def test_a_finding_with_a_url_is_not_rekeyed_in_a_batch(self):
        finding = {"type": "missing_coop", "url": "https://api.beta.test", "domain": "beta.test"}
        session = self._write([finding], domain_batch=True)
        self.assertEqual(self._vuln_ids(session),
                         [stable_vuln_id("missing_coop", "https://api.beta.test", "", "u1", "p1")])


class TestHostScopeFallback(unittest.TestCase):
    def test_with_no_subdomains_every_root_apex_is_in_scope(self):
        self.assertEqual(build_host_scope({"domain": "alpha.test", "domains": ROOTS, "subdomains": []}),
                         set(ROOTS))

    def test_the_single_domain_form_is_unchanged(self):
        self.assertEqual(build_host_scope({"domain": "Alpha.test", "subdomains": []}), {"alpha.test"})

    def test_subdomains_still_win_over_the_apexes(self):
        self.assertEqual(build_host_scope({"domain": "alpha.test", "domains": ROOTS,
                                           "subdomains": ["api.beta.test"]}), {"api.beta.test"})


if __name__ == "__main__":
    unittest.main()
