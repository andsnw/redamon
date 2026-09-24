"""Partial-recon graph builders over several project roots.

Every builder used to MATCH one Domain by name, so a Domain-batch project fed a
partial run the targets of one arbitrary root. They now take the run's roots and
each root's group scope:

  - every root's Subdomains are loaded;
  - a root's apex is a target only when its group includes it ('.' prefix);
  - a LITERAL batch group loads only its listed hosts. Writers hang other names
    under a root (certificate SANs, urlscan), and a literal group's contract is
    "scan exactly what was uploaded";
  - a wildcard group, and a single-domain project, keep every Subdomain.

The fake graph applies the same `IN $list` filters Neo4j would, so a builder that
passes the wrong list loads the wrong rows here too.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules import graph_builders as gb  # noqa: E402

APEX_IPS = {"alpha.test": "10.0.0.1", "beta.test": "10.0.0.2", "gamma.test": "10.0.0.3"}
SUBDOMAINS = [
    # (root, subdomain, ip)
    ("alpha.test", "www.alpha.test", "10.0.1.1"),
    ("alpha.test", "san-only.alpha.test", "10.0.1.2"),   # hung there by a writer
    ("beta.test", "api.beta.test", "10.0.2.1"),
    ("beta.test", "san-only.beta.test", "10.0.2.2"),
    ("gamma.test", "mail.gamma.test", "10.0.3.1"),
    ("old.test", "www.old.test", "10.0.9.1"),             # a stale root's host
]
PORTS = {"10.0.0.1": [443], "10.0.0.2": [8443], "10.0.1.1": [443, 993], "10.0.2.1": [443]}

# alpha: literal, www + apex. beta: wildcard. gamma: wildcard + apex.
GROUPS = [
    {"rootDomain": "alpha.test", "prefixes": ["www.", "."], "batch": True},
    {"rootDomain": "beta.test", "prefixes": ["*"], "batch": True},
    {"rootDomain": "gamma.test", "prefixes": ["*", "."], "batch": True},
]


def _ports(ip):
    nums = PORTS.get(ip)
    if not nums:
        return [{"number": None, "protocol": None}]
    return [{"number": n, "protocol": "tcp"} for n in nums]


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        rows = []
        if "HAS_SUBDOMAIN" in cypher:
            for root, sub, ip in SUBDOMAINS:
                if root in params["domains"]:
                    rows.append({"root": root, "subdomain": sub, "address": ip, "ip": ip,
                                 "version": "ipv4", "ports": _ports(ip)})
        elif "RESOLVES_TO" in cypher:
            for root in params["apex_roots"]:
                ip = APEX_IPS[root]
                rows.append({"root": root, "address": ip, "ip": ip, "version": "ipv4",
                             "ports": _ports(ip)})
        return rows


class _Client:
    calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda: _Session(_Client.calls)
        return driver


@pytest.fixture
def graph(monkeypatch):
    _Client.calls = []
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    return _Client.calls


ROOTS = ["alpha.test", "beta.test", "gamma.test"]


class TestPortScanBuilder:
    def build(self, **kw):
        return gb._build_port_scan_data_from_graph(ROOTS, "u1", "p1", domain_groups=GROUPS, **kw)

    def test_every_root_is_loaded_and_a_stale_one_is_not(self, graph):
        by_host = self.build()["port_scan"]["by_host"]
        assert "api.beta.test" in by_host and "mail.gamma.test" in by_host
        assert "www.old.test" not in by_host
        sub_query = next(p for c, p in graph if "HAS_SUBDOMAIN" in c)
        assert sub_query["domains"] == ROOTS

    def test_the_apex_follows_each_group(self, graph):
        data = self.build()
        apex_query = next(p for c, p in graph if "HAS_SUBDOMAIN" not in c)
        assert apex_query["apex_roots"] == ["alpha.test", "gamma.test"]
        assert "beta.test" not in data["port_scan"]["by_host"]
        assert data["port_scan"]["by_ip"]["10.0.0.3"]["hostnames"] == ["gamma.test"]

    def test_the_first_root_apex_fills_dns_domain_and_others_are_hosts(self, graph):
        data = self.build()
        assert data["domain"] == "alpha.test" and data["domains"] == ROOTS
        assert data["dns"]["domain"]["ips"]["ipv4"] == ["10.0.0.1"]
        assert data["dns"]["subdomains"]["gamma.test"]["ips"]["ipv4"] == ["10.0.0.3"]
        assert data["metadata"]["include_root_domain"] is True

    def test_a_literal_group_excludes_a_host_it_never_listed(self, graph):
        by_host = self.build()["port_scan"]["by_host"]
        assert "www.alpha.test" in by_host
        assert "san-only.alpha.test" not in by_host
        assert "10.0.1.2" not in self.build()["port_scan"]["by_ip"]

    def test_a_wildcard_group_keeps_it(self, graph):
        assert "san-only.beta.test" in self.build()["port_scan"]["by_host"]

    def test_ports_come_through(self, graph):
        data = self.build()
        assert sorted(data["port_scan"]["by_host"]["www.alpha.test"]["ports"]) == [443, 993]
        # 8443 is only open on beta.test's apex, which its group does not include.
        assert data["port_scan"]["all_ports"] == [443, 993]

    def test_a_legacy_single_root_call_is_unchanged(self, graph):
        # No domain_groups: the single flag rules and nothing is narrowed.
        data = gb._build_port_scan_data_from_graph("alpha.test", "u1", "p1", include_root_domain=False)
        assert data["domain"] == "alpha.test" and data["domains"] == ["alpha.test"]
        assert set(data["port_scan"]["by_host"]) == {"www.alpha.test", "san-only.alpha.test"}
        assert not any("apex_roots" in p for _, p in graph)
        assert data["metadata"]["include_root_domain"] is False

    def test_a_single_project_keeps_every_subdomain(self, graph):
        single = [{"rootDomain": "alpha.test", "prefixes": ["www."], "batch": False}]
        data = gb._build_port_scan_data_from_graph(["alpha.test"], "u1", "p1", domain_groups=single)
        assert set(data["port_scan"]["by_host"]) == {"www.alpha.test", "san-only.alpha.test"}

    def test_no_roots_queries_nothing(self, graph):
        data = gb._build_port_scan_data_from_graph([], "u1", "p1", domain_groups=GROUPS)
        assert data["port_scan"]["by_ip"] == {} and graph == []
