"""LIVE-Neo4j proof of the node-filter sweep, the Muted Nodes reads and the prune carve-out.

The unit tests pin the decisions against a fake graph and the Cypher's shape.
This runs the real Cypher: the keyset projection, the guard re-check in the
mute write, `datetime(toString(...))` on restored string timestamps, the tenant
scoping, and that nothing here ever changes `updated_at`.

Skipped unless the neo4j driver is importable AND a database answers. To run it:

  docker run --rm --network redamon-network -v "$PWD:/repo" -w /repo \\
    -e PYTHONPATH=/repo -e NEO4J_URI=bolt://redamon-neo4j:7687 \\
    -e NEO4J_USER -e NEO4J_PASSWORD \\
    redamon-agent python -m unittest tests.test_node_filters_graph_live -v

Everything it creates lives under a throwaway tenant (two projects, so the
cross-project check has something to leak into) and is deleted in tearDown.
"""

import os
import sys
import unittest
import uuid

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

_SKIP_REASON = None
try:
    import neo4j as _neo4j  # noqa: F401
except ImportError:
    _SKIP_REASON = "neo4j driver not installed"

_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
_USER = os.getenv("NEO4J_USER", "neo4j")
_PASSWORD = os.getenv("NEO4J_PASSWORD")

if _SKIP_REASON is None and not _PASSWORD:
    _SKIP_REASON = "NEO4J_PASSWORD not set"


def _probe():
    if _SKIP_REASON:
        return False
    try:
        drv = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))
        with drv.session() as s:
            s.run("RETURN 1").single()
        drv.close()
        return True
    except Exception:
        return False


_ALIVE = _probe()

INFO = {"id": "k3f9a2", "name": "Informational templates", "enabled": True,
        "all": [{"field": "severity", "op": "in", "value": ["info"]}]}
KEEP_HIGH = {"id": "p81c0d", "name": "High and above", "enabled": True,
             "all": [{"field": "severity", "op": "gte", "value": "high"}]}


def cfg(*rules, mode="denylist", enabled=True):
    return {"mode": mode, "rules": {"version": 1, "kinds": {
        "vuln.nuclei": {"enabled": enabled, "action": "mute", "rules": list(rules)}}}}


@unittest.skipUnless(_ALIVE, _SKIP_REASON or "no Neo4j reachable")
class LiveNodeFilterCase(unittest.TestCase):
    def setUp(self):
        from graph_db.mixins.base_mixin import BaseMixin
        from graph_db.mixins.node_filter_mixin import NodeFilterMixin
        from graph_db.mixins.recon.triage_mixin import TriageMixin

        run = uuid.uuid4().hex[:8]
        self.uid = f"nf-{run}"
        self.pid = f"NF_{run}"
        self.pid2 = f"NF2_{run}"
        self.driver = _neo4j.GraphDatabase.driver(_URI, auth=(_USER, _PASSWORD))

        class _Client(NodeFilterMixin, TriageMixin, BaseMixin):
            def __init__(self, driver):
                self.driver = driver

        self.client = _Client(self.driver)
        self.lines = []
        for pid in (self.pid, self.pid2):
            self._seed(pid)

    def _seed(self, pid):
        with self.driver.session() as s:
            s.run(
                """
                CREATE (ip:IP {address: '192.0.2.10', user_id: $u, project_id: $p})
                WITH ip
                UNWIND $rows AS r
                CREATE (v:Vulnerability {id: r.id, user_id: $u, project_id: $p,
                        name: r.id, severity: r.sev, source: r.source,
                        template_id: 'tmpl-' + r.id, updated_at: datetime(r.updated)})
                CREATE (ip)-[:HAS_VULNERABILITY]->(v)
                """,
                u=self.uid, p=pid, rows=[
                    {"id": "info-1", "sev": "info", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "info-2", "sev": "info", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "info-old", "sev": "info", "source": "nuclei", "updated": "2026-01-01T00:00:00Z"},
                    {"id": "high-1", "sev": "high", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "info-human", "sev": "info", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "info-proven", "sev": "info", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "info-person", "sev": "info", "source": "nuclei", "updated": "2026-09-23T10:00:00Z"},
                    {"id": "osv-1", "sev": "info", "source": "osv", "updated": "2026-09-23T10:00:00Z"},
                ])
            s.run("MATCH (v:Vulnerability {id: 'info-human', user_id: $u, project_id: $p}) "
                  "SET v.triage_source = 'human', v.triage_status = 'likely_noise'", u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'info-proven', user_id: $u, project_id: $p}) "
                  "CREATE (:ChainFinding {id: 'cf-' + $p, user_id: $u, project_id: $p})-[:CONFIRMS]->(v)",
                  u=self.uid, p=pid)
            s.run("MATCH (v:Vulnerability {id: 'info-person', user_id: $u, project_id: $p}) "
                  "SET v:Muted, v.muted = true, v.muted_at = datetime(), v.muted_by = 'alice', "
                  "v.muted_reason = 'noise'", u=self.uid, p=pid)

    def tearDown(self):
        with self.driver.session() as s:
            s.run("MATCH (n) WHERE n.user_id = $u DETACH DELETE n", u=self.uid)
        self.driver.close()

    def sweep(self, config, pid=None, **kw):
        return self.client.apply_node_filters(self.uid, pid or self.pid, config,
                                              log=self.lines.append, **kw)

    def state(self, pid=None):
        with self.driver.session() as s:
            return {r["id"]: (r["muted"], r["by"], r["reason"]) for r in s.run(
                "MATCH (v:Vulnerability {user_id: $u, project_id: $p}) "
                "RETURN v.id AS id, v:Muted AS muted, v.muted_by AS by, v.muted_reason AS reason",
                u=self.uid, p=pid or self.pid)}

    def updated_ats(self):
        with self.driver.session() as s:
            return {r["id"]: r["t"] for r in s.run(
                "MATCH (v:Vulnerability {user_id: $u, project_id: $p}) "
                "RETURN v.id AS id, toString(v.updated_at) AS t", u=self.uid, p=self.pid)}

    # --- apply, both modes -------------------------------------------------

    def test_denylist_mutes_matches_and_leaves_guarded_and_people_alone(self):
        stats = self.sweep(cfg(INFO))
        st = self.state()
        for key in ("info-1", "info-2", "info-old"):
            self.assertEqual(st[key][:2], (True, "rule:vuln.nuclei/k3f9a2"), key)
            self.assertEqual(st[key][2], "Filter rule: Informational templates")
        self.assertFalse(st["high-1"][0])
        self.assertFalse(st["info-human"][0], "a human-judged finding was muted")
        self.assertFalse(st["info-proven"][0], "an agent-proven finding was muted")
        self.assertEqual(st["info-person"][:2], (True, "alice"))
        self.assertFalse(st["osv-1"][0], "another kind's node was muted")
        ks = stats["kinds"]["vuln.nuclei"]
        self.assertEqual((ks["muted"], ks["guarded"], ks["operator_muted"]), (3, 2, 1))

    def test_a_second_project_is_untouched(self):
        self.sweep(cfg(INFO))
        self.assertFalse(any(m and str(by).startswith("rule:") for m, by, _ in self.state(self.pid2).values()))

    def test_preview_counts_equal_applied_counts(self):
        preview = self.sweep(cfg(INFO), dry_run=True)
        self.assertFalse(any(m and str(by).startswith("rule:") for m, by, _ in self.state().values()))
        applied = self.sweep(cfg(INFO))
        self.assertEqual(preview["kinds"]["vuln.nuclei"]["to_mute"], applied["kinds"]["vuln.nuclei"]["muted"])
        self.assertEqual(preview["kinds"]["vuln.nuclei"]["guarded"], applied["kinds"]["vuln.nuclei"]["guarded"])

    def test_disabling_the_rule_and_applying_again_brings_them_back(self):
        self.sweep(cfg(INFO))
        stats = self.sweep(cfg({**INFO, "enabled": False}))
        st = self.state()
        self.assertFalse(any(st[k][0] for k in ("info-1", "info-2", "info-old")))
        self.assertEqual(st["info-person"][:2], (True, "alice"))
        self.assertEqual(stats["kinds"]["vuln.nuclei"]["unmuted"], 3)

    def test_allowlist_mutes_everything_below_high(self):
        preview = self.sweep(cfg(KEEP_HIGH, mode="allowlist"), dry_run=True)
        self.assertEqual(preview["kinds"]["vuln.nuclei"]["rules"][KEEP_HIGH["id"]]["matched"], 1,
                         "a keep rule counts what it keeps")
        self.sweep(cfg(KEEP_HIGH, mode="allowlist"))
        st = self.state()
        self.assertEqual(st["info-1"][:2], (True, "rule:vuln.nuclei/allowlist"))
        self.assertFalse(st["high-1"][0])
        self.assertFalse(st["info-human"][0])

    def test_a_guard_set_after_the_projection_still_stops_the_mute_write(self):
        # The sweep reads a page, decides, then writes. A person can judge a
        # finding, or the agent prove it, in between; the write must re-check.
        from graph_db.node_filters.catalog import load_catalog
        from graph_db.node_filters.cypher import mute_query

        u, p = self.uid, self.pid
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id: 'info-1', user_id: $u, project_id: $p}) "
                  "SET v.triage_source = 'human'", u=u, p=p)
            s.run("MATCH (v:Vulnerability {id: 'info-2', user_id: $u, project_id: $p}) "
                  "SET v.triage_status = 'confirmed'", u=u, p=p)
            s.run("MATCH (v:Vulnerability {id: 'info-old', user_id: $u, project_id: $p}) "
                  "SET v.triage_proof = 'poc.txt'", u=u, p=p)
            rows = [{"key": k, "muted_by": "rule:vuln.nuclei/k3f9a2", "reason": "Filter rule: x"}
                    for k in ("info-1", "info-2", "info-old", "info-proven")]
            written = s.run(mute_query(load_catalog().kinds["vuln.nuclei"]),
                            rows=rows, uid=u, pid=p).single()["n"]
            # The control: the same write on an unguarded node does mute it, so a
            # query that wrote nothing at all could not pass this test.
            control = s.run(mute_query(load_catalog().kinds["vuln.nuclei"]),
                            rows=[{**rows[0], "key": "high-1"}], uid=u, pid=p).single()["n"]
        self.assertEqual(written, 0)
        self.assertEqual(control, 1)
        st = self.state()
        self.assertFalse(any(st[k][0] for k in ("info-1", "info-2", "info-old", "info-proven")))

    def test_the_sweep_never_writes_updated_at(self):
        before = self.updated_ats()
        self.sweep(cfg(INFO))
        self.sweep(cfg({**INFO, "enabled": False}))
        self.assertEqual(self.updated_ats(), before)
        # Nor leaves the write lock's scratch property behind.
        with self.driver.session() as s:
            left = s.run("MATCH (n) WHERE n.user_id = $u AND n._node_filter_lock IS NOT NULL "
                         "RETURN count(n) AS c", u=self.uid).single()["c"]
        self.assertEqual(left, 0)

    # --- guards ------------------------------------------------------------

    def test_a_human_verdict_on_a_rule_muted_finding_is_released_next_sweep(self):
        self.sweep(cfg(INFO))
        self.assertTrue(self.state()["info-1"][0])
        self.client.set_human_verdict(self.uid, self.pid, "info-1", "confirmed")
        self.sweep(cfg(INFO))
        self.assertFalse(self.state()["info-1"][0])

    def test_an_exempt_finding_stays_visible(self):
        self.sweep(cfg(INFO), exemptions=[("Vulnerability", "info-1")])
        self.assertFalse(self.state()["info-1"][0])
        self.assertTrue(self.state()["info-2"][0])

    # --- scan-time scoping -------------------------------------------------

    def test_a_scan_sweep_reconciles_only_what_that_scan_wrote(self):
        self.sweep(cfg(INFO), touched_since="2026-09-01T00:00:00+00:00", sources=["nuclei"])
        st = self.state()
        self.assertTrue(st["info-1"][0])
        self.assertFalse(st["info-old"][0], "a node the scan did not touch was swept")

    def test_restored_string_timestamps_are_still_in_scope(self):
        with self.driver.session() as s:
            s.run("MATCH (v:Vulnerability {id: 'info-2', user_id: $u, project_id: $p}) "
                  "SET v.updated_at = '2026-09-23T11:00:00.123456789Z'", u=self.uid, p=self.pid)
        self.sweep(cfg(INFO), touched_since="2026-09-01T00:00:00+00:00", sources=["nuclei"])
        self.assertTrue(self.state()["info-2"][0])

    # --- the prune carve-out -----------------------------------------------

    def test_a_stale_rule_mute_is_pruned_but_a_persons_is_kept(self):
        self.sweep(cfg(INFO))
        result = self.client.prune_unseen_findings(
            self.uid, self.pid, ["nuclei"], "2026-12-01T00:00:00+00:00")
        st = self.state()
        self.assertNotIn("info-1", st, "a rule-muted stale finding survived the prune")
        self.assertIn("info-person", st, "an operator's mute was pruned")
        self.assertIn("info-human", st)
        self.assertGreaterEqual(result["pruned"], 3)

    # --- Muted Nodes reads --------------------------------------------------

    def test_muted_nodes_paging_filters_and_facets(self):
        self.sweep(cfg(INFO))
        with self.driver.session() as s:
            # A restored mute: its timestamp is a string, and it must still sort by time.
            s.run("MATCH (v:Vulnerability {id: 'info-old', user_id: $u, project_id: $p}) "
                  "SET v.muted_at = '2020-01-01T00:00:00Z'", u=self.uid, p=self.pid)
        rows = self.client.list_muted(self.uid, self.pid)
        self.assertEqual(rows[-1]["id"], "info-old")
        self.assertEqual({r["muted_via"] for r in rows}, {"rule", "person"})
        self.assertEqual(self.client.count_muted(self.uid, self.pid, muted_via="person"), 1)
        self.assertEqual(self.client.count_muted(self.uid, self.pid, muted_via="rule"), 3)
        page = self.client.list_muted(self.uid, self.pid, limit=2, offset=1)
        self.assertEqual(len(page), 2)
        self.assertEqual(self.client.list_muted(self.uid, self.pid, order="person_first", limit=1)[0]["id"],
                         "info-person")
        self.assertEqual(self.client.count_muted(self.uid, self.pid, muted_via="deleted_rule",
                                                 live_rules=["rule:vuln.nuclei/k3f9a2"]), 0)
        self.assertEqual(self.client.count_muted(self.uid, self.pid, muted_via="deleted_rule",
                                                 live_rules=[]), 3)
        self.assertEqual(self.client.count_muted(self.uid, self.pid, search="INFO-1"), 1)
        facets = self.client.muted_facets(self.uid, self.pid)
        self.assertEqual(facets["total"], 4)
        self.assertEqual(facets["by_person"], 1)
        self.assertEqual(facets["rules"][0]["count"], 3)

    def test_batch_unmute_reports_what_it_unmuted(self):
        self.sweep(cfg(INFO))
        result = self.client.unmute_findings(self.uid, self.pid, ["info-1", "info-person", "nope"])
        self.assertEqual({i["key"]: i["muted_by"] for i in result["items"]},
                         {"info-1": "rule:vuln.nuclei/k3f9a2", "info-person": "alice"})
        st = self.state()
        self.assertFalse(st["info-1"][0] or st["info-person"][0])
        # The other project's same-id finding is still muted.
        self.assertTrue(self.state(self.pid2)["info-person"][0])

    def test_batch_unmute_scans_muted_nodes_once_per_key(self):
        # The query matched `(n:Muted)` once PER KEY with an OR the index cannot
        # serve, so a 500-key unmute read the whole database's muted set 500
        # times. Rule mutes make that set large. Its cost must not grow with
        # the number of keys.
        with self.driver.session() as s:
            s.run("UNWIND range(0, 299) AS i "
                  "CREATE (:Vulnerability:Muted {id: 'bulk-' + toString(i), user_id: $u, project_id: $p, "
                  "severity: 'info', source: 'nuclei', muted: true, muted_by: 'rule:vuln.nuclei/k3f9a2'})",
                  u=self.uid, p=self.pid)
        profiled = _Profiling(self.driver)
        self.client.driver = profiled
        try:
            one = self.client.unmute_findings(self.uid, self.pid, ["bulk-0"])
            many = self.client.unmute_findings(self.uid, self.pid, [f"bulk-{i}" for i in range(1, 300)])
        finally:
            self.client.driver = self.driver
        self.assertEqual((one["unmuted"], many["unmuted"]), (1, 299))
        hits_one, hits_many = profiled.hits
        self.assertLess(hits_many, 10 * hits_one, (hits_one, hits_many))


class _Profiling:
    """A driver whose sessions PROFILE every query and keep its total db hits."""

    def __init__(self, driver):
        self._driver = driver
        self.hits = []

    def session(self):
        return _ProfilingSession(self._driver.session(), self.hits)


class _ProfilingSession:
    def __init__(self, session, hits):
        self._session, self._hits = session, hits

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._session.close()
        return False

    def run(self, query, **params):
        result = self._session.run("PROFILE " + query, **params)
        rows = list(result)
        self._hits.append(_db_hits(result.consume().profile))
        return rows


def _db_hits(plan) -> int:
    return int(plan.get("dbHits", 0)) + sum(_db_hits(c) for c in plan.get("children", []))


if __name__ == "__main__":
    unittest.main()
