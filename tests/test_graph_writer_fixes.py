"""Graph-writer defects the triage review found (Phase 1a).

WHY THESE ARE TESTED BY READING THE CYPHER
Each one is a single clause in a query string, and each one was invisible
precisely because nothing failed: the write succeeded, it just wrote the wrong
thing, or matched nothing and carried on. A behavioural test needs a database
and a scan; a clause test catches the re-introduction, which is what actually
happens.

The live-tier equivalents (a second scan really keeping is_injectable, a chain
finding really linking to its CVE) live in tests/*_graph_live.py.

Run: python -m pytest tests/test_graph_writer_fixes.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


def source(relative: str) -> str:
    with open(os.path.join(_REPO, relative)) as handle:
        return handle.read()


class TestProofReachesTheGraph(unittest.TestCase):
    """K1. The single most consequential one.

    `CVE` is a shared reference node and carries no tenant keys: 58 of 58 in the
    dev graph have none. Every match in the chain writer supplied
    `{user_id, project_id}` anyway, so it matched NOTHING, every time. The dev
    graph had 0 FINDING_RELATES_CVE relationships, which means the board could
    never show a single proven finding, which means the top of the ranking was
    always a guess.
    """

    SRC = source("agentic/orchestrator_helpers/chain_graph_writer.py")

    def test_no_cve_match_asks_for_tenant_keys(self):
        for match in re.finditer(r"MATCH \(c:CVE([^)]*)\)", self.SRC):
            with self.subTest(pattern=match.group(0)):
                self.assertNotIn("user_id", match.group(1))
                self.assertNotIn("project_id", match.group(1))

    def test_the_chain_writer_still_matches_a_cve_at_all(self):
        """Guards the opposite mistake: deleting the match instead of fixing it."""
        self.assertGreaterEqual(len(re.findall(r"MATCH \(c:CVE", self.SRC)), 4)

    def test_chain_findings_are_still_tenant_scoped_themselves(self):
        """Only the SHARED node loses its tenant map; the project's own nodes
        keep theirs, or the fix would be a cross-tenant leak."""
        self.assertIn("ChainFinding {finding_id:", self.SRC)


class TestAScanDoesNotUndoWhatAnotherProved(unittest.TestCase):
    """K7. `is_injectable` is set by a fuzzing run that TESTED the parameter.

    Two writers that do no such test assigned it `false` unconditionally, so a
    later crawl erased the proof. A parameter can therefore be injectable on
    Monday and not on Tuesday with nothing having changed on the target.
    """

    FILES = ("graph_db/mixins/recon/resource_mixin.py",
             "graph_db/mixins/recon/vuln_mixin.py")

    def test_no_writer_assigns_is_injectable_false(self):
        for path in self.FILES:
            with self.subTest(file=path):
                self.assertNotIn("p.is_injectable = false", source(path))

    def test_they_coalesce_instead(self):
        for path in self.FILES:
            with self.subTest(file=path):
                self.assertIn("p.is_injectable = coalesce(p.is_injectable, false)",
                              source(path))


class TestLivenessHasOneOwner(unittest.TestCase):
    """K2. `status_code` is what the score model reads reachability from.

    The HTTP probe owns it. JS recon's own, weaker probe overwrote it, so a
    finding on a live endpoint could read as unreachable because a JS pass had
    since recorded a 404 for a path it guessed at.
    """

    SRC = source("graph_db/mixins/recon/js_recon_mixin.py")

    def test_js_recon_keeps_its_own_probe_in_its_own_property(self):
        self.assertIn("e.js_status_code", self.SRC)

    def test_js_recon_no_longer_overwrites_the_probe_s_value(self):
        self.assertNotIn("e.status_code = COALESCE($status_code, e.status_code)",
                         self.SRC)
        self.assertIn("e.status_code = COALESCE(e.status_code, $status_code)",
                      self.SRC)


class TestEveryFindingCanBeAddressed(unittest.TestCase):
    """K6. An nmap_nse finding had no `id`.

    Mute, verdicts, remediation links and the board's row key are all keyed on
    the id, so a finding without one could be SEEN and never acted on.
    """

    SRC = source("graph_db/mixins/recon/port_mixin.py")

    def test_nmap_nse_findings_get_a_stable_id(self):
        self.assertIn("nse_id", self.SRC)
        self.assertIn("v.id = COALESCE(v.id, $nse_id)", self.SRC)

    def test_the_id_is_derived_from_the_same_key_the_merge_uses(self):
        """So a second scan of an unchanged target produces the same id, and
        the mute a person applied last week survives."""
        self.assertIn('f"{script_id}|{ip_addr}|{port_number}"', self.SRC)

    def test_its_cve_is_written_where_the_scorer_reads(self):
        """C2: nmap_nse stored `cve_id`; the scorer reads `cve_ids`."""
        self.assertIn("v.cve_ids", self.SRC)


class TestRelationshipsAreNotDuplicatedEveryRun(unittest.TestCase):
    """K12. `datetime()` inside a MERGE pattern is part of the KEY.

    Every run produced a different key and therefore a brand-new relationship.
    Anything counting them counted scans, not facts.
    """

    def test_no_merge_pattern_contains_a_timestamp(self):
        for path in ("graph_db/mixins/osint_mixin.py",
                     "graph_db/mixins/recon/vuln_mixin.py"):
            src = source(path)
            with self.subTest(file=path):
                self.assertNotIn("timestamp: datetime()", src)
                self.assertNotIn("discovered_at: datetime()", src)

    def test_resolves_to_keeps_its_timestamp_on_create(self):
        src = source("graph_db/mixins/osint_mixin.py")
        self.assertIn("ON CREATE SET r.timestamp = datetime()", src)

    def test_waf_bypass_keeps_its_timestamp_on_create(self):
        src = source("graph_db/mixins/recon/vuln_mixin.py")
        self.assertIn("ON CREATE SET w.discovered_at = datetime()", src)


class TestSharedCveNodesAreNotOverwritten(unittest.TestCase):
    """K22. `CVE` is shared by every project.

    An unconditional SET let one project's CriminalIP reading overwrite the
    authoritative NVD score another project's GVM scan had written — and the
    second project would never know.
    """

    SRC = source("graph_db/mixins/osint_mixin.py")

    def test_criminalip_only_fills_in_what_is_missing(self):
        self.assertIn("c.cvss = coalesce(c.cvss, $cvss)", self.SRC)
        self.assertNotIn("SET c.cvss = $cvss, c.description = $description",
                         self.SRC)


class TestRescansCanReopenAFinding(unittest.TestCase):
    """K21. `remediated` was set and never cleared.

    A vulnerability that came back stayed in the board's Resolved section for
    ever, which is the worst possible direction for that mistake.
    """

    SRC = source("graph_db/mixins/gvm_mixin.py")

    def test_a_current_detection_clears_the_remediated_flag(self):
        self.assertIn("REMOVE v.remediated, v.remediated_at", self.SRC)

    def test_remediation_records_when(self):
        self.assertIn("v.remediated_at = datetime()", self.SRC)


class TestAiSurfaceWriterKeepsWhatItFound(unittest.TestCase):
    """K17. Two bugs in one writer, both of which DELETED data."""

    SRC = source("graph_db/mixins/recon/ai_surface_recon_mixin.py")

    def test_coalesce_arguments_are_the_right_way_round(self):
        """COALESCE('mcp', x) can only ever be 'mcp', so "keep what is there"
        was inverted into "always overwrite"."""
        self.assertNotIn("COALESCE('mcp', e.ai_interface_type)", self.SRC)
        self.assertIn("COALESCE(e.ai_interface_type, 'mcp')", self.SRC)

    def test_none_values_are_stripped_before_a_property_merge(self):
        """`SET v += $props` with a None REMOVES that property, so a rescan
        that could not read the evidence deleted the evidence."""
        self.assertIn("props = {k: v for k, v in props.items() if v is not None}",
                      self.SRC)


class TestImportsAreNotInsideBranches(unittest.TestCase):
    """K19. Two crashes that dropped data silently."""

    def test_graphql_imports_urlparse_at_module_level(self):
        src = source("graph_db/mixins/graphql_mixin.py")
        # It was imported inside one branch, so the OTHER call site raised
        # NameError and every GraphQL vulnerability was dropped whenever no
        # endpoint had been confirmed.
        self.assertIn("from urllib.parse import urlparse", src.split("def ")[0])
        self.assertNotIn("                    from urllib.parse import urlparse", src)

    def test_osint_defines_the_logger_its_error_handler_uses(self):
        src = source("graph_db/mixins/osint_mixin.py")
        # The handler raised NameError while HANDLING an error, so the original
        # failure was lost and the whole batch died with it.
        self.assertIn("logger = logging.getLogger(__name__)", src)
        self.assertIn("import logging", src.split("class ")[0])


if __name__ == "__main__":
    unittest.main()
