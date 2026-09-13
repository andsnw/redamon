"""The tenant-scoped property census that replaced apoc.meta.data in the prompt.

The Cypher generator used to be handed `Neo4jGraph.get_schema`, which is
`apoc.meta.data` and therefore DATABASE-GLOBAL. Every generation embedded the
label and property shape of every other tenant's projects into the prompt, and
then told the model never to filter on the tenant keys it had just been shown.

The census answers the same question - "which properties can I reference?" -
about the caller's project only. What is pinned here is the part that is easy to
regress and impossible to notice: the scoping, and that a failure degrades to
NOTHING rather than back to a global view.
"""
import sys
import types
import unittest
from unittest import mock


def _manager():
    """A Neo4jToolManager with no __init__ run: the census only needs .graph."""
    from tools import Neo4jToolManager

    m = Neo4jToolManager.__new__(Neo4jToolManager)
    m.graph = None
    return m


class TestProjectPropertyCensus(unittest.TestCase):
    def setUp(self):
        from agent_context import current_project_id, current_user_id

        self.uid, self.pid = current_user_id, current_project_id
        # contextvars cannot be mock.patch.object'd; set and restore by token.
        self._tu = self.uid.set("u1")
        self._tp = self.pid.set("p1")

    def tearDown(self):
        self.uid.reset(self._tu)
        self.pid.reset(self._tp)

    # -- fails closed ------------------------------------------------------

    def test_no_user_context_yields_nothing_not_a_global_census(self):
        """Failing open here would restore the cross-tenant leak verbatim."""
        m = _manager()
        m.graph = mock.Mock()
        self.uid.set("")
        self.assertEqual(m._project_property_census(), {})
        m.graph.query.assert_not_called()

    def test_no_project_context_yields_nothing(self):
        m = _manager()
        m.graph = mock.Mock()
        self.pid.set("")
        self.assertEqual(m._project_property_census(), {})
        m.graph.query.assert_not_called()

    def test_no_graph_yields_nothing(self):
        self.assertEqual(_manager()._project_property_census(), {})

    def test_a_query_failure_degrades_to_nothing(self):
        """A broken census must not fall back to the global schema."""
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.side_effect = RuntimeError("neo4j is down")
        self.assertEqual(m._project_property_census(), {})

    # -- scoping -----------------------------------------------------------

    def test_the_query_is_bound_to_the_caller_tenant(self):
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = []
        m._project_property_census()
        cypher, kwargs = m.graph.query.call_args[0][0], m.graph.query.call_args[1]
        self.assertIn("n.user_id = $uid", cypher)
        self.assertIn("n.project_id = $pid", cypher)
        self.assertEqual(kwargs["params"], {"uid": "u1", "pid": "p1"})

    def test_muted_nodes_are_excluded(self):
        """The schema tells the model suppressed findings are invisible and that
        naming the label is rejected. Leaking their property shape contradicts it."""
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = []
        m._project_property_census()
        self.assertIn("NOT n:Muted", m.graph.query.call_args[0][0])

    def test_the_scan_is_bounded(self):
        """A census is a hint for writing queries, not an inventory. An unbounded
        scan would put a full-graph read on the critical path of every question."""
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = []
        m._project_property_census()
        self.assertIn("LIMIT", m.graph.query.call_args[0][0])

    # -- output ------------------------------------------------------------

    def test_tenant_keys_are_not_returned(self):
        """The rules tell the model never to filter on them, so surfacing them
        invites exactly the query the rules forbid."""
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = [
            {"lab": "Domain", "props": ["name", "user_id", "project_id", "source"]}
        ]
        self.assertEqual(m._project_property_census(), {"Domain": ["name", "source"]})

    def test_it_returns_a_mapping_keyed_by_label(self):
        """The renderer merges these names into each label's attribute list, so
        the shape matters: a flat list could not be attributed to a label."""
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = [
            {"lab": "Domain", "props": ["name"]},
            {"lab": "IP", "props": ["address"]},
        ]
        self.assertEqual(
            m._project_property_census(), {"Domain": ["name"], "IP": ["address"]}
        )

    def test_an_empty_project_yields_an_empty_mapping(self):
        m = _manager()
        m.graph = mock.Mock()
        m.graph.query.return_value = []
        self.assertEqual(m._project_property_census(), {})


if __name__ == "__main__":
    unittest.main()
