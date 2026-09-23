"""/graph/triage: the MCP concurrency gate and the findings cap.

This endpoint is the backing store for the inbound MCP server's findings tools,
and it took NEITHER of the two bounds `/graph/exec` applies: no concurrency
ceiling, and no cap on how many rows the mixin returns. Both matter beyond
performance. The published guarantee is that graph reads from MCP run at most
two at a time across all tokens, and the contention lands on the operator's own
Priority Board, which reads the same data through this same endpoint.

The browser paths deliberately keep their previous behaviour: they set no
`source`, so nothing about how they are scheduled changes.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class _RecordingSemaphore:
    """Stands in for the real asyncio.Semaphore so entry is observable."""

    def __init__(self):
        self.entered = 0
        self.exited = 0

    async def __aenter__(self):
        self.entered += 1
        return self

    async def __aexit__(self, *exc):
        self.exited += 1
        return False


class _FakeTriageClient:
    def __init__(self):
        self.calls = []
        self.verdict_updates = True

    def list_triage_findings(self, user_id, project_id, **kwargs):
        self.calls.append(("list_triage_findings", user_id, project_id, kwargs))
        return [{"id": "f1", "label": "Vulnerability"}]

    def count_triage_findings(self, user_id, project_id):
        self.calls.append(("count_triage_findings", user_id, project_id))
        return 137

    def list_muted(self, user_id, project_id, limit=None, **kwargs):
        self.calls.append(("list_muted", user_id, project_id, limit, kwargs))
        return [{"id": "m1"}]

    def count_muted(self, user_id, project_id, **kwargs):
        self.calls.append(("count_muted", user_id, project_id, kwargs))
        return 42

    def muted_facets(self, user_id, project_id):
        self.calls.append(("muted_facets", user_id, project_id))
        return {"total": 1, "by_person": 1, "labels": {}, "rules": []}

    def unmute_findings(self, user_id, project_id, keys):
        self.calls.append(("unmute_findings", user_id, project_id, list(keys)))
        return {"unmuted": len(keys),
                "items": [{"key": k, "label": "Vulnerability", "muted_by": "rule:x/abc123"}
                          for k in keys]}

    def set_human_verdict(self, user_id, project_id, node_id, status, reason,
                          channel="", verdict_by=""):
        self.calls.append(
            ("set_human_verdict", node_id, status, reason, channel, verdict_by))
        return {"updated": self.verdict_updates, "label": "Vulnerability"}


class TriageGateTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = _FakeTriageClient()
        self.sem = _RecordingSemaphore()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "_graph_exec_mcp_semaphore", lambda: self.sem),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_findings", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    async def test_an_mcp_call_takes_the_concurrency_ceiling(self):
        await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(self.sem.entered, 1)
        # And releases it, or the second caller waits forever.
        self.assertEqual(self.sem.exited, 1)

    async def test_a_browser_call_is_unchanged_and_takes_no_ceiling(self):
        # The operator's own Triage board must not be throttled by a bound that
        # exists for external tokens.
        resp = await api.graph_triage(self._req())
        self.assertEqual(self.sem.entered, 0)
        self.assertEqual(_body(resp)["total"], 137)

    async def test_every_mcp_op_is_gated_not_just_the_read(self):
        for op, extra in (
            ("list_findings", {}),
            ("list_muted", {}),
            ("human_verdict", {"node_id": "n1", "status": "confirmed"}),
        ):
            self.sem.entered = 0
            await api.graph_triage(self._req(op=op, source="mcp", **extra))
            self.assertEqual(self.sem.entered, 1, op)

    async def test_the_ceiling_is_released_even_when_the_op_raises(self):
        def boom(*a, **k):
            raise RuntimeError("neo4j down")

        self.client.list_triage_findings = boom
        resp = await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(self.sem.exited, 1)


class TriageLimitTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_findings", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _list_kwargs(self):
        for call in self.client.calls:
            if call[0] == "list_triage_findings":
                return call[3]
        self.fail("list_triage_findings was never called")

    async def test_no_limit_leaves_the_mixin_default_alone(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._list_kwargs(), {})

    async def test_a_limit_is_passed_through(self):
        await api.graph_triage(self._req(limit=25))
        self.assertEqual(self._list_kwargs(), {"limit": 25})

    async def test_a_limit_is_clamped_to_the_mixin_ceiling(self):
        await api.graph_triage(self._req(limit=10_000_000))
        self.assertEqual(self._list_kwargs(), {"limit": api._TRIAGE_LIST_MAX})

    async def test_a_nonsense_limit_cannot_produce_an_empty_page(self):
        # 0 or a negative would return no rows beside a non-zero `total`, which
        # reads as "the scan found nothing" rather than "you asked for nothing".
        await api.graph_triage(self._req(limit=0))
        self.assertEqual(self._list_kwargs(), {"limit": 1})

    async def test_total_stays_the_UNCAPPED_count(self):
        # The whole point of `total`: a capped page must never pass for a
        # complete one.
        resp = await api.graph_triage(self._req(limit=1))
        body = _body(resp)
        self.assertEqual(len(body["findings"]), 1)
        self.assertEqual(body["total"], 137)


class TriageOpValidationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: _FakeTriageClient()),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    async def test_an_unknown_op_is_still_refused(self):
        resp = await api.graph_triage(
            api.GraphTriageRequest(op="drop_everything", user_id="u1", project_id="p1"))
        self.assertEqual(resp.status_code, 400)
        self.assertIn("unknown op", _body(resp)["error"])

    async def test_the_known_op_set_matches_what_the_handler_dispatches(self):
        self.assertEqual(
            api._TRIAGE_OPS,
            frozenset({"mute", "unmute", "unmute_many", "list_muted", "muted_facets",
                       "list_findings", "human_verdict", "preflight", "stop_run"}))

    async def test_a_node_op_without_a_node_id_is_refused_before_dispatch(self):
        for op in ("mute", "unmute", "human_verdict"):
            resp = await api.graph_triage(
                api.GraphTriageRequest(op=op, user_id="u1", project_id="p1"))
            self.assertEqual(resp.status_code, 400, op)


if __name__ == "__main__":
    unittest.main()


class VerdictProvenanceTests(unittest.IsolatedAsyncioTestCase):
    """A verdict records HOW it arrived and WHO it is by, and is audited.

    Before this, a verdict was audited nowhere: the webapp route wrote no audit
    row and this endpoint logged `log_event` only for mute and unmute. A
    decision that is durable and suppresses future AI review of that finding was
    invisible to any later reconstruction.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self.events = []
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

        import session_log
        self._log = mock.patch.object(
            session_log, "log_event",
            lambda name, **kw: self.events.append((name, kw)))
        self._log.start()
        self.addCleanup(self._log.stop)

    def _req(self, **kw):
        base = dict(op="human_verdict", user_id="u1", project_id="p1",
                    node_id="v1", status="confirmed")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _verdict_call(self):
        for c in self.client.calls:
            if c[0] == "set_human_verdict":
                return c
        self.fail("set_human_verdict was never called")

    async def test_the_source_becomes_the_recorded_channel(self):
        await api.graph_triage(self._req(source="mcp"))
        self.assertEqual(self._verdict_call()[4], "mcp")

    async def test_a_browser_verdict_records_the_app_channel(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._verdict_call()[4], "app")

    async def test_the_actor_defaults_to_the_tenant(self):
        await api.graph_triage(self._req())
        self.assertEqual(self._verdict_call()[5], "u1")

    async def test_an_explicit_actor_is_carried(self):
        await api.graph_triage(self._req(verdict_by="alice"))
        self.assertEqual(self._verdict_call()[5], "alice")

    async def test_a_verdict_is_logged(self):
        await api.graph_triage(self._req(source="mcp", reason="dup"))
        names = [n for n, _ in self.events]
        self.assertIn("finding_verdict_set", names)
        kw = dict(self.events[0][1])
        self.assertEqual(kw["node_id"], "v1")
        self.assertEqual(kw["status"], "confirmed")
        self.assertEqual(kw["channel"], "mcp")

    async def test_a_verdict_that_matched_NOTHING_is_not_logged_as_one(self):
        # `updated: false` means no node was touched. Logging it would record a
        # decision that was never made.
        self.client.verdict_updates = False
        await api.graph_triage(self._req())
        self.assertEqual(self.events, [])


class MutedLimitTests(unittest.IsolatedAsyncioTestCase):
    """`list_muted` is unbounded for the UI and bounded for MCP.

    The Muted table counts the rows it receives, so a default cap would silently
    change an operator-visible number; the MCP path has no record cap on this
    dependency at all, so its bound has to travel with the request.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _req(self, **kw):
        base = dict(op="list_muted", user_id="u1", project_id="p1")
        base.update(kw)
        return api.GraphTriageRequest(**base)

    def _limit(self):
        for c in self.client.calls:
            if c[0] == "list_muted":
                return c[3]
        self.fail("list_muted was never called")

    async def test_no_limit_stays_unbounded_for_the_browser(self):
        await api.graph_triage(self._req())
        self.assertIsNone(self._limit())

    async def test_a_limit_is_passed_through(self):
        await api.graph_triage(self._req(limit=2000, source="mcp"))
        self.assertEqual(self._limit(), 2000)

    async def test_a_limit_is_clamped_to_the_same_ceiling(self):
        await api.graph_triage(self._req(limit=10_000_000))
        self.assertEqual(self._limit(), api._TRIAGE_LIST_MAX)

    async def test_a_nonsense_limit_cannot_produce_an_empty_page(self):
        await api.graph_triage(self._req(limit=0))
        self.assertEqual(self._limit(), 1)


class MutedNodesPagingTests(unittest.IsolatedAsyncioTestCase):
    """Muted Nodes pages the muted list instead of loading every row.

    The filters and the page reach the mixin untouched, and the total is
    counted with the SAME filters, so "N of M" describes what is on screen.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    def _call(self, name):
        for c in self.client.calls:
            if c[0] == name:
                return c
        self.fail(f"{name} was never called")

    async def test_filters_and_page_reach_the_mixin(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_muted", user_id="u1", project_id="p1", limit=50, offset=100,
            label="Secret", muted_via="rule", rule="rule:secret/abc123",
            search="aws", order="person_first"))
        body = _body(resp)
        listed = self._call("list_muted")
        self.assertEqual(listed[3], 50)
        self.assertEqual(listed[4]["offset"], 100)
        self.assertEqual(listed[4]["order"], "person_first")
        self.assertEqual(listed[4]["label"], "Secret")
        counted = self._call("count_muted")
        # The same filters, minus the page: the total is of the filtered set.
        for key in ("label", "muted_via", "rule", "search", "live_rules"):
            self.assertEqual(counted[3][key], listed[4][key], key)
        self.assertNotIn("offset", counted[3])
        self.assertEqual(body["total"], 42)

    async def test_a_negative_offset_is_no_offset(self):
        await api.graph_triage(api.GraphTriageRequest(
            op="list_muted", user_id="u1", project_id="p1", offset=-5))
        self.assertIsNone(self._call("list_muted")[4]["offset"])

    async def test_unmute_many_passes_the_keys_and_returns_what_was_unmuted(self):
        with mock.patch("session_log.log_event") as log:
            resp = await api.graph_triage(api.GraphTriageRequest(
                op="unmute_many", user_id="u1", project_id="p1", keys=["v1", "v2"]))
        body = _body(resp)
        self.assertEqual(self._call("unmute_findings")[3], ["v1", "v2"])
        self.assertEqual([i["key"] for i in body["items"]], ["v1", "v2"])
        # One log line per finding actually unmuted, naming what had muted it.
        self.assertEqual(log.call_count, 2)
        self.assertEqual(log.call_args.kwargs["muted_by"], "rule:x/abc123")

    async def test_facets(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="muted_facets", user_id="u1", project_id="p1"))
        self.assertEqual(_body(resp)["total"], 1)


class GateAcknowledgementTests(unittest.IsolatedAsyncioTestCase):
    """The caller can tell whether this agent understood the MCP gate.

    Without it, a deploy that rebuilds only the webapp leaves an older agent
    that ignores `source`, `limit` and `verdict_by`, answers 200, and silently
    applies neither the concurrency ceiling nor the verdict provenance.
    """

    def setUp(self):
        self.client = _FakeTriageClient()
        self._patches = [
            mock.patch.object(api, "_triage_graph_client", lambda: self.client),
            mock.patch.object(api, "master_key_is_weak", lambda: False),
        ]
        for p in self._patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in self._patches])

    async def test_an_mcp_call_is_acknowledged(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1", source="mcp"))
        self.assertIs(_body(resp)["mcp_gated"], True)

    async def test_a_browser_call_gets_no_extra_field(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1"))
        self.assertNotIn("mcp_gated", _body(resp))

    async def test_the_acknowledgement_does_not_displace_the_result(self):
        resp = await api.graph_triage(api.GraphTriageRequest(
            op="list_findings", user_id="u1", project_id="p1", source="mcp"))
        body = _body(resp)
        self.assertEqual(body["total"], 137)
        self.assertEqual(len(body["findings"]), 1)
