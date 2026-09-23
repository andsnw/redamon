"""The node-filter rollback script releases rule mutes and nothing else.

Pinned on the Cypher it runs, with a fake driver: it only ever matches
`muted_by STARTS WITH 'rule:'`, scopes to one project when asked, writes
nothing on a dry run, and refuses to run without saying which projects.

Run: ./redamon.sh test unit   (root-agent section)
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "tooling" / "scripts"))

import node_filters_rollback as rb  # noqa: E402


def driver(found):
    queries = []
    session = MagicMock()

    def run(query, **params):
        queries.append((query, params))
        result = MagicMock()
        if "RETURN n.project_id" in query:
            result.__iter__ = lambda _s: iter([{"project_id": p, "n": n} for p, n in found.items()])
        else:
            result.single.return_value = {"n": sum(found.values())}
        return result

    session.run = run
    session.__enter__ = lambda _s: session
    session.__exit__ = lambda *_: False
    drv = MagicMock()
    drv.session.return_value = session
    return drv, queries


class TestRollback(unittest.TestCase):
    def test_releases_rule_mutes_only(self):
        drv, queries = driver({"p1": 3})
        stats = rb.rollback(drv, None, dry_run=False, out=lambda *_: None)
        self.assertEqual(stats, {"found": {"p1": 3}, "released": 3})
        release = queries[-1][0]
        self.assertIn("STARTS WITH $prefix", release)
        self.assertEqual(queries[-1][1]["prefix"], "rule:")
        self.assertIn("REMOVE n:Muted, n.muted, n.muted_at, n.muted_by, n.muted_reason", release)
        self.assertNotIn("triage_", release)
        self.assertIn("IN TRANSACTIONS", release)

    def test_one_project_is_scoped_to_it(self):
        drv, queries = driver({"p1": 1})
        rb.rollback(drv, "p1", dry_run=False, out=lambda *_: None)
        for query, params in queries:
            self.assertIn("n.project_id = $pid", query)
            self.assertEqual(params["pid"], "p1")

    def test_a_dry_run_writes_nothing(self):
        drv, queries = driver({"p1": 5, "p2": 2})
        stats = rb.rollback(drv, None, dry_run=True, out=lambda *_: None)
        self.assertEqual(len(queries), 1)
        self.assertNotIn("REMOVE", queries[0][0])
        self.assertEqual(stats["released"], 0)

    def test_nothing_to_do_runs_no_write(self):
        drv, queries = driver({})
        rb.rollback(drv, None, dry_run=False, out=lambda *_: None)
        self.assertEqual(len(queries), 1)

    def test_blank_project_id_widens_to_every_project(self):
        # `--project "$PID"` with PID unset used to pass argparse, read as "no
        # project" and release the rule mutes of EVERY project.
        for blank in ("", "   "):
            with self.assertRaises(SystemExit):
                rb.main(["--project", blank])
            drv, queries = driver({"p1": 1, "p2": 1})
            with self.assertRaises(ValueError):
                rb.rollback(drv, blank, dry_run=False, out=lambda *_: None)
            self.assertEqual(queries, [])

    def test_it_must_be_told_which_projects(self):
        with self.assertRaises(SystemExit):
            rb.main([])
        with self.assertRaises(SystemExit):
            rb.main(["--project", "p1", "--all"])


if __name__ == "__main__":
    unittest.main()
