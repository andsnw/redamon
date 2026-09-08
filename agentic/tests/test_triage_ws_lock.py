"""The per-project single-flight lock on triage runs.

A second concurrent run for the same project would collect the same findings,
classify them twice against a graph that is still changing, race the first run
writing verdicts back, and bill the operator for both. It is rejected rather
than queued.

The failure mode worth guarding is not "two runs started" -- that is the easy
half. It is the lock LEAKING: a run that crashes, or a socket that drops
mid-run, must not lock the project out until the process restarts. A leaked
slot is indistinguishable from a hung run and there is no UI to clear it.

Run: python -m pytest agentic/tests/test_triage_ws_lock.py
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_triage.websocket_handler import (  # noqa: E402
    _TRIAGE_IN_FLIGHT,
    _claim_triage_slot,
    _release_triage_slot,
)

P1, P2 = "project-one", "project-two"


class TriageSlotTest(unittest.TestCase):
    def setUp(self):
        _TRIAGE_IN_FLIGHT.clear()

    tearDown = setUp


class TestOneRunPerProject(TriageSlotTest):
    def test_the_first_claim_wins(self):
        self.assertTrue(_claim_triage_slot(P1))

    def test_a_second_concurrent_claim_is_refused(self):
        _claim_triage_slot(P1)
        self.assertFalse(_claim_triage_slot(P1))

    def test_a_different_project_is_unaffected(self):
        # The lock is per project, not global: two operators triaging two
        # projects must not block each other.
        _claim_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P2))


class TestTheSlotIsNeverLeaked(TriageSlotTest):
    """A leaked slot locks a project out with no way to clear it."""

    def test_release_frees_the_slot_for_a_later_run(self):
        _claim_triage_slot(P1)
        _release_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P1), "slot not reusable after release")

    def test_a_run_that_raises_still_releases(self):
        # Mirrors run_triage()'s try/finally: the orchestrator raising must not
        # strand the lock.
        _claim_triage_slot(P1)
        try:
            raise RuntimeError("orchestrator blew up")
        except RuntimeError:
            pass
        finally:
            _release_triage_slot(P1)
        self.assertTrue(_claim_triage_slot(P1))

    def test_releasing_twice_is_safe(self):
        # The handler releases in the task's `finally` AND in the socket's, so a
        # normal run releases twice. That must not raise or free someone else's
        # slot.
        _claim_triage_slot(P1)
        _release_triage_slot(P1)
        _release_triage_slot(P1)
        self.assertNotIn(P1, _TRIAGE_IN_FLIGHT)

    def test_releasing_a_project_that_never_ran_is_safe(self):
        # The socket `finally` runs even when start_triage was never sent.
        _release_triage_slot("never-started")
        self.assertEqual(_TRIAGE_IN_FLIGHT, set())

    def test_releasing_one_project_does_not_free_another(self):
        _claim_triage_slot(P1)
        _claim_triage_slot(P2)
        _release_triage_slot(P1)
        self.assertFalse(_claim_triage_slot(P2), "P2's slot was freed by P1's release")


class TestTheHandlerWiresTheLockOnBothExitPaths(unittest.TestCase):
    """The lock is only as good as the places that release it."""

    @staticmethod
    def _handler_source() -> str:
        import cypherfix_triage.websocket_handler as mod
        with open(mod.__file__, encoding="utf-8") as fh:
            return fh.read()

    def test_a_refused_claim_does_not_start_an_orchestrator(self):
        src = self._handler_source()
        claim = src.index("_claim_triage_slot")
        orchestrator = src.index("orchestrator = TriageOrchestrator", claim)
        between = src[claim:orchestrator]
        self.assertIn("continue", between,
                      "a refused claim must skip the run, not fall through to it")

    def test_the_slot_is_released_on_the_task_path_and_the_socket_path(self):
        # Two exit paths: the run finishing (or raising), and the websocket
        # closing while the task is cancelled. A cancelled task's `finally` may
        # not run, so the socket path is not redundant.
        src = self._handler_source()
        self.assertEqual(src.count("_release_triage_slot("), 3,
                         "expected release in the task finally, the socket "
                         "finally, and the helper definition")


if __name__ == "__main__":
    unittest.main()
