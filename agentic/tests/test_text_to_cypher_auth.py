"""P0-3 — /text-to-cypher must be auth-gated and must not echo detail.

The endpoint was unauthenticated while spending the BODY-NAMED user's LLM
provider key, and one request can cost up to 9 provider calls (3 attempts, each
wrapped in retry_llm_call). With the agent port on 0.0.0.0 in the base compose,
anyone on the LAN could burn any user's budget without logging in.

`require_internal_auth` is the right dependency rather than the auth-only one:
this is a BILLED endpoint, so it needs the token bucket and the daily spend cap,
not just a key check.

Runs inside the agent container (imports the FastAPI app + its deps).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method="POST"):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


class TextToCypherAuthTests(unittest.TestCase):
    def test_endpoint_is_registered(self):
        self.assertIsNotNone(_route("/text-to-cypher"), "/text-to-cypher route missing")

    def test_requires_billed_internal_auth(self):
        deps = _dep_names(_route("/text-to-cypher"))
        self.assertIn(
            "require_internal_auth",
            deps,
            f"/text-to-cypher is not gated by the BILLED dependency (deps: {deps})",
        )

    def test_not_merely_auth_only(self):
        # require_internal_auth_only skips the token bucket and the daily spend
        # cap, which is exactly what this endpoint needs.
        deps = _dep_names(_route("/text-to-cypher"))
        self.assertNotIn("require_internal_auth_only", deps)

    def test_unauthenticated_call_is_rejected_before_the_handler_runs(self):
        import os
        from unittest import mock

        from fastapi.testclient import TestClient

        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}, clear=False):
            os.environ.pop("SCANNER_API_KEY", None)
            client = TestClient(api.app)
            resp = client.post(
                "/text-to-cypher",
                json={"question": "list ips", "user_id": "u1", "project_id": "p1"},
            )
        self.assertEqual(resp.status_code, 401)


class TextToCypherErrorNormalisationTests(unittest.TestCase):
    """A stable safe string leaves the process; detail goes to the server log.

    Asserted over the AST of the returned responses only, so interpolating the
    exception into a `logger` call (which is where it belongs) still passes.
    """

    # Names that hold an upstream provider message, a Neo4j error or a Cypher
    # fragment. None of them may reach the caller inside an ERROR body. (The
    # success body returns `cypher` on purpose — that is the endpoint's output.)
    BANNED = {"e", "err", "last_error", "last_cypher"}

    def _error_bodies(self):
        """Every JSONResponse content dict that carries an "error" key."""
        import ast
        import inspect
        import textwrap

        tree = ast.parse(textwrap.dedent(inspect.getsource(api.text_to_cypher)))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = getattr(func, "id", None) or getattr(func, "attr", None)
            if name != "JSONResponse":
                continue
            for kw in node.keywords:
                if kw.arg != "content" or not isinstance(kw.value, ast.Dict):
                    continue
                keys = [k.value for k in kw.value.keys if isinstance(k, ast.Constant)]
                if "error" in keys:
                    yield kw.value

    def test_no_error_response_interpolates_an_exception(self):
        import ast

        bodies = list(self._error_bodies())
        self.assertTrue(bodies, "no JSONResponse error bodies found — did the handler move?")

        for body in bodies:
            for sub in ast.walk(body):
                if isinstance(sub, ast.Name) and sub.id in self.BANNED:
                    self.fail(
                        f"text-to-cypher returns '{sub.id}' to the caller; "
                        "log the detail and return a stable safe string instead"
                    )
                # str(e) survives as a Call even when the Name check is dodged.
                if isinstance(sub, ast.Call):
                    fn = getattr(sub.func, "id", None)
                    if fn == "str":
                        self.fail("text-to-cypher stringifies a value into a response body")


if __name__ == "__main__":
    unittest.main()
