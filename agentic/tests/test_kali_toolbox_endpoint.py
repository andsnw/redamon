"""GET /kali/toolbox — the Kali catalogue the inbound MCP server serves.

The webapp's `kali_toolbox` tool reads this endpoint and nothing else. It exists
so the MCP layer never holds MCP_AUTH_TOKEN and never speaks to the
kali-sandbox: the catalogue is a constant in THIS image, so the answer costs no
container call and still arrives when the sandbox is stopped.

The behaviours pinned here are the ones whose absence produces a FALSE NEGATIVE:
an empty catalogue reads as "this image ships no tools", which would have an
agent report a capability gap that does not exist. The other is drift: the
catalogue must BE the registry description, not a copy of it, or it will promise
tools the image does not carry.
"""
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


def _body(resp):
    import json

    return json.loads(bytes(resp.body).decode())


class RouteRegistrationTests(unittest.TestCase):
    def test_it_is_registered_and_auth_gated(self):
        route = _route("/kali/toolbox", "GET")
        self.assertIsNotNone(route)
        deps = _dep_names(route)
        # Auth-only, like /graph/schema-doc: it costs no LLM call, so the LLM
        # token bucket and daily cap must not throttle it.
        self.assertIn("require_internal_auth_only", deps)
        self.assertNotIn("require_internal_auth", deps)

    def test_it_takes_no_arguments(self):
        """No projectId, so there is no tenant data to leak and no ownership
        check to forget. The MCP tool advertises an empty input schema on the
        strength of this."""
        import inspect

        self.assertEqual(list(inspect.signature(api.kali_toolbox).parameters), [])


class CatalogueTests(unittest.IsolatedAsyncioTestCase):
    async def test_it_serves_the_kali_shell_registry_description(self):
        """One source, no second copy. A transcription would drift from the
        image the moment a tool is added or removed."""
        from prompts.tool_registry import TOOL_REGISTRY

        expected = TOOL_REGISTRY["kali_shell"]["description"].strip()
        body = _body(await api.kali_toolbox())
        self.assertEqual(body["toolbox"], expected)

    async def test_the_catalogue_is_categorised_and_substantial(self):
        """Guards the registry entry being gutted to a stub: the tool's whole
        value is that an agent can tell what exists before planning around it."""
        body = _body(await api.kali_toolbox())
        toolbox = body["toolbox"]
        self.assertGreater(len(toolbox), 2000)
        for category in ("Exploitation:", "Password cracking:", "Windows/AD:"):
            self.assertIn(category, toolbox)

    async def test_a_missing_description_is_an_error_not_an_empty_catalogue(self):
        """An empty string would read as "no tools installed". A 500 makes the
        MCP tool raise, which is the honest answer."""
        from prompts import tool_registry

        with mock.patch.dict(tool_registry.TOOL_REGISTRY, {"kali_shell": {}}, clear=False):
            resp = await api.kali_toolbox()
        self.assertEqual(resp.status_code, 500)
        self.assertNotIn("toolbox", _body(resp))

    async def test_a_renamed_registry_key_is_an_error_not_an_empty_catalogue(self):
        from prompts import tool_registry

        registry = {k: v for k, v in tool_registry.TOOL_REGISTRY.items() if k != "kali_shell"}
        with mock.patch.object(tool_registry, "TOOL_REGISTRY", registry):
            resp = await api.kali_toolbox()
        self.assertEqual(resp.status_code, 500)


if __name__ == "__main__":
    unittest.main()
