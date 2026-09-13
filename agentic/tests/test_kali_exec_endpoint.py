"""The three agent endpoints behind the inbound MCP kali_exec tools.

Admission itself is covered by test_kali_exec_guard.py. What is pinned here is
the wiring, where the failures are different in kind:

  - a command must reach the sandbox ONLY through `admit`, and only re-quoted;
  - an unresolvable scope must refuse, never fall through to "no scope";
  - the log path must be derived from the tenant, NEVER read from the job's own
    metadata (see LogPathTrustTests - that was an arbitrary file read);
  - a tool that failed must not be published as exit 0.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402
from kali_exec_guard import KaliScope  # noqa: E402

SCOPE = KaliScope(domains=("acme.tld",), ips=("10.0.0.5",), project_id="p1")
JOB = "a" * 32          # a well-formed uuid4 hex
OTHER_JOB = "b" * 32


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


class _FakeExecutor:
    def __init__(self, output="OK", success=True):
        self.calls = []
        self._output = output
        self._success = success

    async def execute(self, name, args, phase, skip_phase_check=False):
        self.calls.append({"name": name, "args": args, "phase": phase})
        return {"success": self._success, "output": self._output, "error": None}


class _FakeRegistry:
    """A job registry that runs the job inline and writes where the real one
    would: <WORKSPACE_ROOT>/<project>/jobs/<job_id>.log."""

    def __init__(self, root, spawn_error=None, job_id=JOB):
        self.root = root
        self.spawn_error = spawn_error
        self.job_id = job_id
        self.spawned = []
        self.cancelled = []
        self._state = {}

    def _log(self, project_id, job_id):
        d = Path(self.root) / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{job_id}.log"

    async def spawn(self, project_id, tool_name, args, runner, label=None):
        if self.spawn_error:
            return {"error": self.spawn_error}
        self.spawned.append({"project_id": project_id, "tool_name": tool_name, "args": args})
        log = self._log(project_id, self.job_id)
        log.touch()

        async def append_log(chunk):
            with log.open("a", encoding="utf-8") as fh:
                fh.write(chunk)

        result = await runner(tool_name, args, append_log)
        self._state[(project_id, self.job_id)] = {
            "job_id": self.job_id,
            "status": "done" if result.get("success") else "failed",
            "exit_code": 0 if result.get("success") else 1,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(log),
        }
        return {"job_id": self.job_id, "status": "running", "output_path": str(log)}

    async def wait(self, project_id, job_id, timeout_sec=30.0):
        return self.status(project_id, job_id)

    def status(self, project_id, job_id):
        return self._state.get((project_id, job_id), {"error": f"unknown job {job_id}"})

    async def cancel(self, project_id, job_id):
        self.cancelled.append(job_id)
        self._state[(project_id, job_id)]["status"] = "cancelled"
        return {"ok": True}


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = self._tmp.name
        self.executor = _FakeExecutor()
        self.registry = _FakeRegistry(self.root)
        patches = [
            mock.patch.dict(os.environ, {"WORKSPACE_ROOT": self.root}),
            mock.patch.object(api, "orchestrator", mock.Mock(tool_executor=self.executor)),
            mock.patch.object(api.job_runner, "get_registry", return_value=self.registry),
            mock.patch.object(api, "_kali_scope", return_value=SCOPE),
        ]
        for p in patches:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in patches])

    async def _exec(self, command, **kw):
        return await api.kali_exec(api.KaliExecRequest(project_id="p1", command=command, **kw))

    def _seed(self, project_id, job_id, text):
        d = Path(self.root) / project_id / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{job_id}.log").write_text(text)
        self.registry._state[(project_id, job_id)] = {
            "job_id": job_id, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(d / f"{job_id}.log"),
        }


class RouteRegistrationTests(unittest.TestCase):
    def test_all_three_routes_are_registered_and_master_key_gated(self):
        """require_internal_auth_only also accepts SCANNER_API_KEY, which the
        kali-sandbox and every spawned scan container hold. A leaked scanner
        token must not be able to run commands."""
        for path, method in (
            ("/kali/exec", "POST"),
            ("/kali/exec/{job_id}", "GET"),
            ("/kali/exec/{job_id}/cancel", "POST"),
        ):
            route = _route(path, method)
            self.assertIsNotNone(route, f"{method} {path} is not registered")
            deps = _dep_names(route)
            self.assertIn("require_master_internal_auth", deps, f"{method} {path}")
            self.assertNotIn("require_internal_auth_only", deps, f"{method} {path}")


class LogPathTrustTests(_Base):
    """REGRESSION: arbitrary file read on the AGENT container.

    JobRegistry.status() falls back to reading
    <workspace>/<project>/jobs/<job_id>.meta.json off disk and returns its
    parsed contents. kali_exec can write into that same workspace, so a caller
    who got one attacker-chosen body onto disk could set `output_path` to
    /proc/self/environ and page out INTERNAL_API_KEY and NEO4J_PASSWORD.
    """

    async def test_the_log_path_is_derived_not_taken_from_the_job_metadata(self):
        secret = Path(self.root) / "secret.env"
        secret.write_text("INTERNAL_API_KEY=super-secret")
        real = Path(self.root) / "p1" / "jobs"
        real.mkdir(parents=True, exist_ok=True)
        (real / f"{JOB}.log").write_text("the real output")
        # A poisoned meta pointing somewhere else entirely.
        self.registry._state[("p1", JOB)] = {
            "job_id": JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1",
            "output_path": str(secret),
        }
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertEqual(body["output"], "the real output")
        self.assertNotIn("super-secret", body["output"])

    async def test_a_job_id_that_is_not_a_uuid_hex_is_rejected(self):
        # The job id reaches a filesystem path, so traversal in it must not.
        for bad in ("../../../proc/self/environ", "a" * 31, "g" * 32, "", "../x"):
            resp = await api.kali_exec_status(bad, project_id="p1", cursor=0)
            self.assertEqual(resp.status_code, 404, bad)

    async def test_a_traversing_job_id_is_rejected_on_cancel_too(self):
        resp = await api.kali_exec_cancel("../../etc/passwd", project_id="p1")
        self.assertEqual(resp.status_code, 404)


class ExecTests(_Base):
    async def test_an_admitted_command_runs_and_returns_its_output(self):
        self.executor._output = "HTTP/1.1 200 OK"
        body = _body(await self._exec("curl -I https://acme.tld"))
        self.assertEqual(body["status"], "done")
        self.assertEqual(body["exit_code"], 0)
        self.assertIn("HTTP/1.1 200 OK", body["output"])

    async def test_the_sandbox_only_ever_receives_a_requoted_command(self):
        await self._exec("curl -A 'Mozilla 5.0' https://acme.tld")
        call = self.executor.calls[0]
        self.assertEqual(call["name"], "kali_shell")
        self.assertIn("'Mozilla 5.0'", call["args"]["command"])

    async def test_the_command_actually_run_is_echoed_back(self):
        body = _body(await self._exec("curl -I https://acme.tld"))
        # Includes the injected safety bounds: the caller should see what ran.
        self.assertIn("--max-filesize", body["command"])

    async def test_a_refused_command_never_reaches_the_sandbox(self):
        resp = await self._exec("curl https://victim.tld")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(_body(resp)["code"], "refused")
        self.assertEqual(self.executor.calls, [])
        self.assertEqual(self.registry.spawned, [])

    async def test_a_shell_metacharacter_never_reaches_the_sandbox(self):
        resp = await self._exec("curl https://acme.tld; id")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(self.executor.calls, [])

    async def test_an_unresolvable_scope_refuses_rather_than_running_unchecked(self):
        with mock.patch.object(api, "_kali_scope", side_effect=RuntimeError("webapp down")):
            resp = await self._exec("curl https://acme.tld")
        self.assertEqual(resp.status_code, 503)
        self.assertEqual(self.executor.calls, [])

    async def test_an_uninitialised_sandbox_is_unavailable_not_silent(self):
        with mock.patch.object(api, "orchestrator", None):
            resp = await self._exec("curl https://acme.tld")
        self.assertEqual(resp.status_code, 503)

    async def test_a_missing_project_id_is_refused(self):
        resp = await api.kali_exec(api.KaliExecRequest(project_id="", command="curl https://acme.tld"))
        self.assertEqual(resp.status_code, 400)

    async def test_the_job_cap_is_reported_as_a_retryable_limit(self):
        self.registry.spawn_error = "Too many background jobs running"
        resp = await self._exec("curl https://acme.tld")
        self.assertEqual(resp.status_code, 429)

    async def test_the_wait_is_clamped(self):
        captured = {}

        async def _wait(project_id, job_id, timeout_sec=30.0):
            captured["timeout"] = timeout_sec
            return self.registry.status(project_id, job_id)

        self.registry.wait = _wait
        await self._exec("curl https://acme.tld", wait_seconds=9999)
        self.assertEqual(captured["timeout"], api.KALI_EXEC_MAX_WAIT)


class FailureReportingTests(_Base):
    """REGRESSION: a failed tool was published as exit 0.

    PhaseAwareToolExecutor reports success for ANY MCP call that returned a
    string, and kali_shell encodes failure in its OUTPUT ("[ERROR] ...") rather
    than by raising. A caller told "exitCode 0" for a scan that never ran has a
    false negative, which is the bug class this surface exists to avoid.
    """

    async def test_a_tool_error_is_reported_as_a_failure(self):
        self.executor._output = "[ERROR] kali_shell failed: returncode=7, stderr=boom"
        body = _body(await self._exec("curl https://acme.tld"))
        self.assertEqual(body["status"], "failed")
        self.assertEqual(body["exit_code"], 1)

    async def test_a_timeout_is_reported_as_a_failure(self):
        self.executor._output = "[ERROR] Command timed out after 300 seconds."
        body = _body(await self._exec("curl https://acme.tld"))
        self.assertEqual(body["status"], "failed")

    async def test_ordinary_output_is_still_a_success(self):
        self.executor._output = "HTTP/2 200"
        body = _body(await self._exec("curl -I https://acme.tld"))
        self.assertEqual(body["status"], "done")


class PollAndCancelTests(_Base):
    async def test_an_unknown_job_is_not_found(self):
        resp = await api.kali_exec_status("c" * 32, project_id="p1", cursor=0)
        self.assertEqual(resp.status_code, 404)

    async def test_another_projects_job_id_reads_nothing(self):
        self._seed("p1", JOB, "secret output")
        resp = await api.kali_exec_status(JOB, project_id="p2", cursor=0)
        self.assertEqual(resp.status_code, 404)

    async def test_the_cursor_resumes_where_the_last_read_stopped(self):
        self._seed("p1", JOB, "line one\nline two\n")
        first = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertEqual(first["output"], "line one\nline two\n")
        second = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=first["next_cursor"]))
        self.assertEqual(second["output"], "")

    async def test_an_oversized_output_is_paged_never_silently_cut(self):
        self._seed("p1", JOB, "x" * (api.KALI_EXEC_MAX_OUTPUT_BYTES + 500))
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertTrue(body["truncated"])
        self.assertEqual(len(body["output"]), api.KALI_EXEC_MAX_OUTPUT_BYTES)
        rest = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=body["next_cursor"]))
        self.assertEqual(len(rest["output"]), 500)
        self.assertFalse(rest["truncated"])

    async def test_undecodable_tool_output_does_not_lose_the_run(self):
        d = Path(self.root) / "p1" / "jobs"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{JOB}.log").write_bytes(b"before \xff\xfe after")
        self.registry._state[("p1", JOB)] = {
            "job_id": JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1", "output_path": "",
        }
        body = _body(await api.kali_exec_status(JOB, project_id="p1", cursor=0))
        self.assertIn("before", body["output"])
        self.assertIn("after", body["output"])

    async def test_a_missing_log_reads_empty_rather_than_erroring(self):
        self.registry._state[("p1", OTHER_JOB)] = {
            "job_id": OTHER_JOB, "status": "done", "exit_code": 0,
            "started_at": "t0", "ended_at": "t1", "output_path": "",
        }
        body = _body(await api.kali_exec_status(OTHER_JOB, project_id="p1", cursor=0))
        self.assertEqual(body["output"], "")

    async def test_cancel_stops_the_job_and_says_what_that_means(self):
        """The note matters: cancelling the asyncio task does not stop the
        subprocess in the sandbox, so promising "stopped" would be a lie."""
        self._seed("p1", JOB, "partial")
        body = _body(await api.kali_exec_cancel(JOB, project_id="p1"))
        self.assertEqual(self.registry.cancelled, [JOB])
        self.assertEqual(body["status"], "cancelled")
        self.assertIn("may still be running", body["note"])

    async def test_cancelling_another_projects_job_is_not_found(self):
        self._seed("p1", JOB, "x")
        resp = await api.kali_exec_cancel(JOB, project_id="p2")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(self.registry.cancelled, [])


if __name__ == "__main__":
    unittest.main()
