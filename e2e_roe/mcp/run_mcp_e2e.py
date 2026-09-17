#!/usr/bin/env python3
"""Phase 2: an agent opens 20 engagements over the inbound MCP server.

WHAT IS BEING TESTED

Not "does the API store what I sent". The claim under test is that a pipeline
opened by an AGENT respects every clause of the scope document that authorized
it, and that the surface refuses the things an agent must never be able to do -
re-point an engagement, read or write the client record, plant a credential -
whatever the document tells the agent to do.

So each case checks three different things, and a case passes only if all three
hold:

  the database      what was actually stored
  preflight         what the scan will RESOLVE to, which is not the same thing:
                    a per-tool rate above the engagement ceiling is written as
                    asked and run at the ceiling
  the gate          whether the agent's own dispatch really refuses the tools
                    the document forbids

A tool answering "ok" is not evidence of any of these.

Run:  python3 e2e_roe/mcp/run_mcp_e2e.py
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CASES = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]

MCP_URL = os.environ.get("E2E_MCP_URL", "http://localhost:3000/api/mcp-server")
TOKEN = os.environ.get("E2E_MCP_TOKEN", "")
NAME_PREFIX = "e2e-mcp-roe"
WEBAPP = os.environ.get("E2E_WEBAPP", "http://localhost:3000")
EMAIL = os.environ.get("E2E_EMAIL", "admin@redamon.local")
PASSWORD = os.environ.get("E2E_PASSWORD", "")
KEEP = "--keep" in sys.argv

# The SDK refuses a request that does not accept both, even in plain JSON mode.
HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}

_rpc_id = 0


def rpc(method: str, params: dict | None = None) -> dict:
    global _rpc_id
    _rpc_id += 1
    body = {"jsonrpc": "2.0", "method": method, "id": _rpc_id}
    if params is not None:
        body["params"] = params
    r = requests.post(
        MCP_URL, headers={**HEADERS, "Authorization": f"Bearer {TOKEN}"},
        json=body, timeout=120,
    )
    r.raise_for_status()
    return r.json()


def call_tool(name: str, arguments: dict) -> tuple[bool, str]:
    """Returns (ok, text). A refusal is a normal result with isError set.

    The surface rate-limits a token, and says how long to wait. Honouring that
    is the difference between testing the tools and testing the rate limiter:
    without it, case 8 onwards all failed with "try again in 42s" and told us
    nothing about the engagement rules they exist to check.
    """
    for _ in range(6):
        out = rpc("tools/call", {"name": name, "arguments": arguments})
        text = _text_of(out)
        wait = re.search(r"Try again in (\d+)s", text)
        if not wait:
            break
        time.sleep(int(wait.group(1)) + 2)
    return _verdict(out)


def _text_of(out: dict) -> str:
    if "error" in out:
        return json.dumps(out["error"])
    return "\n".join(
        b.get("text", "") for b in out.get("result", {}).get("content", [])
        if b.get("type") == "text"
    )


def _verdict(out: dict) -> tuple[bool, str]:
    if "error" in out:
        return False, json.dumps(out["error"])
    result = out.get("result", {})
    return not result.get("isError", False), _text_of(out)


def psql(sql: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "redamon-postgres", "psql", "-U", "redamon", "-d", "redamon", "-tAc", sql],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def camel_to_snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in name)


def project_row(pid: str, keys: list[str]) -> dict:
    cols = ", ".join(f'"{camel_to_snake(k)}"' for k in keys)
    raw = psql(f"SELECT row_to_json(t) FROM (SELECT {cols} FROM projects WHERE id = '{pid}') t;")
    return json.loads(raw) if raw else {}


def same(expected, actual) -> bool:
    if isinstance(expected, list) and isinstance(actual, list):
        return sorted(map(str, expected)) == sorted(map(str, actual))
    return expected == actual


def gate_verdicts(pid: str, specs: list[str]) -> dict:
    """Ask the agent's own dispatch gate, in the agent image, for this project.

    The only place that settles whether a forbidden tool is actually refused.
    A `tool@phase` spec checks that phase; a bare tool name uses exploitation.
    """
    pairs = []
    for spec in specs:
        tool, _, phase = spec.partition("@")
        pairs.append((tool, phase or "exploitation"))
    script = (
        "import os, json\n"
        "import project_settings as ps\n"
        "ps.load_project_settings(os.environ['PID'])\n"
        "from orchestrator_helpers.nodes.execute_plan_node import _check_roe_blocked\n"
        f"pairs = {pairs!r}\n"
        "print('GATE_JSON=' + json.dumps({f'{t}@{p}': _check_roe_blocked(t, p) for t, p in pairs}))\n"
    )
    out = subprocess.run(
        ["docker", "exec", "-e", f"PID={pid}", "redamon-agent", "python", "-c", script],
        capture_output=True, text=True,
    )
    for line in out.stdout.splitlines():
        if line.startswith("GATE_JSON="):
            return json.loads(line[len("GATE_JSON="):])
    return {"_error": (out.stderr or out.stdout)[-400:]}


def run_case(case: dict, index: int) -> dict:
    started = time.time()
    result = {"id": case["id"], "name": case["name"], "doc": case["doc"],
              "focus": case.get("focus", ""), "misses": []}
    miss = result["misses"].append

    # --- open the engagement -------------------------------------------------
    create = json.loads(json.dumps(case["create"]))
    create["name"] = f"{NAME_PREFIX}-{case['id'].lower()}-{int(time.time())}"
    create.setdefault("description", f"Phase 2 case {case['id']}")
    auth = create.get("authorization") or {}
    if isinstance(auth.get("documentText"), str) and auth["documentText"].startswith("@"):
        auth["documentText"] = (HERE / "docs" / auth["documentText"][1:]).read_text(encoding="utf-8")

    ok, text = call_tool("create_project", create)

    # Some engagements must not be openable at all.
    if case.get("expect_create_refused"):
        result["create_response"] = text[:400]
        if ok:
            miss({"what": "an engagement that must be refused was OPENED",
                  "expected_refusal": case["expect_create_refused"]})
            pid = psql(f"SELECT id FROM projects WHERE name = '{create['name']}';")
            if pid:
                result["projectId"] = pid
        elif case["expect_create_refused"].lower() not in text.lower():
            miss({"what": "refused for the wrong reason",
                  "expected_refusal": case["expect_create_refused"], "detail": text[:300]})
        result["status"] = "PASS" if not result["misses"] else "FAIL"
        result["seconds"] = round(time.time() - started, 1)
        return result

    if not ok:
        result.update(status="ERROR", detail=f"create_project refused: {text[:400]}",
                      seconds=round(time.time() - started, 1))
        return result
    result["create_response"] = text[:400]

    pid = psql(f"SELECT id FROM projects WHERE name = '{create['name']}';")
    if not pid:
        result.update(status="ERROR", detail="project not found in the database after create",
                      seconds=round(time.time() - started, 1))
        return result
    result["projectId"] = pid

    # --- a following tuning call --------------------------------------------
    if case.get("update"):
        ok, text = call_tool("update_recon_settings", {"projectId": pid, **case["update"]})
        result["update_ok"] = ok
        result["update_response"] = text[:300]
        if not ok:
            miss({"what": "update_recon_settings was refused", "detail": text[:300]})

    # --- a second authorization ---------------------------------------------
    if case.get("authorize_again"):
        again = dict(case["authorize_again"])
        if isinstance(again.get("documentText"), str) and again["documentText"].startswith("@"):
            again["documentText"] = (HERE / "docs" / again["documentText"][1:]).read_text(encoding="utf-8")
        ok, text = call_tool("attach_engagement_authorization", {"projectId": pid, **again})
        if not ok:
            miss({"what": "the re-issued authorization was refused", "detail": text[:300]})

    # --- what must be refused ------------------------------------------------
    if case.get("attempt"):
        ok, text = call_tool(
            "update_recon_settings",
            {"projectId": pid, "settings": case["attempt"]["settings"]},
        )
        result["attempt_allowed"] = ok
        result["attempt_response"] = text[:500]
        if ok:
            miss({"what": "a write that must be refused was ACCEPTED",
                  "keys": list(case["attempt"]["settings"]), "detail": text[:300]})
        else:
            # The promise is "refused by name; nothing is silently ignored". The
            # surface refuses on the FIRST offending key and names that one, so
            # requiring every key to appear would be testing a stricter contract
            # than the tool offers. What must hold is that the caller is told a
            # real reason and that NOTHING got through.
            named = [k for k in case["attempt"]["refused_keys"] if k in text]
            if not named:
                miss({"what": "refused without naming any offending key",
                      "keys": case["attempt"]["refused_keys"], "detail": text[:300]})
            result["refusal_named"] = named

            # The security property, checked against the database rather than
            # the message: a refused write must leave no trace of itself.
            attempted = case["attempt"]["settings"]
            after = project_row(pid, list(attempted))
            leaked = {
                k: after.get(camel_to_snake(k))
                for k, v in attempted.items()
                if same(v, after.get(camel_to_snake(k)))
            }
            if leaked:
                miss({"what": "a refused write reached the database anyway", "columns": leaked})

    # --- the database is the verdict ----------------------------------------
    wanted = list(case["expect"])
    stored = project_row(pid, wanted) if wanted else {}
    result["stored"] = stored
    for key, want in case["expect"].items():
        got = stored.get(camel_to_snake(key))
        if not same(want, got):
            miss({"column": key, "expected": want, "stored": got})

    # --- what the scan will really run with ---------------------------------
    want_resolved = case.get("expect_resolved") or {}
    if want_resolved:
        ok, text = call_tool("preflight_scope_check", {"projectId": pid})
        result["preflight"] = text[:6000]
        low = text.lower()
        if "startable" in want_resolved:
            # The tool prints it; read it rather than inferring from success.
            says_true = '"startable": true' in low or "startable: true" in low
            says_false = '"startable": false' in low or "startable: false" in low
            if want_resolved["startable"] and not says_true:
                miss({"what": "preflight did not report startable=true", "detail": text[:400]})
            if not want_resolved["startable"] and not says_false:
                miss({"what": "preflight did not report startable=false", "detail": text[:400]})
        if want_resolved.get("has_silent_noops"):
            if "no-op" not in low and "noop" not in low and "never runs" not in low:
                miss({"what": "preflight named no silent no-ops despite a narrowed scanModules",
                      "detail": text[:400]})
        if want_resolved.get("rate_capped_to_ceiling"):
            # preflight REPORTS both the written and the resolved value - that is
            # its whole purpose - so finding the written number in the text says
            # nothing. Read the structure and check the resolved one.
            try:
                report = json.loads(text)
            except ValueError:
                report = {}
                miss({"what": "preflight did not return JSON", "detail": text[:300]})
            ceiling = report.get("ceilingRps")
            over = [
                row for row in report.get("resolvedRates", [])
                if isinstance(row.get("resolved"), (int, float))
                and ceiling and row["resolved"] > ceiling
            ]
            if over:
                miss({"what": "a resolved rate exceeds the engagement ceiling",
                      "ceiling": ceiling, "rows": over[:3]})
            capped = [r for r in report.get("resolvedRates", []) if r.get("capped")]
            if not capped:
                miss({"what": "preflight reported nothing capped despite a 1 rps ceiling",
                      "detail": text[:300]})
            result["capped_count"] = len(capped)

    # --- does the gate actually refuse? -------------------------------------
    if case.get("expect_blocked"):
        verdicts = gate_verdicts(pid, case["expect_blocked"])
        result["gate"] = verdicts
        for spec, why in verdicts.items():
            if spec == "_error":
                miss({"what": "could not reach the gate", "detail": why})
            elif not why:
                miss({"what": "a forbidden tool was NOT blocked by the gate", "tool": spec})

    # --- append-only authorizations -----------------------------------------
    if case.get("expect_authorizations"):
        n = psql(f"SELECT count(*) FROM engagement_authorizations WHERE project_id = '{pid}';")
        result["authorizations"] = int(n or 0)
        if int(n or 0) != case["expect_authorizations"]:
            miss({"what": "wrong number of authorization records",
                  "expected": case["expect_authorizations"], "stored": n})

    result["status"] = "PASS" if not result["misses"] else "FAIL"
    result["seconds"] = round(time.time() - started, 1)
    return result


def cleanup(results: list[dict]) -> list[str]:
    """Remove every project this run created, through the route that cascades.

    A direct DELETE on `projects` would leave the graph, the scan rows and the
    authorization records behind; the webapp route is what tears an engagement
    down properly. The MCP surface deliberately has no delete tool.
    """
    left = []
    s = requests.Session()
    s.post(f"{WEBAPP}/api/auth/login",
           json={"email": EMAIL, "password": PASSWORD}, timeout=30)
    for r in results:
        pid = r.get("projectId")
        if not pid:
            continue
        if not s.delete(f"{WEBAPP}/api/projects/{pid}", timeout=120).ok:
            left.append(pid)
    return left


def main() -> int:
    if not TOKEN:
        print("E2E_MCP_TOKEN is not set", file=sys.stderr)
        return 2

    only = [a for a in sys.argv[1:] if not a.startswith("-")]
    cases = [c for c in CASES if not only or c["id"] in only]

    results = []
    try:
        for i, case in enumerate(cases):
            r = run_case(case, i)
            results.append(r)
            mark = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "ERR "}[r["status"]]
            print(f"  [{mark}] {r['id']} {r['name']}  ({r['seconds']}s)")
            for m in r["misses"]:
                print(f"          {json.dumps(m)[:220]}")
            if r["status"] == "ERROR":
                print(f"          {r.get('detail')}")
    finally:
        out = {
            "phase": "mcp",
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "endpoint": MCP_URL,
            "results": results,
        }
        (HERE / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if KEEP:
            print("\n--keep: projects left in place for inspection")
        else:
            left = cleanup(results)
            print(f"\n{len(results) - len(left)} project(s) deleted"
                  + (f", {len(left)} could NOT be deleted: {left}" if left else ""))

    passed = sum(1 for r in results if r["status"] == "PASS")
    print(f"{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
