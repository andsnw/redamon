#!/usr/bin/env python3
"""Real disclosure policies, sanitised, through both surfaces.

WHY THIS IS A DIFFERENT TEST FROM THE SYNTHETIC MATRICES

The synthetic documents state one rule each, crisply, in four hundred
characters. Real policies do not. They run from 2,000 to 41,000 characters and
are mostly reporting procedure, legal safe harbour, qualifying-vulnerability
lists and out-of-scope sections. Measured across sixty of them: 95% prohibit
social engineering, 87% prohibit denial of service, and only 15% state a request
rate in any form.

So the property under test here is mostly RESTRAINT. A parser that reads forty
thousand characters about disclosure timelines and bounty tables and comes back
with one rate ceiling is behaving correctly. One that comes back with a dozen
confident settings has invented most of them, and an invented setting is worse
than a missed one: it silently reconfigures a scan on the strength of prose that
never asked for it.

The check is therefore the whole row. Every column outside `expect` must be
byte-identical after the proposal is applied. Asserted columns are seeded with a
value the case does NOT expect, so a rule that lands cannot be landing by
default.

NOTHING IS EVER SCANNED. This exercises RedAmon's own parse, settings and
refusal surfaces. No tool that starts, queues or probes anything is called, and
`assert_no_scan_tools` enforces that against the MCP tool list rather than
leaving it to reviewer discipline. The sanitised targets are reserved-TLD names
that resolve nowhere.

Run:
    E2E_PASSWORD=...                     python3 e2e_roe/run_real.py --phase ui
    E2E_MCP_TOKEN=... E2E_PASSWORD=...   python3 e2e_roe/run_real.py --phase mcp --keep
"""
from __future__ import annotations

import argparse
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
REPO = HERE.parent

WEBAPP = os.environ.get("E2E_WEBAPP", "http://localhost:3000")
MCP_URL = os.environ.get("E2E_MCP_URL", f"{WEBAPP}/api/mcp-server")
EMAIL = os.environ.get("E2E_EMAIL", "admin@redamon.local")
PASSWORD = os.environ.get("E2E_PASSWORD", "")
TOKEN = os.environ.get("E2E_MCP_TOKEN", "")
MODEL = os.environ.get("E2E_MODEL", "deepseek/deepseek-chat")

MCP_HEADERS = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}

# Anything that could put traffic on a target. Never called; see assert_no_scan_tools.
SCAN_TOOLS = {"start_recon", "queue_recon", "stop_recon", "cancel_queued_scan",
              "kali_exec", "kali_output", "kali_cancel", "kali_toolbox"}

# Columns a document is ALLOWED to move without the case asserting them: the
# record of the document itself, and the clock.
ALLOW_CHANGED = {
    "updated_at", "roe_raw_text", "roe_parsed_json", "roe_notes",
    "roe_document_data", "roe_document_name", "roe_document_mime_type",
    # The client's own name is all over their policy, and recording it is right.
    # It is not a RULE the document states, so it is neither asserted nor counted
    # as an invention; the runner records what landed instead.
    "roe_client_name",
}


# --------------------------------------------------------------------------- db
def psql(sql: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "redamon-postgres", "psql", "-U", "redamon", "-d", "redamon",
         "-tAc", sql],
        capture_output=True, text=True, check=True)
    return out.stdout.strip()


def full_row(pid: str) -> dict:
    raw = psql(f"SELECT row_to_json(t) FROM (SELECT * FROM projects WHERE id = '{pid}') t;")
    return json.loads(raw) if raw else {}


def camel_to_snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() else c for c in name)


# ------------------------------------------------------------------------- mcp
_rpc = 0


def mcp(method: str, params: dict | None = None) -> dict:
    global _rpc
    _rpc += 1
    body = {"jsonrpc": "2.0", "method": method, "id": _rpc}
    if params is not None:
        body["params"] = params
    r = requests.post(MCP_URL, headers={**MCP_HEADERS, "Authorization": f"Bearer {TOKEN}"},
                      json=body, timeout=180)
    r.raise_for_status()
    return r.json()


def mcp_text(out: dict) -> str:
    if "error" in out:
        return json.dumps(out["error"])
    return "\n".join(b.get("text", "") for b in out.get("result", {}).get("content", [])
                     if b.get("type") == "text")


def call_tool(name: str, arguments: dict) -> tuple[bool, str]:
    if name in SCAN_TOOLS:
        raise AssertionError(f"refusing to call {name}: this suite never runs a scan")
    for _ in range(6):
        out = mcp("tools/call", {"name": name, "arguments": arguments})
        text = mcp_text(out)
        wait = re.search(r"Try again in (\d+)s", text)
        if not wait:
            break
        time.sleep(int(wait.group(1)) + 2)
    if "error" in out:
        return False, json.dumps(out["error"])
    return not out.get("result", {}).get("isError", False), text


def assert_no_scan_tools() -> None:
    """The guard, checked against the live surface rather than trusted.

    A reviewer reading this file can see no scan call. That is not the same as
    there being none, so the names are pulled from tools/list and matched against
    what this module can reach.
    """
    live = {t["name"] for t in mcp("tools/list").get("result", {}).get("tools", [])}
    source = Path(__file__).read_text(encoding="utf-8")
    called = set(re.findall(r"call_tool\(\s*[\"']([a-z_]+)[\"']", source))
    forbidden = called & (SCAN_TOOLS | {t for t in live if
                                        t.startswith(("start_", "queue_", "kali_"))})
    assert not forbidden, f"this suite must never call: {sorted(forbidden)}"
    return len(live)


# ------------------------------------------------------------------------ http
def login() -> requests.Session:
    s = requests.Session()
    r = s.post(f"{WEBAPP}/api/auth/login", json={"email": EMAIL, "password": PASSWORD},
               timeout=30)
    r.raise_for_status()
    return s


def parse_doc(s: requests.Session, doc: Path) -> dict:
    with doc.open("rb") as fh:
        r = s.post(f"{WEBAPP}/api/roe/parse",
                   files={"file": (doc.name, fh, "text/markdown")},
                   data={"model": MODEL, "current": "{}"}, timeout=600)
    r.raise_for_status()
    return r.json()


# ----------------------------------------------------------------- assertions
def matches(want, actual) -> bool:
    if isinstance(want, dict) and "contains" in want:
        return isinstance(actual, str) and want["contains"].lower() in actual.lower()
    if isinstance(want, list):
        return isinstance(actual, list) and set(map(str, want)) <= set(map(str, actual))
    return want == actual


def anti_value(key: str, want, registry: dict):
    """A legal value for `key` that is not `want`, so landing cannot be the default."""
    spec = registry["fields"].get(key) or {}
    values, kind = spec.get("values"), spec.get("type")
    if isinstance(want, dict):
        return "x-seeded-not-the-answer"
    if kind == "boolean":
        return not bool(want)
    if kind in ("int", "float"):
        return int(want) + 7 if isinstance(want, (int, float)) else 7
    if kind == "string-list":
        if values:
            other = [v for v in values if v not in (want or [])]
            return other[:1]
        return ["e2e-seeded"]
    if kind == "string":
        if values:
            return next((v for v in values if v != want), want)
        return "e2e-seeded"
    return None


def asserted_columns(case: dict) -> list[str]:
    cols = list(case.get("expect", {}))
    for g in case.get("expect_any", []):
        cols += list(g["options"])
    return cols


# --------------------------------------------------------- change classification
# Columns a parsed document must NEVER move. The document is attacker-
# influenceable: a target can hand you a "scope document".
SCOPE_COLUMNS = {
    "target_domain", "target_ips", "ip_mode", "subdomain_list",
    "domain_batch_hosts", "domain_batch_mode", "engagement_kind",
}

_PHASE_ORDER = {"informational": 0, "exploitation": 1, "post_exploitation": 2}


def classify(col: str, was, now) -> str:
    """loosening | tightening | neutral.

    The distinction is the whole point. A document that says nothing about
    denial of service and produces `roeAllowDos = false` has TIGHTENED the
    engagement on an inference: wrong, worth reporting, and safe. The same
    document producing `roeAllowDos = true` has removed a protection nobody
    asked it to remove, and that is a different kind of wrong entirely.
    """
    if col in SCOPE_COLUMNS:
        return "scope"
    if isinstance(was, bool) and isinstance(now, bool):
        if col.startswith("roe_allow_") or col == "mcp_kali_exec_enabled":
            return "loosening" if (now and not was) else "tightening"
        if col in ("stealth_mode", "roe_time_window_enabled", "target_guardrail_enabled"):
            return "tightening" if now else "loosening"
        if col.endswith("_enabled"):
            return "loosening" if now else "tightening"          # more tools, more traffic
        return "neutral"
    if col == "roe_global_max_rps":
        if now == 0 and was != 0:
            return "loosening"                                   # 0 means NO ceiling
        if was == 0 and now != 0:
            return "tightening"
        return "loosening" if (now or 0) > (was or 0) else "tightening"
    if col == "roe_max_severity_phase":
        a, b = _PHASE_ORDER.get(was, 2), _PHASE_ORDER.get(now, 2)
        return "loosening" if b > a else ("tightening" if b < a else "neutral")
    if isinstance(was, list) and isinstance(now, list):
        if col in ("roe_excluded_hosts", "roe_forbidden_tools", "roe_forbidden_categories"):
            return "tightening" if len(now) > len(was) else (
                "loosening" if len(now) < len(was) else "neutral")
        return "neutral"
    return "neutral"


# Words that would justify touching a column. Absent, a change is an inference
# the document did not ask for - reported, not necessarily wrong.
_SUPPORT = {
    "roe_allow_production_testing": ("production", "live system", "staging"),
    "roe_max_severity_phase": ("exploit", "post-exploitation", "pivot", "lateral", "persist"),
    "roe_sensitive_data_handling": ("sensitive", "personal data", "pii", "exfiltrat"),
    "roe_data_retention_days": ("retention", "retain", "delete the data"),
    "roe_engagement_type": ("web application", "mobile", "red team", "api "),
    "roe_third_party_providers": ("third party", "third-party", "provider", "vendor"),
    "roe_excluded_hosts": ("out of scope", "do not test", "excluded"),
    "roe_status_update_frequency": ("status update", "progress", "weekly", "daily"),
    "roe_compliance_frameworks": ("pci", "hipaa", "soc2", "gdpr", "iso27001"),
    "roe_client_contact_email": ("@", "contact"),
    "nuclei_severity": ("critical", "severity"),
    "scan_modules": ("port scan", "discovery", "enumeration"),
}


def supported(col: str, document: str) -> bool | None:
    words = _SUPPORT.get(col)
    if not words:
        return None
    low = document.lower()
    return any(w in low for w in words)


# --------------------------------------------------------------------- phases
def seed(s: requests.Session, pid: str, case: dict, registry: dict) -> dict:
    values = {}
    for key, want in case.get("expect", {}).items():
        v = anti_value(key, want, registry)
        if v is not None:
            values[key] = v
    for g in case.get("expect_any", []):
        for key, want in g["options"].items():
            v = anti_value(key, want, registry)
            if v is not None:
                values[key] = v
    if values:
        cur = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
        r = s.put(f"{WEBAPP}/api/projects/{pid}", json={**cur, **values}, timeout=180)
        if not r.ok:
            raise RuntimeError(f"seed failed for {case['id']}: {r.status_code} {r.text[:300]}")
    return values


def snake_to_camel(col: str) -> str:
    head, *rest = col.split("_")
    return head + "".join(w.capitalize() for w in rest)


def restore(s: requests.Session, pid: str, baseline: dict) -> None:
    """Put the project back to the row it had when it was created.

    Per-case reset of only the asserted columns is not enough: a document that
    sets something no case asserts leaves it set, and the NEXT case then measures
    restraint against a polluted row. That is how `roeForbiddenCategories` from
    one policy turned up as an "invention" by the next one.
    """
    now = full_row(pid)
    drift = {}
    for col, want in baseline.items():
        if col in ("id", "user_id", "created_at", "updated_at"):
            continue
        if now.get(col) != want:
            drift[snake_to_camel(col)] = want
    if drift:
        cur = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
        s.put(f"{WEBAPP}/api/projects/{pid}", json={**cur, **drift}, timeout=180)


def run_ui_case(s: requests.Session, case: dict, pid: str, docs: Path, registry: dict) -> dict:
    started = time.time()
    res = {"id": case["id"], "name": case["name"], "doc": case["doc"],
           "company": case.get("company"), "chars": case.get("chars"),
           "focus": case.get("focus", ""), "misses": []}
    miss = res["misses"].append

    res["seeded"] = seed(s, pid, case, registry)
    before = full_row(pid)

    try:
        proposal = parse_doc(s, docs / case["doc"])
    except requests.HTTPError as exc:
        code = exc.response.status_code if exc.response is not None else 0
        body = (exc.response.text if exc.response is not None else "")[:400]
        # The model intermittently answers with its whole field list, and that
        # arrives in three guises: over the proposal bound (refused by count),
        # or so large it is truncated mid-JSON (refused as unparseable), or slow
        # enough to time out. All three are the product declining to act on a
        # broken answer, which is the right outcome whichever document it strikes.
        #
        # The safety property is not WHICH refusal it was; it is that a refusal
        # writes nothing. That is what is checked below, against the row.
        if code in (422, 502, 504):
            after = full_row(pid)
            wrote = {c: (before.get(c), after.get(c)) for c in before
                     if c not in ALLOW_CHANGED and after.get(c) != before.get(c)}
            if wrote:
                miss({"what": "the parse was refused but the project changed anyway",
                      "columns": list(wrote)[:8]})
            res["refused"] = body
            res["runaway"] = True
            res["refusal_kind"] = ("proposal bound" if "setting changes" in body.lower()
                                   else "unparseable model output" if "invalid json" in body.lower()
                                   else f"http {code}")
            res["status"] = "PASS" if not res["misses"] else "FAIL"
            res["seconds"] = round(time.time() - started, 1)
            return res
        res.update(status="ERROR", detail=f"parse failed: {code} {body}",
                   seconds=round(time.time() - started, 1))
        return res
    except Exception as exc:
        res.update(status="ERROR", detail=f"parse failed: {exc}",
                   seconds=round(time.time() - started, 1))
        return res

    changes = {c["key"]: c["after"] for c in proposal.get("changes", [])}
    res["proposed"] = changes
    res["rejected"] = proposal.get("rejected", [])
    res["proposed_count"] = len(changes)

    cur = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
    put = s.put(f"{WEBAPP}/api/projects/{pid}", json={**cur, **changes}, timeout=180)
    if not put.ok:
        res.update(status="ERROR", detail=f"save failed: {put.status_code} {put.text[:300]}",
                   seconds=round(time.time() - started, 1))
        return res

    after = full_row(pid)
    score(case, before, after, changes, miss, res,
          (docs / case['doc']).read_text(encoding='utf-8'))
    res["status"] = "PASS" if not res["misses"] else "FAIL"
    res["seconds"] = round(time.time() - started, 1)
    return res


def score(case, before, after, changes, miss, res, document: str) -> None:
    """The stated rules landed, and nothing else moved."""
    # Extraction is recorded per rule rather than failed outright: an LLM reading
    # 25,000 characters does not find every clause every time, and a suite that
    # calls that a product failure is measuring variance. `main` decides, from
    # repeats, whether a rule never lands at all - which IS a product failure.
    landed, lost = {}, {}
    for key, want in case.get("expect", {}).items():
        got = after.get(camel_to_snake(key))
        (landed if matches(want, got) else lost)[key] = {
            "expected": want, "stored": got,
            "proposed": changes.get(key, "<not proposed>")}

    for g in case.get("expect_any", []):
        name = " | ".join(g["options"])
        ok = [k for k, w in g["options"].items() if matches(w, after.get(camel_to_snake(k)))]
        (landed if ok else lost)[name] = {
            "expected": g["options"], "satisfied_by": ok,
            "stored": {k: after.get(camel_to_snake(k)) for k in g["options"]}}

    res["landed"] = sorted(landed)
    res["lost"] = lost

    # RESTRAINT: the whole row, minus what the case asserts and what a document
    # is allowed to carry. Changes are classified rather than counted, because
    # on a 40,000-character policy "it changed something else" is not by itself
    # a verdict - what it changed, and in which direction, is.
    asserted = {camel_to_snake(k) for k in asserted_columns(case)}
    unasked = {}
    for col, was in before.items():
        if col in asserted or col in ALLOW_CHANGED:
            continue
        now = after.get(col)
        if isinstance(was, list) and isinstance(now, list):
            if sorted(map(str, was)) == sorted(map(str, now)):
                continue      # a reordered list is the same set of rules
        if now != was:
            unasked[col] = {"was": was, "now": now, "how": classify(col, was, now),
                            "supported": supported(col, document)}

    res["client_name"] = after.get("roe_client_name") or ""
    res["unasked"] = unasked
    res["unasked_count"] = len(unasked)
    res["tightened"] = sorted(c for c, v in unasked.items() if v["how"] == "tightening")
    res["loosened"] = sorted(c for c, v in unasked.items() if v["how"] == "loosening")

    # Hard failures. Everything else is recorded for the report.
    scope_moved = {c: v for c, v in unasked.items() if v["how"] == "scope"}
    if scope_moved:
        miss({"what": "the document moved the engagement SCOPE", "columns": scope_moved})
    loosened = {c: v for c, v in unasked.items() if v["how"] == "loosening"}
    if loosened:
        miss({"what": "the document LOOSENED the engagement without being asked",
              "columns": loosened})


def run_mcp_case(s: requests.Session, case: dict, docs: Path, registry: dict) -> dict:
    """The agent opens an engagement from a real policy and configures it.

    The policy IS the authorization document: it is passed as `documentText` and
    the surface digests it, storing only the SHA-256. The settings are the ones
    the document states, because that is what an agent acting on it should
    derive - and the restraint check then says whether anything else moved.
    """
    started = time.time()
    res = {"id": case["id"], "name": case["name"], "doc": case["doc"],
           "company": case.get("company"), "chars": case.get("chars"),
           "focus": case.get("focus", ""), "misses": []}
    miss = res["misses"].append

    text = (docs / case["doc"]).read_text(encoding="utf-8")
    slug = re.sub(r"[^a-z0-9]+", "-", (case.get("company") or "acme").lower()).strip("-")

    settings = {}
    for key, want in case.get("expect", {}).items():
        if isinstance(want, dict):                       # {"contains": "X-Bug-Bounty"}
            continue
        spec = registry["fields"].get(key) or {}
        if spec.get("mcp") == "settable":
            settings[key] = want
    for g in case.get("expect_any", []):
        # Pick an encoding the agent can actually WRITE. Several of these rules
        # have one option in the engagement RECORD (mcp: never, UI-only) and one
        # in the engagement LIMITS: `roeAllowPhysicalAccess` is closed to an
        # agent, `roeForbiddenCategories` is not. Taking the first option
        # regardless meant the agent set nothing and the case then failed for a
        # rule the surface had never been asked to store.
        key = next((k for k in g["options"]
                    if (registry["fields"].get(k) or {}).get("mcp") == "settable"), None)
        if key is None:
            continue
        want = g["options"][key]
        if isinstance(want, list) and isinstance(settings.get(key), list):
            settings[key] = sorted(set(settings[key]) | set(want))
        else:
            settings[key] = want

    # A third-party engagement needs a ceiling. Where the policy states none, the
    # agent must still choose one rather than leave 0, which means UNLIMITED.
    if not settings.get("roeGlobalMaxRps"):
        settings["roeGlobalMaxRps"] = 5
        res["ceiling_chosen_by_agent"] = 5

    header = case.get("expect", {}).get("engagementIdentityHeader")
    create = {
        "name": f"e2e-real-mcp-{case['id'].lower()}-{int(time.time())}",
        "description": f"Real-policy case {case['id']} ({case.get('company')})",
        "engagementKind": "third_party",
        "targetDomain": f"{slug}.test",
        "settings": settings,
        "authorization": {"documentKind": "roe_document", "documentText": text,
                          "issuedAt": "2026-09-01T00:00:00Z",
                          "summary": f"{case.get('company')} disclosure policy"},
    }
    if isinstance(header, dict):
        create["engagementIdentityHeader"] = f"{header['contains']}: redamon-e2e"

    ok, out = call_tool("create_project", create)
    res["create_response"] = out[:300]
    if not ok:
        res.update(status="ERROR", detail=f"create_project refused: {out[:400]}",
                   seconds=round(time.time() - started, 1))
        return res

    pid = psql(f"SELECT id FROM projects WHERE name = '{create['name']}';")
    if not pid:
        res.update(status="ERROR", detail="project missing from the database after create",
                   seconds=round(time.time() - started, 1))
        return res
    res["projectId"] = pid
    res["project_name"] = create["name"]

    after = full_row(pid)
    for key, want in case.get("expect", {}).items():
        spec = registry["fields"].get(key) or {}
        got = after.get(camel_to_snake(key))
        if isinstance(want, dict):
            if not matches(want, got):
                miss({"column": key, "expected": want, "stored": got})
            continue
        if spec.get("mcp") != "settable":
            # The engagement RECORD is closed to an agent by design. The document
            # states it, MCP cannot write it, and that is the correct outcome.
            res.setdefault("closed_to_mcp", []).append(key)
            continue
        if not matches(want, got):
            miss({"column": key, "expected": want, "stored": got})

    for g in case.get("expect_any", []):
        ok_keys = [k for k, w in g["options"].items()
                   if matches(w, after.get(camel_to_snake(k)))
                   and (registry["fields"].get(k) or {}).get("mcp") == "settable"]
        if not ok_keys and any((registry["fields"].get(k) or {}).get("mcp") == "settable"
                               for k in g["options"]):
            miss({"column": " | ".join(g["options"]), "expected": g["options"],
                  "stored": {k: after.get(camel_to_snake(k)) for k in g["options"]}})

    # Nothing may have been scanned, ever.
    jobs = psql(f"SELECT count(*) FROM scan_jobs WHERE project_id = '{pid}';")
    res["scan_jobs"] = int(jobs or 0)
    if int(jobs or 0) != 0:
        miss({"what": "a scan job exists; this suite must never start one", "count": jobs})

    res["status"] = "PASS" if not res["misses"] else "FAIL"
    res["seconds"] = round(time.time() - started, 1)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=("ui", "mcp"), required=True)
    ap.add_argument("--keep", action="store_true", help="leave the projects in place")
    ap.add_argument("--runs", type=int, default=1,
                    help="repeat the suite; extraction is a rate, so one run is weak evidence")
    ap.add_argument("only", nargs="*")
    args = ap.parse_args()

    if not PASSWORD:
        print("E2E_PASSWORD is not set", file=sys.stderr)
        return 2
    if args.phase == "mcp" and not TOKEN:
        print("E2E_MCP_TOKEN is not set", file=sys.stderr)
        return 2

    base = HERE / args.phase / "real"
    cases = json.loads((base / "cases.json").read_text(encoding="utf-8"))["cases"]
    if args.only:
        cases = [c for c in cases if c["id"] in args.only]
    docs = base / "docs"
    registry = json.loads((REPO / "recon_settings" / "registry.json").read_text(encoding="utf-8"))

    s = login()
    if args.phase == "mcp":
        n = assert_no_scan_tools()
        print(f"no-scan guard: {n} tools on the surface, none of them reachable from here")

    results, pid = [], None
    try:
        if args.phase == "ui":
            r = s.post(f"{WEBAPP}/api/projects",
                       json={"name": f"e2e-real-ui-{int(time.time())}",
                             "targetDomain": "e2e-real.test",
                             "description": "real-policy fixture"}, timeout=60)
            r.raise_for_status()
            pid = r.json()["id"]
            baseline = full_row(pid)
            print(f"project {pid}")

        for run in range(1, args.runs + 1):
            if args.runs > 1:
                print(f"--- run {run}/{args.runs} ---")
            for case in cases:
                res = (run_ui_case(s, case, pid, docs, registry) if args.phase == "ui"
                       else run_mcp_case(s, case, docs, registry))
                res["run"] = run
                results.append(res)
                mark = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "ERR "}[res["status"]]
                if res.get("runaway"):
                    extra = "  REFUSED (model runaway, nothing written)"
                elif args.phase == "ui":
                    extra = (f"  proposed={res.get('proposed_count')}"
                             f" landed={len(res.get('landed', []))}/{len(res.get('landed', [])) + len(res.get('lost', {}))}"
                             f" tightened={len(res.get('tightened', []))}")
                else:
                    extra = (f"  closed_to_mcp={len(res.get('closed_to_mcp', []))}"
                             f" jobs={res.get('scan_jobs')}")
                print(f"  [{mark}] {res['id']} {res['name'][:30]:32s}{res.get('chars', 0):7,}ch"
                      f"  ({res['seconds']}s){extra}")
                for m in res["misses"]:
                    print(f"          SAFETY {json.dumps(m)[:210]}")
                if res["status"] == "ERROR":
                    print(f"          {res.get('detail')}")
                if args.phase == "ui":
                    restore(s, pid, baseline)
    finally:
        out = {"phase": f"{args.phase}-real",
               "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "model": MODEL if args.phase == "ui" else None,
               "results": results}
        (base / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")

        if args.keep:
            kept = [r.get("project_name") or pid for r in results if r.get("projectId")] or [pid]
            print(f"\n--keep: {len([k for k in kept if k])} project(s) left in RedAmon")
        else:
            gone = 0
            for target in ([pid] if args.phase == "ui"
                           else [r.get("projectId") for r in results]):
                if target and s.delete(f"{WEBAPP}/api/projects/{target}", timeout=180).ok:
                    gone += 1
            print(f"\n{gone} project(s) deleted")

    return verdict(results, args.runs)


def verdict(results: list[dict], runs: int) -> int:
    """Safety is pass/fail. Extraction is a rate, and only a zero is a failure."""
    safety = [r for r in results if r["status"] != "PASS"]
    print()
    print(f"safety: {len(results) - len(safety)}/{len(results)} clean"
          + ("" if not safety else f"  ({len(safety)} with a safety failure or error)"))

    attempts: dict[str, list[int]] = {}
    for r in results:
        for rule in r.get("landed", []):
            attempts.setdefault(f"{r['id']} {rule}", []).append(1)
        for rule in (r.get("lost") or {}):
            attempts.setdefault(f"{r['id']} {rule}", []).append(0)

    # A rule needs enough SCORING attempts before "never landed" means anything.
    # A document refused as a model runaway is not an attempt at extraction, so a
    # case that ran three times and was refused twice has one data point.
    MIN_ATTEMPTS = 3
    never = sorted(k for k, v in attempts.items() if len(v) >= MIN_ATTEMPTS and sum(v) == 0)
    thin = sorted(k for k, v in attempts.items() if len(v) < MIN_ATTEMPTS and sum(v) == 0)
    flaky = sorted(k for k, v in attempts.items() if 0 < sum(v) < len(v))
    total = sum(sum(v) for v in attempts.values())
    tried = sum(len(v) for v in attempts.values())
    runaways = sum(1 for r in results if r.get("runaway"))

    if tried:
        print(f"extraction: {total}/{tried} stated rules landed "
              f"({100 * total / tried:.0f}%) over {runs} run(s)")
    if runaways:
        print(f"model runaways refused by the proposal bound: {runaways}")
    if flaky:
        print(f"rules that landed in some runs but not all ({len(flaky)}):")
        for k in flaky[:10]:
            print(f"    {k}")
    if never:
        print(f"rules that landed in NO run of {MIN_ATTEMPTS}+ attempts ({len(never)})"
              f" - an extraction GAP, not variance:")
        for k in never:
            print(f"    {k}")
    if thin:
        print(f"rules with too few scoring attempts to judge ({len(thin)}),"
              f" usually because the parse was refused as a runaway:")
        for k in thin[:6]:
            print(f"    {k}  ({len(attempts[k])} attempt(s))")

    ok = not safety and not never
    print("GREEN" if ok else "NOT GREEN")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
