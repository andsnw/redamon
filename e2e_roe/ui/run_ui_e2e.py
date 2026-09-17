#!/usr/bin/env python3
"""Phase 1: drive the real RoE upload path for 20 documents and check the database.

WHAT THIS EXERCISES, AND WHY IT IS THE REAL PATH

Every request below goes through the running webapp with a real session cookie,
exactly as the browser does:

    POST /api/roe/parse        multipart upload -> text extraction -> the agent
                               -> an LLM -> re-validation against the registry
                               -> a PROPOSAL (a diff), not a write
    PUT  /api/projects/{id}    applying the confirmed proposal, as the form does

Then it reads the project row back out of Postgres. That last step is the point:
a proposal that looks right and a row that holds something else is precisely the
failure this feature can have, and only the database settles it.

The browser itself is driven separately (see report.md); what a browser adds is
rendering, and what it cannot add is certainty about what was stored.

Run:  python3 e2e_roe/ui/run_ui_e2e.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
DOCS = HERE / "docs"
CASES = json.loads((HERE / "cases.json").read_text(encoding="utf-8"))["cases"]

WEBAPP = os.environ.get("E2E_WEBAPP", "http://localhost:3000")
EMAIL = os.environ.get("E2E_EMAIL", "admin@redamon.local")
PASSWORD = os.environ.get("E2E_PASSWORD", "")
MODEL = os.environ.get("E2E_MODEL", "deepseek/deepseek-chat")
PROJECT_PREFIX = "e2e-roe-ui"


def psql(sql: str) -> str:
    """One row of answer out of the running database."""
    out = subprocess.run(
        ["docker", "exec", "redamon-postgres", "psql", "-U", "redamon", "-d", "redamon", "-tAc", sql],
        capture_output=True, text=True, check=True,
    )
    return out.stdout.strip()


def login() -> requests.Session:
    s = requests.Session()
    r = s.post(f"{WEBAPP}/api/auth/login", json={"email": EMAIL, "password": PASSWORD}, timeout=30)
    r.raise_for_status()
    return s


def create_project(s: requests.Session, name: str) -> str:
    r = s.post(
        f"{WEBAPP}/api/projects",
        json={"name": name, "targetDomain": "e2e-roe.test", "description": "RoE e2e fixture"},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["id"]


def delete_project(s: requests.Session, pid: str) -> bool:
    return s.delete(f"{WEBAPP}/api/projects/{pid}", timeout=120).ok


def parse(s: requests.Session, doc: Path, current: dict) -> dict:
    """The upload, exactly as the form sends it."""
    with doc.open("rb") as fh:
        r = s.post(
            f"{WEBAPP}/api/roe/parse",
            files={"file": (doc.name, fh, "text/markdown")},
            data={"model": MODEL, "current": json.dumps(current)},
            timeout=300,
        )
    r.raise_for_status()
    return r.json()


def project_row(pid: str, columns: list[str]) -> dict:
    """The stored truth, read as JSON so array and scalar columns both survive."""
    cols = ", ".join(f'"{c}"' for c in columns)
    raw = psql(f'SELECT row_to_json(t) FROM (SELECT {cols} FROM projects WHERE id = \'{pid}\') t;')
    return json.loads(raw) if raw else {}


def camel_to_snake(name: str) -> str:
    out = []
    for ch in name:
        if ch.isupper():
            out.append("_")
            out.append(ch.lower())
        else:
            out.append(ch)
    return "".join(out)


def same(expected, actual, allow_extra=()) -> bool:
    """Exact by default.

    `allow_extra` names tokens a case will tolerate ON TOP of what it expects,
    and exists for one situation: the document states two rules and the stricter
    reading of it produces both tokens. UI-15 forbids social engineering AND
    physical tailgating, so a parse answering with both is more right than the
    case was, not wrong.

    It is opt-in per token rather than a blanket "superset passes", because the
    over-reach cases (UI-08, UI-19, UI-20) are only meaningful while an
    unexpected value is still a failure.
    """
    if isinstance(expected, list) and isinstance(actual, list):
        want = sorted(map(str, expected))
        got = sorted(map(str, actual))
        if want == got:
            return True
        return sorted(set(got) - set(allow_extra)) == want
    return expected == actual


def run_case(s: requests.Session, case: dict, pid: str) -> dict:
    """One document, from upload to a verdict read out of the database."""
    doc = DOCS / case["doc"]
    started = time.time()
    result = {
        "id": case["id"], "name": case["name"], "doc": case["doc"],
        "focus": case.get("focus", ""),
    }

    # Seed every asserted column with a value the case does NOT expect, so a pass
    # can only mean the parse wrote it.
    #
    # Without this the matrix lies by omission: "DoS is prohibited" expects
    # roeAllowDos=false, which is also the shipped default, so the case went
    # green on a document the parser had ignored entirely. Three cases were
    # passing that way. Starting from the opposite value makes every assertion
    # earn its result.
    seeded = seed_anti_values(s, pid, case)
    result["seeded"] = seeded
    before = project_row(pid, [camel_to_snake(k) for k in
                               list(case["expect"]) + case.get("expect_absent", [])])
    try:
        proposal = parse(s, doc, {})
    except Exception as exc:
        result.update(status="ERROR", detail=f"parse failed: {exc}", seconds=round(time.time() - started, 1))
        return result

    changes = {c["key"]: c["after"] for c in proposal.get("changes", [])}
    result["proposed"] = changes
    result["rejected"] = proposal.get("rejected", [])
    result["ignored"] = proposal.get("ignored", [])

    # Apply the confirmed proposal the way the form does: the whole row back.
    current = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
    payload = {**current, **changes}
    put = s.put(f"{WEBAPP}/api/projects/{pid}", json=payload, timeout=120)
    if not put.ok:
        result.update(status="ERROR", detail=f"save failed: {put.status_code} {put.text[:200]}",
                      seconds=round(time.time() - started, 1))
        return result

    # The verdict comes from the database, never from the response.
    wanted = list(case["expect"]) + case.get("expect_absent", [])
    stored = project_row(pid, [camel_to_snake(k) for k in wanted])

    misses = []
    for key, want in case["expect"].items():
        got = stored.get(camel_to_snake(key))
        if not same(want, got, case.get("allow_extra", {}).get(key, ())):
            misses.append({"column": key, "expected": want, "stored": got,
                           "proposed": changes.get(key, "<not proposed>")})
    for key in case.get("expect_absent", []):
        col = camel_to_snake(key)
        if stored.get(col) != before.get(col):
            misses.append({"column": key, "expected": f"untouched ({before.get(col)!r})",
                           "stored": stored.get(col), "proposed": changes.get(key, "<not proposed>")})

    result["stored"] = stored
    result["misses"] = misses
    result["status"] = "PASS" if not misses else "FAIL"
    result["seconds"] = round(time.time() - started, 1)
    return result


def main() -> int:
    if not PASSWORD:
        print("E2E_PASSWORD is not set", file=sys.stderr)
        return 2

    only = sys.argv[1:] or None
    cases = [c for c in CASES if not only or c["id"] in only]

    s = login()
    pid = create_project(s, f"{PROJECT_PREFIX}-{int(time.time())}")
    print(f"project {pid}")

    results = []
    try:
        for case in cases:
            r = run_case(s, case, pid)
            results.append(r)
            mark = {"PASS": "PASS", "FAIL": "FAIL", "ERROR": "ERR "}[r["status"]]
            print(f"  [{mark}] {r['id']} {r['name']}  ({r['seconds']}s)")
            for m in r.get("misses", []):
                print(f"          {m['column']}: expected {m['expected']!r}, stored {m['stored']!r}"
                      f" (proposed {m['proposed']!r})")
            if r["status"] == "ERROR":
                print(f"          {r.get('detail')}")
            # Each case starts from a clean slate so one document cannot mask
            # the next: a value left behind would pass a later case for the
            # wrong reason.
            reset_project(s, pid)
    finally:
        out = {
            "phase": "ui",
            "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "model": MODEL,
            "project": pid,
            "results": results,
        }
        (HERE / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        if delete_project(s, pid):
            print(f"project {pid} deleted")
        else:
            print(f"WARNING: project {pid} was NOT deleted", file=sys.stderr)

    passed = sum(1 for r in results if r["status"] == "PASS")
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


def anti_value(key: str, expected, registry: dict):
    """A legal value for `key` that is not `expected`.

    Legal matters: a closed vocabulary refuses anything outside it, so a sentinel
    like "SEEDED" would be rejected at the save and the case would start from
    whatever was already there - quietly restoring the trivial pass this exists
    to remove.
    """
    spec = registry["fields"].get(key) or {}
    values = spec.get("values")
    kind = spec.get("type")

    if kind == "boolean":
        return not bool(expected)
    if kind in ("int", "float"):
        base = expected if isinstance(expected, (int, float)) else 0
        return int(base) + 7
    if kind == "string-list":
        if values:
            other = [v for v in values if v not in (expected or [])]
            return other[:1]
        return ["e2e-seeded-value"]
    if kind == "string":
        if values:
            for v in values:
                if v != expected:
                    return v
            return expected
        return "e2e-seeded-value"
    return None


def seed_anti_values(s: requests.Session, pid: str, case: dict) -> dict:
    """Put the project in a state where every expectation is currently false."""
    registry = json.loads((REPO / "recon_settings" / "registry.json").read_text(encoding="utf-8"))
    seed = {}
    for key, want in case["expect"].items():
        value = anti_value(key, want, registry)
        if value is not None and value != want:
            seed[key] = value
    if not seed:
        return {}
    current = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
    put = s.put(f"{WEBAPP}/api/projects/{pid}", json={**current, **seed}, timeout=120)
    if not put.ok:
        raise RuntimeError(f"could not seed {case['id']}: {put.status_code} {put.text[:300]}")
    return seed


def reset_project(s: requests.Session, pid: str) -> None:
    """Return every column any case asserts to its shipped default."""
    registry = json.loads((REPO / "recon_settings" / "registry.json").read_text(encoding="utf-8"))
    touched = {k for c in CASES for k in list(c["expect"]) + c.get("expect_absent", [])}
    reset = {}
    for key in touched:
        spec = registry["fields"].get(key)
        if spec and spec.get("has_default"):
            reset[key] = spec["default"]
    current = s.get(f"{WEBAPP}/api/projects/{pid}", timeout=60).json()
    s.put(f"{WEBAPP}/api/projects/{pid}", json={**current, **reset}, timeout=120)


if __name__ == "__main__":
    raise SystemExit(main())
