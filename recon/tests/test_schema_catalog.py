"""The generated graph-schema catalog and renderer.

Two jobs, and they pull in opposite directions on purpose.

**1. Nothing was lost.** The catalog was seeded by slicing the hand-written
`TEXT_TO_CYPHER_SYSTEM` into addressable segments. `render_schema()` with no
arguments must reproduce the committed baseline fixture BYTE-FOR-BYTE. That is
what turns "the dynamic version has everything the hardcoded one had" from a
claim into a fact: the prose was cut, never re-typed, re-wrapped or summarised.
If someone edits the catalog and the render drifts, this goes red and the diff
shows exactly what moved.

**2. Nothing new goes missing.** `graph_db/schema.py` is the executable truth
about which labels exist. A label declared there with no catalog entry means the
agent silently cannot query that node type: no error, no warning, just an
authoritative-looking empty answer. That failure mode is why this file exists.

Run:
    docker run --rm --entrypoint python3 -v "$PWD:/work:ro" -w /work \\
        redamon-recon:latest recon/tests/test_schema_catalog.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
CATALOG_PY = PROJECT_ROOT / "graph_db" / "schema_catalog.py"
RENDER_PY = PROJECT_ROOT / "graph_db" / "schema_render.py"
SCHEMA_PY = PROJECT_ROOT / "graph_db" / "schema.py"
BASELINE = PROJECT_ROOT / "recon" / "tests" / "fixtures" / "text_to_cypher_baseline.md"
KNOWN_UNDOCUMENTED_PROPS = (
    PROJECT_ROOT / "recon" / "tests" / "fixtures" / "undocumented_properties.json"
)
PROMPT_PY = PROJECT_ROOT / "agentic" / "prompts" / "base.py"


def _load(path: Path, name: str):
    """Import by PATH, not by package.

    `graph_db/__init__.py` imports the neo4j driver, which would make these
    tests need a driver they have no use for. Loading the module directly keeps
    the renderer's "pure, no dependencies" property honest rather than assumed.
    """
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


catalog = _load(CATALOG_PY, "schema_catalog")
render = _load(RENDER_PY, "schema_render")


# ---------------------------------------------------------------------------
# 1. Fidelity: the catalog is the same document, cut up
# ---------------------------------------------------------------------------

def test_segments_reassemble_into_the_baseline_byte_for_byte():
    rebuilt = "".join(s["body"] for s in catalog.SEGMENTS)
    baseline = BASELINE.read_text(encoding="utf-8")
    assert rebuilt == baseline, (
        "concatenating SEGMENTS no longer reproduces the baseline. Either a body "
        "was edited by hand, or the seeder changed. Re-run "
        "tooling/scripts/seed_schema_catalog.py and review the diff."
    )


def test_render_schema_with_no_arguments_is_the_baseline():
    """THE information-loss guard. If this passes, the renderer can serve any
    subset and nobody has to trust that the whole is still intact."""
    out = render.render_schema()
    baseline = BASELINE.read_text(encoding="utf-8")
    assert hashlib.sha1(out.encode()).hexdigest() == hashlib.sha1(baseline.encode()).hexdigest(), (
        f"render_schema() is {len(out)} chars, baseline is {len(baseline)}. "
        "The full render must be byte-identical to the committed baseline."
    )


def test_baseline_fixture_still_matches_the_live_prompt():
    """The fixture is only meaningful while it tracks the real prompt.

    When the prompt is legitimately edited, this goes red and the fixture is
    updated deliberately, in the same commit, which is the point.
    """
    src = PROMPT_PY.read_text(encoding="utf-8")
    tok = 'TEXT_TO_CYPHER_SYSTEM = """'
    start = src.index(tok) + len(tok)
    body = src[start : src.index('"""', start)]
    assert body == BASELINE.read_text(encoding="utf-8"), (
        "TEXT_TO_CYPHER_SYSTEM changed but the baseline fixture did not. "
        "Re-run tooling/scripts/seed_schema_catalog.py and commit both."
    )


# ---------------------------------------------------------------------------
# 2. Completeness: code declares the labels, the catalog must explain them
# ---------------------------------------------------------------------------

# Declared in graph_db/schema.py but deliberately NOT described as queryable
# node types. Each needs a reason, or it belongs in the debt list below.
INTENTIONALLY_UNDOCUMENTED = {
    # A suppression marker, not a node type. The schema tells the model the
    # label is invisible and that any query mentioning it is rejected, so
    # documenting it as something to query would contradict that.
    "Muted",
    # Knowledge-base RAG chunks. Not attack surface, never a recon answer.
    "KBChunk",
    # Its uniqueness constraint is explicitly dropped in schema.py; it survives
    # as an index only, so it is not a stable queryable entity.
    "Exploit",
}

# Real documentation debt. EMPTY, and the test below keeps it that way: a label
# listed here that turns out to be documented fails, and a declared label that is
# neither documented nor listed fails too. The GitHub secret-hunt subgraph named
# in graph_schema_track.md §12.1 was the last entry and is now documented.
UNDOCUMENTED_DEBT: set[str] = set()


def declared_labels() -> set[str]:
    """Every label graph_db/schema.py declares, from constraints and indexes.

    A bare `FOR (x:Label)` count over the file is wrong: it also catches the
    index-only statements, and the Exploit constraint is explicitly dropped. So
    constraints, indexes and the global reference labels are unioned by name.
    """
    src = SCHEMA_PY.read_text(encoding="utf-8")
    constraints = set(re.findall(r"CREATE CONSTRAINT[^;]*?FOR \(\w+:(\w+)\)", src, re.S))
    indexes = set(re.findall(r"CREATE INDEX[^;]*?FOR \(\w+:(\w+)\)", src, re.S))
    m = re.search(r"GLOBAL_REFERENCE_LABELS\s*=\s*\(([^)]*)\)", src)
    globals_ = set(re.findall(r'"(\w+)"', m.group(1))) if m else set()
    return constraints | indexes | globals_


def test_every_declared_label_is_catalogued_or_explicitly_excluded():
    """The anti-staleness guard.

    Add a node label to schema.py, forget the schema docs, and today NOTHING
    fails: the agent just silently cannot query it. This is the test that makes
    that loud. A genuinely new gap fails here; the known set is listed above
    with reasons so the debt is visible instead of ambient.
    """
    missing = declared_labels() - catalog.DOCUMENTED
    unexpected = missing - INTENTIONALLY_UNDOCUMENTED - UNDOCUMENTED_DEBT
    assert not unexpected, (
        f"{len(unexpected)} label(s) are declared in graph_db/schema.py with no "
        f"catalog entry: {', '.join(sorted(unexpected))}.\n"
        "An agent asked about these has no property names and will guess. Add a "
        "catalog entry, or list it in INTENTIONALLY_UNDOCUMENTED with a reason."
    )


def test_the_known_gaps_are_still_real_gaps():
    """Keeps the allowlists honest.

    Once a label IS documented, leaving it listed as debt would mask a future
    regression on that same label. So documenting one requires removing it here.
    """
    stale = (INTENTIONALLY_UNDOCUMENTED | UNDOCUMENTED_DEBT) & catalog.DOCUMENTED
    assert not stale, (
        f"these are listed as undocumented but now HAVE catalog entries: "
        f"{', '.join(sorted(stale))}. Remove them from the list."
    )


def test_catalog_documents_no_label_the_code_does_not_declare():
    """Documentation ahead of the code is its own drift: the model is told a
    node type exists that nothing ever writes, and queries come back empty for
    a reason no one can find."""
    phantom = catalog.DOCUMENTED - declared_labels()
    assert not phantom, (
        f"catalogued but not declared in schema.py: {', '.join(sorted(phantom))}"
    )


# ---------------------------------------------------------------------------
# 2b. Property drift: the live graph as an ORACLE, never as prompt content
#
# Label names are fully derivable from schema.py. Property names are NOT: 22 of
# 36 labels are written with `SET n += $props`, where the dict is assembled in
# Python from scanner output, so the names never appear literally in any source
# file. A static parse of the mixins finds 57 of Domain's 75.
#
# The live database is the one place that knows all of them, because it holds
# what was actually written. So it is used HERE, in a test, instead of being
# pasted into the prompt the way apoc.meta.data used to be. Same information,
# none of the costs: nothing cross-tenant reaches a model, no tokens are spent
# per query, and it cannot go stale in a cached snapshot.
#
# Skips cleanly without a database, like the EXPLAIN tests next door.
# ---------------------------------------------------------------------------

#: Properties every tenant-scoped node carries. They are deliberately NOT
#: documented per label: the schema states the rule once and tells the model
#: never to filter on them.
_TENANT_KEYS = {"user_id", "project_id"}

#: Bookkeeping written by the triage/mute feature onto many finding types. The
#: schema documents the family once rather than repeating ~25 keys per label.
_TRIAGE_PREFIX = "triage"


def _neo4j_driver():
    """Connect, or return None so the caller skips. Credentials from the env."""
    import os

    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    uri = os.environ.get("NEO4J_URI") or "bolt://localhost:7687"
    user = os.environ.get("NEO4J_USER") or "neo4j"
    password = os.environ.get("NEO4J_PASSWORD") or "changeme123"
    try:
        drv = GraphDatabase.driver(uri, auth=(user, password))
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


def test_no_property_in_the_live_graph_is_missing_from_the_schema():
    """A scanner adds a property, the schema never learns about it, and the
    agent cannot ask for it. Nothing fails today. This is that alarm."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_no_property_in_the_live_graph_is_missing_from_the_schema (neo4j unreachable)")
        return

    doc = BASELINE.read_text(encoding="utf-8")
    undocumented: dict[str, list[str]] = {}
    try:
        with drv.session() as sess:
            labels = [r["label"] for r in sess.run("CALL db.labels() YIELD label RETURN label")]
            for lab in labels:
                if lab not in catalog.DOCUMENTED:
                    continue  # completeness is the other test's job
                rows = sess.run(
                    "CALL apoc.meta.nodeTypeProperties({includeLabels:[$l]}) "
                    "YIELD propertyName RETURN propertyName",
                    l=lab,
                ).data()
                missing = [
                    r["propertyName"]
                    for r in rows
                    if r["propertyName"] not in _TENANT_KEYS
                    and not r["propertyName"].startswith(_TRIAGE_PREFIX)
                    and r["propertyName"] not in doc
                ]
                if missing:
                    undocumented[lab] = sorted(missing)
    finally:
        drv.close()

    # Known drift, measured once and recorded. 134 properties across 21 labels
    # exist today with no schema entry. They are NOT invented descriptions here:
    # guessing at what a property means would put a wrong claim into a security
    # tool's schema, which is worse than a gap the agent can see. So the debt is
    # frozen, and anything NEW fails immediately.
    import json

    known = json.loads(KNOWN_UNDOCUMENTED_PROPS.read_text(encoding="utf-8"))
    new_drift = {
        lab: [p for p in ps if p not in known.get(lab, [])]
        for lab, ps in undocumented.items()
    }
    new_drift = {lab: ps for lab, ps in new_drift.items() if ps}
    assert not new_drift, (
        "NEW properties exist in the graph that the schema never mentions, so an "
        "agent cannot ask for them:\n"
        + "\n".join(f"  {lab}: {', '.join(ps)}" for lab, ps in sorted(new_drift.items()))
        + "\n\nDocument them in TEXT_TO_CYPHER_SYSTEM, re-seed the catalog, and "
        "re-run. Do not add them to the known-drift fixture to silence this."
    )


def test_the_schema_does_not_promise_properties_that_were_removed():
    """The opposite drift: a property documented but no longer written. The
    model asks for it, gets null, and nobody can explain why."""
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_the_schema_does_not_promise_properties_that_were_removed (neo4j unreachable)")
        return
    # Only checked for labels that HAVE nodes here: an absent label proves
    # nothing about its properties, and this database is one deployment.
    phantom: dict[str, list[str]] = {}
    try:
        with drv.session() as sess:
            present = {r["label"] for r in sess.run("CALL db.labels() YIELD label RETURN label")}
            for lab in sorted(present & set(catalog.LABELS)):
                live = {
                    r["propertyName"]
                    for r in sess.run(
                        "CALL apoc.meta.nodeTypeProperties({includeLabels:[$l]}) "
                        "YIELD propertyName RETURN propertyName",
                        l=lab,
                    ).data()
                }
                if not live:
                    continue
                documented = set(
                    re.findall(r"^- ([a-z_][a-z0-9_]*)\s*\(", catalog.LABELS[lab]["body"], re.M)
                )
                gone = sorted(documented - live - _TENANT_KEYS)
                if gone:
                    phantom[lab] = gone
    finally:
        drv.close()

    # Reported, not enforced: a property can be legitimately documented before
    # any scan in THIS database has produced it. Printing keeps it visible
    # without failing a gate on one deployment's coverage.
    if phantom:
        print("NOTE: documented but absent from this database (may simply be unscanned):")
        for lab, ps in phantom.items():
            print(f"      {lab}: {', '.join(ps)}")


# ---------------------------------------------------------------------------
# 2c. Field rendering: the attribute list is GENERATED, not transcribed
#
# The catalog stores each label as parsed fields - description, property groups,
# relationships, sub-types, notes - alongside the verbatim body it came from.
# The parse is proven lossless below: re-rendering from the fields reproduces
# every word of the source. That is what allows the attribute list to be driven
# by the property names that actually exist, with the catalog supplying meaning.
# ---------------------------------------------------------------------------

def test_the_parse_loses_no_word_of_any_label_block():
    """The information-loss guard for decomposition.

    Byte-identity cannot apply here: field rendering normalises whitespace and
    expands comma-grouped properties onto their own lines. So the guarantee is
    word-level - every word in the source block still appears in the render.
    """
    from collections import Counter

    def words(t):
        return Counter(re.findall(r"[A-Za-z0-9_]+", t))

    lost = Counter()
    for lab, seg in catalog.LABELS.items():
        lost += words(seg["body"]) - words(render.render_label(lab))
    assert not lost, (
        "field rendering dropped words that the verbatim body contains: "
        f"{dict(list(lost.items())[:12])}"
    )


def test_every_label_has_a_description_and_properties_as_fields():
    for lab, seg in catalog.LABELS.items():
        assert seg["description"], f"{lab} parsed with no description"
    total = sum(len(catalog.label_properties(l)) for l in catalog.LABELS)
    assert total > 400, f"only {total} properties parsed into fields; the parser regressed"


def test_a_live_property_the_catalog_never_heard_of_is_still_rendered():
    """THE point of the split. A scanner starts writing a new property; nobody
    edits the prose. It must still reach the model, undescribed but nameable,
    or the agent cannot return a column that exists."""
    out = render.render_label("Domain", live_props=["name", "brand_new_scanner_prop"])
    assert "brand_new_scanner_prop" in out
    assert "not described above" in out


def test_live_properties_do_not_leak_the_tenant_keys():
    out = render.render_label("Domain", live_props=["user_id", "project_id", "name"])
    assert "user_id" not in out.split("not described above")[-1]


def test_a_documented_property_absent_from_this_graph_is_still_rendered():
    """One database is one deployment. Absent here means "not scanned yet", so
    dropping it would hide a property the agent can legitimately ask about."""
    out = render.render_label("Domain", live_props=["name"])
    assert "vt_jarm" in out


def test_field_rendering_is_off_unless_live_properties_are_supplied():
    """Without a database, graph_schema must still serve the full document, and
    the no-argument render must stay byte-identical to the baseline."""
    assert render.render_schema() == BASELINE.read_text(encoding="utf-8")
    with_live = render.render_schema(live_properties={"Domain": ["zzz_new_prop"]})
    assert "zzz_new_prop" in with_live
    assert with_live != BASELINE.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# 3. Scoping: a subset must still be usable, and honest about what it omitted
# ---------------------------------------------------------------------------

def test_a_scoped_render_carries_the_requested_labels_in_full():
    want = ["Certificate", "Domain", "IP", "Subdomain"]
    out = render.render_schema(labels=want)
    for lab in want:
        body = catalog.LABELS[lab]["body"]
        assert body in out, f"{lab}'s block is not present verbatim in a scoped render"


def test_a_scoped_render_drops_the_labels_not_asked_for():
    out = render.render_schema(labels=["Certificate"])
    assert catalog.LABELS["MalPackageFinding"]["body"] not in out
    assert len(out) < len(render.render_schema()), "scoping did not reduce anything"


def test_omitted_labels_are_still_NAMED_so_absence_stays_askable():
    """The false-negative guard.

    A model that has never heard of MalPackageFinding cannot query for it, so
    "scanned and clean" and "never scanned" become the same empty answer. Naming
    the omitted types keeps the question askable.
    """
    out = render.render_schema(labels=["Certificate"])
    assert "MalPackageFinding" in out, "omitted label is not even named"
    assert "Other node types" in out


def test_an_unknown_label_raises_rather_than_rendering_nothing():
    """Silently rendering nothing for a typo is indistinguishable from "that
    node type has no documentation"."""
    try:
        render.render_schema(labels=["Subdomian"])  # deliberate typo
    except ValueError as e:
        assert "Subdomian" in str(e)
    else:
        raise AssertionError("a misspelled label rendered silently")


def test_detail_modes_are_ordered_by_size():
    full = len(render.render_schema())
    rels = len(render.render_schema(detail="relationships"))
    names = len(render.render_schema(detail="labels"))
    assert names < rels < full, f"labels={names} relationships={rels} full={full}"


def test_an_unknown_detail_mode_raises():
    try:
        render.render_schema(detail="everything")
    except ValueError as e:
        assert "everything" in str(e)
    else:
        raise AssertionError("an unknown detail mode was accepted")


if __name__ == "__main__":
    passed, failures = 0, []
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"  PASS  {name}")
                passed += 1
            except AssertionError as exc:
                print(f"  FAIL  {name}: {exc}")
                failures.append((name, str(exc)))
            except Exception as exc:  # noqa: BLE001
                print(f"  ERROR {name}: {type(exc).__name__}: {exc}")
                failures.append((name, f"{type(exc).__name__}: {exc}"))
    print()
    print(f"{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
