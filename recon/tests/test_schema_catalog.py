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

# Real documentation debt, measured in graph_schema_track.md §12.1. These node
# types EXIST and an agent asked about them has no property names to work with,
# so it guesses. Shrinking this set is the work; growing it is a regression.
UNDOCUMENTED_DEBT = {
    "GithubHunt",
    "GithubPath",
    "GithubRepository",
    "GithubSecret",
    "GithubSensitiveFile",
    "MultiscannerBucket",
    "MultiscannerEndpoint",
    "MultiscannerImage",
    "MultiscannerModel",
    "MultiscannerRepository",
    "SbomDocument",
}


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
    missing = declared_labels() - set(catalog.LABELS)
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
    stale = (INTENTIONALLY_UNDOCUMENTED | UNDOCUMENTED_DEBT) & set(catalog.LABELS)
    assert not stale, (
        f"these are listed as undocumented but now HAVE catalog entries: "
        f"{', '.join(sorted(stale))}. Remove them from the list."
    )


def test_catalog_documents_no_label_the_code_does_not_declare():
    """Documentation ahead of the code is its own drift: the model is told a
    node type exists that nothing ever writes, and queries come back empty for
    a reason no one can find."""
    phantom = set(catalog.LABELS) - declared_labels()
    assert not phantom, (
        f"catalogued but not declared in schema.py: {', '.join(sorted(phantom))}"
    )


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
