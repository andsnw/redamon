"""Render the graph-schema document, whole or in part.

Pure: no database, no network, no I/O beyond importing the catalog. That is what
lets `graph_schema` keep its promise of still answering when Neo4j and Postgres
are down, and what makes this unit-testable without a stack.

Two things this buys over the 81KB constant it replaces:

1. **Scope.** Every Cypher generation currently receives all 33 documented
   labels regardless of the question. A certificate question drags in
   supply-chain, JS-recon, attack-chain and multiscanner sections. `labels=`
   renders the ones that matter in full.

2. **Honest absence.** Rendering *only* the labels present in a project would
   recreate the false-negative this whole surface exists to avoid: a model that
   has never heard of `MalPackageFinding` cannot query for it, so "scanned and
   clean" and "never scanned" collapse into the same empty answer. So labels
   left out are still NAMED, under a line saying they exist but were not
   expanded. The model can still ask; it just has to ask for the detail.

`render_schema()` with no arguments reproduces the source document
byte-for-byte. `recon/tests/test_schema_catalog.py` asserts that against a
committed fixture, which is what makes "the dynamic version lost nothing" a
mechanical fact instead of a claim.
"""
from __future__ import annotations

import re

try:  # normal import inside the package
    from graph_db.schema_catalog import LABELS, SEGMENTS
except ImportError:  # loaded by path (pure unit tests, no package side effects)
    from schema_catalog import LABELS, SEGMENTS  # type: ignore

#: Sections that are pure query guidance rather than schema description. They
#: are dropped by the narrower detail modes, never by `full`.
_EXAMPLE_SECTIONS = ("Common Query Patterns",)

DETAIL_MODES = ("labels", "nodes", "relationships", "full")


def label_names() -> list[str]:
    """Every label the catalog documents, in source order."""
    return [s["key"] for s in SEGMENTS if s["kind"] == "LABEL"]


_REL_LINE = re.compile(r"^- `\((\w+):(\w+)\)-\[:(\w+)[^\]]*\]->\((\w+):(\w+)\)`")


def _filter_relationship_lines(body: str, labels: set[str]) -> str:
    """Keep only relationship bullets whose BOTH endpoints are in scope.

    Relationships are the bulk of what survives a label filter otherwise, and a
    `(Package)-[:FLAGGED_AS]->(MalPackageFinding)` line is noise for someone
    asking about certificates. Lines that are not relationship bullets (the
    heading, prose notes) are kept: they are cheap and carry the direction
    warnings.
    """
    kept = []
    for line in body.split("\n"):
        m = _REL_LINE.match(line)
        if m and not (m.group(2) in labels and m.group(5) in labels):
            continue
        kept.append(line)
    return "\n".join(kept)



def render_label(label: str, live_props: list[str] | None = None) -> str:
    """Render ONE label block from its parsed fields.

    With `live_props`, the attribute list is driven by the property names that
    actually exist in the caller's graph, and the catalog supplies the meaning:

        vt_jarm (string): JARM TLS fingerprint from VirusTotal   <- both
        cache_header                                             <- live only

    That is the whole point of the split. A property a scanner started writing
    last week appears in the prompt automatically, undescribed but NAMEABLE, so
    the agent can return it. Previously it was invisible until someone
    remembered to edit 1300 lines of prose.

    A property the catalog describes but the graph does not have is still
    rendered: this graph is one project, and absence here means "not scanned
    yet", not "does not exist".
    """
    seg = LABELS.get(label)
    if seg is None:
        raise ValueError(f"unknown label {label!r}")

    out = [f"**{label}** - {seg['description']}"]
    described: set[str] = set()

    for g in seg["groups"]:
        if g["header"]:
            out.append("")
            out.append(g["header"])
        for pr in g["properties"]:
            described.add(pr["name"])
            typ = f" ({pr['type']})" if pr["type"] else ""
            desc = f": {pr['desc']}" if pr["desc"] else ""
            out.append(f"- {pr['name']}{typ}{desc}")

    if live_props:
        extra = sorted(set(live_props) - described - {"user_id", "project_id"})
        if extra:
            out.append("")
            out.append(
                "Present on this project's nodes but not described above "
                "(returnable, meaning undocumented):"
            )
            out.append("- " + ", ".join(extra))

    for st in seg["subtypes"]:
        qual = f" ({st['qualifier']})" if st["qualifier"] else ""
        out.append("")
        out.append(f"{st.get('lead', '')}**{st['name']}**{qual} - {st['desc']}")

    for r in seg["relationships"]:
        out.append(
            f"{r.get('prefix', '')}`({r['source_var']}:{r['source']})"
            f"-[:{r['type']}{r.get('rel_props', '')}]->"
            f"({r['target_var']}:{r['target']})` {r.get('sep', '')} {r['desc']}".rstrip()
        )

    if seg["notes"]:
        out.append("")
        out.extend(n.rstrip() for n in seg["notes"])

    return "\n".join(out) + "\n"


def _wanted(seg: dict, detail: str, labels: set[str] | None, include_examples: bool) -> bool:
    kind, section = seg["kind"], seg["section"]

    if kind == "LABEL":
        if detail in ("relationships", "labels"):
            return False
        return labels is None or seg["key"] in labels

    if not include_examples and any(e in section for e in _EXAMPLE_SECTIONS):
        return False

    if detail == "full":
        return True
    if detail == "labels":
        # Just enough frame to make the name list readable.
        return kind == "PREAMBLE"
    if detail == "nodes":
        return kind == "PREAMBLE" or "Relationships" not in section
    if detail == "relationships":
        return kind == "PREAMBLE" or "Relationships" in section
    return True


def render_schema(
    detail: str = "full",
    labels: list[str] | None = None,
    include_examples: bool = True,
    name_omitted_labels: bool = True,
    live_properties: dict[str, list[str]] | None = None,
) -> str:
    """Render the schema document.

    Args:
        detail: one of DETAIL_MODES. "full" is the whole document.
        labels: restrict expanded label blocks to these. None means all, and
            with detail="full" that reproduces the source byte-for-byte.
        include_examples: keep the worked query-pattern sections.
        name_omitted_labels: when `labels` filters some out, still name the rest
            so the model knows they exist and can be asked about.

    Raises:
        ValueError: on an unknown detail mode, or an unknown label name. An
            unknown label is raised rather than ignored: silently rendering
            nothing for a typo would look identical to "that node type has no
            documentation", which is the confusion this module exists to end.
    """
    if detail not in DETAIL_MODES:
        raise ValueError(f"unknown detail mode {detail!r}; expected one of {DETAIL_MODES}")

    wanted: set[str] | None = None
    if labels is not None:
        unknown = [x for x in labels if x not in LABELS]
        if unknown:
            raise ValueError(
                f"unknown label(s): {', '.join(sorted(unknown))}. "
                f"Known labels: {', '.join(sorted(LABELS))}"
            )
        wanted = set(labels)

    out = []
    for s in SEGMENTS:
        if not _wanted(s, detail, wanted, include_examples):
            continue
        body = s["body"]
        # Field-rendered ONLY when live property names are supplied. Without
        # them the verbatim body is emitted, which keeps the no-argument render
        # byte-identical to the committed baseline and keeps graph_schema
        # answering when no database is reachable.
        if live_properties is not None and s["kind"] == "LABEL":
            body = render_label(s["key"], live_properties.get(s["key"]))
        if wanted is not None and "Relationships" in s["section"]:
            body = _filter_relationship_lines(body, wanted)
        out.append(body)
    text = "".join(out)

    if detail == "labels":
        return text + "\n## Node Types\n" + "\n".join(f"- {n}" for n in label_names()) + "\n"

    if wanted is not None and name_omitted_labels:
        omitted = [n for n in label_names() if n not in wanted]
        if omitted:
            text += (
                "\n## Other node types\n"
                "These node types exist in RedAmon but are not expanded above. A query "
                "against one is legitimate: an empty result means the project has none, "
                "not that the node type is unavailable. Ask for its detail if you need "
                "its properties.\n"
                + ", ".join(omitted)
                + "\n"
            )
    return text
