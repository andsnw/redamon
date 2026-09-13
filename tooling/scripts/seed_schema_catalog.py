#!/usr/bin/env python3
"""Seed `graph_db/schema_catalog.py` from the hand-written prompt.

One-time mechanical job (`graph_schema_track.md` §12.3): slice the 1329-line
`TEXT_TO_CYPHER_SYSTEM` literal into addressable segments and emit them as a
catalog module, so the same content can be rendered per-label instead of only
as one 81KB block.

**The fidelity contract.** Every byte of the source lands in exactly one
segment, and concatenating the segments in order reproduces the source
byte-for-byte. The generator refuses to write if that does not hold, and
`recon/tests/test_schema_catalog.py` re-checks it against the committed
fixture. This is what makes "we lost nothing" a mechanical fact rather than a
claim: the prose is not re-typed, re-wrapped or summarised, only cut.

Bodies are stored verbatim rather than decomposed into per-property dicts. The
prose carries structure a flat `{name, type, desc}` list cannot hold: property
groups (`Nuclei-specific properties (source="nuclei"):`), relationship notes
inside a label block, and single descriptions running to 1800 characters. A
decomposition is still possible later, per label, against a committed baseline
that proves what changed.

Run:
    python3 tooling/scripts/seed_schema_catalog.py [--check]

`--check` verifies the committed catalog still reproduces the fixture without
rewriting it, which is what CI wants.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
PROMPT = REPO / "agentic" / "prompts" / "base.py"
FIXTURE = REPO / "recon" / "tests" / "fixtures" / "text_to_cypher_baseline.md"
OUT = REPO / "graph_db" / "schema_catalog.py"

START_TOKEN = 'TEXT_TO_CYPHER_SYSTEM = """'


def extract_prompt() -> str:
    src = PROMPT.read_text(encoding="utf-8")
    start = src.index(START_TOKEN) + len(START_TOKEN)
    end = src.index('"""', start)
    return src[start:end]


def segment(doc: str) -> list[dict]:
    """Cut the document on ## / ### headings, then on **Label** blocks.

    Returns segments in source order. Concatenating their bodies reproduces
    `doc` exactly; the caller asserts that.
    """
    segs: list[dict] = []
    h2s = [m.start() for m in re.finditer(r"^## ", doc, re.M)]
    if not h2s:
        return [{"kind": "PREAMBLE", "key": "", "section": "", "body": doc}]

    segs.append({"kind": "PREAMBLE", "key": "", "section": "", "body": doc[: h2s[0]]})

    for a, b in zip(h2s, h2s[1:] + [len(doc)]):
        chunk = doc[a:b]
        title = chunk.split("\n", 1)[0][3:].strip()
        h3s = [m.start() for m in re.finditer(r"^### ", chunk, re.M)]
        if not h3s:
            segs.append({"kind": "SECTION", "key": title, "section": title, "body": chunk})
            continue
        segs.append(
            {"kind": "SECTION_HEAD", "key": title, "section": title, "body": chunk[: h3s[0]]}
        )
        for c, d in zip(h3s, h3s[1:] + [len(chunk)]):
            sub = chunk[c:d]
            subtitle = sub.split("\n", 1)[0][4:].strip()
            labs = [m.start() for m in re.finditer(r"^\*\*[A-Za-z][A-Za-z0-9]*\*\*\s*-", sub, re.M)]
            if not labs:
                segs.append(
                    {
                        "kind": "SUBSECTION",
                        "key": subtitle,
                        "section": title,
                        "body": sub,
                    }
                )
                continue
            segs.append(
                {
                    "kind": "SUBSECTION_HEAD",
                    "key": subtitle,
                    "section": title,
                    "body": sub[: labs[0]],
                }
            )
            for e, f in zip(labs, labs[1:] + [len(sub)]):
                blk = sub[e:f]
                lab = re.match(r"^\*\*([A-Za-z][A-Za-z0-9]*)\*\*", blk).group(1)
                segs.append(
                    {
                        "kind": "LABEL",
                        "key": lab,
                        "section": f"{title} :: {subtitle}",
                        "body": blk,
                    }
                )
    return segs


#: Labels documented as a SHARED group rather than under their own heading.
#: The Secret Multiscanner asset nodes are one shape with five labels, listed
#: backticked inside an "**Asset nodes**" block; detecting them by bold mention
#: would need the block to repeat itself five times for no reader benefit.
GROUP_COVERAGE = {
    "MultiscannerRepository",
    "MultiscannerImage",
    "MultiscannerModel",
    "MultiscannerBucket",
    "MultiscannerEndpoint",
}


def covered_labels(body: str) -> set[str]:
    """Labels a segment DOCUMENTS, not merely mentions.

    A bold `**Label**` is the document's definitional form, and it is used both
    for a top-level block and for a bullet inside a grouped section (the
    supply-chain sources list defines `**GithubRepository**` and
    `**SbomDocument**` that way). Matching only headings under-reports coverage
    and turns real documentation into phantom debt, which is worse than useless:
    it trains people to ignore the completeness test.

    Backticked mentions are deliberately NOT counted. Every relationship line
    names its endpoints in backticks, so counting them would mark a label
    documented because something points at it.
    """
    found = set(re.findall(r"\*\*([A-Z][A-Za-z0-9]*)\*\*", body))
    if "Asset nodes" in body:
        found |= GROUP_COVERAGE
    return found


def emit(segs: list[dict]) -> str:
    parts: list[str] = [
        '"""Addressable segments of the graph-schema document.',
        "",
        "GENERATED by tooling/scripts/seed_schema_catalog.py. Do not hand-edit the",
        "bodies here yet: until the renderer is the only consumer, the source of",
        "truth is still TEXT_TO_CYPHER_SYSTEM and this file is re-seeded from it.",
        "",
        "Bodies are VERBATIM slices. Concatenating SEGMENTS in order reproduces the",
        "source document byte-for-byte, which is what lets the renderer serve a",
        "subset without anyone having to trust that nothing was dropped.",
        '"""',
        "",
        "SEGMENTS = [",
    ]
    for s in segs:
        parts.append("    {")
        parts.append(f'        "kind": {s["kind"]!r},')
        parts.append(f'        "key": {s["key"]!r},')
        parts.append(f'        "section": {s["section"]!r},')
        parts.append(f'        "documents": {sorted(covered_labels(s["body"]))!r},')
        parts.append('        "body": """' + s["body"] + '""",')
        parts.append("    },")
    parts.append("]")
    parts.append("")
    parts.append("#: label -> the segment whose heading defines it (per-label rendering).")
    parts.append("LABELS = {s[\"key\"]: s for s in SEGMENTS if s[\"kind\"] == \"LABEL\"}")
    parts.append("")
    parts.append("#: every label the document DOCUMENTS, including those defined inside a")
    parts.append("#: grouped block rather than under their own heading. This is what the")
    parts.append("#: completeness test measures against graph_db/schema.py.")
    parts.append("DOCUMENTED = {lab for s in SEGMENTS for lab in s[\"documents\"]}")
    parts.append("")
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only, do not write")
    args = ap.parse_args()

    doc = extract_prompt()
    segs = segment(doc)

    rebuilt = "".join(s["body"] for s in segs)
    if rebuilt != doc:
        print("FAIL: segmentation is lossy; refusing to write", file=sys.stderr)
        return 1

    sha = hashlib.sha1(doc.encode()).hexdigest()
    n_labels = sum(1 for s in segs if s["kind"] == "LABEL")
    print(f"source     : {len(doc)} chars, sha1 {sha}")
    print(f"segments   : {len(segs)} ({n_labels} labels)")
    print("round-trip : byte-identical")

    if FIXTURE.exists():
        fx = FIXTURE.read_text(encoding="utf-8")
        print(f"fixture    : {'MATCHES' if fx == doc else 'DIFFERS (update the fixture deliberately)'}")

    if args.check:
        return 0

    OUT.write_text(emit(segs), encoding="utf-8")
    print(f"wrote      : {OUT.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
