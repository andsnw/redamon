"""What a recon scan's node-filter sweep did, against an independent oracle.

    snapshot OUT.json                  every finding of the project, with its mute state
    check BEFORE AFTER CONFIG [--full] what the sweep should have done vs what it did
    coverage SNAPSHOT                  which filter fields real findings actually carry

Take BEFORE right before starting the scan (after any operator action) and AFTER
once it has finished. CONFIG is the project's node-filter row plus the run's
start time, as the README exports it:
    {"mode", "applyToScans", "rules": {"kinds": ...}, "exemptions": [[label, key]],
     "run_started": ISO-8601}

The oracle does not import graph_db.node_filters. Each rule is graded by a
predicate written here from the catalog's field definitions, keyed by the rule's
NAME, so an engine bug cannot grade itself. A rule whose name has no predicate
here is an error, not a pass.

Run inside the recon image, which has the neo4j driver:
    NEO4J_URI NEO4J_USER NEO4J_PASSWORD LAB_UID LAB_PID
"""
import json
import os
import re
import sys
from datetime import datetime, timezone

RULE_PREFIX = "rule:"

# The recon pipeline's own finding sources: the scan sweep's scope
# (recon/helpers/finding_sources.py). A kind none of whose sources is here is
# never swept by a scan.
RECON_SOURCES = {
    "nuclei", "security_check", "js_recon", "jsluice", "takeover_scan",
    "cache_poisoning", "graphql_scan", "graphql_cop", "ai_surface_recon",
    "vhost_sni_enum", "origin_discovery", "nmap_nse", "resource_enum",
    "http_probe", "vuln_scan", "wcvs",
}
PASSIVE = {"shodan_api", "internetdb", "shodan_host_lookup", "shodan", "netlas", "criminalip"}

# kind -> (graph label, selector, sources), from catalog.yaml.
KINDS = {
    "vuln.nuclei": ("Vulnerability", lambda n: n.get("source") == "nuclei", {"nuclei"}),
    "vuln.security_check": ("Vulnerability", lambda n: n.get("source") == "security_check" and n.get("type") != "waf_bypass", {"security_check"}),
    "vuln.waf_bypass": ("Vulnerability", lambda n: n.get("type") == "waf_bypass" and n.get("source") in ("security_check", "origin_discovery"), {"security_check", "origin_discovery"}),
    "vuln.nmap_nse": ("Vulnerability", lambda n: n.get("source") == "nmap_nse", {"nmap_nse"}),
    "vuln.takeover": ("Vulnerability", lambda n: n.get("source") == "takeover_scan", {"takeover_scan"}),
    "vuln.vhost_sni": ("Vulnerability", lambda n: n.get("source") == "vhost_sni_enum", {"vhost_sni_enum"}),
    "vuln.cache_poisoning": ("Vulnerability", lambda n: n.get("source") == "cache_poisoning", {"cache_poisoning"}),
    "vuln.graphql": ("Vulnerability", lambda n: n.get("source") in ("graphql_scan", "graphql_cop"), {"graphql_scan", "graphql_cop"}),
    "vuln.ai_surface": ("Vulnerability", lambda n: n.get("source") == "ai_surface_recon", {"ai_surface_recon"}),
    "vuln.passive_cve": ("Vulnerability", lambda n: n.get("source") in PASSIVE, PASSIVE),
    "vuln.osv": ("Vulnerability", lambda n: n.get("source") == "osv", {"osv"}),
    "js.finding": ("JsReconFinding", lambda n: n.get("finding_type") != "js_file", {"js_recon"}),
    "secret": ("Secret", lambda n: True, {"js_recon", "jsluice"}),
    "malpackage": ("MalPackageFinding", lambda n: True, set()),
}

# --- field semantics, from the catalog spec -----------------------------------
SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE = {"low": 0, "medium": 1, "high": 2}
CVE_RX = re.compile(r"CVE-(\d{4})-(\d{4,})", re.I)


def text(n, k):
    v = n.get(k)
    return None if v is None or (isinstance(v, str) and not v.strip()) else str(v).strip().lower()


def severity(n):
    return text(n, "severity")


def cves(n):
    found = set()
    for k in ("cves", "cve_ids", "aliases"):
        items = n.get(k)
        for item in [items] if isinstance(items, str) else (items or []):
            found |= {f"CVE-{y}-{d}" for y, d in CVE_RX.findall(str(item))}
    for extra in (n.get("cve_id"), n.get("id")):
        if extra and re.fullmatch(r"CVE-\d{4}-\d{4,}", str(extra), re.I):
            found.add(str(extra).upper())
    return found


def cve_year(n):
    years = [int(CVE_RX.match(c).group(1)) for c in cves(n)]
    return max(years) if years else None


def number(n, k):
    v = n.get(k)
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# Rule NAME -> (kind, predicate). In allowlist mode the predicate is what the
# rule KEEPS. Named so the UI shows what each one tests.
ORACLE = {
    "NF1 nuclei info": ("vuln.nuclei", lambda n: severity(n) == "info"),
    "NF2 nuclei low without CVE": ("vuln.nuclei", lambda n: not cves(n) and severity(n) == "low"),
    "NF3 nuclei ghost template": ("vuln.nuclei", lambda n: text(n, "template_id") == "nf-lab-no-such-template"),
    "NF4 nuclei high (disabled)": ("vuln.nuclei", lambda n: severity(n) in ("high", "critical")),
    "NF5 headers on port 80": ("vuln.security_check", lambda n: text(n, "type") in ("missing_referrer_policy", "missing_permissions_policy") and number(n, "port") == 80),
    "NF6 TLS self-signed": ("vuln.security_check", lambda n: text(n, "type") == "tls_self_signed"),
    "NF7 vhost info and low": ("vuln.vhost_sni", lambda n: severity(n) in ("info", "low")),
    "NF8 JS low confidence": ("js.finding", lambda n: text(n, "confidence") == "low"),
    "NF9 jsluice secrets": ("secret", lambda n: text(n, "source") == "jsluice"),
    "NF10 AI info (kind off)": ("vuln.ai_surface", lambda n: severity(n) == "info"),
    "NF11 nuclei CVE before 2022": ("vuln.nuclei", lambda n: cve_year(n) is not None and cve_year(n) < 2022),
    "KEEP nuclei high and critical": ("vuln.nuclei", lambda n: severity(n) in ("high", "critical")),
    "KEEP security checks high": ("vuln.security_check", lambda n: severity(n) in ("high", "critical")),
    "KEEP JS high confidence": ("js.finding", lambda n: text(n, "confidence") == "high"),
    "NF12 OSV all": ("vuln.osv", lambda n: text(n, "advisory_id") is not None),
    "NF13 malicious packages all": ("malpackage", lambda n: text(n, "advisory_id") is not None),
}


# --- the graph -----------------------------------------------------------------
SNAPSHOT_QUERY = """
MATCH (n) WHERE n.user_id = $uid AND n.project_id = $pid
  AND (n:Vulnerability OR n:JsReconFinding OR n:Secret OR n:MalPackageFinding)
RETURN labels(n) AS labels, properties(n) AS props, n:Muted AS muted,
       coalesce(n.muted_by, '') AS muted_by,
       coalesce(n.triage_source, '') = 'human' AS g_human,
       (coalesce(n.triage_status, '') = 'confirmed' OR n.triage_proof IS NOT NULL) AS g_confirmed,
       EXISTS { MATCH (:ChainFinding)-[:CONFIRMS]->(n) } AS g_chain
"""


def _plain(v):
    if hasattr(v, "iso_format"):
        return v.iso_format()
    if isinstance(v, (list, tuple)):
        return [_plain(x) for x in v]
    return v


def kind_of(label, props):
    for kind, (klabel, select, _sources) in KINDS.items():
        if klabel == label and select(props):
            return kind
    return None


def snapshot(out_path):
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(os.environ["NEO4J_URI"],
                                  auth=(os.environ.get("NEO4J_USER", "neo4j"), os.environ["NEO4J_PASSWORD"]))
    nodes = {}
    with driver.session() as s:
        for r in s.run(SNAPSHOT_QUERY, uid=os.environ["LAB_UID"], pid=os.environ["LAB_PID"]):
            label = next(x for x in ("Vulnerability", "JsReconFinding", "Secret", "MalPackageFinding") if x in r["labels"])
            props = {k: _plain(v) for k, v in r["props"].items()}
            key = props.get("finding_id") if label == "MalPackageFinding" else props.get("id")
            nodes[f"{label}|{key}"] = {
                "label": label, "key": key, "kind": kind_of(label, props), "props": props,
                "muted": r["muted"], "muted_by": r["muted_by"],
                "guarded": [g for g in ("g_human", "g_confirmed", "g_chain") if r[g]],
            }
    driver.close()
    json.dump({"taken_at": datetime.now(timezone.utc).isoformat(), "nodes": nodes}, open(out_path, "w"), indent=1)
    print(f"{len(nodes)} findings -> {out_path}")


# --- the oracle ------------------------------------------------------------------
def when(v):
    if not v:
        return None
    v = re.sub(r"(\.\d{6})\d+", r"\1", str(v)).replace("Z", "+00:00")
    v = re.sub(r"\[.*\]$", "", v)
    d = datetime.fromisoformat(v)
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def active_rules(config, kind):
    """The rules that decide a kind, in order; empty when the kind filters nothing."""
    entry = (config["rules"].get("kinds") or {}).get(kind) or {}
    if not entry.get("enabled"):
        return []
    rules = [r for r in entry.get("rules") or [] if r.get("enabled", True)]
    for r in rules:
        if r.get("name") not in ORACLE:
            raise SystemExit(f"no oracle predicate for rule {r.get('name')!r} in {kind}")
        if ORACLE[r["name"]][0] != kind:
            raise SystemExit(f"rule {r['name']!r} sits in {kind}, its predicate is for {ORACLE[r['name']][0]}")
    return rules


def expected_state(node, before, config, started, exempt):
    """(muted, muted_by) the sweep must leave, and why."""
    kind, props = node["kind"], node["props"]
    prior = before.get(f"{node['label']}|{node['key']}")
    person_muted = prior is not None and prior["muted"] and not prior["muted_by"].startswith(RULE_PREFIX)
    if person_muted:
        return True, prior["muted_by"], "person mute"
    in_scope = (
        config.get("applyToScans") and kind is not None
        and KINDS[kind][2] & RECON_SOURCES and props.get("source") in RECON_SOURCES
        and when(props.get("updated_at")) is not None and when(props["updated_at"]) >= started
    )
    if not in_scope:
        if prior is None:
            return False, "", "new, out of the sweep's scope"
        return prior["muted"], prior["muted_by"], "out of the sweep's scope: unchanged"
    rules = active_rules(config, kind)
    if not rules:
        return False, "", "kind filters nothing"
    matched = [r for r in rules if ORACLE[r["name"]][1](props)]
    filtered = bool(matched) if config["mode"] == "denylist" else not matched
    if not filtered:
        return False, "", "no rule filters it"
    if node["guarded"]:
        return False, "", f"guarded ({', '.join(node['guarded'])})"
    if (node["label"], str(node["key"])) in exempt:
        return False, "", "exempt"
    rule_id = matched[0]["id"] if config["mode"] == "denylist" else "allowlist"
    return True, f"{RULE_PREFIX}{kind}/{rule_id}", f"filtered by {matched[0]['name'] if matched else 'allowlist'}"


def check(before_path, after_path, config_path, full_run):
    before = json.load(open(before_path))["nodes"]
    after = json.load(open(after_path))["nodes"]
    config = json.load(open(config_path))
    started = when(config["run_started"])
    exempt = {(label, str(key)) for label, key in config.get("exemptions") or []}
    failures, per_kind, per_rule = [], {}, {}

    for node in after.values():
        want_muted, want_by, why = expected_state(node, before, config, started, exempt)
        row = per_kind.setdefault(node["kind"] or "(no kind)", {"findings": 0, "rule_muted": 0, "expected": 0, "wrong": 0})
        row["findings"] += 1
        row["expected"] += bool(want_muted and want_by.startswith(RULE_PREFIX))
        row["rule_muted"] += bool(node["muted"] and node["muted_by"].startswith(RULE_PREFIX))
        if node["muted"] and node["muted_by"].startswith(RULE_PREFIX):
            per_rule[node["muted_by"]] = per_rule.get(node["muted_by"], 0) + 1
        if (node["muted"], node["muted_by"] if node["muted"] else "") != (want_muted, want_by if want_muted else ""):
            row["wrong"] += 1
            failures.append(f"{node['kind']} {node['key']} ({node['props'].get('name') or node['props'].get('title')}): "
                            f"expected {'muted by ' + want_by if want_muted else 'not muted'} [{why}], "
                            f"got {'muted by ' + node['muted_by'] if node['muted'] else 'not muted'}")

    for ref, prior in before.items():
        if ref in after:
            continue
        if not full_run:
            failures.append(f"{prior['kind']} {prior['key']} disappeared, and a partial run prunes nothing")
        elif prior["guarded"] and "g_human" in prior["guarded"]:
            failures.append(f"{prior['kind']} {prior['key']} had a human verdict and was deleted")
        elif prior["muted"] and not prior["muted_by"].startswith(RULE_PREFIX):
            failures.append(f"{prior['kind']} {prior['key']} was muted by a person and was deleted")

    stale = [n for n in after.values()
             if full_run and n["props"].get("source") in RECON_SOURCES
             and (when(n["props"].get("updated_at")) or started) < started and not n["props"].get("stale_since")]

    print(f"{'kind':22} {'findings':>8} {'expected':>9} {'rule-muted':>11} {'wrong':>6}")
    for kind, row in sorted(per_kind.items()):
        print(f"{kind:22} {row['findings']:>8} {row['expected']:>9} {row['rule_muted']:>11} {row['wrong']:>6}")
    print("rule mutes by rule:", json.dumps(per_rule, indent=1, sort_keys=True))
    gone = [r for r in before if r not in after]
    print(f"disappeared since BEFORE: {len(gone)}")
    if stale:
        print(f"WARN {len(stale)} recon findings neither refreshed nor stamped stale by this full run:")
        for n in stale[:20]:
            print(f"  {n['kind']} {n['key']} updated_at={n['props'].get('updated_at')}")
    if failures:
        print(f"FAIL {len(failures)}:")
        for f in failures:
            print("  " + f)
        return 1
    print("PASS")
    return 0


# --- what real findings carry -----------------------------------------------------
def coverage(snapshot_path, catalog_path):
    nodes = json.load(open(snapshot_path))["nodes"].values()
    catalog = json.load(open(catalog_path))["kinds"]
    derived = {"severity": severity, "cve_ids": lambda n: cves(n) or None, "has_cve": lambda n: True,
               "cve_year": cve_year, "cvss": lambda n: number(n, "cvss_score") if number(n, "cvss_score") is not None else number(n, "cvss"),
               "name": lambda n: text(n, "name") or text(n, "title")}
    for kind, spec in catalog.items():
        members = [n["props"] for n in nodes if n["kind"] == kind]
        if not members:
            continue
        print(f"{kind} ({len(members)} findings)")
        for field, fdef in spec["fields"].items():
            if fdef.get("prop"):
                have = sum(1 for p in members if p.get(fdef["prop"]) not in (None, "", []))
            elif fdef.get("normalizer") in derived or field in derived:
                fn = derived.get(fdef.get("normalizer")) or derived[field]
                have = sum(1 for p in members if fn(p) not in (None, "", set()))
            else:
                have = "?"
            print(f"  {field:26} {have}/{len(members)}")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "snapshot":
        snapshot(sys.argv[2])
    elif cmd == "check":
        sys.exit(check(sys.argv[2], sys.argv[3], sys.argv[4], "--full" in sys.argv))
    elif cmd == "coverage":
        coverage(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "graph_db/node_filters/catalog.json")
    else:
        print(__doc__)
        sys.exit(2)
