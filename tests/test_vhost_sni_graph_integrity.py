from pathlib import Path


SOURCE = (
    Path(__file__).resolve().parents[1]
    / "graph_db"
    / "mixins"
    / "recon"
    / "vhost_sni_mixin.py"
)


def test_vhost_sni_does_not_create_subdomains_or_dns_resolution_edges():
    text = SOURCE.read_text(encoding="utf-8")

    # VHost/SNI probing proves routing behaviour, not public DNS existence.
    assert "MERGE (s:Subdomain {name: $hostname" not in text
    assert "MERGE (s)-[:RESOLVES_TO {discovered_via: 'vhost_sni_enum'}]->(i)" not in text

    # Findings may still enrich/link an independently discovered Subdomain.
    assert "OPTIONAL MATCH (s:Subdomain" in text
    assert "MERGE (s)-[:HAS_VULNERABILITY]->(v)" in text


def test_discovered_vhost_baseurls_only_link_existing_subdomains():
    text = SOURCE.read_text(encoding="utf-8")

    assert "MERGE (b:BaseURL" in text
    assert "b.discovery_source = 'vhost_sni_enum'" in text
    assert "OPTIONAL MATCH (s:Subdomain" in text
    assert "MERGE (s)-[:HAS_BASE_URL]->(b)" in text
    assert "ON CREATE SET s.source = 'vhost_sni_enum'" not in text
