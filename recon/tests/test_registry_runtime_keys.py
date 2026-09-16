"""
T36: the registry against the runtime keys the pipeline actually reads.

T1 asserts that every Prisma column has a registry entry. This is the reverse
direction, and it is the one that would have caught `masscanEnabled` as a
QUESTION rather than an accident: a runtime key the pipeline reads but the
registry has never heard of is either a missing entry or a CLI-only key nobody
wrote down, and the two need different answers.

Also covers the loader's fail-closed rule. A scan container that cannot read the
registry must refuse to start rather than fall back to shipped defaults, because
a scan running on fallback defaults is a scan running without the engagement
ceiling.

Run: python -m pytest recon/tests/test_registry_runtime_keys.py -v
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from recon import settings_registry as reg
from recon.project_settings import DEFAULT_SETTINGS


@pytest.fixture(autouse=True)
def _fresh_registry():
    reg.load_registry.cache_clear()
    yield
    reg.load_registry.cache_clear()


# --- T36: both directions between DEFAULT_SETTINGS and the registry -----------------

def test_every_default_settings_key_is_in_the_registry():
    """
    Every runtime key is either mapped from a column or declared runtime-only.

    A key in neither is invisible: no bound, no meaning, no cap, and nothing
    tells anyone it exists.
    """
    mapped = set(reg.by_runtime_key())
    runtime_only = set(reg.runtime_only())
    unknown = sorted(set(DEFAULT_SETTINGS) - mapped - runtime_only)
    assert unknown == [], (
        f"{len(unknown)} runtime key(s) the pipeline reads have no registry entry: {unknown}. "
        "Add a Prisma column plus a fields: entry, or declare it under runtime_only: "
        "in recon_settings/registry.yaml."
    )


def test_no_registry_runtime_key_is_unknown_to_the_pipeline():
    """A runtime key the registry describes but nothing reads is documentation for nothing."""
    known = set(DEFAULT_SETTINGS)
    ghosts = sorted(k for k in reg.runtime_only() if k not in known)
    assert ghosts == [], f"runtime_only keys that DEFAULT_SETTINGS does not have: {ghosts}"


def test_every_mapped_runtime_key_has_a_default():
    """A mapping whose runtime key has no default would KeyError at settings load."""
    missing = sorted(k for k in reg.by_runtime_key() if k not in DEFAULT_SETTINGS)
    assert missing == [], f"mapped runtime keys with no DEFAULT_SETTINGS entry: {missing}"


# --- the derived lists match what the pipeline hardcodes today ------------------------

SHIPPED_RATE_LIMIT_KEYS = [
    "NAABU_RATE_LIMIT", "MASSCAN_RATE", "HTTPX_RATE_LIMIT", "NUCLEI_RATE_LIMIT",
    "KATANA_RATE_LIMIT", "GAU_VERIFY_RATE_LIMIT", "GAU_METHOD_DETECT_RATE_LIMIT",
    "KITERUNNER_RATE_LIMIT", "KITERUNNER_METHOD_DETECT_RATE_LIMIT",
    "FFUF_RATE", "ARJUN_RATE_LIMIT", "PUREDNS_RATE_LIMIT", "HAKRAWLER_THREADS",
    "GRAPHQL_RATE_LIMIT", "ORIGIN_DISCOVERY_RATE",
]


def test_the_derived_cap_list_covers_every_hardcoded_one():
    derived = set(reg.roe_capped_runtime_keys())
    missing = sorted(k for k in SHIPPED_RATE_LIMIT_KEYS if k not in derived)
    assert missing == [], f"the derived cap list LOST a key the hardcoded one had: {missing}"


def test_the_derived_cap_list_closes_the_known_bypasses():
    """
    Three rate fields were reachable and uncapped, and one runtime-only rate was
    never in the list at all. Deriving the list from `roe_capped` is what closes
    them; this names them so a future edit cannot quietly drop one again.
    """
    derived = set(reg.roe_capped_runtime_keys())
    for key in (
        "TAKEOVER_RATE_LIMIT",
        "JSLUICE_VERIFY_RATE_LIMIT",
        "WEB_CACHE_POISON_MAX_RPS_PER_HOST",
        "VIRUSTOTAL_RATE_LIMIT",
    ):
        assert key in derived, f"{key} is still not capped"


def test_every_zero_unlimited_rate_is_also_capped():
    """
    Being in the cap list is not the same as being capped: a 0 sails past a
    `value > ceiling` test, which is exactly how puredns ran unlimited on a
    3 rps project while looking covered.
    """
    capped = set(reg.roe_capped_runtime_keys())
    uncapped = sorted(k for k in reg.unlimited_zero_runtime_keys() if k not in capped)
    assert uncapped == [], f"these rates mean unlimited at 0 and nothing caps them: {uncapped}"


def test_the_capped_keys_are_all_real_settings():
    unknown = sorted(k for k in reg.roe_capped_runtime_keys() if k not in DEFAULT_SETTINGS)
    assert unknown == [], f"capped keys that no scan ever reads: {unknown}"


# --- fail closed ----------------------------------------------------------------------

def test_a_missing_registry_raises_rather_than_falling_back(tmp_path):
    """
    The single most important property of this loader.

    A scan that silently ran on fallback defaults would be a scan running with
    no engagement ceiling, which is the one failure the whole layer exists to
    prevent.
    """
    reg.load_registry.cache_clear()
    with patch.dict(os.environ, {"RECON_SETTINGS_REGISTRY": str(tmp_path / "nope.json")}):
        with pytest.raises(reg.RegistryUnavailable) as exc:
            reg.registry_path()
    assert "not a readable file" in str(exc.value)


def test_an_unparseable_registry_raises(tmp_path):
    bad = tmp_path / "registry.json"
    bad.write_text("{ this is not json", encoding="utf-8")
    reg.load_registry.cache_clear()
    with patch.dict(os.environ, {"RECON_SETTINGS_REGISTRY": str(bad)}):
        with pytest.raises(reg.RegistryUnavailable) as exc:
            reg.load_registry()
    assert "unreadable" in str(exc.value)


def test_a_registry_missing_a_section_raises(tmp_path):
    bad = tmp_path / "registry.json"
    bad.write_text(json.dumps({"version": 1, "fields": {}}), encoding="utf-8")
    reg.load_registry.cache_clear()
    with patch.dict(os.environ, {"RECON_SETTINGS_REGISTRY": str(bad)}):
        with pytest.raises(reg.RegistryUnavailable):
            reg.load_registry()


def test_the_shipped_registry_loads_where_a_scan_would_find_it():
    """Not a mock: the real artifact, found by the real search order."""
    path = reg.registry_path()
    assert Path(path).is_file()
    data = reg.load_registry()
    assert len(data["fields"]) > 600
    assert len(data["tools"]) > 20


# --- the two loaders agree -------------------------------------------------------------

def test_python_and_typescript_read_the_same_bytes():
    """
    Two copies of the artifact exist because a scan container mounts recon/ and
    never webapp/. One build writes both; this is what stops them diverging.
    """
    repo = Path(__file__).resolve().parents[2]
    a = repo / "recon_settings" / "registry.json"
    b = repo / "webapp" / "src" / "lib" / "reconSettings" / "registry.json"
    assert a.read_text(encoding="utf-8") == b.read_text(encoding="utf-8"), (
        "the two registry artifacts differ; run python3 recon_settings/build.py"
    )
