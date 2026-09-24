"""The full pipeline hands the whole batch's roots to the graph writers.

run_domain_group scans one group at a time, so recon_data["domain"] is the group
root. _stamp_project_roots adds recon_data["all_project_roots"] (every batch
root) so the writers attach a cross-root host to the right root. It is NOT
"domains", which would widen the per-group scan scope. A single-domain project
gets no such key.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import recon.main as main  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]
BATCH = {
    "DOMAIN_BATCH_MODE": True,
    "DOMAIN_BATCH_GROUPS": [{"rootDomain": r, "prefixes": ["*"]} for r in ROOTS],
}


@pytest.fixture
def batch_settings(monkeypatch):
    monkeypatch.setattr(main, "_settings", dict(BATCH))


@pytest.fixture
def single_settings(monkeypatch):
    monkeypatch.setattr(main, "_settings", {"DOMAIN_BATCH_MODE": False})


def test_batch_root_names(batch_settings):
    assert main._batch_root_names() == ROOTS


def test_stamp_adds_all_project_roots_in_batch_mode(batch_settings):
    recon_data = {"domain": "alpha.test"}
    main._stamp_project_roots(recon_data)
    assert recon_data["all_project_roots"] == ROOTS
    # The scan scope stays the group root: "domains" is never set here.
    assert "domains" not in recon_data


def test_stamp_is_a_noop_for_a_single_domain_project(single_settings):
    recon_data = {"domain": "alpha.test"}
    main._stamp_project_roots(recon_data)
    assert "all_project_roots" not in recon_data


def test_stamp_returns_the_same_dict(batch_settings):
    recon_data = {"domain": "alpha.test"}
    assert main._stamp_project_roots(recon_data) is recon_data
