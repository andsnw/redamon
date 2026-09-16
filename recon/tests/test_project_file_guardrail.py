"""
T22: path-valued settings cannot point a scan tool at an arbitrary file.

Several columns hold a filesystem path a scan container opens, and nothing on
the recon side validated them: no realpath, no commonpath, no basename check
anywhere in the consumers. The MCP deny list WAS the control, and this replaces
it so the column can be opened.

Why it is worse than an ordinary file read: ffuf sends each wordlist LINE as a
URL path and records which ones responded, so a wordlist pointed at a file
inside the scan container gets its contents reflected into the graph and the
scan output. That is exfiltration, not just disclosure.

Two validators, because two shapes of value exist and the dangerous input is
different for each:

  project_file       an absolute path. Must resolve inside an allowed root.
  project_file_name  a BASENAME the scan joins onto a mounted directory
                     (`-t /custom-templates/<x>`). Must carry no separator.

This side is authoritative. The MCP write path rejects the same values outright,
but a row can also be written through the webapp, a project import or a version
restore, so the check that matters is the one at settings load.

Run: python -m pytest recon/tests/test_project_file_guardrail.py -v
"""
from __future__ import annotations

import pytest

from recon import settings_registry as reg
from recon.project_settings import (
    DEFAULT_SETTINGS,
    _inside_allowed_root,
    _is_safe_basename,
    sanitize_project_file_settings,
)

PATH_KEYS = reg.project_file_runtime_keys()
NAME_KEYS = reg.project_file_name_runtime_keys()


def test_the_registry_knows_about_the_path_columns():
    """If this list is empty the rest of the file passes while checking nothing."""
    assert PATH_KEYS, "no project_file fields in the registry"
    assert NAME_KEYS, "no project_file_name fields in the registry"
    assert "FFUF_WORDLIST" in PATH_KEYS
    assert "NUCLEI_SELECTED_CUSTOM_TEMPLATES" in NAME_KEYS


# --- the root check ---------------------------------------------------------------

@pytest.mark.parametrize("path", [
    "/etc/shadow",
    "/etc/passwd",
    "/proc/self/environ",
    "/app/recon/output/results.json",
    "/root/.ssh/id_rsa",
    "/app/recon/project_settings.py",
    "../../etc/passwd",
    "relative/path.txt",
    "/usr/share/seclists/../../../etc/shadow",
])
def test_a_path_outside_the_allowed_roots_is_rejected(path):
    assert _inside_allowed_root(path) is False


@pytest.mark.parametrize("path", [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/app/recon/wordlists/vhost-common.txt",
    "/app/recon/wordlists/proj123/custom.txt",
    "/usr/share/wordlists/rockyou.txt",
])
def test_a_path_inside_an_allowed_root_is_accepted(path):
    assert _inside_allowed_root(path) is True


@pytest.mark.parametrize("value", [None, "", "   ", 42, [], {}, True])
def test_a_non_path_fails_closed(value):
    """A value that cannot be resolved counts as escaping, never as allowed."""
    assert _inside_allowed_root(value) is False


def test_a_traversal_that_lands_back_inside_is_accepted():
    """
    The check is on the RESOLVED path, not the written one.

    Refusing a legitimate value because it contains '..' would be a bound that
    is wrong in the other direction, and the caller would have no way to express
    a path the tool would happily open.
    """
    assert _inside_allowed_root("/usr/share/seclists/../seclists/common.txt") is True


# --- the settings pass -------------------------------------------------------------

def test_an_escaping_scalar_is_pinned_to_the_shipped_default(capsys):
    settings = dict(DEFAULT_SETTINGS)
    settings["FFUF_WORDLIST"] = "/etc/shadow"
    out = sanitize_project_file_settings(settings)
    assert out["FFUF_WORDLIST"] == DEFAULT_SETTINGS["FFUF_WORDLIST"]
    assert "[guardrail]" in capsys.readouterr().out


def test_an_allowed_scalar_is_left_alone():
    settings = dict(DEFAULT_SETTINGS)
    settings["FFUF_WORDLIST"] = "/app/recon/wordlists/proj1/mine.txt"
    assert sanitize_project_file_settings(settings)["FFUF_WORDLIST"] == \
        "/app/recon/wordlists/proj1/mine.txt"


def test_an_empty_scalar_is_not_treated_as_an_escape():
    """
    "" is "not set", which every consumer already handles. Rewriting it to a
    default would silently turn a deliberate opt-out into an opt-in.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings["VHOST_SNI_CUSTOM_WORDLIST"] = ""
    assert sanitize_project_file_settings(settings)["VHOST_SNI_CUSTOM_WORDLIST"] == ""


def test_a_list_drops_only_the_escaping_entries(capsys):
    settings = dict(DEFAULT_SETTINGS)
    settings["NUCLEI_CUSTOM_TEMPLATES"] = [
        "/app/custom_templates/mine.yaml",
        "/etc/shadow",
        "/usr/share/seclists/ok.txt",
    ]
    out = sanitize_project_file_settings(settings)
    assert out["NUCLEI_CUSTOM_TEMPLATES"] == [
        "/app/custom_templates/mine.yaml",
        "/usr/share/seclists/ok.txt",
    ]
    assert "[guardrail]" in capsys.readouterr().out


@pytest.mark.parametrize("key", PATH_KEYS)
def test_every_registered_path_key_is_guarded(key):
    """
    Iterating the registry, so a path column added tomorrow is covered the day
    it declares its validator rather than the day someone remembers.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings[key] = ["/etc/shadow"] if isinstance(DEFAULT_SETTINGS.get(key), list) else "/etc/shadow"
    resolved = sanitize_project_file_settings(settings)[key]
    assert "/etc/shadow" not in (resolved if isinstance(resolved, list) else [resolved])


# --- the basename check -------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "../../etc/passwd",
    "/etc/passwd",
    "sub/dir.yaml",
    "..",
    ".",
    ".hidden.yaml",
    "",
    "a\\b.yaml",
])
def test_a_non_filename_is_rejected(name):
    assert _is_safe_basename(name) is False


@pytest.mark.parametrize("name", ["mine.yaml", "cve-2024-1234.yaml", "a_b-c.yml"])
def test_a_plain_filename_is_accepted(name):
    assert _is_safe_basename(name) is True


def test_a_traversing_template_name_is_dropped(capsys):
    """
    `-t /custom-templates/<value>` is a join, so a value carrying separators
    escapes the mounted directory entirely.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings["NUCLEI_SELECTED_CUSTOM_TEMPLATES"] = ["ok.yaml", "../../../etc/passwd"]
    out = sanitize_project_file_settings(settings)
    assert out["NUCLEI_SELECTED_CUSTOM_TEMPLATES"] == ["ok.yaml"]
    assert "[guardrail]" in capsys.readouterr().out


def test_nothing_else_in_the_settings_dict_is_touched():
    before = dict(DEFAULT_SETTINGS)
    before["FFUF_WORDLIST"] = "/etc/shadow"
    after = sanitize_project_file_settings(dict(before))
    moved = {k for k in before if before[k] != after[k]}
    assert moved == {"FFUF_WORDLIST"}
