"""
T6, T39, T40, T41: what the registry actually does at settings load.

The registry's own tests prove its structure. These prove its EFFECT, which is
the only thing a scope violation cares about. The distinction is not academic:
`PUREDNS_RATE_LIMIT` was in the shipped cap list and ran unlimited anyway,
because being in a list is not the same as being capped.

So every assertion here reads a RESOLVED value, and the exhaustive cases iterate
the registry rather than naming fields, because the registry is the list of
things that could regress.

Run: python -m pytest recon/tests/test_registry_runtime.py -v
"""
from __future__ import annotations

import pytest

from recon import settings_registry as reg
from recon.project_settings import (
    ALLOWED_TOOL_IMAGES,
    DEFAULT_SETTINGS,
    apply_memory_governor,
    apply_roe_rate_cap,
    apply_stealth_overrides,
    sanitize_image_settings,
)

CEILING = 3


def _with_roe(**over) -> dict:
    settings = dict(DEFAULT_SETTINGS)
    settings["ROE_ENABLED"] = True
    settings["ROE_GLOBAL_MAX_RPS"] = CEILING
    settings.update(over)
    return settings


CAPPED_KEYS = reg.roe_capped_runtime_keys()
NUMERIC_CAPPED = [k for k in CAPPED_KEYS if isinstance(DEFAULT_SETTINGS.get(k), (int, float))]


# --- T39: the exhaustive cap test ----------------------------------------------------

@pytest.mark.parametrize("key", NUMERIC_CAPPED)
@pytest.mark.parametrize("written", ["max", "min", "zero", "far_above"])
def test_every_capped_rate_resolves_at_or_below_the_ceiling(key, written):
    """
    For EVERY capped key, at its bound extremes and at zero.

    Iterating the registry beats example-based cases: a rate field added
    tomorrow is covered the day it is added, which is the property that would
    have stopped takeoverRateLimit shipping uncapped.
    """
    bounds = reg.bounds_for(key)
    if written == "max":
        value = int(bounds[1]) if bounds else 100000
    elif written == "min":
        value = int(bounds[0]) if bounds else 0
    elif written == "zero":
        value = 0
    else:
        value = 1_000_000

    resolved = apply_roe_rate_cap(_with_roe(**{key: value}))[key]
    assert resolved <= CEILING, (
        f"{key} written as {value} resolved to {resolved}, above the {CEILING} rps ceiling"
    )


@pytest.mark.parametrize("key", sorted(reg.unlimited_zero_runtime_keys()))
def test_a_zero_that_means_unlimited_becomes_the_ceiling(key):
    """
    The failure that is invisible to a `value > ceiling` test.

    0 is the FASTEST value these fields accept. Left alone under a 3 rps
    engagement they run without any limit at all, and nothing logs it.
    """
    if key not in DEFAULT_SETTINGS:
        pytest.skip(f"{key} is not a runtime setting in this build")
    assert apply_roe_rate_cap(_with_roe(**{key: 0}))[key] == CEILING


def test_the_three_shipped_bypasses_are_closed():
    """Named, so a future edit that drops one from the derived list fails here."""
    settings = apply_roe_rate_cap(_with_roe(
        TAKEOVER_RATE_LIMIT=500,
        JSLUICE_VERIFY_RATE_LIMIT=1000,
        WEB_CACHE_POISON_MAX_RPS_PER_HOST=0,
        PUREDNS_RATE_LIMIT=0,
    ))
    assert settings["TAKEOVER_RATE_LIMIT"] == CEILING
    assert settings["JSLUICE_VERIFY_RATE_LIMIT"] == CEILING
    assert settings["WEB_CACHE_POISON_MAX_RPS_PER_HOST"] == CEILING
    assert settings["PUREDNS_RATE_LIMIT"] == CEILING


# --- T6: the capper's gates ------------------------------------------------------------

def test_capping_does_not_apply_when_roe_is_off():
    """
    The ceiling is inert while roeEnabled is false, whatever the value says.

    Asserted rather than assumed, because the whole registry work leans on the
    RoE layer as its main control and a change that started capping unasked
    would be as surprising as one that stopped.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings.update(ROE_ENABLED=False, ROE_GLOBAL_MAX_RPS=CEILING, NAABU_RATE_LIMIT=5000)
    assert apply_roe_rate_cap(settings)["NAABU_RATE_LIMIT"] == 5000


def test_capping_does_not_apply_when_the_ceiling_is_zero():
    settings = dict(DEFAULT_SETTINGS)
    settings.update(ROE_ENABLED=True, ROE_GLOBAL_MAX_RPS=0, NAABU_RATE_LIMIT=5000)
    assert apply_roe_rate_cap(settings)["NAABU_RATE_LIMIT"] == 5000


def test_a_rate_already_below_the_ceiling_is_left_alone():
    assert apply_roe_rate_cap(_with_roe(NAABU_RATE_LIMIT=1))["NAABU_RATE_LIMIT"] == 1


def test_a_boolean_is_never_treated_as_a_rate():
    """`True == 1` in Python, so a bool reaching the capper would be rewritten."""
    settings = _with_roe()
    settings["HAKRAWLER_THREADS"] = True
    assert apply_roe_rate_cap(settings)["HAKRAWLER_THREADS"] is True


def test_no_setting_outside_the_capped_list_is_touched():
    before = _with_roe(NAABU_RATE_LIMIT=5000)
    after = apply_roe_rate_cap(dict(before))
    moved = {k for k in before if before[k] != after[k]}
    assert moved <= set(CAPPED_KEYS), f"the capper changed keys it does not own: {moved - set(CAPPED_KEYS)}"


# --- T40: the pass ordering ---------------------------------------------------------------

def test_the_governor_never_raises_what_an_earlier_pass_lowered():
    """
    Documented ordering: stealth and RoE win first, then the governor tightens
    further under live memory pressure. A reordered generator produces different
    effective settings with nothing failing, so the direction is asserted.
    """
    settings = apply_stealth_overrides(_with_roe())
    lowered = {k: v for k, v in settings.items() if isinstance(v, int) and not isinstance(v, bool)}
    after = apply_memory_governor(dict(settings))
    raised = {
        k: (lowered[k], after[k])
        for k in lowered
        if isinstance(after.get(k), int) and after[k] > lowered[k]
    }
    assert raised == {}, f"the governor RAISED values an earlier pass had lowered: {raised}"


def test_the_governor_tables_are_registry_queries():
    """
    The lists used to live in two dicts in project_settings.py. They are the
    registry's now, and they must still name only real settings.
    """
    ratio = reg.governor_ratio_keys()
    budget = reg.governor_budget_keys()
    assert ratio and budget
    unknown = sorted(k for k in {**ratio, **budget} if k not in DEFAULT_SETTINGS)
    assert unknown == [], f"governed keys that no scan ever reads: {unknown}"
    overlap = sorted(set(ratio) & set(budget))
    assert overlap == [], f"a key cannot be both ratio-scaled and byte-budgeted: {overlap}"


def test_every_budget_key_declares_a_family():
    """A budget with no bytes-per-unit family cannot be budgeted at all."""
    missing = sorted(k for k, (family, _) in reg.governor_budget_keys().items() if not family)
    assert missing == [], f"budget keys with no family: {missing}"


# --- T41: the image guardrail across every image field --------------------------------------

IMAGE_KEYS = sorted(k for k in DEFAULT_SETTINGS if k.endswith("_DOCKER_IMAGE"))


@pytest.mark.parametrize("key", IMAGE_KEYS)
def test_a_non_allowlisted_image_resolves_to_the_shipped_default(key):
    """
    The registry leaves every image column OPEN, because the runtime is the
    control. This is that control, for all of them rather than for one.
    """
    settings = dict(DEFAULT_SETTINGS)
    settings[key] = "attacker/evil:latest"
    resolved = sanitize_image_settings(settings)[key]
    assert resolved != "attacker/evil:latest"
    assert resolved in ALLOWED_TOOL_IMAGES


def test_every_image_field_has_a_registry_entry_with_the_docker_image_validator():
    """A new image column that skipped the validator would be open with no control."""
    by_key = reg.by_runtime_key()
    problems = []
    for key in IMAGE_KEYS:
        entry = by_key.get(key)
        if not entry:
            problems.append(f"{key}: no registry entry")
        elif entry.get("validator") != "docker_image":
            problems.append(f"{key}: validator is {entry.get('validator')!r}")
    assert problems == [], problems


def test_the_shipped_image_defaults_are_the_allowlist():
    """
    `ALLOWED_TOOL_IMAGES` is derived from the defaults, so the two cannot
    disagree. Asserted because the guardrail's substitution target IS that set.
    """
    shipped = {DEFAULT_SETTINGS[k] for k in IMAGE_KEYS if DEFAULT_SETTINGS[k]}
    assert shipped == set(ALLOWED_TOOL_IMAGES)
